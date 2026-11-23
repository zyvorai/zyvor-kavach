// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Infrastructure-as-code exposure parsers for the config assessor: Terraform
// plan JSON (`terraform show -json`) and CloudFormation templates (JSON, or
// YAML with the short-form intrinsic tags stripped). Both are parsed offline
// from text the analyst submits; nothing is evaluated, expanded, fetched or
// applied. Each recognised risky pattern becomes a `risk.<name>` setting whose
// value is the resource address, so the embedded policies (iac.json) can stay
// plain declarative conditions. Unknown values (computed at apply time,
// intrinsic functions, variables) never produce a marker: a missing marker is
// not a pass for that resource, it only means no known-bad literal was seen.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	iacMaxResources = 5000
	iacMaxDepth     = 24
	iacMaxPolicyDoc = 64 << 10
)

type iacRes struct {
	typ   string
	addr  string
	attrs map[string]any
}

type iacMarks struct {
	d    *cfgDoc
	seen map[string]bool
}

func (m *iacMarks) mark(name, addr string) {
	k := name + "\x00" + addr
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	if m.seen[k] || m.d.full() {
		return
	}
	m.seen[k] = true
	m.d.add("risk."+name, addr, 0)
}

// ---- small value helpers (all tolerate arbitrary, hostile JSON shapes) ----

func iacStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func iacBool(v any) (val, known bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(x) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func iacInt(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return def
}

func iacList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case nil:
		return nil
	}
	return []any{v}
}

func iacMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// iacFirstMap returns the first map of a list-of-blocks value (Terraform plans
// render nested blocks as lists).
func iacFirstMap(v any) map[string]any {
	for _, e := range iacList(v) {
		if m := iacMap(e); m != nil {
			return m
		}
	}
	return nil
}

func iacStrings(v any) []string {
	var out []string
	for _, e := range iacList(v) {
		if s := iacStr(e); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func iacAnyOpen(cidrs ...string) bool {
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "0.0.0.0/0" || c == "::/0" || c == "*" || strings.EqualFold(c, "internet") || strings.EqualFold(c, "any") {
			return true
		}
	}
	return false
}

var iacAdminPorts = []int{22, 23, 3389, 5900, 5985, 5986}
var iacDataPorts = []int{1433, 1521, 2379, 3306, 5432, 6379, 9042, 9092, 9200, 11211, 27017}

func iacCovers(from, to int, ports []int) bool {
	for _, p := range ports {
		if from <= p && p <= to {
			return true
		}
	}
	return false
}

// iacIngress classifies one world-open ingress allowance.
func (m *iacMarks) ingress(addr, proto string, from, to int) {
	proto = strings.ToLower(proto)
	if proto == "-1" || proto == "all" || proto == "*" || (from <= 0 && to >= 65535) {
		m.mark("sg-open-all", addr)
		return
	}
	if to < from {
		from, to = to, from
	}
	if iacCovers(from, to, iacAdminPorts) {
		m.mark("sg-open-admin", addr)
	}
	if iacCovers(from, to, iacDataPorts) {
		m.mark("sg-open-data", addr)
	}
}

// iacPolicyDoc decodes an IAM-style policy given as an object or JSON string.
func iacPolicyDoc(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return x
	case string:
		if len(x) > iacMaxPolicyDoc || !strings.HasPrefix(strings.TrimSpace(x), "{") {
			return nil
		}
		var m map[string]any
		if json.Unmarshal([]byte(x), &m) == nil {
			return m
		}
	}
	return nil
}

func iacHasStar(v any) bool {
	for _, s := range iacStrings(v) {
		if s == "*" {
			return true
		}
	}
	if m := iacMap(v); m != nil {
		for _, e := range m {
			if iacHasStar(e) {
				return true
			}
		}
	}
	return false
}

// iacIdentityPolicy flags over-broad grants in an identity-based policy.
func (m *iacMarks) identityPolicy(addr string, doc map[string]any) {
	for _, s := range iacList(doc["Statement"]) {
		st := iacMap(s)
		if st == nil || !strings.EqualFold(iacStr(st["Effect"]), "Allow") {
			continue
		}
		allRes := false
		for _, r := range iacStrings(st["Resource"]) {
			if r == "*" {
				allRes = true
			}
		}
		if !allRes {
			continue
		}
		for _, a := range iacStrings(st["Action"]) {
			la := strings.ToLower(a)
			switch {
			case la == "*" || la == "*:*":
				m.mark("iam-admin-wildcard", addr)
			case strings.HasSuffix(la, ":*"):
				m.mark("iam-service-wildcard", addr)
			case la == "iam:passrole":
				m.mark("iam-passrole-any", addr)
			}
		}
	}
}

// iacPrincipalPolicy flags Allow statements for any principal with no condition.
func iacPublicPrincipal(doc map[string]any) bool {
	for _, s := range iacList(doc["Statement"]) {
		st := iacMap(s)
		if st == nil || !strings.EqualFold(iacStr(st["Effect"]), "Allow") {
			continue
		}
		if len(iacMap(st["Condition"])) > 0 {
			continue
		}
		if iacHasStar(st["Principal"]) {
			return true
		}
	}
	return false
}

// ---- Terraform plan JSON ----

func parseTFPlan(d *cfgDoc, text string) error {
	var root map[string]any
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		return fmt.Errorf("not valid JSON: %v", err)
	}
	var res []iacRes
	for _, rc := range iacList(root["resource_changes"]) {
		r := iacMap(rc)
		if r == nil {
			continue
		}
		ch := iacMap(r["change"])
		skip := false
		acts := iacStrings(ch["actions"])
		if len(acts) == 1 && acts[0] == "delete" {
			skip = true
		}
		after := iacMap(ch["after"])
		if skip || after == nil {
			continue
		}
		res = append(res, iacRes{typ: iacStr(r["type"]), addr: iacStr(r["address"]), attrs: after})
		if len(res) >= iacMaxResources {
			d.Notes = append(d.Notes, "resource list truncated at "+strconv.Itoa(iacMaxResources))
			break
		}
	}
	if len(res) == 0 {
		// A plan with only planned_values (no resource_changes) is still readable.
		walkPlannedValues(iacMap(iacMap(root["planned_values"])["root_module"]), &res, 0)
	}
	m := &iacMarks{d: d}
	for _, r := range res {
		m.tfResource(r)
	}
	if len(res) > 0 {
		d.add("iac.resources", strconv.Itoa(len(res)), 0)
	}
	return nil
}

func walkPlannedValues(mod map[string]any, out *[]iacRes, depth int) {
	if mod == nil || depth > 8 || len(*out) >= iacMaxResources {
		return
	}
	for _, r := range iacList(mod["resources"]) {
		rm := iacMap(r)
		if rm == nil {
			continue
		}
		if vals := iacMap(rm["values"]); vals != nil {
			*out = append(*out, iacRes{typ: iacStr(rm["type"]), addr: iacStr(rm["address"]), attrs: vals})
		}
	}
	for _, c := range iacList(mod["child_modules"]) {
		walkPlannedValues(iacMap(c), out, depth+1)
	}
}

func (m *iacMarks) tfResource(r iacRes) {
	a, t, addr := r.attrs, r.typ, r.addr
	switch t {
	case "aws_security_group":
		for _, e := range iacList(a["ingress"]) {
			in := iacMap(e)
			if in == nil {
				continue
			}
			if iacAnyOpen(append(iacStrings(in["cidr_blocks"]), iacStrings(in["ipv6_cidr_blocks"])...)...) {
				m.ingress(addr, iacStr(in["protocol"]), iacInt(in["from_port"], 0), iacInt(in["to_port"], 0))
			}
		}
	case "aws_security_group_rule":
		if strings.EqualFold(iacStr(a["type"]), "ingress") && iacAnyOpen(append(iacStrings(a["cidr_blocks"]), iacStrings(a["ipv6_cidr_blocks"])...)...) {
			m.ingress(addr, iacStr(a["protocol"]), iacInt(a["from_port"], 0), iacInt(a["to_port"], 0))
		}
	case "aws_vpc_security_group_ingress_rule":
		if iacAnyOpen(iacStr(a["cidr_ipv4"]), iacStr(a["cidr_ipv6"])) {
			m.ingress(addr, iacStr(a["ip_protocol"]), iacInt(a["from_port"], 0), iacInt(a["to_port"], 65535))
		}
	case "aws_s3_bucket", "aws_s3_bucket_acl":
		switch strings.ToLower(iacStr(a["acl"])) {
		case "public-read", "public-read-write", "authenticated-read":
			m.mark("s3-public-acl", addr)
		}
	case "aws_s3_bucket_public_access_block":
		for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			if v, ok := iacBool(a[k]); ok && !v {
				m.mark("s3-pab-disabled", addr)
			}
		}
	case "aws_s3_bucket_policy":
		if doc := iacPolicyDoc(a["policy"]); doc != nil && iacPublicPrincipal(doc) {
			m.mark("s3-policy-public", addr)
		}
	case "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key", "aws_lambda_permission", "aws_ecr_repository_policy", "aws_secretsmanager_secret_policy":
		if doc := iacPolicyDoc(a["policy"]); doc != nil && iacPublicPrincipal(doc) {
			m.mark("resource-policy-public", addr)
		}
		if t == "aws_lambda_permission" && iacStr(a["principal"]) == "*" && iacStr(a["source_arn"]) == "" {
			m.mark("resource-policy-public", addr)
		}
	case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
		if doc := iacPolicyDoc(a["policy"]); doc != nil {
			m.identityPolicy(addr, doc)
		}
	case "aws_iam_role":
		if doc := iacPolicyDoc(a["assume_role_policy"]); doc != nil && iacPublicPrincipal(doc) {
			m.mark("iam-trust-any", addr)
		}
	case "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance":
		if v, ok := iacBool(a["publicly_accessible"]); ok && v {
			m.mark("rds-public", addr)
		}
		if v, ok := iacBool(a["storage_encrypted"]); ok && !v {
			m.mark("storage-unencrypted", addr)
		}
	case "aws_ebs_volume":
		if v, ok := iacBool(a["encrypted"]); ok && !v {
			m.mark("storage-unencrypted", addr)
		}
	case "aws_instance", "aws_launch_template":
		if md := iacFirstMap(a["metadata_options"]); md != nil && strings.EqualFold(iacStr(md["http_tokens"]), "optional") {
			m.mark("ec2-imdsv1", addr)
		}
	case "azurerm_storage_account":
		if v, ok := iacBool(a["allow_nested_items_to_be_public"]); ok && v {
			m.mark("azure-storage-public", addr)
		}
		if v, ok := iacBool(a["https_traffic_only_enabled"]); ok && !v {
			m.mark("storage-no-tls", addr)
		}
	case "azurerm_network_security_rule":
		if strings.EqualFold(iacStr(a["direction"]), "Inbound") && strings.EqualFold(iacStr(a["access"]), "Allow") &&
			iacAnyOpen(append(iacStrings(a["source_address_prefix"]), iacStrings(a["source_address_prefixes"])...)...) {
			m.azurePorts(addr, append(iacStrings(a["destination_port_range"]), iacStrings(a["destination_port_ranges"])...))
		}
	case "google_compute_firewall":
		if d := strings.ToUpper(iacStr(a["direction"])); (d == "" || d == "INGRESS") && iacAnyOpen(iacStrings(a["source_ranges"])...) {
			for _, e := range iacList(a["allow"]) {
				al := iacMap(e)
				if al == nil {
					continue
				}
				ports := iacStrings(al["ports"])
				if len(ports) == 0 {
					m.mark("sg-open-all", addr)
					continue
				}
				m.azurePorts(addr, ports)
			}
		}
	case "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding", "google_storage_bucket_acl":
		for _, mem := range append(iacStrings(a["member"]), iacStrings(a["members"])...) {
			if mem == "allUsers" || mem == "allAuthenticatedUsers" {
				m.mark("bucket-public-principal", addr)
			}
		}
	}
}

// azurePorts classifies port range strings such as "22", "1000-2000" or "*".
func (m *iacMarks) azurePorts(addr string, ranges []string) {
	for _, p := range ranges {
		p = strings.TrimSpace(p)
		if p == "*" || strings.EqualFold(p, "any") {
			m.mark("sg-open-all", addr)
			continue
		}
		lo, hi := p, p
		if i := strings.Index(p, "-"); i > 0 {
			lo, hi = p[:i], p[i+1:]
		}
		l, e1 := strconv.Atoi(lo)
		h, e2 := strconv.Atoi(hi)
		if e1 != nil || e2 != nil {
			continue
		}
		if l <= 0 && h >= 65535 {
			m.mark("sg-open-all", addr)
			continue
		}
		if iacCovers(l, h, iacAdminPorts) {
			m.mark("sg-open-admin", addr)
		}
		if iacCovers(l, h, iacDataPorts) {
			m.mark("sg-open-data", addr)
		}
	}
}

// ---- CloudFormation ----

var cfnTagRe = regexp.MustCompile(`(^|[\s:\[,{-])!(?:Ref|Sub|GetAtt|Join|If|Equals|Not|And|Or|Select|Split|FindInMap|ImportValue|Base64|Cidr|GetAZs|Condition|Transform|Length|ToJsonString)\b[ \t]*`)

func parseCFN(d *cfgDoc, text string) error {
	var root map[string]any
	trim := strings.TrimSpace(text)
	if strings.HasPrefix(trim, "{") {
		if err := json.Unmarshal([]byte(trim), &root); err != nil {
			return fmt.Errorf("not valid JSON: %v", err)
		}
	} else {
		// Short-form intrinsics (!Ref x) are not plain YAML; drop the tag and keep the scalar.
		clean := cfnTagRe.ReplaceAllString(text, "$1")
		docs, errs := cfgYAMLDocs(clean)
		for _, e := range errs {
			d.Notes = append(d.Notes, "yaml: "+e)
		}
		if len(docs) == 0 {
			return fmt.Errorf("no CloudFormation document parsed")
		}
		root = docs[0]
	}
	resMap := iacMap(root["Resources"])
	names := make([]string, 0, len(resMap))
	for k := range resMap {
		names = append(names, k)
	}
	sort.Strings(names)
	m := &iacMarks{d: d}
	n := 0
	for _, name := range names {
		r := iacMap(resMap[name])
		if r == nil {
			continue
		}
		if n++; n > iacMaxResources {
			d.Notes = append(d.Notes, "resource list truncated at "+strconv.Itoa(iacMaxResources))
			break
		}
		m.cfnResource(iacStr(r["Type"]), name, iacMap(r["Properties"]))
	}
	if n > 0 {
		d.add("iac.resources", strconv.Itoa(n), 0)
	}
	return nil
}

func (m *iacMarks) cfnIngress(addr string, in map[string]any) {
	if in == nil {
		return
	}
	if iacAnyOpen(iacStr(in["CidrIp"]), iacStr(in["CidrIpv6"])) {
		m.ingress(addr, iacStr(in["IpProtocol"]), iacInt(in["FromPort"], 0), iacInt(in["ToPort"], 0))
	}
}

func (m *iacMarks) cfnResource(typ, addr string, p map[string]any) {
	if p == nil {
		return
	}
	switch typ {
	case "AWS::EC2::SecurityGroup":
		for _, e := range iacList(p["SecurityGroupIngress"]) {
			m.cfnIngress(addr, iacMap(e))
		}
	case "AWS::EC2::SecurityGroupIngress":
		m.cfnIngress(addr, p)
	case "AWS::S3::Bucket":
		switch strings.ToLower(iacStr(p["AccessControl"])) {
		case "publicread", "publicreadwrite", "authenticatedread":
			m.mark("s3-public-acl", addr)
		}
		if pab := iacMap(p["PublicAccessBlockConfiguration"]); pab != nil {
			for _, k := range []string{"BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"} {
				if v, ok := iacBool(pab[k]); ok && !v {
					m.mark("s3-pab-disabled", addr)
				}
			}
		}
	case "AWS::S3::BucketPolicy":
		if doc := iacPolicyDoc(p["PolicyDocument"]); doc != nil && iacPublicPrincipal(doc) {
			m.mark("s3-policy-public", addr)
		}
	case "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy":
		if doc := iacPolicyDoc(p["PolicyDocument"]); doc != nil && iacPublicPrincipal(doc) {
			m.mark("resource-policy-public", addr)
		}
	case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
		if doc := iacPolicyDoc(p["PolicyDocument"]); doc != nil {
			m.identityPolicy(addr, doc)
		}
	case "AWS::IAM::Role":
		if doc := iacPolicyDoc(p["AssumeRolePolicyDocument"]); doc != nil && iacPublicPrincipal(doc) {
			m.mark("iam-trust-any", addr)
		}
		for _, e := range iacList(p["Policies"]) {
			if pm := iacMap(e); pm != nil {
				if doc := iacPolicyDoc(pm["PolicyDocument"]); doc != nil {
					m.identityPolicy(addr, doc)
				}
			}
		}
	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
		if v, ok := iacBool(p["PubliclyAccessible"]); ok && v {
			m.mark("rds-public", addr)
		}
		if v, ok := iacBool(p["StorageEncrypted"]); ok && !v {
			m.mark("storage-unencrypted", addr)
		}
	case "AWS::EC2::Volume":
		if v, ok := iacBool(p["Encrypted"]); ok && !v {
			m.mark("storage-unencrypted", addr)
		}
	case "AWS::EC2::LaunchTemplate":
		if ld := iacMap(p["LaunchTemplateData"]); ld != nil {
			if md := iacMap(ld["MetadataOptions"]); md != nil && strings.EqualFold(iacStr(md["HttpTokens"]), "optional") {
				m.mark("ec2-imdsv1", addr)
			}
		}
	}
}
