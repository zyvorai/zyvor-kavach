// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Configuration parsers and the format sniffer. All parsers are hand-written
// and parse-only: they build a flat list of (key, value, line) settings and
// never execute, include or fetch anything. Includes are noted, not followed.
//
// Setting key schemes (all keys are lower-cased):
//
//	sshd/sysctl/logindefs   keyword -> value (sshd: first wins, others: last wins)
//	sudoers                 defaults.<opt>, defaults_scoped.<opt>, rule.*
//	auditd                  watch, syscall, enable, backlog, failure, rate, delete_all
//	pam                     pam.<type>.<module>, pam.module.<module>
//	nginx/apache            directive -> args; header.<name>; tls.enabled
//	k8s                     k8s.kind, k8s.workload, pod.*, container.*, container.unset.*, doc.*
//	compose                 service.*, service.unset.*
//	dockerfile              df.<instruction>, df.env.<name>, df.arg.<name>, df.final.*
//	terraform               <resource_type>.<attr>, <type>.<block>.<attr>, <key>#lit, <..>.summary

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

const cfgMaxEntries = 20000

func (d *cfgDoc) full() bool { return len(d.Entries) >= cfgMaxEntries }

// parseConfig parses text as the given format.
func parseConfig(format, text string) (*cfgDoc, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	d := &cfgDoc{Format: format, DefOcc: "all"}
	switch format {
	case CfgSSHD:
		d.DefOcc = "first"
		parseSSHD(d, text)
	case CfgSysctl:
		d.DefOcc = "last"
		parseSysctl(d, text)
	case CfgLoginDefs:
		d.DefOcc = "last"
		parseLoginDefs(d, text)
	case CfgSudoers:
		parseSudoers(d, text)
	case CfgAuditd:
		parseAuditd(d, text)
	case CfgPAM:
		parsePAM(d, text)
	case CfgNginx:
		parseNginx(d, text)
	case CfgApache:
		parseApache(d, text)
	case CfgK8s:
		return d, parseK8s(d, text)
	case CfgCompose:
		return d, parseCompose(d, text)
	case CfgDockerfile:
		parseDockerfile(d, text)
	case CfgTerraform:
		parseTerraform(d, text)
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
	return d, nil
}

func cfgLines(text string) []string { return strings.Split(text, "\n") }

func cfgUnquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// cfgKV splits "key value" or "key = value" or "key=value".
func cfgKV(line string) (string, string, bool) {
	i := strings.IndexAny(line, " \t=")
	if i <= 0 {
		return line, "", line != ""
	}
	k := line[:i]
	v := strings.TrimSpace(line[i:])
	v = strings.TrimSpace(strings.TrimPrefix(v, "="))
	return k, v, true
}

// cfgJoinContinuations joins backslash-continued lines, keeping the first
// line number of each logical line.
func cfgJoinContinuations(text string) ([]string, []int) {
	var out []string
	var nums []int
	var cur strings.Builder
	start := 0
	for i, ln := range cfgLines(text) {
		t := strings.TrimRight(ln, " \t")
		if cur.Len() == 0 {
			start = i + 1
		}
		if strings.HasSuffix(t, "\\") && len(out) < 1<<20 {
			cur.WriteString(strings.TrimSuffix(t, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(t)
		out = append(out, cur.String())
		nums = append(nums, start)
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
		nums = append(nums, start)
	}
	return out, nums
}

func parseSSHD(d *cfgDoc, text string) {
	inMatch := false
	for i, ln := range cfgLines(text) {
		if d.full() {
			return
		}
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' {
			continue
		}
		k, v, ok := cfgKV(t)
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		v = cfgUnquote(v)
		if k == "match" {
			inMatch = true
			d.add("match", v, i+1)
			continue
		}
		if k == "include" {
			d.Notes = append(d.Notes, "Include directive not followed (parse-only)")
		}
		if inMatch {
			d.add("match."+k, v, i+1)
			continue
		}
		d.add(k, v, i+1)
	}
}

func parseSysctl(d *cfgDoc, text string) {
	for i, ln := range cfgLines(text) {
		if d.full() {
			return
		}
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		eq := strings.Index(t, "=")
		if eq <= 0 {
			continue
		}
		k := strings.TrimPrefix(strings.TrimSpace(t[:eq]), "-")
		k = strings.ReplaceAll(k, "/", ".")
		k = strings.TrimPrefix(k, ".")
		d.add(k, strings.TrimSpace(t[eq+1:]), i+1)
	}
}

func parseLoginDefs(d *cfgDoc, text string) {
	for i, ln := range cfgLines(text) {
		if d.full() {
			return
		}
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' {
			continue
		}
		k, v, ok := cfgKV(t)
		if ok {
			d.add(k, cfgUnquote(v), i+1)
		}
	}
}

var (
	sudoDefaultsRe = regexp.MustCompile(`^Defaults([:@!>]\S*)?\s+(.*)$`)
	sudoAliasRe    = regexp.MustCompile(`^(User|Runas|Host|Cmnd|Cmd)_Alias\b`)
	sudoTagRe      = regexp.MustCompile(`^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT):\s*`)
)

// splitQuoted splits on sep outside double quotes.
func splitQuoted(s string, sep byte) []string {
	var out []string
	inQ := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			inQ = !inQ
		case s[i] == sep && !inQ:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func parseSudoers(d *cfgDoc, text string) {
	lines, nums := cfgJoinContinuations(text)
	for i, t := range lines {
		if d.full() {
			return
		}
		t = strings.TrimSpace(t)
		ln := nums[i]
		if t == "" {
			continue
		}
		if t[0] == '#' || t[0] == '@' {
			if strings.HasPrefix(t, "#include") || strings.HasPrefix(t, "@include") {
				d.Notes = append(d.Notes, "include directive not followed (parse-only)")
			}
			continue
		}
		if m := sudoDefaultsRe.FindStringSubmatch(t); m != nil {
			prefix := "defaults."
			if m[1] != "" {
				prefix = "defaults_scoped."
			}
			for _, opt := range splitQuoted(m[2], ',') {
				if opt == "" {
					continue
				}
				neg := strings.HasPrefix(opt, "!")
				opt = strings.TrimPrefix(opt, "!")
				name, val := opt, "true"
				if j := strings.IndexAny(opt, "=+-"); j > 0 {
					// name=val, name+=val, name-=val
					name = opt[:j]
					rest := opt[j:]
					if rest[0] != '=' && len(rest) > 1 && rest[1] == '=' {
						rest = rest[1:] // += or -=
					}
					val = cfgUnquote(strings.TrimPrefix(rest, "="))
				} else if neg {
					val = "false"
				}
				d.add(prefix+strings.TrimSpace(name), val, ln)
			}
			continue
		}
		if sudoAliasRe.MatchString(t) {
			d.add("alias", t, ln)
			continue
		}
		eq := strings.Index(t, "=")
		if eq <= 0 {
			continue
		}
		who := strings.TrimSpace(t[:eq])
		rest := strings.TrimSpace(t[eq+1:])
		runas := ""
		if strings.HasPrefix(rest, "(") {
			if j := strings.Index(rest, ")"); j > 0 {
				runas = rest[1:j]
				rest = strings.TrimSpace(rest[j+1:])
			}
		}
		var tags []string
		for {
			m := sudoTagRe.FindStringSubmatch(rest)
			if m == nil {
				break
			}
			tags = append(tags, m[1])
			rest = strings.TrimSpace(rest[len(m[0]):])
		}
		cmds := rest
		d.add("rule", t, ln)
		if f := strings.Fields(who); len(f) > 0 {
			who = f[0] // the rest of the left side is the host list
		}
		d.add("rule.who", who, ln)
		d.add("rule.runas", runas, ln)
		d.add("rule.cmds", cmds, ln)
		for _, tg := range tags {
			d.add("rule.tag", tg, ln)
		}
		nopass := false
		for _, tg := range tags {
			nopass = nopass || tg == "NOPASSWD"
		}
		for _, c := range splitQuoted(cmds, ',') {
			c = strings.TrimSpace(c)
			if strings.Contains(c, "*") {
				d.add("rule.wildcard_cmd", c, ln)
			}
			if nopass {
				d.add("rule.nopasswd_cmd", c, ln)
				if strings.EqualFold(c, "ALL") {
					d.add("rule.nopasswd_all", t, ln)
				}
			}
		}
	}
}

func parseAuditd(d *cfgDoc, text string) {
	for i, ln := range cfgLines(text) {
		if d.full() {
			return
		}
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' {
			continue
		}
		f := strings.Fields(t)
		switch f[0] {
		case "-w":
			d.add("watch", t, i+1)
		case "-a", "-A":
			d.add("syscall", t, i+1)
		case "-e":
			if len(f) > 1 {
				d.add("enable", f[1], i+1)
			}
		case "-b":
			if len(f) > 1 {
				d.add("backlog", f[1], i+1)
			}
		case "-f":
			if len(f) > 1 {
				d.add("failure", f[1], i+1)
			}
		case "-r":
			if len(f) > 1 {
				d.add("rate", f[1], i+1)
			}
		case "-D":
			d.add("delete_all", "true", i+1)
		}
		d.add("rule", t, i+1)
	}
}

var pamLineRe = regexp.MustCompile(`^-?(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$`)

func parsePAM(d *cfgDoc, text string) {
	lines, nums := cfgJoinContinuations(text)
	for i, t := range lines {
		t = strings.TrimSpace(t)
		if t == "" || t[0] == '#' {
			continue
		}
		if strings.HasPrefix(t, "@include") {
			d.Notes = append(d.Notes, "@include not followed (parse-only)")
			continue
		}
		m := pamLineRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		mod := strings.TrimSuffix(path.Base(m[3]), ".so")
		val := strings.TrimSpace(m[2] + " " + m[4])
		d.add("pam."+m[1]+"."+mod, val, nums[i])
		d.add("pam.module."+mod, m[1]+" "+val, nums[i])
	}
}

// cfgStripHashComment removes a trailing #-comment outside quotes.
func cfgStripHashComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'' && !inD:
			inS = !inS
		case s[i] == '"' && !inS:
			inD = !inD
		case s[i] == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == ';' || s[i-1] == '{'):
			return s[:i]
		}
	}
	return s
}

// cfgWords splits on whitespace honouring quotes (quotes removed).
func cfgWords(s string) []string {
	var out []string
	var cur strings.Builder
	var q byte
	has := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			q = c
			has = true
		case c == ' ' || c == '\t':
			if cur.Len() > 0 || has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 || has {
		out = append(out, cur.String())
	}
	return out
}

func parseNginx(d *cfgDoc, text string) {
	// Statement tokenizer: statements end at ';', blocks open at '{' and close at '}'.
	var cur strings.Builder
	line, startLine := 1, 1
	var inQ byte
	flush := func(end byte) {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" {
			return
		}
		w := cfgWords(s)
		if len(w) == 0 {
			return
		}
		nginxStatement(d, w, startLine)
	}
	comment := false
	for i := 0; i < len(text) && !d.full(); i++ {
		c := text[i]
		if c == '\n' {
			line++
			comment = false
			if cur.Len() == 0 {
				startLine = line
			}
		}
		if comment {
			continue
		}
		if inQ != 0 {
			cur.WriteByte(c)
			if c == inQ {
				inQ = 0
			}
			continue
		}
		switch c {
		case '#':
			comment = true
		case '"', '\'':
			inQ = c
			if cur.Len() == 0 {
				startLine = line
			}
			cur.WriteByte(c)
		case ';', '{', '}':
			flush(c)
			startLine = line
		default:
			if cur.Len() == 0 && c != ' ' && c != '\t' && c != '\n' {
				startLine = line
			}
			cur.WriteByte(c)
		}
	}
	flush(0)
}

func nginxStatement(d *cfgDoc, w []string, line int) {
	k := strings.ToLower(w[0])
	args := strings.Join(w[1:], " ")
	d.add(k, args, line)
	switch k {
	case "add_header":
		if len(w) >= 3 {
			d.add("header."+strings.ToLower(w[1]), strings.Join(w[2:], " "), line)
		}
	case "listen":
		for _, a := range w[1:] {
			if strings.EqualFold(a, "ssl") {
				d.add("tls.enabled", "true", line)
			}
		}
	case "ssl_certificate":
		d.add("tls.enabled", "true", line)
	}
}

var apacheSectionRe = regexp.MustCompile(`^<(/?)(\w+)\s*([^>]*)>$`)

func parseApache(d *cfgDoc, text string) {
	lines, nums := cfgJoinContinuations(text)
	for i, t := range lines {
		if d.full() {
			return
		}
		t = strings.TrimSpace(t)
		if t == "" || t[0] == '#' {
			continue
		}
		ln := nums[i]
		if m := apacheSectionRe.FindStringSubmatch(t); m != nil {
			if m[1] == "" {
				d.add("section."+strings.ToLower(m[2]), strings.TrimSpace(m[3]), ln)
				if strings.EqualFold(m[2], "VirtualHost") && strings.Contains(m[3], ":443") {
					d.add("tls.enabled", "true", ln)
				}
			}
			continue
		}
		w := cfgWords(t)
		if len(w) == 0 {
			continue
		}
		k := strings.ToLower(w[0])
		d.add(k, strings.Join(w[1:], " "), ln)
		switch k {
		case "header", "requestheader":
			r := w[1:]
			if len(r) > 0 && (strings.EqualFold(r[0], "always") || strings.EqualFold(r[0], "onsuccess")) {
				r = r[1:]
			}
			if len(r) >= 2 {
				act := strings.ToLower(r[0])
				val := strings.Join(r[2:], " ")
				if act == "unset" {
					val = "unset"
				}
				d.add(k+"."+strings.ToLower(r[1]), val, ln)
			}
		case "sslengine":
			if len(w) > 1 && strings.EqualFold(w[1], "on") {
				d.add("tls.enabled", "true", ln)
			}
		case "listen":
			if len(w) > 1 && strings.HasSuffix(w[1], ":443") || len(w) > 1 && w[1] == "443" {
				d.add("tls.enabled", "true", ln)
			}
		}
	}
}

// ---- YAML based formats (K8s manifests, docker-compose) via the Sigma
// importer's safe YAML-subset parser (miniYAMLParse). ----

func cfgYAMLDocs(text string) (docs []map[string]any, errs []string) {
	var chunks []string
	var cur []string
	for _, ln := range cfgLines(text) {
		tr := strings.TrimSpace(ln)
		if tr == "---" || strings.HasPrefix(tr, "--- ") || tr == "..." {
			chunks = append(chunks, strings.Join(cur, "\n"))
			cur = nil
			continue
		}
		cur = append(cur, ln)
	}
	chunks = append(chunks, strings.Join(cur, "\n"))
	for i, c := range chunks {
		if strings.TrimSpace(c) == "" {
			continue
		}
		v, err := miniYAMLParse(c)
		if err != nil {
			errs = append(errs, fmt.Sprintf("document %d: %v", i+1, err))
			continue
		}
		if m, ok := v.(map[string]any); ok {
			docs = append(docs, m)
		}
		if len(docs) >= 200 {
			break
		}
	}
	return
}

func yamlFlatten(prefix string, v any, depth int, emit func(k, val string)) {
	if depth > 24 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			yamlFlatten(p, x[k], depth+1, emit)
		}
	case []any:
		for _, e := range x {
			yamlFlatten(prefix+"[]", e, depth+1, emit)
		}
	case nil:
		emit(prefix, "")
	default:
		emit(prefix, fmt.Sprint(x))
	}
}

var k8sPodSpecPath = map[string][]string{
	"pod": {"spec"}, "podtemplate": {"template", "spec"},
	"deployment": {"spec", "template", "spec"}, "statefulset": {"spec", "template", "spec"},
	"daemonset": {"spec", "template", "spec"}, "replicaset": {"spec", "template", "spec"},
	"replicationcontroller": {"spec", "template", "spec"}, "job": {"spec", "template", "spec"},
	"cronjob": {"spec", "jobTemplate", "spec", "template", "spec"},
}

var k8sUnsetFields = []string{
	"securitycontext.runasnonroot", "securitycontext.allowprivilegeescalation", "securitycontext.readonlyrootfilesystem",
	"securitycontext.capabilities.drop[]", "securitycontext.seccompprofile.type", "securitycontext.runasuser",
	"resources.limits.cpu", "resources.limits.memory", "resources.requests.cpu", "resources.requests.memory",
}

func yamlDig(m map[string]any, p []string) map[string]any {
	for _, k := range p {
		n, ok := m[k].(map[string]any)
		if !ok {
			return nil
		}
		m = n
	}
	return m
}

// cfgEmitContainer flattens one container-like map under prefix and adds
// "<prefix>.unset.<field>" markers for important fields it does not set.
func cfgEmitContainer(d *cfgDoc, prefix string, c map[string]any, fields []string) {
	have := map[string]bool{}
	yamlFlatten(prefix, c, 0, func(k, v string) {
		d.add(k, v, 0)
		have[strings.ToLower(k)] = true
	})
	name, _ := c["name"].(string)
	if envs, ok := c["env"].([]any); ok && prefix == "container" {
		for _, e := range envs {
			if em, ok := e.(map[string]any); ok {
				if n, ok := em["name"].(string); ok {
					if v, ok := em["value"]; ok && v != nil && fmt.Sprint(v) != "" {
						d.add("container.env_literal", n+"="+fmt.Sprint(v), 0)
					}
				}
			}
		}
	}
	for _, f := range fields {
		if !have[prefix+"."+f] {
			d.add(prefix+".unset."+f, name, 0)
		}
	}
}

func parseK8s(d *cfgDoc, text string) error {
	docs, errs := cfgYAMLDocs(text)
	d.Notes = append(d.Notes, errs...)
	if len(docs) == 0 && len(errs) > 0 {
		return fmt.Errorf("yaml: %s", errs[0])
	}
	for _, doc := range docs {
		kind, _ := doc["kind"].(string)
		lk := strings.ToLower(kind)
		d.add("k8s.kind", kind, 0)
		if md, ok := doc["metadata"].(map[string]any); ok {
			if ns, ok := md["namespace"].(string); ok {
				d.add("meta.namespace", ns, 0)
			}
			if n, ok := md["name"].(string); ok {
				d.add("meta.name", n, 0)
			}
		}
		if p, ok := k8sPodSpecPath[lk]; ok {
			spec := yamlDig(doc, p)
			if spec == nil {
				continue
			}
			d.add("k8s.workload", kind, 0)
			rest := map[string]any{}
			for k, v := range spec {
				if k != "containers" && k != "initContainers" && k != "ephemeralContainers" {
					rest[k] = v
				}
			}
			yamlFlatten("pod", rest, 0, func(k, v string) { d.add(k, v, 0) })
			for _, ck := range []string{"containers", "initContainers", "ephemeralContainers"} {
				if cs, ok := spec[ck].([]any); ok {
					for _, c := range cs {
						if cm, ok := c.(map[string]any); ok {
							cfgEmitContainer(d, "container", cm, k8sUnsetFields)
						}
					}
				}
			}
			continue
		}
		switch lk {
		case "role", "clusterrole", "rolebinding", "clusterrolebinding":
			yamlFlatten("doc", doc, 0, func(k, v string) { d.add(k, v, 0) })
		}
	}
	return nil
}

func parseCompose(d *cfgDoc, text string) error {
	docs, errs := cfgYAMLDocs(text)
	d.Notes = append(d.Notes, errs...)
	if len(docs) == 0 && len(errs) > 0 {
		return fmt.Errorf("yaml: %s", errs[0])
	}
	for _, doc := range docs {
		svcs, ok := doc["services"].(map[string]any)
		if !ok {
			continue
		}
		names := make([]string, 0, len(svcs))
		for n := range svcs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if sm, ok := svcs[n].(map[string]any); ok {
				d.add("service.name", n, 0)
				sm2 := map[string]any{}
				for k, v := range sm {
					sm2[k] = v
				}
				if _, ok := sm2["name"]; !ok {
					sm2["name"] = n
				}
				cfgEmitContainer(d, "service", sm2, []string{"user", "read_only", "cap_drop[]", "security_opt[]", "healthcheck.test[]", "mem_limit"})
			}
		}
	}
	return nil
}

// ---- Dockerfile ----

var dfEnvSecretRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func parseDockerfile(d *cfgDoc, text string) {
	// join continuation lines; skip comment lines even inside continuations
	var logical []string
	var nums []int
	var cur strings.Builder
	start := 0
	for i, ln := range cfgLines(text) {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if cur.Len() == 0 {
			if t == "" {
				continue
			}
			start = i + 1
		}
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSpace(strings.TrimSuffix(t, "\\")))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(t)
		logical = append(logical, cur.String())
		nums = append(nums, start)
		cur.Reset()
	}
	if cur.Len() > 0 {
		logical = append(logical, cur.String())
		nums = append(nums, start)
	}
	stageAlias := map[string]bool{}
	stage := 0
	type fin struct {
		key, val string
		line     int
	}
	var finals []fin
	for i, t := range logical {
		if d.full() {
			return
		}
		sp := strings.IndexAny(t, " \t")
		instr, rest := strings.ToLower(t), ""
		if sp > 0 {
			instr, rest = strings.ToLower(t[:sp]), strings.TrimSpace(t[sp:])
		}
		ln := nums[i]
		d.add("df."+instr, rest, ln)
		switch instr {
		case "from":
			stage++
			finals = finals[:0]
			w := strings.Fields(rest)
			for len(w) > 0 && strings.HasPrefix(w[0], "--") {
				w = w[1:]
			}
			if len(w) > 0 {
				img := w[0]
				if !stageAlias[strings.ToLower(img)] && !strings.EqualFold(img, "scratch") {
					d.add("df.from.image", img, ln)
				}
				if len(w) >= 3 && strings.EqualFold(w[1], "as") {
					stageAlias[strings.ToLower(w[2])] = true
				}
			}
		case "user":
			finals = append(finals, fin{"df.final.user", rest, ln})
		case "healthcheck":
			finals = append(finals, fin{"df.final.healthcheck", rest, ln})
		case "env", "arg":
			dfEnvArg(d, instr, rest, ln)
		}
	}
	d.add("df.stages", fmt.Sprint(stage), 0)
	for _, f := range finals {
		d.add(f.key, f.val, f.line)
	}
}

func dfEnvArg(d *cfgDoc, instr, rest string, ln int) {
	w := cfgWords(rest)
	if len(w) == 0 {
		return
	}
	if instr == "env" && !strings.Contains(w[0], "=") {
		// legacy form: ENV key value
		d.add("df.env."+w[0], strings.Join(w[1:], " "), ln)
		return
	}
	for _, p := range w {
		if i := strings.Index(p, "="); i > 0 {
			d.add("df."+instr+"."+p[:i], p[i+1:], ln)
		} else if instr == "arg" && dfEnvSecretRe.MatchString(p) {
			d.add("df.arg."+p, "", ln)
		}
	}
}

// ---- Terraform HCL (line level: no expressions, modules or interpolation are
// evaluated; attribute values are kept as the literal text) ----

var (
	tfResRe    = regexp.MustCompile(`^(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{\s*$`)
	tfBlockRe  = regexp.MustCompile(`^([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{\s*$`)
	tfAttrRe   = regexp.MustCompile(`^([A-Za-z_][\w.-]*)\s*=\s*(.*)$`)
	tfSummAttr = map[string]bool{"type": true, "from_port": true, "to_port": true, "protocol": true, "cidr_blocks": true,
		"ipv6_cidr_blocks": true, "source_ranges": true, "direction": true, "access": true,
		"source_address_prefix": true, "source_address_prefixes": true, "destination_port_range": true}
)

type tfFrame struct {
	name  string
	attrs map[string]string
	line  int
}

func tfBalance(s string) int {
	n := 0
	inQ := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && inQ:
			i++
		case s[i] == '"':
			inQ = !inQ
		case !inQ && (s[i] == '[' || s[i] == '{' || s[i] == '('):
			n++
		case !inQ && (s[i] == ']' || s[i] == '}' || s[i] == ')'):
			n--
		}
	}
	return n
}

func tfStripComment(s string) string {
	inQ := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && inQ:
			i++
		case s[i] == '"':
			inQ = !inQ
		case !inQ && s[i] == '#':
			return s[:i]
		case !inQ && s[i] == '/' && i+1 < len(s) && s[i+1] == '/':
			return s[:i]
		}
	}
	return s
}

func parseTerraform(d *cfgDoc, text string) {
	lines := cfgLines(text)
	var stack []tfFrame
	ctx := func() string {
		var p []string
		for _, f := range stack {
			p = append(p, f.name)
		}
		return strings.Join(p, ".")
	}
	inComment := false
	for i := 0; i < len(lines) && !d.full(); i++ {
		t := strings.TrimSpace(lines[i])
		if inComment {
			if strings.Contains(t, "*/") {
				inComment = false
			}
			continue
		}
		if strings.HasPrefix(t, "/*") {
			inComment = !strings.Contains(t, "*/")
			continue
		}
		t = strings.TrimSpace(tfStripComment(t))
		if t == "" {
			continue
		}
		ln := i + 1
		if m := tfResRe.FindStringSubmatch(t); m != nil && len(stack) == 0 {
			rt := strings.ToLower(m[2])
			if m[1] == "data" {
				d.add("tf.data", rt+" "+m[3], ln)
				rt = "data." + rt
			} else {
				d.add("tf.resource", rt+" "+m[3], ln)
				d.add("resource."+rt, m[3], ln)
			}
			stack = append(stack, tfFrame{name: rt, attrs: map[string]string{}, line: ln})
			continue
		}
		if strings.HasPrefix(t, "}") {
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if len(f.attrs) > 0 {
					full := f.name
					if len(stack) > 0 {
						full = ctx() + "." + f.name
					}
					keys := make([]string, 0, len(f.attrs))
					for k := range f.attrs {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					var parts []string
					for _, k := range keys {
						parts = append(parts, k+"="+f.attrs[k])
					}
					d.add(full+".summary", strings.Join(parts, " "), f.line)
				}
			}
			continue
		}
		if m := tfAttrRe.FindStringSubmatch(t); m != nil {
			attr, val := strings.ToLower(m[1]), strings.TrimSpace(m[2])
			if strings.HasPrefix(val, "<<") {
				// heredoc: gather until the marker line
				mark := strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(val, "<<"), "-"), " ")
				var b strings.Builder
				for i++; i < len(lines); i++ {
					if strings.TrimSpace(lines[i]) == mark {
						break
					}
					if b.Len() < 4096 {
						b.WriteString(strings.TrimSpace(lines[i]) + " ")
					}
				}
				val = b.String()
			} else {
				for bal := tfBalance(val); bal > 0 && i+1 < len(lines) && len(val) < 8192; bal = tfBalance(val) {
					i++
					val += " " + strings.TrimSpace(tfStripComment(lines[i]))
				}
			}
			key := attr
			if len(stack) > 0 {
				key = ctx() + "." + attr
			}
			lit := false
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' && strings.Count(val, `"`) == 2 {
				val = val[1 : len(val)-1]
				lit = true
			}
			d.add(key, val, ln)
			if lit && !strings.Contains(val, "${") {
				d.add(key+"#lit", val, ln)
			}
			if len(stack) > 0 && tfSummAttr[attr] {
				stack[len(stack)-1].attrs[attr] = val
			}
			continue
		}
		if m := tfBlockRe.FindStringSubmatch(t); m != nil {
			name := strings.ToLower(m[1])
			if len(stack) == 0 {
				for _, l := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[2], -1) {
					name += "." + strings.ToLower(l[1])
				}
			}
			stack = append(stack, tfFrame{name: name, attrs: map[string]string{}, line: ln})
			continue
		}
		// An unrecognised line that opens a block we cannot name: track depth
		// so closing braces stay balanced.
		if strings.HasSuffix(t, "{") {
			stack = append(stack, tfFrame{name: "_", attrs: map[string]string{}, line: ln})
		}
	}
}

// ---- sniffer ----

var (
	sniffSSHDRe    = regexp.MustCompile(`(?im)^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|X11Forwarding|MaxAuthTries|UsePAM|AllowUsers|Subsystem\s+sftp|HostKey|ListenAddress|ChallengeResponseAuthentication|KbdInteractiveAuthentication)\s`)
	sniffSysctlRe  = regexp.MustCompile(`(?m)^\s*-?(net|kernel|fs|vm|user|dev)[./][A-Za-z0-9_./-]+\s*=`)
	sniffLoginRe   = regexp.MustCompile(`(?m)^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD|UID_MIN|LOGIN_RETRIES|USERGROUPS_ENAB|SYS_UID_MIN)\s`)
	sniffSudoRe    = regexp.MustCompile(`(?m)^\s*(Defaults\b|(User|Cmnd|Host|Runas)_Alias\b|[%A-Za-z_][\w%.-]*\s+\S+\s*=\s*(\([^)]*\)\s*)?(NOPASSWD:|PASSWD:)?\s*(ALL|/))`)
	sniffAuditRe   = regexp.MustCompile(`(?m)^\s*(-w\s+/|-a\s+(always|never),(exit|task|user|exclude)|-A\s+(always|never),|-e\s+[012]\s*$|-D\s*$|-b\s+\d+|-f\s+[012]\s*$)`)
	sniffPAMRe     = regexp.MustCompile(`(?m)^-?(auth|account|password|session)\s+(required|requisite|sufficient|optional|include|substack|\[[^\]]*\])\s+\S+`)
	sniffNginxRe   = regexp.MustCompile(`(?m)^\s*(server\s*\{|http\s*\{|events\s*\{|location\s+\S+\s*\{|worker_processes\s|server_name\s|ssl_protocols\s|proxy_pass\s|listen\s+[\w.:\[\]*]+)`)
	sniffApacheRe  = regexp.MustCompile(`(?im)^\s*(<VirtualHost\b|<Directory\b|ServerRoot\b|DocumentRoot\b|LoadModule\b|SSLProtocol\b|SSLEngine\b|ServerTokens\b|ServerSignature\b|TraceEnable\b)`)
	sniffTFRe      = regexp.MustCompile(`(?m)^\s*(resource|data|provider|module|variable|terraform)\s+("|\{)`)
	sniffComposeRe = regexp.MustCompile(`(?m)^services\s*:\s*$`)
	sniffK8sKind   = regexp.MustCompile(`(?m)^kind\s*:\s*\S+`)
	sniffK8sAPI    = regexp.MustCompile(`(?m)^apiVersion\s*:\s*\S+`)
	sniffDFRe      = regexp.MustCompile(`(?im)^\s*FROM\s+\S+`)
)

// SniffConfigFormat guesses the format from the (untrusted) name label and the
// content. It returns "" when nothing matches.
func SniffConfigFormat(name, text string) string {
	base := strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	switch {
	case base == "sshd_config" || strings.HasSuffix(base, "sshd_config") || strings.HasPrefix(base, "sshd_config."):
		return CfgSSHD
	case base == "sysctl.conf" || strings.HasSuffix(base, ".sysctl") || (strings.HasSuffix(base, ".conf") && strings.Contains(base, "sysctl")):
		return CfgSysctl
	case base == "login.defs":
		return CfgLoginDefs
	case base == "sudoers" || strings.HasPrefix(base, "sudoers"):
		return CfgSudoers
	case base == "audit.rules" || strings.HasSuffix(base, ".rules") && strings.Contains(base, "audit"):
		return CfgAuditd
	case base == "nginx.conf":
		return CfgNginx
	case base == "httpd.conf" || base == "apache2.conf":
		return CfgApache
	case strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile":
		return CfgDockerfile
	case strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose."):
		return CfgCompose
	case strings.HasSuffix(base, ".tf"):
		return CfgTerraform
	}
	head := text
	if len(head) > 256<<10 {
		head = head[:256<<10]
	}
	switch {
	case sniffK8sAPI.MatchString(head) && sniffK8sKind.MatchString(head):
		return CfgK8s
	case sniffComposeRe.MatchString(head):
		return CfgCompose
	case sniffTFRe.MatchString(head):
		return CfgTerraform
	case sniffDFRe.MatchString(head) && cfgLooksDockerfile(head):
		return CfgDockerfile
	case sniffAuditRe.MatchString(head):
		return CfgAuditd
	case sniffPAMRe.MatchString(head):
		return CfgPAM
	case sniffApacheRe.MatchString(head):
		return CfgApache
	case sniffNginxRe.MatchString(head) && strings.ContainsAny(head, "{;"):
		return CfgNginx
	case sniffSudoRe.MatchString(head) && regexp.MustCompile(`(?m)^\s*(Defaults\b|(User|Cmnd|Host|Runas)_Alias\b|\S+\s+\S+\s*=\s*(\([^)]*\)\s*)?(NOPASSWD:|PASSWD:)?\s*(ALL|/))`).MatchString(head):
		return CfgSudoers
	case sniffLoginRe.MatchString(head):
		return CfgLoginDefs
	case sniffSysctlRe.MatchString(head):
		return CfgSysctl
	case sniffSSHDRe.MatchString(head):
		return CfgSSHD
	}
	return ""
}

// cfgLooksDockerfile requires the first instruction to be FROM/ARG (comments
// and parser directives aside), to avoid matching prose that contains "from".
func cfgLooksDockerfile(text string) bool {
	for _, ln := range cfgLines(text) {
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' {
			continue
		}
		u := strings.ToUpper(t)
		return strings.HasPrefix(u, "FROM ") || strings.HasPrefix(u, "ARG ")
	}
	return false
}
