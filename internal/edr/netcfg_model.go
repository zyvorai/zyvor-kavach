// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Network-device configuration posture review (observation only, offline). The parsers read a
// documented subset of configuration exports that the analyst sends; nothing connects to a device,
// a cloud or a controller. All parsers feed one normalised model that the rule-base analytics read.

const (
	ncMaxLines     = 200000
	ncMaxLine      = 16 << 10
	ncMaxRules     = 20000
	ncMaxObjects   = 50000
	ncExpandMax    = 64 // addresses or services kept per rule field after expansion
	ncExpandDepth  = 4
	ncShadowMax    = 2000 // rules per scope entering pairwise shadow analysis
	ncCompareMax   = 4000000
	ncBudget       = 4 * time.Second
	ncCapPerRule   = 25
	ncXMLDepth     = 48
	ncXMLNodes     = 400000
	ncXMLText      = 4096
	ncIssueMax     = 5000
	ncEvidenceMax  = 300
	ncFormatsLabel = "auto|pan-xml|fortigate|asa|iptables|nft"
)

var ncFormats = []string{"auto", "pan-xml", "fortigate", "asa", "iptables", "nft"}

type ncRuleMeta struct {
	ID, Sev, Tactic, Technique, TechID string
	Title, Why, Benign, Reference      string
	Inv, Rem                           []string
}

// netcfgRules is the rule inventory. References are original guidance sentences naming ideas from
// benchmark and vendor guidance; they quote no benchmark or vendor text.
var netcfgRules = []ncRuleMeta{
	{"netcfg-permit-any-any", "critical", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "Permit rule matches any source, destination and service",
		"A rule that allows everything removes the filtering the device exists to provide, and any later deny rule that depends on it is moot.",
		"Outbound allow-all rules scoped to one trusted zone, lab segments and temporary migration rules look like this.",
		"Rule-base guidance from firewall vendors and NIST SP 800-41 (ideas only): permit only what is needed, keep any/any off the policy.",
		[]string{"Find which zone or interface the rule applies to.", "Check hit counts, if the export has them, to see what actually uses it.", "Ask the owner for the change record."},
		[]string{"Consider replacing it with rules for the sources, destinations and services that are needed (advisory).", "Consider adding a final explicit deny with logging."}},
	{"netcfg-permit-any-service", "high", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "Permit rule allows every service",
		"Allowing all services between a source and destination widens the attack surface to every listening port, not only the needed ones.",
		"Server-to-server trust inside one tier, or a rule written before the service list was known.",
		"Least-privilege rule-base guidance: name the services instead of allowing all of them.",
		[]string{"List the services the pair really uses from logs.", "Check who owns the rule and why it was written that broadly."},
		[]string{"Consider narrowing the service field to the needed ports (advisory)."}},
	{"netcfg-permit-risky-service", "high", "Initial Access", "External Remote Services", "T1133", "Permit rule exposes a high-risk service to untrusted sources",
		"Telnet, FTP, TFTP, SMB, RDP, SNMP, database and similar services are common intrusion and brute-force targets when reachable from outside the trusted network.",
		"Published services on purpose (an FTP drop, an exposed database for a partner) and rules that rely on a VPN in front of them.",
		"Benchmark ideas for perimeter policy: no inbound management, file-sharing or database protocols from untrusted networks.",
		[]string{"Confirm the source really is untrusted (zone and address).", "Check authentication and patch level of the service behind the rule."},
		[]string{"Consider limiting the source addresses or placing the service behind a VPN (advisory)."}},
	{"netcfg-rule-shadowed", "medium", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "Rule is fully covered by an earlier rule with the opposite action",
		"First match wins, so this rule never applies; a deny hidden behind a permit gives a false sense of protection.",
		"The export omits inherited or global policy, address objects that resolve differently at run time, or negations this review does not model.",
		"Rule-base analysis ideas (shadow detection in commercial and open tools): order specific rules before general ones.",
		[]string{"Compare the two rules side by side and confirm the order.", "Check whether the earlier rule is meant to be broad."},
		[]string{"Consider reordering or removing the dead rule after review (advisory)."}},
	{"netcfg-rule-redundant", "low", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "Rule is covered by an earlier rule with the same action",
		"Redundant rules add review cost and hide the rules that matter; bloat is a common cause of mistakes.",
		"Kept deliberately for logging, counters or hit-based clean-up.",
		"Rule-base hygiene guidance: remove duplicates after confirming hit counts.",
		[]string{"Check hit counters for the redundant rule."}, []string{"Consider removing it once confirmed (advisory)."}},
	{"netcfg-rule-no-logging", "medium", "Defense Evasion", "Impair Defenses", "T1562", "Rule has traffic logging turned off",
		"Without a log record a permitted or denied flow leaves no trace for investigation.",
		"High-volume internal rules where logging is intentionally off, or logging done by a separate device.",
		"Logging guidance (NIST SP 800-41 and vendor best practice, ideas only): log denies and permits that cross a trust boundary.",
		[]string{"Check whether another system records the same flows."}, []string{"Consider enabling logging for rules that cross a trust boundary (advisory)."}},
	{"netcfg-rule-disabled", "low", "Defense Evasion", "Impair Defenses", "T1562", "Disabled rule left in the rule base",
		"Disabled rules are forgotten and can be re-enabled by mistake, and they add to review cost.",
		"A rule disabled for a planned change window.",
		"Rule-base hygiene guidance: tag a disabled rule with the date, delete it after a period.",
		[]string{"Find out when and why it was disabled."}, []string{"Consider deleting rules that are no longer needed (advisory)."}},
	{"netcfg-rule-temporary", "low", "Defense Evasion", "Impair Defenses", "T1562", "Rule looks temporary or its marker date has passed",
		"Temporary rules that stay in place become permanent exceptions nobody owns.",
		"Words such as test or temp in a name that is in fact permanent, or a date that is only a creation date.",
		"Change-control guidance: temporary access needs an owner and an expiry that is enforced.",
		[]string{"Ask the rule owner whether it is still needed."}, []string{"Consider removing or re-approving the rule (advisory)."}},
	{"netcfg-rule-no-description", "low", "Defense Evasion", "Impair Defenses", "T1562", "Permit rule has no description",
		"A permit rule with no recorded purpose cannot be reviewed or safely removed.",
		"Description kept in a ticketing system instead of the device.",
		"Policy-management guidance: every rule carries an owner and a purpose.",
		[]string{"Find the change record for the rule."}, []string{"Consider adding a description with owner and ticket (advisory)."}},
	{"netcfg-permit-no-inspection", "low", "Defense Evasion", "Impair Defenses", "T1562", "Permit rule has no security or inspection profile",
		"A permit with no threat or decryption profile passes traffic that the device could have inspected.",
		"Rules for traffic that is deliberately not inspected (backups, latency-sensitive links), or profiles applied through a group or default setting that the export does not show.",
		"Vendor best-practice ideas: attach threat-prevention and inspection profiles to permit rules.",
		[]string{"Check whether a profile group or global default applies."}, []string{"Consider attaching profiles to internet-facing permit rules (advisory)."}},
	{"netcfg-object-unused", "low", "Defense Evasion", "Impair Defenses", "T1562", "Address or service object is not referenced",
		"Unused objects are clutter and are sometimes reused later with a stale meaning.",
		"Objects staged for a planned change, or referenced from a part of the configuration that was not exported.",
		"Rule-base hygiene guidance: remove unreferenced objects.",
		[]string{"Search the full configuration for the name."}, []string{"Consider removing unreferenced objects (advisory)."}},
	{"netcfg-object-duplicate", "low", "Defense Evasion", "Impair Defenses", "T1562", "Several objects hold the same value",
		"Duplicate objects drift apart when only one is updated, which silently changes what a rule matches.",
		"Objects kept separate on purpose for ownership.",
		"Object-hygiene guidance: one object per value.",
		[]string{"Compare where each duplicate is used."}, []string{"Consider merging them (advisory)."}},
	{"netcfg-mgmt-exposed-untrusted", "high", "Initial Access", "External Remote Services", "T1133", "Management service is reachable from an untrusted network",
		"Administrative interfaces reachable from outside are a primary target for brute force and for exploitation of appliance flaws.",
		"A deliberately published admin interface with strict source restrictions that the export does not show.",
		"Hardening guidance from firewall vendors and benchmarks (ideas only): management on a dedicated, trusted interface, restricted by source.",
		[]string{"Check the interface role or zone and any permitted-address list.", "Review authentication logs for the interface."},
		[]string{"Consider moving management to a trusted interface or restricting source addresses (advisory)."}},
	{"netcfg-mgmt-weak-protocol", "high", "Credential Access", "Network Sniffing", "T1040", "Cleartext or weak administrative protocol is enabled",
		"Telnet and plain HTTP management send credentials and sessions in the clear.",
		"Isolated out-of-band lab networks.",
		"Hardening guidance: administer over SSH and HTTPS only.",
		[]string{"Confirm which interfaces and networks can reach the service."}, []string{"Consider disabling Telnet and HTTP administration (advisory)."}},
	{"netcfg-admin-unrestricted", "medium", "Initial Access", "External Remote Services", "T1133", "Administrator account or management service is not restricted by source",
		"An administrator login that works from any address widens the reach of a stolen password.",
		"Centrally controlled access (jump host, VPN) enforced elsewhere.",
		"Hardening guidance: restrict administrator logins to trusted hosts.",
		[]string{"Check where administrators actually log in from."}, []string{"Consider restricting administrators to trusted source addresses (advisory)."}},
	{"netcfg-weak-crypto", "medium", "Defense Evasion", "Weaken Encryption", "T1600", "Weak protocol version or cryptographic setting",
		"SSLv3, TLS 1.0 and 1.1, SSH protocol 1, DES, 3DES, MD5 and small Diffie-Hellman groups are broken or deprecated.",
		"Legacy peers that cannot be upgraded yet, with a plan to retire them.",
		"Benchmark ideas: require TLS 1.2 or later, SSH 2, AES and SHA-2, DH group 14 or larger.",
		[]string{"List the peers that need the weak setting."}, []string{"Consider raising the minimum versions and removing weak suites (advisory)."}},
	{"netcfg-weak-snmp", "high", "Initial Access", "Default Accounts", "T1078.001", "SNMP v1 or v2c with a default or weak community",
		"Default communities such as public and private are guessed first; a read-write community can change device configuration.",
		"A monitoring system with an isolated, filtered management network.",
		"Hardening guidance: use SNMPv3 with authentication and privacy; never keep default communities.",
		[]string{"Check which hosts may query SNMP and whether write access exists."}, []string{"Consider moving to SNMPv3 and restricting the allowed hosts (advisory)."}},
	{"netcfg-default-credentials", "high", "Initial Access", "Default Accounts", "T1078.001", "Cleartext, empty or default credential pattern in the configuration",
		"Credentials stored in clear text or left empty are exposed to anyone who can read the export or the device.",
		"A placeholder in a template or lab device.",
		"Hardening guidance: store credentials hashed, no empty passwords, no shared defaults. The value is never shown here.",
		[]string{"Check the device for the account named in the location."}, []string{"Consider rotating the credential and enabling hashed storage (advisory)."}},
	{"netcfg-default-policy-accept", "medium", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "Default policy accepts traffic",
		"A default accept policy lets through everything that no rule denies, so a missing rule becomes an open port.",
		"A host that relies on another firewall in front of it, or a tool that manages rules elsewhere.",
		"NIST SP 800-41 idea: default deny, explicit permits.",
		[]string{"Check for a final catch-all deny in the chain."}, []string{"Consider setting the default to drop and adding explicit permits (advisory)."}},
	{"netcfg-logging-disabled", "medium", "Defense Evasion", "Impair Defenses", "T1562", "Device logging is disabled or not configured",
		"Without device logs, administrator actions and denied traffic cannot be investigated.",
		"The export omits the logging section, or logs are collected by another mechanism.",
		"Logging guidance: send logs to a remote collector.",
		[]string{"Check the full configuration for a logging section."}, []string{"Consider enabling logging to a remote collector (advisory)."}},
}

func ncMeta(id string) *ncRuleMeta {
	for i := range netcfgRules {
		if netcfgRules[i].ID == id {
			return &netcfgRules[i]
		}
	}
	return nil
}

func init() {
	for _, r := range netcfgRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func netcfgRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(netcfgRules))
	for _, a := range netcfgRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

func netcfgGuidance() []GuidanceEntry {
	var out []GuidanceEntry
	for _, r := range netcfgRules {
		out = append(out, ruleEntry(r.ID, r.Title, r.Title+". A heuristic over a configuration export, not proof that the device is exposed.", r.Why, r.Benign, r.TechID, r.Inv, r.Rem))
	}
	return out
}

// ---- normalised model ----

type ncSet struct {
	Any bool
	Pfx []netip.Prefix
	Opq map[string]bool
}

func (s *ncSet) addPrefix(p netip.Prefix) {
	p = p.Masked()
	if p.Bits() == 0 {
		s.Any = true
		return
	}
	for _, q := range s.Pfx {
		if q == p {
			return
		}
	}
	s.Pfx = append(s.Pfx, p)
}
func (s *ncSet) addOpq(t string) {
	if s.Opq == nil {
		s.Opq = map[string]bool{}
	}
	s.Opq[t] = true
}
func (s *ncSet) size() int { return len(s.Pfx) + len(s.Opq) }
func (s *ncSet) merge(o ncSet) {
	if o.Any {
		s.Any = true
	}
	for _, p := range o.Pfx {
		s.addPrefix(p)
	}
	for k := range o.Opq {
		s.addOpq(k)
	}
}

// covers reports whether every member of b is inside a.
func (a *ncSet) covers(b *ncSet) bool {
	if a.Any {
		return true
	}
	if b.Any {
		return false
	}
	for _, bp := range b.Pfx {
		ok := false
		for _, ap := range a.Pfx {
			if ap.Addr().BitLen() == bp.Addr().BitLen() && ap.Bits() <= bp.Bits() && ap.Contains(bp.Addr()) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for k := range b.Opq {
		if !a.Opq[k] {
			return false
		}
	}
	return true
}

func (s *ncSet) sig() string {
	if s.Any {
		return "any"
	}
	var p []string
	for _, x := range s.Pfx {
		p = append(p, x.String())
	}
	for k := range s.Opq {
		p = append(p, k)
	}
	sort.Strings(p)
	return strings.Join(p, ",")
}

type ncRange struct {
	Proto  string // tcp, udp, icmp, ip (any protocol) or another protocol name
	Lo, Hi int
}

type ncSvc struct {
	Any bool
	R   []ncRange
	Opq map[string]bool
}

func (s *ncSvc) addRange(r ncRange) {
	if r.Proto == "ip" && r.Lo == 0 && r.Hi == 65535 {
		s.Any = true
		return
	}
	for _, q := range s.R {
		if q == r {
			return
		}
	}
	s.R = append(s.R, r)
}
func (s *ncSvc) addOpq(t string) {
	if s.Opq == nil {
		s.Opq = map[string]bool{}
	}
	s.Opq[t] = true
}
func (s *ncSvc) size() int { return len(s.R) + len(s.Opq) }
func (s *ncSvc) merge(o ncSvc) {
	if o.Any {
		s.Any = true
	}
	for _, r := range o.R {
		s.addRange(r)
	}
	for k := range o.Opq {
		s.addOpq(k)
	}
}
func (a *ncSvc) covers(b *ncSvc) bool {
	if a.Any {
		return true
	}
	if b.Any {
		return false
	}
	for _, br := range b.R {
		ok := false
		for _, ar := range a.R {
			if ncProtoCovers(ar.Proto, br.Proto) && ar.Lo <= br.Lo && br.Hi <= ar.Hi {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for k := range b.Opq {
		if !a.Opq[k] {
			return false
		}
	}
	return true
}
func (s *ncSvc) sig() string {
	if s.Any {
		return "any"
	}
	var p []string
	for _, r := range s.R {
		p = append(p, fmt.Sprintf("%s/%d-%d", r.Proto, r.Lo, r.Hi))
	}
	for k := range s.Opq {
		p = append(p, k)
	}
	sort.Strings(p)
	return strings.Join(p, ",")
}

type ncStrSet struct {
	Any bool
	M   map[string]bool
}

func (s *ncStrSet) add(v string) {
	v = strings.ToLower(v)
	if v == "any" || v == "" {
		s.Any = true
		return
	}
	if s.M == nil {
		s.M = map[string]bool{}
	}
	s.M[v] = true
}
func (a *ncStrSet) covers(b *ncStrSet) bool {
	if a.Any {
		return true
	}
	if b.Any {
		return false
	}
	for k := range b.M {
		if !a.M[k] {
			return false
		}
	}
	return true
}
func (s *ncStrSet) list() []string {
	var o []string
	for k := range s.M {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}

type ncRule struct {
	Scope, Name, Loc, Desc string
	Idx                    int
	Allow, Terminal        bool
	Disabled               bool
	SrcZ, DstZ, App        ncStrSet
	Src, Dst               ncSet
	Svc                    ncSvc
	Extra                  string // conditions this model does not compare; a rule with Extra only covers a rule with the same Extra
	Complex                bool   // expansion hit a cap or a name did not resolve: skipped by shadow analysis
	Log                    string // on, off, unknown
	Inspect                string // yes, no, unknown
	Egress                 bool   // an output chain: permit-breadth checks do not apply
	Apps                   []string
	UntrustedSrc           bool // the parser knows the source side is an untrusted interface (for example security level 0)
}

type ncObj struct {
	Kind, Name, Loc, Sig string
	Used                 bool
}

type ncIssue struct {
	Rule, Sev, Loc, Detail string
}

type ncModel struct {
	Vendor        string
	Lines         int
	Rules         []*ncRule
	Objs          map[string]*ncObj
	Issues        []ncIssue
	Notes         []string
	DescSupported bool
	ScopeCount    map[string]int
	truncated     bool
}

func newNcModel(vendor string) *ncModel {
	return &ncModel{Vendor: vendor, Objs: map[string]*ncObj{}, ScopeCount: map[string]int{}}
}

func (m *ncModel) note(s string) {
	if len(m.Notes) < 40 {
		m.Notes = append(m.Notes, webTruncate(webSanitise(s), 200))
	}
}

func (m *ncModel) issue(rule, loc, detail string) { m.issueSev(rule, "", loc, detail) }
func (m *ncModel) issueSev(rule, sev, loc, detail string) {
	if len(m.Issues) >= ncIssueMax {
		m.truncated = true
		return
	}
	m.Issues = append(m.Issues, ncIssue{Rule: rule, Sev: sev, Loc: loc, Detail: detail})
}

func (m *ncModel) addObj(kind, name, loc, sig string) {
	k := kind + ":" + strings.ToLower(name)
	if len(m.Objs) >= ncMaxObjects {
		m.truncated = true
		return
	}
	if _, ok := m.Objs[k]; !ok {
		m.Objs[k] = &ncObj{Kind: kind, Name: name, Loc: loc, Sig: sig}
	}
}
func (m *ncModel) use(kind, name string) {
	if o := m.Objs[kind+":"+strings.ToLower(name)]; o != nil {
		o.Used = true
	}
}

func (m *ncModel) addRule(r *ncRule) bool {
	if len(m.Rules) >= ncMaxRules {
		m.truncated = true
		return false
	}
	m.ScopeCount[r.Scope]++
	r.Idx = m.ScopeCount[r.Scope]
	m.Rules = append(m.Rules, r)
	return true
}

// ---- shared parsing helpers ----

var ncUntrustedRe = regexp.MustCompile(`(?i)(untrust|outside|internet|external|\bwan\b|^wan|public|^ext|-ext\b|_ext\b|^isp)`)

// ncUntrustedName is a name heuristic only: zone and interface names are the operator's choice.
func ncUntrustedName(n string) bool { return ncUntrustedRe.MatchString(n) }

func ncParseAddrTok(tok string) (netip.Prefix, bool, bool) { // prefix, isAny, ok
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return netip.Prefix{}, false, false
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		if p.Bits() == 0 {
			return p, true, true
		}
		return p.Masked(), false, true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), false, true
	}
	return netip.Prefix{}, false, false
}

// ncMaskPrefix turns an address and a dotted netmask into a prefix.
func ncMaskPrefix(addr, mask string) (netip.Prefix, bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, false
	}
	mk, err := netip.ParseAddr(mask)
	if err != nil || !mk.Is4() {
		return netip.Prefix{}, false
	}
	b := mk.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bits := 0
	for i := 31; i >= 0 && v&(1<<uint(i)) != 0; i-- {
		bits++
	}
	if bits < 32 && v<<uint(bits) != 0 {
		return netip.Prefix{}, false // non-contiguous mask
	}
	return netip.PrefixFrom(a, bits).Masked(), true
}

// ncParsePorts reads "80", "80,443", "1000-2000" or space separated forms for one protocol.
func ncParsePorts(proto, spec string) ([]ncRange, bool) {
	var out []ncRange
	spec = strings.NewReplacer(",", " ").Replace(spec)
	for _, f := range strings.Fields(spec) {
		if i := strings.IndexByte(f, ':'); i > 0 { // destination:source form: keep the destination
			f = f[:i]
		}
		lo, hi := f, f
		if i := strings.IndexByte(f, '-'); i > 0 {
			lo, hi = f[:i], f[i+1:]
		}
		l, e1 := strconv.Atoi(lo)
		h, e2 := strconv.Atoi(hi)
		if e1 != nil || e2 != nil || l < 0 || h > 65535 || l > h {
			return nil, false
		}
		out = append(out, ncRange{proto, l, h})
		if len(out) > ncExpandMax {
			return out, false
		}
	}
	return out, len(out) > 0
}

type ncRisky struct {
	Name, Proto string
	Lo, Hi      int
}

var ncRiskyPorts = []ncRisky{
	{"telnet", "tcp", 23, 23}, {"ftp", "tcp", 20, 21}, {"tftp", "udp", 69, 69}, {"rsh/rexec/rlogin", "tcp", 512, 514},
	{"smb", "tcp", 445, 445}, {"netbios", "tcp", 137, 139}, {"netbios", "udp", 137, 138}, {"msrpc", "tcp", 135, 135},
	{"rdp", "tcp", 3389, 3389}, {"rdp", "udp", 3389, 3389}, {"ssh", "tcp", 22, 22}, {"snmp", "udp", 161, 162},
	{"vnc", "tcp", 5900, 5903}, {"winrm", "tcp", 5985, 5986}, {"x11", "tcp", 6000, 6007}, {"ldap", "tcp", 389, 389},
	{"mssql", "tcp", 1433, 1433}, {"oracle", "tcp", 1521, 1521}, {"mysql", "tcp", 3306, 3306}, {"postgresql", "tcp", 5432, 5432},
	{"mongodb", "tcp", 27017, 27017}, {"redis", "tcp", 6379, 6379}, {"elasticsearch", "tcp", 9200, 9200}, {"memcached", "tcp", 11211, 11211},
	{"docker-api", "tcp", 2375, 2375},
}

// ncRiskyApps are PAN-OS-style application names; the spellings are unverified against a real export.
var ncRiskyApps = map[string]bool{"telnet": true, "ftp": true, "tftp": true, "ms-rdp": true, "smb": true, "mssql-db": true, "mysql": true, "postgres": true, "snmp": true, "vnc-base": true, "rlogin": true}

// builtin service names shared by several vendors (original table).
var ncWellKnown = map[string][]ncRange{
	"ssh": {{"tcp", 22, 22}}, "telnet": {{"tcp", 23, 23}}, "ftp": {{"tcp", 21, 21}}, "tftp": {{"udp", 69, 69}},
	"smtp": {{"tcp", 25, 25}}, "dns": {{"tcp", 53, 53}, {"udp", 53, 53}}, "http": {{"tcp", 80, 80}}, "https": {{"tcp", 443, 443}},
	"pop3": {{"tcp", 110, 110}}, "imap": {{"tcp", 143, 143}}, "ntp": {{"udp", 123, 123}}, "snmp": {{"udp", 161, 162}},
	"ldap": {{"tcp", 389, 389}}, "smb": {{"tcp", 445, 445}}, "rdp": {{"tcp", 3389, 3389}}, "mysql": {{"tcp", 3306, 3306}},
	"ms-sql": {{"tcp", 1433, 1433}}, "mssql": {{"tcp", 1433, 1433}}, "ping": {{"icmp", 0, 0}}, "ldaps": {{"tcp", 636, 636}},
	"syslog": {{"udp", 514, 514}}, "radius": {{"udp", 1812, 1813}}, "vnc": {{"tcp", 5900, 5900}}, "kerberos": {{"tcp", 88, 88}, {"udp", 88, 88}},
	"ntp-udp": {{"udp", 123, 123}}, "postgresql": {{"tcp", 5432, 5432}}, "oracle": {{"tcp", 1521, 1521}}, "domain": {{"tcp", 53, 53}, {"udp", 53, 53}},
	"www": {{"tcp", 80, 80}}, "ftp-data": {{"tcp", 20, 20}}, "netbios-ssn": {{"tcp", 139, 139}}, "sunrpc": {{"tcp", 111, 111}},
}

func ncOverlap(a ncRange, name string, rp ncRisky) bool {
	return ncProtoCovers(a.Proto, rp.Proto) && a.Lo <= rp.Hi && rp.Lo <= a.Hi
}

// risky lists the risky service names a rule's service field reaches.
func (r *ncRule) risky() []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range r.Svc.R {
		for _, rp := range ncRiskyPorts {
			if ncOverlap(a, rp.Name, rp) && !seen[rp.Name] {
				seen[rp.Name] = true
				out = append(out, rp.Name)
			}
		}
	}
	for _, a := range r.Apps {
		if ncRiskyApps[strings.ToLower(a)] && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// exposed reports whether the rule's source may be an untrusted network: any address with no
// zone limit, or a zone whose name looks untrusted.
func (r *ncRule) exposed() bool {
	if r.UntrustedSrc {
		return true
	}
	if !r.SrcZ.Any {
		for z := range r.SrcZ.M {
			if ncUntrustedName(z) {
				return true
			}
		}
		return false
	}
	return r.Src.Any
}

func ncLine(i int) string { return "line " + strconv.Itoa(i) }

// ncSplitLines splits on LF, drops CR, bounds the line count and line length.
func ncSplitLines(text string, m *ncModel) []string {
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.ReplaceAll(text, "\x00", " ")
	lines := strings.Split(text, "\n")
	if len(lines) > ncMaxLines {
		lines = lines[:ncMaxLines]
		m.truncated = true
		m.note(fmt.Sprintf("only the first %d lines were read", ncMaxLines))
	}
	for i, l := range lines {
		if len(l) > ncMaxLine {
			lines[i] = webTruncate(l, ncMaxLine)
		}
	}
	m.Lines = len(lines)
	return lines
}

// ncTokens splits a configuration line on spaces, honouring double quotes.
func ncTokens(s string) []string {
	var out []string
	var b strings.Builder
	inQ, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ && c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '"':
			inQ = !inQ
			have = true
		case !inQ && (c == ' ' || c == '\t'):
			if have || b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteByte(c)
		}
		if len(out) > 512 {
			break
		}
	}
	if have || b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

var ncSecretRe = regexp.MustCompile(`(?i)\b(pass(word|wd)?|secret|community|psk|psksecret|pre-shared-key|key|token|credential|authkey|privkey)\b(\s*[=:]\s*|\s+)("[^"]*"|\S+)`)

// ncClean makes configuration-derived text safe to place in a finding: control characters out,
// credential-looking values redacted, bounded length.
func ncClean(s string) string {
	s = webSanitise(s)
	s = ncSecretRe.ReplaceAllString(s, "$1 [redacted]")
	s = govRedact(s)
	return webTruncate(s, ncEvidenceMax)
}

var ncTempRe = regexp.MustCompile(`(?i)\b(temp|tmp|temporary|test|testing|poc|todo|fixme|remove|delete|expires?|expired|until|decom|migration)\b`)
var ncDateRe = regexp.MustCompile(`\b(20\d{2})[-/.]?(0[1-9]|1[0-2])[-/.]?(0[1-9]|[12]\d|3[01])\b`)

// ncExpiredDate returns the first date in s that is before now.
func ncExpiredDate(s string, now time.Time) (string, bool) {
	for _, m := range ncDateRe.FindAllStringSubmatch(s, 5) {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		if time.Date(y, time.Month(mo), d, 23, 59, 59, 0, time.UTC).Before(now) {
			return m[0], true
		}
	}
	return "", false
}

func ncProtoCovers(a, b string) bool {
	return a == b || a == "ip" || (a == "tcp-udp" && (b == "tcp" || b == "udp"))
}
