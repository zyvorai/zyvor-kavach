// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Firewall / WAF-style rule export review for kind "config" (analyzer
// "config-firewall"). The analyst converts a vendor export to the documented
// generic format (JSON "kavach-fwrules/1" or a CSV with a header row); Kavach
// never connects to a firewall. Checks are generic rule-hygiene concepts: any-any
// allows, world-reachable administration and datastore ports, shadowed and
// redundant rules, missing explicit default deny, unused or disabled rules and
// unreferenced objects. Rules are evaluated top to bottom, first match wins.
//
// Limits: address and service objects are expanded only through the "objects"
// table supplied in the same file (depth 4); zones, users, applications, time
// schedules and negated matches are not modelled, so shadow findings are a
// review aid and can miss or over-report on rule bases that use them.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	fwMaxRules    = 5000
	fwMaxAtoms    = 64
	fwMaxExpand   = 2000
	fwCompareBudg = 20_000_000
	fwMaxEvidence = 10
)

// FwList accepts a JSON string (split on ; , |) or a list of strings.
type FwList []string

func (l *FwList) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*l = fwSplit(s)
		return nil
	}
	var a []any
	if err := json.Unmarshal(b, &a); err != nil {
		return fmt.Errorf("expected string or list")
	}
	for _, e := range a {
		if x, ok := e.(string); ok {
			*l = append(*l, fwSplit(x)...)
		} else if f, ok := e.(float64); ok {
			*l = append(*l, strconv.FormatFloat(f, 'f', -1, 64))
		}
	}
	return nil
}

func fwSplit(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == '|' || r == '\n' })
	out := make([]string, 0, len(f))
	for _, x := range f {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// FwRule is one rule of the generic export format.
type FwRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Action      string `json:"action"`
	Enabled     *bool  `json:"enabled"`
	Source      FwList `json:"source"`
	Destination FwList `json:"destination"`
	Service     FwList `json:"service"`
	Log         *bool  `json:"log"`
	Hits        *int64 `json:"hits"`
	Comment     string `json:"comment"`
	// Aliases some exports use; folded into the fields above after parsing.
	Src      FwList `json:"src"`
	Dst      FwList `json:"dst"`
	Services FwList `json:"services"`
}

// FwObject is a named group of addresses or services.
type FwObject struct {
	Name    string `json:"name"`
	Members FwList `json:"members"`
}

// FwRuleSet is the generic export.
type FwRuleSet struct {
	Format        string     `json:"format"`
	Vendor        string     `json:"vendor"`
	DefaultAction string     `json:"default_action"`
	Rules         []FwRule   `json:"rules"`
	Objects       []FwObject `json:"objects"`
}

func fwTrimmed(text string) string { return strings.TrimSpace(strings.TrimPrefix(text, "\ufeff")) }

// fwLooksLike reports "json", "csv" or "" without fully parsing.
func fwLooksLike(text string) string {
	t := fwTrimmed(text)
	if t == "" {
		return ""
	}
	head := t
	if len(head) > 8192 {
		head = head[:8192]
	}
	if t[0] == '{' || t[0] == '[' {
		if strings.Contains(head, `"kavach-fwrules/1"`) || (t[0] == '[' && strings.Contains(head, `"action"`)) || (strings.Contains(head, `"action"`) && (strings.Contains(head, `"source"`) || strings.Contains(head, `"src"`) || strings.Contains(head, `"destination"`) || strings.Contains(head, `"dst"`) || strings.Contains(head, `"service`) || strings.Contains(head, `"rules"`))) {
			return "json"
		}
		return ""
	}
	first := strings.ToLower(strings.SplitN(head, "\n", 2)[0])
	if strings.Contains(first, "action") && (strings.Contains(first, "source") || strings.Contains(first, "src")) && strings.ContainsAny(first, ",;\t") {
		return "csv"
	}
	return ""
}

// ParseFwRules parses the generic JSON or CSV export.
func ParseFwRules(text string) (*FwRuleSet, error) {
	switch fwLooksLike(text) {
	case "json":
		return fwParseJSON(fwTrimmed(text))
	case "csv":
		return fwParseCSV(fwTrimmed(text))
	}
	return nil, fmt.Errorf("not a recognised firewall rule export")
}

func fwParseJSON(t string) (*FwRuleSet, error) {
	var rs FwRuleSet
	if t[0] == '[' {
		if err := json.Unmarshal([]byte(t), &rs.Rules); err != nil {
			return nil, fmt.Errorf("rules: %v", err)
		}
	} else {
		if err := json.Unmarshal([]byte(t), &rs); err != nil {
			return nil, fmt.Errorf("json: %v", err)
		}
	}
	if len(rs.Rules) > fwMaxRules {
		rs.Rules = rs.Rules[:fwMaxRules]
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if len(r.Source) == 0 {
			r.Source = r.Src
		}
		if len(r.Destination) == 0 {
			r.Destination = r.Dst
		}
		if len(r.Service) == 0 {
			r.Service = r.Services
		}
	}
	return &rs, nil
}

func fwParseCSV(t string) (*FwRuleSet, error) {
	delim := ','
	first := strings.SplitN(t, "\n", 2)[0]
	switch {
	case strings.Count(first, "\t") >= 2:
		delim = '\t'
	case strings.Count(first, ";") >= 2 && strings.Count(first, ",") == 0:
		delim = ';'
	}
	r := csv.NewReader(strings.NewReader(t))
	r.Comma = delim
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	hdr, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("csv header: %v", err)
	}
	col := map[string]int{}
	for i, h := range hdr {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	idx := func(names ...string) int {
		for _, n := range names {
			if i, ok := col[n]; ok {
				return i
			}
		}
		return -1
	}
	cID, cName, cAct, cEn := idx("id", "rule_id", "number"), idx("name", "rule", "rule_name"), idx("action"), idx("enabled", "status")
	cSrc, cDst, cSvc := idx("source", "src", "source_address"), idx("destination", "dst", "destination_address"), idx("service", "services", "port", "ports")
	cLog, cHits, cCom := idx("log", "logging"), idx("hits", "hit_count"), idx("comment", "description")
	if cAct < 0 || cSrc < 0 {
		return nil, fmt.Errorf("csv needs at least action and source columns")
	}
	get := func(rec []string, i int) string {
		if i >= 0 && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	boolOf := func(s string) *bool {
		switch strings.ToLower(s) {
		case "true", "yes", "y", "1", "enabled", "on":
			v := true
			return &v
		case "false", "no", "n", "0", "disabled", "off":
			v := false
			return &v
		}
		return nil
	}
	rs := &FwRuleSet{Format: "kavach-fwrules/1"}
	for len(rs.Rules) < fwMaxRules {
		rec, err := r.Read()
		if err != nil {
			break
		}
		fr := FwRule{ID: get(rec, cID), Name: get(rec, cName), Action: get(rec, cAct), Source: fwSplit(get(rec, cSrc)),
			Destination: fwSplit(get(rec, cDst)), Service: fwSplit(get(rec, cSvc)), Comment: get(rec, cCom)}
		fr.Enabled, fr.Log = boolOf(get(rec, cEn)), boolOf(get(rec, cLog))
		if h := get(rec, cHits); h != "" {
			if n, err := strconv.ParseInt(h, 10, 64); err == nil && n >= 0 {
				fr.Hits = &n
			}
		}
		rs.Rules = append(rs.Rules, fr)
	}
	return rs, nil
}

// ---- atoms ----

type fwAddr struct {
	any  bool
	pfx  netip.Prefix
	name string
}

type fwSvc struct {
	any    bool
	proto  string // "" = any protocol
	lo, hi int
	name   string
}

func fwAnyWord(s string) bool {
	switch strings.ToLower(s) {
	case "any", "*", "all", "0.0.0.0/0", "::/0", "0.0.0.0", "any/any":
		return true
	}
	return false
}

func fwParseAddr(s string) fwAddr {
	s = strings.TrimSpace(s)
	if fwAnyWord(s) {
		return fwAddr{any: true}
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return fwAddr{pfx: p.Masked()}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return fwAddr{pfx: netip.PrefixFrom(a, a.BitLen())}
	}
	return fwAddr{name: strings.ToLower(s)}
}

var fwNamedSvc = map[string]fwSvc{
	"ssh": {proto: "tcp", lo: 22, hi: 22}, "telnet": {proto: "tcp", lo: 23, hi: 23}, "http": {proto: "tcp", lo: 80, hi: 80},
	"https": {proto: "tcp", lo: 443, hi: 443}, "rdp": {proto: "tcp", lo: 3389, hi: 3389}, "dns": {proto: "udp", lo: 53, hi: 53},
	"snmp": {proto: "udp", lo: 161, hi: 161}, "mysql": {proto: "tcp", lo: 3306, hi: 3306}, "postgres": {proto: "tcp", lo: 5432, hi: 5432},
}

func fwParseSvc(s string) fwSvc {
	s = strings.ToLower(strings.TrimSpace(s))
	if fwAnyWord(s) || s == "ip" {
		return fwSvc{any: true}
	}
	if v, ok := fwNamedSvc[s]; ok {
		return v
	}
	proto, ports := "", s
	for _, sep := range []string{"/", ":"} {
		if i := strings.Index(s, sep); i > 0 {
			proto, ports = s[:i], s[i+1:]
			break
		}
	}
	switch proto {
	case "tcp", "udp", "sctp":
	case "icmp", "icmpv6":
		return fwSvc{proto: proto, lo: 0, hi: 65535}
	case "":
		if s == "tcp" || s == "udp" {
			return fwSvc{proto: s, lo: 0, hi: 65535}
		}
	default:
		return fwSvc{name: s}
	}
	if fwAnyWord(ports) {
		return fwSvc{proto: proto, lo: 0, hi: 65535}
	}
	lo, hi := ports, ports
	if i := strings.Index(ports, "-"); i > 0 {
		lo, hi = ports[:i], ports[i+1:]
	}
	l, e1 := strconv.Atoi(strings.TrimSpace(lo))
	h, e2 := strconv.Atoi(strings.TrimSpace(hi))
	if e1 != nil || e2 != nil || l < 0 || h > 65535 || l > h {
		return fwSvc{name: s}
	}
	return fwSvc{proto: proto, lo: l, hi: h}
}

func (a fwAddr) covers(b fwAddr) bool {
	switch {
	case a.any:
		return true
	case b.any:
		return false
	case a.name != "" || b.name != "":
		return a.name == b.name
	}
	return a.pfx.Bits() <= b.pfx.Bits() && a.pfx.Addr().BitLen() == b.pfx.Addr().BitLen() && a.pfx.Contains(b.pfx.Addr())
}

func (a fwSvc) covers(b fwSvc) bool {
	switch {
	case a.any:
		return true
	case b.any:
		return false
	case a.name != "" || b.name != "":
		return a.name == b.name
	}
	if a.proto != "" && a.proto != b.proto {
		return false
	}
	return a.lo <= b.lo && b.hi <= a.hi
}

func (a fwSvc) touches(ports []int) bool {
	if a.any {
		return true
	}
	if a.name != "" || (a.proto != "tcp" && a.proto != "udp" && a.proto != "") {
		return false
	}
	return iacCovers(a.lo, a.hi, ports)
}

type fwCompiled struct {
	idx                    int
	label                  string
	allow, enabled         bool
	src, dst               []fwAddr
	svc                    []fwSvc
	srcAny, dstAny, svcAny bool
	truncated              bool
	referenced             []string
	log                    *bool
	hits                   *int64
	action                 string
}

func fwActionAllow(a string) (allow, known bool) {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "allow", "accept", "permit", "pass", "allowed":
		return true, true
	case "deny", "drop", "reject", "block", "discard", "denied", "blocked":
		return false, true
	}
	return false, false
}

func fwCompile(rs *FwRuleSet) ([]fwCompiled, map[string]bool, []string) {
	objs := map[string][]string{}
	for _, o := range rs.Objects {
		if len(objs) < fwMaxExpand {
			objs[strings.ToLower(strings.TrimSpace(o.Name))] = o.Members
		}
	}
	used := map[string]bool{}
	var notes []string
	expand := func(items []string, isSvc bool) ([]fwAddr, []fwSvc, bool) {
		var as []fwAddr
		var ss []fwSvc
		trunc := false
		type qe struct {
			s string
			d int
		}
		queue := make([]qe, 0, len(items))
		for _, it := range items {
			queue = append(queue, qe{it, 0})
		}
		total := 0
		for len(queue) > 0 {
			e := queue[0]
			queue = queue[1:]
			key := strings.ToLower(strings.TrimSpace(e.s))
			if m, ok := objs[key]; ok && e.d < 4 {
				used[key] = true
				for _, x := range m {
					queue = append(queue, qe{x, e.d + 1})
				}
				continue
			}
			if total++; total > fwMaxAtoms {
				trunc = true
				break
			}
			if isSvc {
				ss = append(ss, fwParseSvc(e.s))
			} else {
				as = append(as, fwParseAddr(e.s))
			}
		}
		return as, ss, trunc
	}
	out := make([]fwCompiled, 0, len(rs.Rules))
	for i, r := range rs.Rules {
		c := fwCompiled{idx: i, label: r.ID, log: r.Log, hits: r.Hits, action: strings.ToLower(strings.TrimSpace(r.Action))}
		if c.label == "" {
			c.label = r.Name
		}
		if c.label == "" {
			c.label = "#" + strconv.Itoa(i+1)
		}
		if len(c.label) > 60 {
			c.label = c.label[:60]
		}
		c.enabled = r.Enabled == nil || *r.Enabled
		c.allow, _ = fwActionAllow(r.Action)
		var t1, t2, t3 bool
		c.src, _, t1 = expand(r.Source, false)
		c.dst, _, t2 = expand(r.Destination, false)
		_, c.svc, t3 = expand(r.Service, true)
		c.truncated = t1 || t2 || t3
		// An omitted field means "any" in most exports; say so rather than guess silently.
		if len(r.Source) == 0 {
			c.src = []fwAddr{{any: true}}
		}
		if len(r.Destination) == 0 {
			c.dst = []fwAddr{{any: true}}
		}
		if len(r.Service) == 0 {
			c.svc = []fwSvc{{any: true}}
		}
		for _, a := range c.src {
			c.srcAny = c.srcAny || a.any
		}
		for _, a := range c.dst {
			c.dstAny = c.dstAny || a.any
		}
		for _, s := range c.svc {
			c.svcAny = c.svcAny || s.any
		}
		out = append(out, c)
	}
	// Objects referenced only from other objects were marked used while expanding.
	return out, used, notes
}

func fwCoversAddrs(a, b []fwAddr, budget *int) bool {
	for _, y := range b {
		ok := false
		for _, x := range a {
			*budget--
			if x.covers(y) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func fwCoversSvcs(a, b []fwSvc, budget *int) bool {
	for _, y := range b {
		ok := false
		for _, x := range a {
			*budget--
			if x.covers(y) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// FwReview is the analyzer outcome.
type FwReview struct {
	Rules       int            `json:"rules"`
	Enabled     int            `json:"enabled"`
	Counts      map[string]int `json:"counts"`
	Notes       []string       `json:"notes,omitempty"`
	Findings    []fwFinding    `json:"-"`
	Vendor      string         `json:"vendor,omitempty"`
	DefaultAct  string         `json:"default_action,omitempty"`
	ShadowCheck string         `json:"shadow_analysis"`
}

type fwFinding struct {
	id, title, sev, tech string
	evidence             []string
	n                    int
}

// ReviewFwRules evaluates a parsed rule set. The context is polled during the
// quadratic shadow analysis.
func ReviewFwRules(ctx context.Context, rs *FwRuleSet) *FwReview {
	cr, used, _ := fwCompile(rs)
	rv := &FwReview{Rules: len(cr), Counts: map[string]int{}, Vendor: cfgAdvClip(rs.Vendor, 60), DefaultAct: cfgAdvClip(rs.DefaultAction, 20), ShadowCheck: "complete"}
	acc := map[string]*fwFinding{}
	order := []string{}
	add := func(id, title, sev, tech, label, extra string) {
		f := acc[id]
		if f == nil {
			f = &fwFinding{id: id, title: title, sev: sev, tech: tech}
			acc[id] = f
			order = append(order, id)
		}
		f.n++
		if len(f.evidence) < fwMaxEvidence {
			e := label
			if extra != "" {
				e += " (" + extra + ")"
			}
			f.evidence = append(f.evidence, e)
		}
	}
	anyHits := false
	for _, c := range cr {
		if c.hits != nil {
			anyHits = true
		}
		if c.truncated {
			rv.Notes = append(rv.Notes, "rule "+c.label+": more than "+strconv.Itoa(fwMaxAtoms)+" addresses or services in a field; the rest were ignored")
		}
	}
	var enabled []fwCompiled
	for _, c := range cr {
		if !c.enabled {
			add("fw-disabled-rule", "Disabled rules remain in the rule base", "low", "", c.label, "")
			continue
		}
		enabled = append(enabled, c)
	}
	rv.Enabled = len(enabled)
	logless := 0
	for _, c := range enabled {
		if c.allow {
			switch {
			case c.srcAny && c.dstAny && c.svcAny:
				add("fw-any-any-allow", "Allow rule matches any source, destination and service", "critical", "T1562.004", c.label, "")
			case c.srcAny && c.svcAny:
				add("fw-any-source-any-service", "Allow rule accepts any source on any service", "high", "T1190", c.label, "")
			case c.dstAny && c.svcAny:
				add("fw-any-destination-any-service", "Allow rule lets a source reach any destination on any service", "medium", "T1041", c.label, "")
			}
			if c.srcAny && !c.svcAny {
				for _, s := range c.svc {
					if s.touches(iacAdminPorts) {
						add("fw-world-admin-port", "Administration port reachable from any source", "high", "T1133", c.label, "")
						break
					}
				}
				for _, s := range c.svc {
					if s.touches(iacDataPorts) {
						add("fw-world-data-port", "Database or cache port reachable from any source", "high", "T1190", c.label, "")
						break
					}
				}
			}
			if !c.srcAny {
				for _, a := range c.src {
					if a.name == "" && ((a.pfx.Addr().Is4() && a.pfx.Bits() <= 8) || (a.pfx.Addr().Is6() && a.pfx.Bits() <= 16)) {
						add("fw-broad-source-network", "Allow rule uses a very large source network", "medium", "T1190", c.label, a.pfx.String())
						break
					}
				}
			}
			if c.log != nil && !*c.log {
				logless++
				add("fw-allow-no-logging", "Allow rules without logging", "low", "", c.label, "")
			}
		}
		if anyHits && c.hits != nil && *c.hits == 0 {
			add("fw-unused-rule", "Enabled rule with zero hits", "low", "", c.label, "")
		}
	}
	// Shadowing: a later rule fully covered by an earlier enabled rule.
	budget := fwCompareBudg
	if len(enabled) > 3000 {
		rv.ShadowCheck = "skipped: more than 3000 enabled rules"
	} else {
	outer:
		for j := 1; j < len(enabled); j++ {
			if j%32 == 0 && ctx.Err() != nil {
				rv.ShadowCheck = "stopped: context ended"
				break
			}
			b := enabled[j]
			for i := 0; i < j; i++ {
				if budget <= 0 {
					rv.ShadowCheck = "truncated: comparison budget exhausted at rule " + b.label
					break outer
				}
				a := enabled[i]
				if a.truncated || b.truncated {
					continue
				}
				if fwCoversAddrs(a.src, b.src, &budget) && fwCoversAddrs(a.dst, b.dst, &budget) && fwCoversSvcs(a.svc, b.svc, &budget) {
					if a.allow != b.allow {
						add("fw-shadowed-conflict", "Rule is never reached: an earlier rule with the opposite action covers it", "medium", "", b.label, "shadowed by "+a.label)
					} else {
						add("fw-redundant-rule", "Rule is redundant: an earlier rule with the same action covers it", "low", "", b.label, "covered by "+a.label)
					}
					break
				}
			}
		}
	}
	// Default deny.
	def := strings.ToLower(strings.TrimSpace(rs.DefaultAction))
	last := (*fwCompiled)(nil)
	if len(enabled) > 0 {
		last = &enabled[len(enabled)-1]
	}
	catchDeny := last != nil && !last.allow && last.srcAny && last.dstAny && last.svcAny
	switch {
	case def == "deny" || def == "drop" || def == "block" || def == "reject" || catchDeny:
	case def == "allow" || def == "accept":
		add("fw-no-default-deny", "Default action is allow and there is no final deny-all rule", "medium", "T1562.004", "rule base", "default_action allow")
	default:
		add("fw-no-default-deny", "No final deny-all rule and the default action is not stated", "low", "", "rule base", "set default_action in the export to confirm")
	}
	// Unused objects.
	for _, o := range rs.Objects {
		k := strings.ToLower(strings.TrimSpace(o.Name))
		if k != "" && !used[k] {
			add("fw-unused-object", "Address or service object is not referenced by any rule", "low", "", cfgAdvClip(o.Name, 60), "")
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return fwSevRank(acc[order[i]].sev) < fwSevRank(acc[order[j]].sev) })
	for _, id := range order {
		rv.Findings = append(rv.Findings, *acc[id])
		rv.Counts[id] = acc[id].n
	}
	_ = logless
	return rv
}

func fwSevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

func init() {
	RegisterAnalyzer("config-firewall", []string{InspectKindConfig}, firewallAnalyzer)
}

func firewallAnalyzer(ctx context.Context, in InspectInput, b *InspectBuilder) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("config-firewall: recovered: %v", r)
		}
	}()
	if fwLooksLike(in.Text) == "" || SniffConfigFormat(in.Name, in.Text) != "" {
		return nil
	}
	rs, perr := ParseFwRules(in.Text)
	if perr != nil {
		b.Format("config/firewall-rules")
		b.Finding(InspectFinding{ID: "cfg-parse-error", Title: "Firewall rule export could not be parsed: " + perr.Error(), Severity: "info"})
		return nil
	}
	b.Format("config/firewall-rules")
	rv := ReviewFwRules(ctx, rs)
	for _, f := range rv.Findings {
		ev := strings.Join(f.evidence, "; ")
		if f.n > len(f.evidence) {
			ev += fmt.Sprintf("; and %d more", f.n-len(f.evidence))
		}
		b.Finding(InspectFinding{ID: f.id, Title: fmt.Sprintf("[fail] %s (%d)", f.title, f.n), Severity: f.sev, Technique: f.tech, Evidence: previewOf(ev)})
	}
	b.Meta("summary", map[string]any{"rules": rv.Rules, "enabled": rv.Enabled, "counts": rv.Counts, "notes": rv.Notes, "vendor": rv.Vendor,
		"default_action": rv.DefaultAct, "shadow_analysis": rv.ShadowCheck,
		"note": "Generic rule-hygiene review of the submitted export only. Zones, users, applications, schedules, negation and objects outside the file are not modelled; shadowing assumes first-match-wins order as listed."})
	return nil
}
