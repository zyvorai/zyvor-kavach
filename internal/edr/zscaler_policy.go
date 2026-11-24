// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Offline posture review of an exported Zscaler policy set (observation only): ZIA URL filtering,
// cloud firewall, DLP web, SSL inspection and cloud-app rules, and ZPA access policies and
// application segments. The export is a JSON object whose keys name the rule lists (the shapes the
// ZIA and ZPA list APIs return, saved to a file by the operator). Nothing connects to a tenant. The
// field names used here follow those API shapes as remembered; which could not be checked against
// Zscaler's own pages is listed in docs/zscaler-analytics.md.
const (
	zpRulesMax    = 20000
	zpBroadCats   = 10
	zpStaleDays   = 365
	zpEvidenceMax = 300
)

var zsPolRules = []ncRuleMeta{
	{"zspol-url-allow-any", "high", "Defense Evasion", "Impair Defenses", "T1562", "URL filtering rule allows every category for everyone",
		"An allow rule with no category and no user, group, department or location scope lets all web traffic through at its position in the rule order.",
		"A deliberate catch-all at the bottom of the rule base after specific blocks.",
		"URL filtering best practice (ideas only): end the rule base with a deliberate default and keep earlier allows scoped.",
		[]string{"Check the rule's position: is it the last rule, after the blocks?", "Look at who the rule really covers."}, []string{"Consider scoping it by category or group (advisory)."}},
	{"zspol-url-risky-allowed", "high", "Command and Control", "Application Layer Protocol: Web Protocols", "T1071.001", "URL filtering allow rule names a risky category",
		"Anonymisers, proxy-avoidance, newly registered domains, phishing and botnet categories are common attack infrastructure.",
		"A security-research or red-team group with a scoped exception.",
		"Threat-category guidance (ideas only): block or isolate high-risk categories.",
		[]string{"Find who the rule applies to and whether it has an expiry."}, []string{"Consider blocking or isolating those categories (advisory)."}},
	{"zspol-rule-shadowed", "medium", "Defense Evasion", "Impair Defenses", "T1562", "Rule can never match because an earlier rule covers everything",
		"Rules after a universal rule in the same rule base are not reached, so a later block gives no protection.",
		"A rule left over from a migration or disabled in the console but exported as enabled.",
		"Rule-order guidance (ideas only): review ordering after every change.",
		[]string{"Compare rule order values and the universal rule's scope."}, []string{"Consider moving the universal rule to the end (advisory)."}},
	{"zspol-fw-any-any-allow", "critical", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "Cloud firewall rule allows any source, destination and service",
		"An allow with no source, destination or service restriction removes the filtering the firewall provides.",
		"A final catch-all that follows specific blocks, or an outbound-only default.",
		"Firewall rule-base guidance (ideas only): name what is allowed; keep any-any off the policy.",
		[]string{"Check whether blocks above it already cover the risky traffic."}, []string{"Consider replacing it with scoped rules and an explicit default (advisory)."}},
	{"zspol-fw-risky-service-allow", "high", "Initial Access", "External Remote Services", "T1133", "Cloud firewall allows a remote-admin or file-sharing service to any destination",
		"RDP, SMB, Telnet, VNC and WinRM to arbitrary internet destinations are rarely intended.",
		"A vendor remote-support path that has no scoped destination yet.",
		"Remote-service exposure guidance (ideas only).",
		[]string{"Find the business reason and the destinations in use."}, []string{"Consider limiting the destinations (advisory)."}},
	{"zspol-ssl-bypass-broad", "high", "Defense Evasion", "Obfuscated Files or Information", "T1027", "SSL inspection bypass is too broad",
		"A do-not-inspect rule that covers every category, many categories or file-sharing and webmail categories hides threats and data leaving inside TLS.",
		"Pinned-certificate applications, privacy-sensitive categories such as health and finance, or vendor-required exclusions.",
		"TLS inspection guidance (ideas only): keep bypasses narrow, per application and justified.",
		[]string{"List the categories and applications the bypass covers and the owner's reason."}, []string{"Consider narrowing the bypass to named applications (advisory)."}},
	{"zspol-ssl-inspection-absent", "high", "Defense Evasion", "Obfuscated Files or Information", "T1027", "No enabled SSL inspection rule decrypts traffic",
		"Without decryption, URL, DLP and threat controls only see the TLS handshake, not the content.",
		"Inspection configured in a section the export did not include, or an intentional DNS-and-SNI-only design.",
		"TLS inspection guidance (ideas only).",
		[]string{"Check the SSL inspection section of the export and the tenant's default."}, []string{"Consider adding decrypt rules for general traffic (advisory)."}},
	{"zspol-dlp-missing", "medium", "Exfiltration", "Exfiltration Over Web Service", "T1567", "No enabled DLP web rule in the export",
		"With no DLP rule, uploads to file-sharing, mail and cloud applications are not checked for sensitive data.",
		"DLP handled by another product, or the export omits the DLP section.",
		"Data-loss-prevention guidance (ideas only): cover uploads to unsanctioned and sanctioned storage.",
		[]string{"Check whether the DLP section was exported."}, []string{"Consider a DLP rule covering uploads (advisory)."}},
	{"zspol-dlp-monitor-only", "low", "Exfiltration", "Exfiltration Over Web Service", "T1567", "Every enabled DLP rule only allows (monitors)",
		"A DLP rule with an allow action records matches but does not stop the data.",
		"A staged roll-out that starts in monitor mode.",
		"DLP roll-out guidance (ideas only): move from monitor to block after tuning.",
		[]string{"Check hit counts and false-positive rates before enforcing."}, []string{"Consider enforcing the high-confidence dictionaries (advisory)."}},
	{"zspol-app-unsanctioned-allow", "medium", "Exfiltration", "Exfiltration Over Web Service", "T1567", "Cloud-app rule allows applications outside the sanctioned list",
		"Allowing an application nobody approved opens a shadow-IT data path.",
		"A new tool under evaluation that the sanctioned list lacks.",
		"Shadow-IT guidance (ideas only): sanction applications explicitly.",
		[]string{"Compare the rule's applications with the sanctioned list."}, []string{"Consider blocking or isolating unsanctioned applications (advisory)."}},
	{"zspol-rule-stale", "low", "Defense Evasion", "Impair Defenses", "T1562", "Enabled allow rule looks stale or temporary",
		"Old or time-boxed allow rules outlive their reason and widen access.",
		"Long-lived rules that are still needed.",
		"Rule-lifecycle guidance (ideas only): review allow rules on a schedule.",
		[]string{"Ask the owner whether the rule is still needed."}, []string{"Consider disabling it after confirming (advisory)."}},
	{"zspol-zpa-allow-all-apps", "high", "Lateral Movement", "Remote Services", "T1021", "ZPA access rule allows without naming an application or segment group",
		"An allow rule with no application condition gives the matched users every segment the rule base does not later deny.",
		"A rule placed after specific allows to cover remaining internal applications by design.",
		"Zero-trust guidance (ideas only): allow by application, not by network.",
		[]string{"Check the rule's conditions and position."}, []string{"Consider naming segment groups (advisory)."}},
	{"zspol-zpa-any-user", "medium", "Initial Access", "Valid Accounts", "T1078", "ZPA access rule does not restrict by user or group",
		"An allow with no SAML or SCIM group condition applies to every authenticated user.",
		"A rule for an application every employee needs.",
		"Least-privilege guidance (ideas only): scope access by identity group.",
		[]string{"Check which application it grants."}, []string{"Consider adding a group condition (advisory)."}},
	{"zspol-zpa-no-device-posture", "low", "Initial Access", "Valid Accounts", "T1078", "ZPA access rule has no device posture or trusted-network condition",
		"Without a posture check a compromised or unmanaged device reaches the application as long as the user authenticates.",
		"Applications that need to work from personal devices.",
		"Zero-trust guidance (ideas only): include device posture.",
		[]string{"Check whether posture profiles exist and could be added."}, []string{"Consider adding a posture condition (advisory)."}},
	{"zspol-zpa-wildcard-segment", "high", "Lateral Movement", "Remote Services", "T1021", "ZPA application segment is a wildcard or covers every port",
		"A segment with a catch-all domain or the full port range grants far more than one application.",
		"A migration segment that is meant to be temporary.",
		"Segment-definition guidance (ideas only): one segment per application.",
		[]string{"List the domains and ports on the segment."}, []string{"Consider splitting it into per-application segments (advisory)."}},
}

func init() {
	for _, r := range zsPolRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func zsPolMeta(id string) *ncRuleMeta {
	for i := range zsPolRules {
		if zsPolRules[i].ID == id {
			return &zsPolRules[i]
		}
	}
	return nil
}

func zspolRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(zsPolRules))
	for _, a := range zsPolRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

func zspolGuidance() []GuidanceEntry {
	var out []GuidanceEntry
	for _, r := range zsPolRules {
		out = append(out, ruleEntry(r.ID, r.Title, r.Title+". A heuristic over a policy export, not proof of exposure.", r.Why, r.Benign, r.TechID, r.Inv, r.Rem))
	}
	return out
}

type ZspolOptions struct {
	Host string
	Now  time.Time
}

type ZspolReport struct {
	Mode       string         `json:"mode"`
	Rules      map[string]int `json:"rules_by_section"`
	Score      int            `json:"posture_score"`
	Grade      string         `json:"grade"`
	ByRule     map[string]int `json:"by_rule"`
	BySeverity map[string]int `json:"by_severity"`
	Items      []NetcfgItem   `json:"items"`
	Findings   int            `json:"findings"`
	Notes      []string       `json:"notes,omitempty"`
	Note       string         `json:"note"`
}

const zspolNote = "heuristics over a policy export, not proof of exposure: the export may omit inherited, default or tenant-wide settings, empty lists are read as any, and field names follow the API shapes as documented in docs/zscaler-analytics.md. Nothing contacted a tenant."

type zpRule struct {
	Section, Name, Desc, Loc                   string
	Order                                      int
	Enabled, Allow                             bool
	Action                                     string
	Cats, Users, Apps, Svcs, Src, Dst, Engines []string
	Conds                                      map[string]bool
	Modified                                   time.Time
}

func zpGet(m map[string]any, keys ...string) any {
	for k, v := range m {
		nk := zsKey(k)
		for _, w := range keys {
			if nk == w {
				return v
			}
		}
	}
	return nil
}

func zpStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		if x != "" {
			out = append(out, x)
		}
	case json.Number:
		out = append(out, x.String())
	case []any:
		for _, e := range x {
			out = append(out, zpStrings(e)...)
		}
	case map[string]any:
		if n := zpGet(x, "name", "value", "id"); n != nil {
			out = append(out, zpStrings(n)...)
		}
	}
	return out
}

func zpIsAny(l []string) bool {
	if len(l) == 0 {
		return true
	}
	for _, s := range l {
		if strings.EqualFold(s, "any") || s == "*" || strings.EqualFold(s, "ANY") {
			return true
		}
	}
	return false
}

func zpStr(m map[string]any, keys ...string) string {
	s := zpStrings(zpGet(m, keys...))
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func zpAction(m map[string]any) string {
	v := zpGet(m, "action")
	if mm, ok := v.(map[string]any); ok {
		return strings.ToUpper(zpStr(mm, "type", "action", "name"))
	}
	if l := zpStrings(v); len(l) > 0 {
		return strings.ToUpper(l[0])
	}
	return ""
}

func zpAllowWord(a string) bool {
	return strings.Contains(a, "ALLOW") || strings.Contains(a, "PERMIT") || strings.Contains(a, "ACCEPT") || a == "CAUTION"
}

func zpBuildRule(section string, i int, m map[string]any) *zpRule {
	r := &zpRule{Section: section, Conds: map[string]bool{}}
	r.Name = webTruncate(webSanitise(zpStr(m, "name")), 80)
	if r.Name == "" {
		r.Name = "#" + strconv.Itoa(i+1)
	}
	r.Desc = webTruncate(webSanitise(zpStr(m, "description", "desc")), 200)
	r.Loc = fmt.Sprintf("%s[%d] %s", section, i+1, r.Name)
	if n, err := strconv.Atoi(zpStr(m, "order", "rank", "ruleorder")); err == nil {
		r.Order = n
	} else {
		r.Order = i + 1
	}
	st := strings.ToUpper(zpStr(m, "state", "status"))
	r.Enabled = st == "" || st == "ENABLED" || st == "TRUE" || st == "ACTIVE"
	if v, ok := zpGet(m, "disabled").(bool); ok && v {
		r.Enabled = false
	}
	r.Action = zpAction(m)
	r.Allow = zpAllowWord(r.Action)
	r.Cats = zpStrings(zpGet(m, "urlcategories", "urlcategories2", "categories"))
	r.Users = append(append(append(append(zpStrings(zpGet(m, "users")), zpStrings(zpGet(m, "groups"))...), zpStrings(zpGet(m, "departments"))...), zpStrings(zpGet(m, "locations"))...), zpStrings(zpGet(m, "locationgroups"))...)
	r.Apps = append(zpStrings(zpGet(m, "cloudapplications", "applications", "nwapplications")), zpStrings(zpGet(m, "nwapplicationgroups"))...)
	r.Svcs = append(zpStrings(zpGet(m, "nwservices")), zpStrings(zpGet(m, "nwservicegroups"))...)
	r.Src = append(zpStrings(zpGet(m, "srcips")), zpStrings(zpGet(m, "srcipgroups"))...)
	r.Dst = append(append(zpStrings(zpGet(m, "destaddresses")), zpStrings(zpGet(m, "destipgroups"))...), zpStrings(zpGet(m, "destipcategories"))...)
	r.Engines = append(zpStrings(zpGet(m, "dlpengines")), zpStrings(zpGet(m, "dlpdictionaries"))...)
	if ts, err := strconv.ParseInt(zpStr(m, "lastmodifiedtime", "modifiedtime"), 10, 64); err == nil && ts > 1e8 {
		if ts > 1e11 {
			ts /= 1000
		}
		r.Modified = time.Unix(ts, 0).UTC()
	}
	if conds, ok := zpGet(m, "conditions").([]any); ok {
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			ops, _ := zpGet(cm, "operands").([]any)
			for _, o := range ops {
				om, _ := o.(map[string]any)
				if t := strings.ToUpper(zpStr(om, "objecttype")); t != "" {
					r.Conds[t] = true
				}
			}
		}
	}
	return r
}

func zpListOf(root map[string]any, keys ...string) []map[string]any {
	v := zpGet(root, keys...)
	arr, _ := v.([]any)
	var out []map[string]any
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func zpHasAny(c map[string]bool, names ...string) bool {
	for _, n := range names {
		if c[n] {
			return true
		}
	}
	return false
}

// ZspolRun reviews one exported Zscaler policy set.
func ZspolRun(raw []byte, opt ZspolOptions) (*ZspolReport, []Finding, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, fmt.Errorf("empty policy export")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("policy export must be one JSON object whose keys name rule lists")
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	type sec struct {
		name string
		keys []string
	}
	secs := []sec{{"url_filtering", []string{"urlfilteringrules", "urlrules"}}, {"firewall", []string{"firewallfilteringrules", "firewallrules"}}, {"dlp", []string{"dlpwebrules", "dlprules"}},
		{"ssl_inspection", []string{"sslinspectionrules", "sslrules"}}, {"cloud_app", []string{"cloudappcontrolrules", "cloudapprules"}}, {"zpa_access", []string{"zpaaccesspolicies", "zpapolicies", "accesspolicies", "policies"}}}
	by := map[string][]*zpRule{}
	rep := &ZspolReport{Mode: "observe-only", Rules: map[string]int{}, ByRule: map[string]int{}, BySeverity: map[string]int{}, Items: []NetcfgItem{}, Note: zspolNote}
	total := 0
	for _, s := range secs {
		for i, m := range zpListOf(root, s.keys...) {
			total++
			if total > zpRulesMax {
				return nil, nil, fmt.Errorf("more than %d rules", zpRulesMax)
			}
			by[s.name] = append(by[s.name], zpBuildRule(s.name, i, m))
		}
		rep.Rules[s.name] = len(by[s.name])
	}
	segs := zpListOf(root, "zpaappsegments", "appsegments", "applicationsegments")
	rep.Rules["zpa_segments"] = len(segs)
	if total+len(segs) == 0 {
		return nil, nil, fmt.Errorf("no rule lists recognised (expected keys such as url_filtering_rules, firewall_filtering_rules, dlp_web_rules, ssl_inspection_rules, cloud_app_control_rules, zpa_access_policies, zpa_app_segments)")
	}
	sanctioned := map[string]bool{}
	for _, a := range zpStrings(zpGet(root, "sanctionedapps", "sanctionedapplications")) {
		sanctioned[strings.ToLower(a)] = true
	}
	var items []NetcfgItem
	add := func(rule, sev, loc, detail string) {
		mt := zsPolMeta(rule)
		if mt == nil {
			return
		}
		if sev == "" {
			sev = mt.Sev
		}
		items = append(items, NetcfgItem{Rule: rule, Severity: sev, Technique: mt.TechID, Location: webTruncate(ncClean(loc), 200), Title: mt.Title, Detail: ncClean(detail), Why: mt.Why, Benign: mt.Benign, Reference: mt.Reference})
	}
	universal := func(r *zpRule) bool {
		switch r.Section {
		case "url_filtering":
			return zpIsAny(r.Cats) && zpIsAny(r.Users) && zpIsAny(r.Apps)
		case "firewall":
			return zpIsAny(r.Src) && zpIsAny(r.Dst) && zpIsAny(r.Svcs) && zpIsAny(r.Apps) && zpIsAny(r.Users)
		case "ssl_inspection":
			return zpIsAny(r.Cats) && zpIsAny(r.Users) && zpIsAny(r.Apps)
		}
		return false
	}
	for _, sname := range []string{"url_filtering", "firewall", "ssl_inspection"} {
		rs := append([]*zpRule(nil), by[sname]...)
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Order < rs[j].Order })
		var uni *zpRule
		for _, r := range rs {
			if !r.Enabled {
				continue
			}
			if uni != nil && !strings.EqualFold(uni.Action, r.Action) {
				add("zspol-rule-shadowed", map[bool]string{true: "high", false: "medium"}[!r.Allow], r.Loc, fmt.Sprintf("rule %s comes after universal rule %s (%s), so it is never reached", r.Name, uni.Name, uni.Action))
			}
			if uni == nil && universal(r) {
				uni = r
			}
		}
	}
	for _, r := range by["url_filtering"] {
		if !r.Enabled || !r.Allow {
			continue
		}
		if zpIsAny(r.Cats) && zpIsAny(r.Users) && zpIsAny(r.Apps) {
			add("zspol-url-allow-any", "", r.Loc, fmt.Sprintf("rule %s allows every category for every user", r.Name))
		}
		for _, c := range r.Cats {
			if k := zsContains(strings.ReplaceAll(c, "_", " "), zsRiskyCats); k != "" {
				add("zspol-url-risky-allowed", "", r.Loc, fmt.Sprintf("rule %s allows category %s", r.Name, webTruncate(webSanitise(c), 60)))
				break
			}
		}
	}
	for _, r := range by["firewall"] {
		if !r.Enabled || !r.Allow {
			continue
		}
		if universal(r) {
			add("zspol-fw-any-any-allow", "", r.Loc, fmt.Sprintf("rule %s allows any source, destination and service", r.Name))
		}
		if zpIsAny(r.Dst) {
			for _, s := range r.Svcs {
				l := strings.ToLower(s)
				if strings.Contains(l, "rdp") || strings.Contains(l, "smb") || strings.Contains(l, "telnet") || strings.Contains(l, "vnc") || strings.Contains(l, "winrm") || strings.Contains(l, "netbios") {
					add("zspol-fw-risky-service-allow", "", r.Loc, fmt.Sprintf("rule %s allows %s to any destination", r.Name, webTruncate(webSanitise(s), 40)))
					break
				}
			}
		}
	}
	decrypt := 0
	for _, r := range by["ssl_inspection"] {
		if !r.Enabled {
			continue
		}
		a := strings.ToUpper(r.Action)
		if strings.Contains(a, "NOT") || strings.Contains(a, "BYPASS") {
			why := ""
			switch {
			case zpIsAny(r.Cats) && zpIsAny(r.Apps):
				why = "covers every category and application"
			case len(r.Cats) > zpBroadCats:
				why = fmt.Sprintf("covers %d categories", len(r.Cats))
			default:
				for _, c := range append(append([]string{}, r.Cats...), r.Apps...) {
					if zsContains(strings.ReplaceAll(c, "_", " "), []string{"file", "storage", "webmail", "mail", "anonymizer", "proxy"}) != "" {
						why = "covers " + webTruncate(webSanitise(c), 40)
						break
					}
				}
			}
			if why != "" {
				add("zspol-ssl-bypass-broad", "", r.Loc, fmt.Sprintf("bypass rule %s %s", r.Name, why))
			}
		} else if strings.Contains(a, "DECRYPT") || strings.Contains(a, "INSPECT") {
			decrypt++
		}
	}
	if len(by["ssl_inspection"]) > 0 && decrypt == 0 {
		add("zspol-ssl-inspection-absent", "", "ssl_inspection", "no enabled rule has a decrypt or inspect action")
	}
	enabledDLP, blockingDLP := 0, 0
	for _, r := range by["dlp"] {
		if r.Enabled {
			enabledDLP++
			if !r.Allow {
				blockingDLP++
			}
		}
	}
	if enabledDLP == 0 && (len(by["url_filtering"]) > 0 || len(by["cloud_app"]) > 0 || len(by["firewall"]) > 0) {
		add("zspol-dlp-missing", "", "dlp", "the export has web policy but no enabled DLP web rule")
	} else if enabledDLP > 0 && blockingDLP == 0 {
		add("zspol-dlp-monitor-only", "", "dlp", fmt.Sprintf("%d enabled DLP rule(s), none with a blocking action", enabledDLP))
	}
	for _, r := range by["cloud_app"] {
		if !r.Enabled || !r.Allow {
			continue
		}
		if len(sanctioned) > 0 {
			var bad []string
			for _, a := range r.Apps {
				if !sanctioned[strings.ToLower(a)] {
					bad = append(bad, webTruncate(webSanitise(a), 40))
				}
			}
			if len(bad) > 0 {
				add("zspol-app-unsanctioned-allow", "", r.Loc, fmt.Sprintf("rule %s allows %s, not on the sanctioned list", r.Name, strings.Join(bad[:min(len(bad), 5)], ", ")))
			}
		} else if zpIsAny(r.Apps) {
			add("zspol-app-unsanctioned-allow", "", r.Loc, fmt.Sprintf("rule %s allows every application and the export has no sanctioned list", r.Name))
		}
	}
	for _, sname := range []string{"url_filtering", "firewall", "cloud_app", "zpa_access"} {
		for _, r := range by[sname] {
			if !r.Enabled || !r.Allow {
				continue
			}
			txt := r.Name + " " + r.Desc
			if d, expired := ncExpiredDate(txt, now); expired {
				add("zspol-rule-stale", "medium", r.Loc, fmt.Sprintf("rule %s carries the date %s, which has passed", r.Name, d))
			} else if ncTempRe.MatchString(txt) {
				add("zspol-rule-stale", "", r.Loc, fmt.Sprintf("rule %s name or description suggests a temporary rule", r.Name))
			} else if !r.Modified.IsZero() && now.Sub(r.Modified) > zpStaleDays*24*time.Hour {
				add("zspol-rule-stale", "", r.Loc, fmt.Sprintf("rule %s was last modified %s", r.Name, r.Modified.Format("2006-01-02")))
			}
		}
	}
	for _, r := range by["zpa_access"] {
		if !r.Enabled || !r.Allow {
			continue
		}
		if !zpHasAny(r.Conds, "APP", "APP_GROUP") {
			add("zspol-zpa-allow-all-apps", "", r.Loc, fmt.Sprintf("rule %s has no application or segment-group condition", r.Name))
		}
		if !zpHasAny(r.Conds, "SAML", "SCIM", "SCIM_GROUP", "IDP") {
			add("zspol-zpa-any-user", "", r.Loc, fmt.Sprintf("rule %s has no user or group condition", r.Name))
		}
		if !zpHasAny(r.Conds, "POSTURE", "TRUSTED_NETWORK", "CLIENT_TYPE", "MACHINE_GRP") {
			add("zspol-zpa-no-device-posture", "", r.Loc, fmt.Sprintf("rule %s has no posture, trusted-network or machine-group condition", r.Name))
		}
	}
	for i, sg := range segs {
		name := zpStr(sg, "name")
		loc := fmt.Sprintf("zpa_app_segments[%d] %s", i+1, webTruncate(webSanitise(name), 80))
		why := ""
		for _, d := range zpStrings(zpGet(sg, "domainnames", "domains", "applications")) {
			if d == "*" || strings.HasPrefix(d, "*.") && strings.Count(d, ".") == 1 {
				why = "domain " + webTruncate(webSanitise(d), 40)
			}
		}
		for _, p := range zpStrings(zpGet(sg, "tcpportrange", "tcpportranges", "udpportrange", "udpportranges", "tcpports", "ports")) {
			if strings.ReplaceAll(p, " ", "") == "1-65535" || strings.ReplaceAll(p, " ", "") == "0-65535" {
				why = "the full port range"
			}
		}
		if why == "" {
			if arr, ok := zpGet(sg, "tcpportranges", "tcpportrange").([]any); ok {
				for _, e := range arr {
					if em, ok := e.(map[string]any); ok && zpStr(em, "from") == "1" && zpStr(em, "to") == "65535" {
						why = "the full port range"
					}
				}
			}
		}
		if why != "" {
			add("zspol-zpa-wildcard-segment", "", loc, fmt.Sprintf("segment %s covers %s", webTruncate(webSanitise(name), 60), why))
		}
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(items, func(i, j int) bool {
		if rank[items[i].Severity] != rank[items[j].Severity] {
			return rank[items[i].Severity] < rank[items[j].Severity]
		}
		return items[i].Rule < items[j].Rule
	})
	rep.Score, rep.Grade = ncScore(items)
	host := opt.Host
	if host == "" {
		host = "zscaler:policy"
	}
	per := map[string]int{}
	var fs []Finding
	for _, it := range items {
		rep.ByRule[it.Rule]++
		rep.BySeverity[it.Severity]++
		if per[it.Rule] >= ncCapPerRule {
			continue
		}
		per[it.Rule]++
		rep.Items = append(rep.Items, it)
		h := fnv.New64a()
		h.Write([]byte(it.Location + "|" + it.Detail))
		desc := fmt.Sprintf("%s at %s: %s. %s (heuristic over a policy export; the export may omit inherited or default settings. Possible benign cause: %s)", it.Title, it.Location, it.Detail, it.Why, it.Benign)
		fs = append(fs, Finding{ID: fmt.Sprintf("%s:%s:%x:%d", host, it.Rule, h.Sum64(), now.UnixNano()), Time: now, Host: host, Rule: it.Rule, Severity: it.Severity,
			Description: webTruncate(desc, 900), Tags: []string{it.Technique, "zscaler", "policy", "observe-only"},
			Evidence: Event{Time: now, Host: host, Executable: "zscaler:policy", Command: webTruncate(it.Location+" | "+it.Detail, zpEvidenceMax)}})
	}
	rep.Findings = len(fs)
	return rep, fs, nil
}
