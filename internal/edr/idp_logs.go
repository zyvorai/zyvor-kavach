// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Offline identity-provider log analytics (observation only). The operator exports Okta System Log
// or Microsoft Entra sign-in and audit logs and sends them to POST /v1/idp/logs. Kavach never calls
// an identity provider, never looks an address up and never locks, resets or revokes anything: it
// reads a small allow-list of fields, applies fixed windowed heuristics and stores findings.
// Secrets, tokens, passwords and every field outside the allow-list are never read or stored.
const (
	idpMaxRecords     = 50000
	idpFatigueWindow  = 10 * time.Minute
	idpFatigueMin     = 5
	idpFatigueSuccess = 15 * time.Minute
	idpSprayWindow    = 10 * time.Minute
	idpSprayUsers     = 10
	idpSprayPerUser   = 3
	idpPrivWindow     = 30 * time.Minute
	idpResetWindow    = time.Hour
	idpBaselineMin    = 3
	idpSessionWindow  = 10 * time.Minute
	idpDormantDefault = 90
	idpFindCapPerRule = 25
	idpMaxArray       = 20
)

var idpRules = []struct {
	ID, Tactic, Technique, TechID, Sev string
}{
	{"idp-an-mfa-fatigue", "Credential Access", "Multi-Factor Authentication Request Generation", "T1621", "medium"},
	{"idp-an-mfa-fatigue-then-success", "Credential Access", "Multi-Factor Authentication Request Generation", "T1621", "high"},
	{"idp-an-password-spray", "Credential Access", "Password Spraying", "T1110.003", "high"},
	{"idp-an-impossible-travel", "Initial Access", "Cloud Accounts", "T1078.004", "medium"},
	{"idp-an-newdevice-privilege-change", "Persistence", "Account Manipulation", "T1098", "high"},
	{"idp-an-admin-role-grant", "Privilege Escalation", "Additional Cloud Roles", "T1098.003", "medium"},
	{"idp-an-mfa-removed", "Defense Evasion", "Modify Authentication Process: Multi-Factor Authentication", "T1556.006", "medium"},
	{"idp-an-reset-then-mfa-enroll", "Persistence", "Account Manipulation: Device Registration", "T1098.005", "high"},
	{"idp-an-legacy-auth-success", "Initial Access", "Cloud Accounts", "T1078.004", "medium"},
	{"idp-an-dormant-account-use", "Initial Access", "Valid Accounts", "T1078", "medium"},
	{"idp-an-session-multi-source", "Credential Access", "Use Alternate Authentication Material: Web Session Cookie", "T1550.004", "high"},
	{"idp-an-auth-policy-weakened", "Defense Evasion", "Modify Authentication Process", "T1556", "medium"},
	{"idp-an-app-credential-or-consent", "Persistence", "Account Manipulation: Additional Cloud Credentials", "T1098.001", "medium"},
	{"idp-an-provider-risk-signal", "Initial Access", "Cloud Accounts", "T1078.004", "medium"},
}

func init() {
	for _, r := range idpRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

// idpEvent is one normalised identity-provider record.
type idpEvent struct {
	T                          time.Time
	Provider, Class            string
	User, Actor, IP            string
	Country, Device, Session   string
	Role, App, Detail          string
	Success, HasOutcome        bool
	Lat, Lon                   float64
	HasGeo, Legacy, Privileged bool
	Risk                       string // "", "medium", "high"
}

// IdpReport is the JSON response.
type IdpReport struct {
	Mode         string         `json:"mode"`
	Received     int            `json:"received"`
	Parsed       int            `json:"parsed"`
	Rejected     int            `json:"rejected"`
	Providers    map[string]int `json:"by_provider"`
	Classes      map[string]int `json:"by_event_class"`
	Users        int            `json:"distinct_users"`
	From         *time.Time     `json:"from,omitempty"`
	To           *time.Time     `json:"to,omitempty"`
	ByRule       map[string]int `json:"by_rule"`
	Findings     int            `json:"findings"`
	DormantDay   int            `json:"dormant_after_days"`
	TripwireHits int            `json:"tripwire_hits,omitempty"`
	Errors       []string       `json:"errors,omitempty"`
	Note         string         `json:"note"`
}

func idpRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(idpRules))
	for _, a := range idpRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

// idpLower returns a shallow copy of m with lower-case keys.
func idpLower(m map[string]any) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[strings.ToLower(k)] = v
	}
	return o
}

// idpList returns up to idpMaxArray object elements of the array at key.
func idpList(m map[string]any, key string) []map[string]any {
	arr, _ := idpLower(m)[key].([]any)
	var out []map[string]any
	for _, x := range arr {
		if len(out) >= idpMaxArray {
			break
		}
		if e, ok := x.(map[string]any); ok {
			out = append(out, idpLower(e))
		}
	}
	return out
}

func idpStr(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func idpClean(s string, n int) string { return webTruncate(webSanitise(strings.TrimSpace(s)), n) }

var idpPrivRoles = []string{"global admin", "super admin", "privileged", "org admin", "organization admin", "conditional access admin", "application admin", "security admin", "exchange admin", "user admin", "authentication admin", "owner"}

func idpIsPrivRole(r string) bool {
	r = strings.ToLower(r)
	for _, k := range idpPrivRoles {
		if strings.Contains(r, k) {
			return true
		}
	}
	return false
}

var idpLegacyApps = []string{"exchange activesync", "imap", "pop3", "smtp", "other clients", "autodiscover", "offline address book", "mapi over http", "outlook anywhere", "exchange web services", "reporting web services"}

func idpIsLegacyApp(a string) bool {
	a = strings.ToLower(a)
	if a == "" || a == "browser" || strings.HasPrefix(a, "mobile apps") {
		return false
	}
	for _, k := range idpLegacyApps {
		if strings.Contains(a, k) {
			return true
		}
	}
	return false
}

func idpClassifyOkta(et string, ok, hasOK bool) string {
	switch {
	case strings.HasSuffix(et, ".deny_push") || et == "user.mfa.okta_verify.deny_push":
		return "mfa_deny"
	case et == "system.push.send_factor_verify_push":
		return "mfa_push"
	case et == "user.session.start" || et == "user.authentication.auth_via_mfa" || et == "user.authentication.authenticate" || et == "user.authentication.auth_via_richclient":
		if et == "user.authentication.auth_via_mfa" && hasOK && !ok {
			return "mfa_deny"
		}
		return "signin"
	case et == "user.mfa.factor.activate":
		return "mfa_enroll"
	case et == "user.mfa.factor.deactivate" || et == "user.mfa.factor.reset_all" || et == "user.mfa.factor.suspend":
		return "mfa_reset"
	case et == "user.account.privilege.grant" || et == "group.privilege.grant":
		return "role_grant"
	case et == "user.account.reset_password" || et == "user.account.update_password":
		return "pw_reset"
	case et == "policy.rule.deactivate" || et == "policy.lifecycle.deactivate" || et == "policy.rule.delete" || et == "policy.lifecycle.delete" || et == "zone.deactivate" || et == "zone.delete":
		return "policy_change"
	case et == "system.api_token.create" || strings.Contains(et, "consent.grant"):
		return "app_cred"
	case et == "security.threat.detected" || et == "user.risk.detect":
		return "risk"
	}
	return ""
}

func idpClassifyEntraAudit(act string, disabled bool) string {
	a := strings.ToLower(act)
	switch {
	case strings.Contains(a, "member to role") && !strings.Contains(a, "approval requested") && !strings.Contains(a, "removed"):
		return "role_grant"
	case strings.Contains(a, "registered security info") || strings.Contains(a, "registered all required security info"):
		return "mfa_enroll"
	case strings.Contains(a, "deleted security info") || strings.Contains(a, "disable strong authentication"):
		return "mfa_reset"
	case strings.Contains(a, "reset password") || strings.Contains(a, "reset user password") || strings.Contains(a, "change password") || strings.Contains(a, "change user password"):
		return "pw_reset"
	case strings.Contains(a, "delete conditional access policy") || (strings.Contains(a, "update conditional access policy") && disabled):
		return "policy_change"
	case strings.Contains(a, "service principal credentials") || strings.Contains(a, "certificates and secrets") || strings.Contains(a, "consent to application") || strings.Contains(a, "add delegated permission grant"):
		return "app_cred"
	}
	return ""
}

// idpNormalize reads the allow-listed fields of one Okta, Entra or generic record.
func idpNormalize(m map[string]any) (idpEvent, string) {
	var e idpEvent
	flat := map[string]string{}
	webFlatten(m, "", 0, flat)
	lm := idpLower(m)
	t, ok := parseWebTime(webPick(flat, "published", "createddatetime", "activitydatetime", "time", "timestamp", "@timestamp", "eventtime"))
	if !ok {
		return e, "no parseable timestamp"
	}
	e.T = t
	e.IP = idpClean(webPick(flat, "client.ipaddress", "ipaddress", "initiatedby.user.ipaddress", "ip", "source_ip", "src_ip", "source.ip", "client_ip"), 64)
	e.Country = strings.ToUpper(idpClean(webPick(flat, "client.geographicalcontext.country", "location.countryorregion", "country", "country_code", "geo.country_iso_code"), 64))
	if len(e.Country) > 3 && strings.Contains(strings.ToLower(e.Country), " ") == false {
		e.Country = e.Country[:3]
	}
	lat, o1 := authFloat(webPick(flat, "client.geographicalcontext.geolocation.lat", "location.geocoordinates.latitude", "lat", "latitude"))
	lon, o2 := authFloat(webPick(flat, "client.geographicalcontext.geolocation.lon", "location.geocoordinates.longitude", "lon", "lng", "longitude"))
	if o1 && o2 && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 {
		e.Lat, e.Lon, e.HasGeo = lat, lon, true
	}
	e.Session = idpClean(webPick(flat, "authenticationcontext.externalsessionid", "sessionid", "session_id"), 128)

	_, hasOkta := lm["eventtype"]
	_, hasAct := lm["activitydisplayname"]
	_, hasUPN := lm["userprincipalname"]
	switch {
	case hasOkta:
		e.Provider = "okta"
		et := strings.ToLower(strings.TrimSpace(idpStr(lm, "eventtype")))
		res := strings.ToLower(webPick(flat, "outcome.result"))
		e.Success = res == "success" || res == "allow"
		e.HasOutcome = res != ""
		e.Class = idpClassifyOkta(et, e.Success, e.HasOutcome)
		e.Actor = strings.ToLower(idpClean(webPick(flat, "actor.alternateid", "actor.displayname", "actor.id"), 128))
		e.User = e.Actor
		for _, tg := range idpList(m, "target") {
			ty := strings.ToLower(idpStr(tg, "type"))
			if ty == "user" || ty == "usergroup" || ty == "user_group" {
				if u := idpStr(tg, "alternateid"); u != "" && ty == "user" {
					e.User = strings.ToLower(idpClean(u, 128))
				}
			}
			if ty == "appinstance" || ty == "app" {
				e.App = idpClean(idpStr(tg, "displayname"), 100)
			}
		}
		if e.Class == "role_grant" {
			if dd, ok := idpLower(m)["debugcontext"].(map[string]any); ok {
				if d2, ok := idpLower(dd)["debugdata"].(map[string]any); ok {
					e.Role = idpClean(idpStr(idpLower(d2), "privilegegranted"), 120)
				}
			}
		}
		e.Device = strings.ToLower(idpClean(webPick(flat, "client.device", "client.useragent.rawuseragent"), 120))
		e.Detail = et
		if et == "security.threat.detected" {
			e.Risk = "medium"
			if strings.Contains(strings.ToLower(idpStr(lm, "severity")), "high") {
				e.Risk = "high"
			}
		}
	case hasAct:
		e.Provider = "entra"
		act := idpStr(lm, "activitydisplayname")
		res := strings.ToLower(idpStr(lm, "result"))
		e.Success = res == "" || res == "success"
		e.HasOutcome = true
		e.Actor = strings.ToLower(idpClean(webPick(flat, "initiatedby.user.userprincipalname", "initiatedby.app.displayname", "initiatedby.user.displayname"), 128))
		disabled := false
		for _, tr := range idpList(m, "targetresources") {
			ty := strings.ToLower(idpStr(tr, "type"))
			switch ty {
			case "user":
				if u := idpStr(tr, "userprincipalname"); u != "" && e.User == "" {
					e.User = strings.ToLower(idpClean(u, 128))
				}
			case "role":
				if e.Role == "" {
					e.Role = idpClean(idpStr(tr, "displayname"), 120)
				}
			case "application", "serviceprincipal", "app":
				if e.App == "" {
					e.App = idpClean(idpStr(tr, "displayname"), 100)
				}
			}
			for _, mp := range idpList(tr, "modifiedproperties") {
				if strings.Contains(strings.ToLower(idpStr(mp, "newvalue")), "disabled") {
					disabled = true
				}
				if e.Role == "" && strings.Contains(strings.ToLower(idpStr(mp, "displayname")), "role.displayname") {
					e.Role = idpClean(strings.Trim(idpStr(mp, "newvalue"), `"`), 120)
				}
			}
		}
		if e.User == "" {
			e.User = e.Actor
		}
		e.Class = idpClassifyEntraAudit(act, disabled)
		e.Detail = strings.ToLower(idpClean(act, 120))
	case hasUPN:
		e.Provider = "entra"
		e.Class = "signin"
		e.User = strings.ToLower(idpClean(idpStr(lm, "userprincipalname"), 128))
		code := webPick(flat, "status.errorcode")
		e.HasOutcome = code != ""
		e.Success = code == "0"
		if code == "500121" {
			e.Class = "mfa_deny"
		}
		e.Device = strings.ToLower(idpClean(webPick(flat, "devicedetail.deviceid", "useragent"), 120))
		if e.Device == "" {
			e.Device = strings.ToLower(idpClean(webPick(flat, "devicedetail.operatingsystem")+"|"+webPick(flat, "devicedetail.browser"), 120))
		}
		app := webPick(flat, "clientappused")
		e.Legacy = idpIsLegacyApp(app)
		e.App = idpClean(webPick(flat, "appdisplayname"), 100)
		e.Detail = "clientapp=" + idpClean(app, 60)
		switch strings.ToLower(webPick(flat, "risklevelduringsignin", "risklevelaggregated")) {
		case "high":
			e.Risk = "high"
		case "medium":
			e.Risk = "medium"
		}
		if st := strings.ToLower(webPick(flat, "riskstate")); st == "atrisk" || st == "confirmedcompromised" {
			e.Risk = "high"
		}
	default:
		e.Provider = "generic"
		e.Class = "signin"
		e.User = strings.ToLower(idpClean(webPick(flat, "user", "username", "user.name", "email", "account", "principal"), 128))
		oc, ok := authOutcome(webPick(flat, "outcome", "result", "status", "success", "event.outcome"))
		e.Success, e.HasOutcome = oc, ok
	}
	if e.Class == "" {
		e.Class = "other"
	}
	if e.User == "" {
		return e, "missing user"
	}
	if e.Class == "role_grant" {
		e.Privileged = idpIsPrivRole(e.Role)
	}
	return e, ""
}

// AnalyzeIdpLogs normalises records and runs the identity detections.
func AnalyzeIdpLogs(recs []map[string]any, hostLabel string, dormantDays int) (*IdpReport, []Finding) {
	if dormantDays < 7 || dormantDays > 730 {
		dormantDays = idpDormantDefault
	}
	rep := &IdpReport{Mode: "observe-only", Received: len(recs), Providers: map[string]int{}, Classes: map[string]int{}, ByRule: map[string]int{}, DormantDay: dormantDays,
		Note: "offline analysis of identity-provider exports you sent; no provider is called, no address is looked up and nothing is locked, reset or revoked. Baselines exist only inside the file you send, so 'new' means new within that file. VPNs, shared devices and travel cause false positives."}
	if hostLabel == "" {
		hostLabel = "idp:logs"
	}
	var evs []idpEvent
	for i, m := range recs {
		if m == nil {
			rep.Rejected++
			if len(rep.Errors) < 5 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: not a JSON object", i))
			}
			continue
		}
		e, why := idpNormalize(m)
		if why != "" {
			rep.Rejected++
			if len(rep.Errors) < 5 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: %s", i, why))
			}
			continue
		}
		evs = append(evs, e)
		rep.Providers[e.Provider]++
		rep.Classes[e.Class]++
	}
	rep.Parsed = len(evs)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].T.Before(evs[j].T) })
	if len(evs) > 0 {
		f, l := evs[0].T, evs[len(evs)-1].T
		rep.From, rep.To = &f, &l
	}
	var out []Finding
	perRule := map[string]int{}
	add := func(rule string, t time.Time, ip, user, desc string, sevOverride ...string) {
		if perRule[rule] >= idpFindCapPerRule {
			return
		}
		perRule[rule]++
		rep.ByRule[rule]++
		sev := "medium"
		for _, a := range idpRules {
			if a.ID == rule {
				sev = a.Sev
			}
		}
		if len(sevOverride) > 0 {
			sev = sevOverride[0]
		}
		m := ruleMITRE[rule]
		out = append(out, Finding{ID: fmt.Sprintf("%s:%s:%s:%s:%d", hostLabel, rule, ip, user, t.UnixNano()), Time: t, Host: hostLabel, Rule: rule, Severity: sev,
			Description: desc + " (heuristic over the logs you sent; investigate, not proof of compromise)", Destination: ip,
			Tags:     []string{m.ID, "idp", "analytics", "observe-only"},
			Evidence: Event{Time: t, Host: hostLabel, Executable: "idp:log", Command: webTruncate(desc, 300)}})
	}
	users := map[string]bool{}
	prompts := map[string][]time.Time{}
	fatigue := map[string]time.Time{}
	fatigueDone := map[string]bool{}
	fails := map[string][]struct {
		t time.Time
		u string
	}{}
	sprayDone := map[string]bool{}
	type succ struct {
		last      idpEvent
		n         int
		devs      map[string]bool
		countries map[string]bool
	}
	succs := map[string]*succ{}
	newCtx := map[string]time.Time{}
	privDone := map[string]bool{}
	resets := map[string]time.Time{}
	resetDone := map[string]bool{}
	legacyDone := map[string]bool{}
	dormDone := map[string]bool{}
	sessions := map[string]idpEvent{}
	sessDone := map[string]bool{}
	dormant := time.Duration(dormantDays) * 24 * time.Hour
	for _, e := range evs {
		if len(users) < 200000 {
			users[e.User] = true
		}
		switch e.Class {
		case "mfa_deny", "mfa_push":
			if len(prompts) < 100000 || prompts[e.User] != nil {
				p := prompts[e.User]
				cut := e.T.Add(-idpFatigueWindow)
				kept := p[:0]
				for _, x := range p {
					if x.After(cut) {
						kept = append(kept, x)
					}
				}
				kept = append(kept, e.T)
				if len(kept) > 64 {
					kept = kept[len(kept)-64:]
				}
				prompts[e.User] = kept
				if len(kept) >= idpFatigueMin {
					if _, seen := fatigue[e.User]; !seen {
						add("idp-an-mfa-fatigue", e.T, e.IP, e.User, fmt.Sprintf("%s received %d denied or repeated MFA prompts within %s", e.User, len(kept), idpFatigueWindow))
					}
					fatigue[e.User] = e.T
				}
			}
		case "signin":
			if e.Success {
				if ft, ok := fatigue[e.User]; ok && !fatigueDone[e.User] && e.T.Sub(ft) <= idpFatigueSuccess {
					fatigueDone[e.User] = true
					add("idp-an-mfa-fatigue-then-success", e.T, e.IP, e.User, fmt.Sprintf("%s signed in %s after a burst of MFA prompts (possible push fatigue approval)", e.User, e.T.Sub(ft).Round(time.Second)))
				}
				if e.Legacy && !legacyDone[e.User] {
					legacyDone[e.User] = true
					add("idp-an-legacy-auth-success", e.T, e.IP, e.User, fmt.Sprintf("%s signed in with a legacy protocol client (%s), which commonly bypasses multi-factor authentication", e.User, e.Detail))
				}
				if e.Risk != "" {
					add("idp-an-provider-risk-signal", e.T, e.IP, e.User, fmt.Sprintf("successful sign-in for %s carries a provider risk level of %s in the export", e.User, e.Risk))
				}
				if e.Session != "" {
					if first, ok := sessions[e.Session]; ok {
						far := first.IP != e.IP && e.T.Sub(first.T) <= idpSessionWindow
						if far && first.HasGeo && e.HasGeo {
							far = authHaversineKm(first.Lat, first.Lon, e.Lat, e.Lon) >= authTravelMinKm
						} else if far {
							far = first.Country != "" && e.Country != "" && first.Country != e.Country
						}
						if far && !sessDone[e.Session] {
							sessDone[e.Session] = true
							add("idp-an-session-multi-source", e.T, e.IP, e.User, fmt.Sprintf("one session id was used from %s and from %s (%s) within %s", first.IP, e.IP, e.Country, e.T.Sub(first.T).Round(time.Second)))
						}
					} else if len(sessions) < 100000 {
						sessions[e.Session] = e
					}
				}
				s := succs[e.User]
				if s == nil && len(succs) < 200000 {
					s = &succ{devs: map[string]bool{}, countries: map[string]bool{}}
					succs[e.User] = s
				}
				if s != nil {
					if s.n > 0 {
						if gap := e.T.Sub(s.last.T); gap >= dormant && !dormDone[e.User] {
							dormDone[e.User] = true
							add("idp-an-dormant-account-use", e.T, e.IP, e.User, fmt.Sprintf("%s signed in after %d days without a successful sign-in in this export", e.User, int(gap.Hours()/24)))
						}
						if s.last.IP != e.IP && s.last.HasGeo && e.HasGeo {
							dt := e.T.Sub(s.last.T)
							km := authHaversineKm(s.last.Lat, s.last.Lon, e.Lat, e.Lon)
							hrs := math.Max(dt.Hours(), 1.0/60)
							if km >= authTravelMinKm && km/hrs >= authTravelKmh {
								add("idp-an-impossible-travel", e.T, e.IP, e.User, fmt.Sprintf("%s signed in from %s then from %s %.0f km away %s later (%.0f km/h implied)", e.User, s.last.IP, e.IP, km, dt.Round(time.Second), km/hrs))
							}
						}
					}
					if s.n >= idpBaselineMin {
						newDev := e.Device != "" && !s.devs[e.Device]
						newCty := e.Country != "" && !s.countries[e.Country]
						if newDev || newCty {
							newCtx[e.User] = e.T
						}
					}
					if len(s.devs) < 64 && e.Device != "" {
						s.devs[e.Device] = true
					}
					if len(s.countries) < 64 && e.Country != "" {
						s.countries[e.Country] = true
					}
					s.n++
					s.last = e
				}
			} else if e.HasOutcome {
				if len(fails) < 100000 || fails[e.IP] != nil {
					r := fails[e.IP]
					cut := e.T.Add(-idpSprayWindow)
					kept := r[:0]
					for _, x := range r {
						if x.t.After(cut) {
							kept = append(kept, x)
						}
					}
					kept = append(kept, struct {
						t time.Time
						u string
					}{e.T, e.User})
					if len(kept) > 512 {
						kept = kept[len(kept)-512:]
					}
					fails[e.IP] = kept
					if e.IP != "" && !sprayDone[e.IP] {
						per := map[string]int{}
						for _, x := range kept {
							per[x.u]++
						}
						mx := 0
						for _, n := range per {
							if n > mx {
								mx = n
							}
						}
						if len(per) >= idpSprayUsers && mx <= idpSprayPerUser {
							sprayDone[e.IP] = true
							add("idp-an-password-spray", e.T, e.IP, "", fmt.Sprintf("%s failed to sign in to %d accounts within %s with at most %d attempts per account (password spraying pattern)", e.IP, len(per), idpSprayWindow, mx))
						}
					}
				}
			}
		case "role_grant":
			if e.Success || !e.HasOutcome {
				hi := e.Privileged || (e.Actor != "" && e.Actor == e.User)
				d := fmt.Sprintf("%s granted an administrator role (%s) to %s", orDash(e.Actor), orDash(e.Role), e.User)
				if hi {
					add("idp-an-admin-role-grant", e.T, e.IP, e.User, d+"; privileged role or self-grant", "high")
				} else {
					add("idp-an-admin-role-grant", e.T, e.IP, e.User, d)
				}
			}
		case "mfa_reset":
			add("idp-an-mfa-removed", e.T, e.IP, e.User, fmt.Sprintf("an authentication factor of %s was removed or reset (%s) by %s", e.User, e.Detail, orDash(e.Actor)))
		case "pw_reset":
			if len(resets) < 200000 {
				resets[e.User] = e.T
			}
		case "policy_change":
			add("idp-an-auth-policy-weakened", e.T, e.IP, e.User, fmt.Sprintf("%s disabled or deleted an authentication policy or network zone (%s)", orDash(e.Actor), e.Detail))
		case "app_cred":
			add("idp-an-app-credential-or-consent", e.T, e.IP, e.User, fmt.Sprintf("%s added an application credential or consent (%s, app %s)", orDash(e.Actor), e.Detail, orDash(e.App)))
		case "risk":
			add("idp-an-provider-risk-signal", e.T, e.IP, e.User, fmt.Sprintf("the provider recorded a threat event for %s (%s, %s)", e.User, e.Detail, e.Risk))
		}
		// state-changing events that follow a new-context sign-in or a password reset
		if e.Class == "mfa_enroll" || e.Class == "mfa_reset" || e.Class == "role_grant" || e.Class == "pw_reset" {
			if nt, ok := newCtx[e.User]; ok && !privDone[e.User] && e.T.Sub(nt) >= 0 && e.T.Sub(nt) <= idpPrivWindow {
				privDone[e.User] = true
				add("idp-an-newdevice-privilege-change", e.T, e.IP, e.User, fmt.Sprintf("%s: %s %s after a sign-in from a device or country not seen earlier in this export", e.User, strings.ReplaceAll(e.Class, "_", " "), e.T.Sub(nt).Round(time.Second)))
			}
		}
		if e.Class == "mfa_enroll" {
			if rt, ok := resets[e.User]; ok && !resetDone[e.User] && e.T.Sub(rt) >= 0 && e.T.Sub(rt) <= idpResetWindow {
				resetDone[e.User] = true
				add("idp-an-reset-then-mfa-enroll", e.T, e.IP, e.User, fmt.Sprintf("a new MFA method was registered for %s %s after a password reset", e.User, e.T.Sub(rt).Round(time.Second)))
			}
		}
	}
	rep.Users = len(users)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	rep.Findings = len(out)
	return rep, out
}

// RegisterIdpLogs mounts POST /v1/idp/logs (admin token) and GET /v1/idp/sources.
func RegisterIdpLogs(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/idp/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "providers": []string{"okta", "entra", "generic"},
			"rules": idpRuleList(), "max_records": idpMaxRecords, "dormant_default_days": idpDormantDefault})
	})
	mux.HandleFunc("POST /v1/idp/logs", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		recs, err := authUnwrap(raw)
		if err != nil || len(recs) == 0 {
			http.Error(w, "invalid identity log payload", http.StatusBadRequest)
			return
		}
		if len(recs) > idpMaxRecords {
			http.Error(w, fmt.Sprintf("too many records (max %d)", idpMaxRecords), http.StatusRequestEntityTooLarge)
			return
		}
		host := ""
		if h := r.URL.Query().Get("host"); h != "" {
			host = "idp:" + strings.ToLower(webTruncate(webSanitise(h), 120))
		}
		dd := 0
		if v := r.URL.Query().Get("dormant_days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 7 || n > 730 {
				http.Error(w, "dormant_days must be 7..730", http.StatusBadRequest)
				return
			}
			dd = n
		}
		rep, findings := AnalyzeIdpLogs(recs, host, dd)
		twf, twn := twMerge(recs, "idp")
		findings = append(findings, twf...)
		rep.TripwireHits = twn
		if rep.Parsed == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "no record could be parsed", "rejected": rep.Rejected, "errors": rep.Errors})
			return
		}
		stored, err := webStoreFindings(store, findings)
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		rep.Findings = stored
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)
	})
}
