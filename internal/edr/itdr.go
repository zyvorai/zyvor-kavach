// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ITDR: observation-only identity threat detection derived from findings and
// identity events. It never blocks, kills or isolates anything.

type ITDRIndicator struct {
	Kind     string    `json:"kind"` // credential-dumping|kerberoasting|pass-the-hash|impossible-travel|odd-hour-login|privileged-usage
	User     string    `json:"user"`
	Host     string    `json:"host,omitempty"`
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"`
	Detail   string    `json:"detail"`
	Ref      string    `json:"ref,omitempty"`
}

type ITDRRisk struct {
	User       string   `json:"user"`
	Score      int      `json:"score"`
	Level      string   `json:"level"`
	Privileged bool     `json:"privileged"`
	Indicators int      `json:"indicators"`
	Factors    []string `json:"factors"`
}

type ITDRTimelineEntry struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"` // finding|identity-event
	Kind   string    `json:"kind"`
	Host   string    `json:"host,omitempty"`
	Detail string    `json:"detail"`
}

var itdrKindWeight = map[string]int{
	"credential-dumping": 40, "kerberoasting": 30, "pass-the-hash": 35,
	"impossible-travel": 25, "odd-hour-login": 10, "privileged-usage": 8,
}

func itdrUser(uid int) string {
	if uid == 0 {
		return "root"
	}
	return fmt.Sprintf("uid:%d", uid)
}

func itdrClassify(rule, cmd string) string {
	s := strings.ToLower(rule + " " + cmd)
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("mimikatz", "sekurlsa", "lsass", "procdump", "/etc/shadow", "unshadow", "secretsdump", "credential-dump", "gcore", "lazagne"):
		return "credential-dumping"
	case has("kerberoast", "getuserspns", "rubeus", "tgsrep", "asktgs", "kirbi"):
		return "kerberoasting"
	case has("pass-the-hash", "pth-", "sekurlsa::pth", "wmiexec", "psexec", "-hashes", "overpass"):
		return "pass-the-hash"
	}
	return ""
}

func itdrSev(sev, def string) string {
	if sev == "" {
		return def
	}
	return sev
}

func itdrIsLogin(a string) bool {
	a = strings.ToLower(a)
	return strings.Contains(a, "login") || strings.Contains(a, "logon") || strings.Contains(a, "ssh") || strings.Contains(a, "auth")
}

func itdrTrunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ComputeITDR derives indicators, per-user risk and per-user timelines.
func ComputeITDR(findings []Finding, events []IdentityEvent) ([]ITDRIndicator, map[string]*ITDRRisk, map[string][]ITDRTimelineEntry) {
	var inds []ITDRIndicator
	timeline := map[string][]ITDRTimelineEntry{}
	priv := map[string]bool{}

	for _, f := range findings {
		u := itdrUser(f.Evidence.UID)
		if f.Evidence.UID == 0 {
			priv[u] = true
		}
		timeline[u] = append(timeline[u], ITDRTimelineEntry{Time: f.Time, Source: "finding", Kind: f.Rule, Host: f.Host, Detail: f.Description})
		if k := itdrClassify(f.Rule, f.Evidence.Command); k != "" {
			inds = append(inds, ITDRIndicator{Kind: k, User: u, Host: f.Host, Time: f.Time, Severity: itdrSev(f.Severity, "high"), Detail: f.Description, Ref: f.ID})
		}
		if f.Evidence.UID == 0 && (strings.Contains(f.Evidence.Command, "sudo ") || strings.Contains(f.Evidence.Command, "su -")) {
			inds = append(inds, ITDRIndicator{Kind: "privileged-usage", User: u, Host: f.Host, Time: f.Time, Severity: "low", Detail: "privileged command: " + itdrTrunc(f.Evidence.Command, 120), Ref: f.ID})
		}
	}

	byUser := map[string][]IdentityEvent{}
	for _, e := range events {
		if e.User == "" {
			continue
		}
		byUser[e.User] = append(byUser[e.User], e)
		timeline[e.User] = append(timeline[e.User], ITDRTimelineEntry{Time: e.Time, Source: "identity-event", Kind: e.Action, Host: e.Host, Detail: e.Detail})
		if k := itdrClassify(e.Rule, e.Detail+" "+e.Action); k != "" {
			inds = append(inds, ITDRIndicator{Kind: k, User: e.User, Host: e.Host, Time: e.Time, Severity: itdrSev(e.Severity, "high"), Detail: e.Detail, Ref: e.ID})
		}
		if l := strings.ToLower(e.User); strings.Contains(l, "admin") || l == "root" {
			priv[e.User] = true
			inds = append(inds, ITDRIndicator{Kind: "privileged-usage", User: e.User, Host: e.Host, Time: e.Time, Severity: "low", Detail: "privileged account activity: " + e.Action, Ref: e.ID})
		}
		if itdrIsLogin(e.Action) {
			if h := e.Time.UTC().Hour(); h < 6 || h >= 22 {
				inds = append(inds, ITDRIndicator{Kind: "odd-hour-login", User: e.User, Host: e.Host, Time: e.Time, Severity: "low", Detail: fmt.Sprintf("login at %02d:00 UTC from %s", h, e.SourceIP), Ref: e.ID})
			}
		}
	}
	// impossible travel: same user, different source IPs within 10 minutes.
	for u, evs := range byUser {
		var logins []IdentityEvent
		for _, e := range evs {
			if itdrIsLogin(e.Action) && e.SourceIP != "" {
				logins = append(logins, e)
			}
		}
		sort.Slice(logins, func(i, j int) bool { return logins[i].Time.Before(logins[j].Time) })
		for i := 1; i < len(logins); i++ {
			a, b := logins[i-1], logins[i]
			if a.SourceIP != b.SourceIP && b.Time.Sub(a.Time) <= 10*time.Minute {
				inds = append(inds, ITDRIndicator{Kind: "impossible-travel", User: u, Host: b.Host, Time: b.Time, Severity: "high",
					Detail: fmt.Sprintf("logins from %s and %s within %s", a.SourceIP, b.SourceIP, b.Time.Sub(a.Time).Round(time.Second)), Ref: b.ID})
			}
		}
	}
	sort.Slice(inds, func(i, j int) bool { return inds[i].Time.After(inds[j].Time) })

	risks := map[string]*ITDRRisk{}
	get := func(u string) *ITDRRisk {
		r := risks[u]
		if r == nil {
			r = &ITDRRisk{User: u, Privileged: priv[u], Factors: []string{}}
			risks[u] = r
		}
		return r
	}
	for u := range timeline {
		get(u)
	}
	seen := map[string]map[string]bool{}
	for _, in := range inds {
		r := get(in.User)
		r.Indicators++
		if seen[in.User] == nil {
			seen[in.User] = map[string]bool{}
		}
		w := itdrKindWeight[in.Kind]
		if seen[in.User][in.Kind] {
			w /= 3
		} else {
			seen[in.User][in.Kind] = true
			r.Factors = append(r.Factors, in.Kind)
		}
		r.Score += w
	}
	for _, r := range risks {
		if r.Privileged && r.Score > 0 {
			r.Score += 10
			r.Factors = append(r.Factors, "privileged-account")
		}
		if r.Score > 100 {
			r.Score = 100
		}
		switch {
		case r.Score >= 70:
			r.Level = "critical"
		case r.Score >= 40:
			r.Level = "high"
		case r.Score >= 15:
			r.Level = "medium"
		default:
			r.Level = "low"
		}
	}
	for u := range timeline {
		tl := timeline[u]
		sort.Slice(tl, func(i, j int) bool { return tl[i].Time.Before(tl[j].Time) })
	}
	return inds, risks, timeline
}

func RegisterITDR(mux *http.ServeMux, token string, store *Store) {
	load := func() ([]ITDRIndicator, map[string]*ITDRRisk, map[string][]ITDRTimelineEntry) {
		var fs []Finding
		if store != nil {
			fs = store.List()
		}
		idMu.Lock()
		evs := append([]IdentityEvent{}, idEvents...)
		idMu.Unlock()
		return ComputeITDR(fs, evs)
	}
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	sortedRisks := func(m map[string]*ITDRRisk, onlyPriv bool) []ITDRRisk {
		out := []ITDRRisk{}
		for _, r := range m {
			if onlyPriv && !r.Privileged {
				continue
			}
			out = append(out, *r)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Score != out[j].Score {
				return out[i].Score > out[j].Score
			}
			return out[i].User < out[j].User
		})
		return out
	}
	get := func(path string, h func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			h(w, r)
		})
	}
	get("/v1/identity/itdr/indicators", func(w http.ResponseWriter, r *http.Request) {
		inds, _, _ := load()
		out := []ITDRIndicator{}
		k := r.URL.Query().Get("kind")
		for _, i := range inds {
			if k == "" || i.Kind == k {
				out = append(out, i)
			}
		}
		reply(w, out)
	})
	get("/v1/identity/itdr/risk", func(w http.ResponseWriter, r *http.Request) {
		_, risks, _ := load()
		reply(w, sortedRisks(risks, false))
	})
	get("/v1/identity/itdr/privileged", func(w http.ResponseWriter, r *http.Request) {
		_, risks, _ := load()
		reply(w, sortedRisks(risks, true))
	})
	get("/v1/identity/itdr/timeline", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("user")
		if u == "" {
			http.Error(w, "user required", 400)
			return
		}
		_, _, tl := load()
		out := tl[u]
		if out == nil {
			out = []ITDRTimelineEntry{}
		}
		reply(w, map[string]any{"user": u, "events": out})
	})
	get("/v1/identity/itdr/summary", func(w http.ResponseWriter, r *http.Request) {
		inds, risks, _ := load()
		kinds := map[string]int{}
		for _, i := range inds {
			kinds[i.Kind]++
		}
		levels := map[string]int{}
		priv := 0
		for _, x := range risks {
			levels[x.Level]++
			if x.Privileged {
				priv++
			}
		}
		reply(w, map[string]any{"users": len(risks), "indicators": len(inds), "by_kind": kinds, "by_risk_level": levels, "privileged_users": priv, "mode": "observe-only"})
	})
}
