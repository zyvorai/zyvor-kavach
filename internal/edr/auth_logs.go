// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Offline authentication-log analytics (observation only): credential stuffing, distributed attacks
// on one account, request velocity, successful logins that follow a failure storm from the same
// source, and impossible travel computed from geolocation the operator already put in the log
// (Kavach never looks an address up and never calls a geo service). Records are sent by the operator
// to POST /v1/auth/logs; nothing is blocked, locked or reset. Passwords and any field outside the
// allow-list below are never read or stored.
const (
	authLogMax         = 50000
	authStuffWindow    = 600 // seconds
	authStuffFails     = 50
	authStuffUsers     = 20
	authStuffIPs       = 10
	authStuffPerIPMax  = 5
	authDistIPs        = 8
	authDistFails      = 10
	authVelocityPerMin = 100
	authSuccPrior      = 5
	authSuccUsers      = 3
	authTravelMinKm    = 500.0
	authTravelKmh      = 900.0
	authCountryHopMins = 60
	authFindCapPerRule = 25
)

var authAnalyticRules = []struct {
	ID, Tactic, Technique, TechID, Sev string
}{
	{"auth-an-credential-stuffing", "Credential Access", "Brute Force: Credential Stuffing", "T1110.004", "high"},
	{"auth-an-distributed-account-attack", "Credential Access", "Brute Force", "T1110", "medium"},
	{"auth-an-high-velocity", "Credential Access", "Brute Force", "T1110", "medium"},
	{"auth-an-success-after-failures", "Initial Access", "Valid Accounts", "T1078", "high"},
	{"auth-an-impossible-travel", "Initial Access", "Valid Accounts", "T1078", "medium"},
	{"auth-an-country-change-fast", "Initial Access", "Valid Accounts", "T1078", "low"},
}

func init() {
	for _, r := range authAnalyticRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func authAnalyticList() []map[string]string {
	out := make([]map[string]string, 0, len(authAnalyticRules))
	for _, a := range authAnalyticRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

// AuthRecord is one normalised authentication attempt.
type AuthRecord struct {
	T          time.Time
	User, IP   string
	Success    bool
	Country    string
	Lat, Lon   float64
	HasGeo     bool
	Source, ID string
}

func authOutcome(v string) (success, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "success", "succeeded", "successful", "ok", "allow", "allowed", "granted", "true", "pass", "passed", "login_success", "authenticated", "200", "1":
		return true, true
	case "fail", "failed", "failure", "denied", "deny", "invalid", "error", "false", "unauthorized", "blocked", "login_failed", "login_failure", "rejected", "401", "403", "0":
		return false, true
	}
	return false, false
}

func authFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// NormalizeAuthRecord reads the allow-listed fields of one log object.
func NormalizeAuthRecord(m map[string]any) (AuthRecord, string) {
	flat := map[string]string{}
	webFlatten(m, "", 0, flat)
	var r AuthRecord
	t, ok := parseWebTime(webPick(flat, "time", "timestamp", "@timestamp", "eventtime", "published", "createddatetime", "ts", "datetime", "_time"))
	if !ok {
		return r, "no parseable timestamp"
	}
	r.T = t
	r.IP = webTruncate(webSanitise(webPick(flat, "ip", "source_ip", "src_ip", "client_ip", "clientip", "ipaddress", "ip_address", "source.ip", "client.ipaddress", "remote_addr", "sourceipaddress")), 64)
	r.User = webTruncate(webSanitise(strings.ToLower(webPick(flat, "user", "username", "user_name", "user.name", "principal", "actor.alternateid", "userprincipalname", "email", "account", "login"))), 128)
	if r.IP == "" || r.User == "" {
		return r, "missing user or source ip"
	}
	oc := webPick(flat, "outcome", "result", "event.outcome", "success", "status", "auth_result", "login_result", "action")
	succ, ok := authOutcome(oc)
	if !ok {
		return r, "unknown outcome"
	}
	r.Success = succ
	r.Country = strings.ToUpper(webTruncate(webSanitise(webPick(flat, "country", "country_code", "geo.country", "geo.country_iso_code", "geo.country_code", "location.country", "countrycode")), 3))
	lat, ok1 := authFloat(webPick(flat, "lat", "latitude", "geo.lat", "geo.latitude", "geo.location.lat", "location.lat", "location.latitude"))
	lon, ok2 := authFloat(webPick(flat, "lon", "lng", "longitude", "geo.lon", "geo.lng", "geo.longitude", "geo.location.lon", "location.lon", "location.longitude"))
	if ok1 && ok2 && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 {
		r.Lat, r.Lon, r.HasGeo = lat, lon, true
	}
	return r, ""
}

func authHaversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const rad = math.Pi / 180
	dLat, dLon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * 6371.0088 * math.Asin(math.Min(1, math.Sqrt(a)))
}

// authUnwrap accepts a JSON array, a wrapper object, one object or JSON lines.
func authUnwrap(raw []byte) ([]map[string]any, error) {
	if recs, err := cloudUnwrap(raw); err == nil {
		if len(recs) == 1 && recs[0] != nil {
			for _, k := range []string{"logs", "records"} {
				if arr, ok := recs[0][k].([]any); ok {
					out := make([]map[string]any, 0, len(arr))
					for _, x := range arr {
						m, _ := x.(map[string]any)
						out = append(out, m)
					}
					return out, nil
				}
			}
		}
		return recs, nil
	}
	var out []map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > webLineMax {
			out = append(out, nil)
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			out = append(out, nil)
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, errors.New("body must be a JSON array, object or JSON lines")
	}
	return out, nil
}

type AuthSource struct {
	IP       string `json:"ip"`
	Failures int    `json:"failures"`
	Users    int    `json:"distinct_users"`
}

type AuthReport struct {
	Mode       string         `json:"mode"`
	Received   int            `json:"received"`
	Parsed     int            `json:"parsed"`
	Rejected   int            `json:"rejected"`
	Failures   int            `json:"failures"`
	Successes  int            `json:"successes"`
	Users      int            `json:"distinct_users"`
	Sources    int            `json:"distinct_sources"`
	From       *time.Time     `json:"from,omitempty"`
	To         *time.Time     `json:"to,omitempty"`
	TopSources []AuthSource   `json:"top_failing_sources"`
	ByRule     map[string]int `json:"by_rule"`
	Findings   int            `json:"findings"`
	GeoRecords int            `json:"records_with_geo"`
	Errors     []string       `json:"errors,omitempty"`
	Note       string         `json:"note"`
}

type authFailRec struct {
	t    time.Time
	user string
}

// AnalyzeAuthLogs normalises records and runs the windowed detections over them.
func AnalyzeAuthLogs(recs []map[string]any, hostLabel string) (*AuthReport, []Finding) {
	rep := &AuthReport{Mode: "observe-only", ByRule: map[string]int{}, TopSources: []AuthSource{}, Received: len(recs),
		Note: "offline analysis of records you sent; geolocation comes from your log fields only, no lookup is made. Thresholds are fixed heuristics; VPNs, proxies and mobile carriers cause impossible-travel false positives."}
	if hostLabel == "" {
		hostLabel = "auth:logs"
	}
	var evs []AuthRecord
	for i, m := range recs {
		if m == nil {
			rep.Rejected++
			if len(rep.Errors) < 5 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: not a JSON object", i))
			}
			continue
		}
		r, why := NormalizeAuthRecord(m)
		if why != "" {
			rep.Rejected++
			if len(rep.Errors) < 5 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: %s", i, why))
			}
			continue
		}
		evs = append(evs, r)
	}
	rep.Parsed = len(evs)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].T.Before(evs[j].T) })
	var out []Finding
	perRule := map[string]int{}
	add := func(rule string, t time.Time, ip, user, desc string) {
		if perRule[rule] >= authFindCapPerRule {
			return
		}
		perRule[rule]++
		rep.ByRule[rule]++
		sev := "medium"
		for _, a := range authAnalyticRules {
			if a.ID == rule {
				sev = a.Sev
			}
		}
		m := ruleMITRE[rule]
		out = append(out, Finding{ID: fmt.Sprintf("%s:%s:%s:%s:%d", hostLabel, rule, ip, user, t.UnixNano()), Time: t, Host: hostLabel, Rule: rule, Severity: sev,
			Description: desc + " (heuristic over the logs you sent; investigate, not proof of compromise)", Destination: ip,
			Tags:     []string{m.ID, "auth", "analytics", "observe-only"},
			Evidence: Event{Time: t, Host: hostLabel, Executable: "auth:log", Command: webTruncate(desc, 300)}})
	}
	users, srcs := map[string]bool{}, map[string]*struct {
		fails int
		users map[string]bool
	}{}
	if len(evs) > 0 {
		f, l := evs[0].T, evs[len(evs)-1].T
		rep.From, rep.To = &f, &l
	}
	// per-source recent failures (for success-after-failures), per-user last geo success, buckets
	recent := map[string][]authFailRec{}
	type geoLast struct {
		r  AuthRecord
		ok bool
	}
	lastOK := map[string]geoLast{}
	type bucket struct {
		id      int64
		fails   int
		users   map[string]bool
		perIP   map[string]int
		perUser map[string]map[string]bool
	}
	var cur *bucket
	stuffN := 0
	userFlag := map[string]bool{}
	closeB := func(b *bucket) {
		if b == nil {
			return
		}
		start := time.Unix(b.id*authStuffWindow, 0).UTC()
		if b.fails >= authStuffFails && len(b.users) >= authStuffUsers && len(b.perIP) >= authStuffIPs && stuffN < 5 {
			c := make([]int, 0, len(b.perIP))
			for _, n := range b.perIP {
				c = append(c, n)
			}
			sort.Ints(c)
			if c[len(c)/2] <= authStuffPerIPMax {
				stuffN++
				add("auth-an-credential-stuffing", start, "", "", fmt.Sprintf("%d failed logins against %d accounts from %d sources within %ds, median %d per source (distributed credential stuffing pattern)", b.fails, len(b.users), len(b.perIP), authStuffWindow, c[len(c)/2]))
			}
		}
		us := make([]string, 0, len(b.perUser))
		for u := range b.perUser {
			us = append(us, u)
		}
		sort.Strings(us)
		for _, u := range us {
			ips := b.perUser[u]
			if len(ips) >= authDistIPs && !userFlag[u] {
				userFlag[u] = true
				add("auth-an-distributed-account-attack", start, "", u, fmt.Sprintf("account %s had failed logins from %d different sources within %ds", u, len(ips), authStuffWindow))
			}
		}
	}
	type minKey struct {
		ip string
		m  int64
	}
	velocity := map[minKey]int{}
	velFlag := map[string]bool{}
	succFlag := map[string]bool{}
	for _, e := range evs {
		users[e.User] = true
		s := srcs[e.IP]
		if s == nil && len(srcs) < 100000 {
			s = &struct {
				fails int
				users map[string]bool
			}{users: map[string]bool{}}
			srcs[e.IP] = s
		}
		if e.HasGeo || e.Country != "" {
			rep.GeoRecords++
		}
		// velocity
		if len(velocity) < 200000 {
			k := minKey{e.IP, e.T.Unix() / 60}
			velocity[k]++
			if velocity[k] >= authVelocityPerMin && !velFlag[e.IP] {
				velFlag[e.IP] = true
				add("auth-an-high-velocity", e.T, e.IP, "", fmt.Sprintf("%s made %d authentication attempts in one minute", e.IP, velocity[k]))
			}
		}
		if !e.Success {
			rep.Failures++
			if s != nil {
				s.fails++
				if len(s.users) < 200 {
					s.users[e.User] = true
				}
			}
			id := e.T.Unix() / authStuffWindow
			if cur == nil || cur.id != id {
				closeB(cur)
				cur = &bucket{id: id, users: map[string]bool{}, perIP: map[string]int{}, perUser: map[string]map[string]bool{}}
			}
			cur.fails++
			if len(cur.users) < 20000 {
				cur.users[e.User] = true
			}
			if _, ok := cur.perIP[e.IP]; ok || len(cur.perIP) < 20000 {
				cur.perIP[e.IP]++
			}
			if pu := cur.perUser[e.User]; pu != nil {
				if len(pu) < 64 {
					pu[e.IP] = true
				}
			} else if len(cur.perUser) < 20000 {
				cur.perUser[e.User] = map[string]bool{e.IP: true}
			}
			if len(recent) < 100000 || recent[e.IP] != nil {
				r := recent[e.IP]
				cut := e.T.Add(-10 * time.Minute)
				kept := r[:0]
				for _, x := range r {
					if x.t.After(cut) {
						kept = append(kept, x)
					}
				}
				kept = append(kept, authFailRec{e.T, e.User})
				if len(kept) > 256 {
					kept = kept[len(kept)-256:]
				}
				recent[e.IP] = kept
			}
			continue
		}
		rep.Successes++
		// success after a failure storm from the same source
		if r := recent[e.IP]; len(r) >= authSuccPrior && !succFlag[e.IP+"|"+e.User] {
			cut := e.T.Add(-10 * time.Minute)
			du, n := map[string]bool{}, 0
			for _, x := range r {
				if x.t.After(cut) {
					n++
					du[x.user] = true
				}
			}
			if n >= authSuccPrior && len(du) >= authSuccUsers {
				succFlag[e.IP+"|"+e.User] = true
				add("auth-an-success-after-failures", e.T, e.IP, e.User, fmt.Sprintf("%s logged in as %s after %d failed attempts against %d accounts from the same source in the last 10 minutes", e.IP, e.User, n, len(du)))
			}
		}
		// impossible travel (successful logins only)
		if prev, ok := lastOK[e.User]; ok && prev.ok && prev.r.IP != e.IP {
			dt := e.T.Sub(prev.r.T)
			switch {
			case prev.r.HasGeo && e.HasGeo:
				km := authHaversineKm(prev.r.Lat, prev.r.Lon, e.Lat, e.Lon)
				hrs := math.Max(dt.Hours(), 1.0/60)
				if km >= authTravelMinKm && km/hrs >= authTravelKmh {
					add("auth-an-impossible-travel", e.T, e.IP, e.User, fmt.Sprintf("%s logged in from %s then from %s %.0f km away %s later (%.0f km/h implied)", e.User, prev.r.IP, e.IP, km, dt.Round(time.Second), km/hrs))
				}
			case prev.r.Country != "" && e.Country != "" && prev.r.Country != e.Country && dt <= authCountryHopMins*time.Minute:
				add("auth-an-country-change-fast", e.T, e.IP, e.User, fmt.Sprintf("%s logged in from %s then from %s (%s) %s later", e.User, prev.r.Country, e.Country, e.IP, dt.Round(time.Second)))
			}
		}
		if len(lastOK) < 200000 || lastOK[e.User].ok {
			lastOK[e.User] = geoLast{e, true}
		}
	}
	closeB(cur)
	rep.Users, rep.Sources = len(users), len(srcs)
	for ip, s := range srcs {
		if s.fails > 0 {
			rep.TopSources = append(rep.TopSources, AuthSource{IP: ip, Failures: s.fails, Users: len(s.users)})
		}
	}
	sort.Slice(rep.TopSources, func(i, j int) bool {
		if rep.TopSources[i].Failures != rep.TopSources[j].Failures {
			return rep.TopSources[i].Failures > rep.TopSources[j].Failures
		}
		return rep.TopSources[i].IP < rep.TopSources[j].IP
	})
	if len(rep.TopSources) > 10 {
		rep.TopSources = rep.TopSources[:10]
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	rep.Findings = len(out)
	return rep, out
}

// RegisterAuthLogs mounts POST /v1/auth/logs (admin token only).
func RegisterAuthLogs(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/auth/logs", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		recs, err := authUnwrap(raw)
		if err != nil || len(recs) == 0 {
			http.Error(w, "invalid auth log payload", http.StatusBadRequest)
			return
		}
		if len(recs) > authLogMax {
			http.Error(w, fmt.Sprintf("too many records (max %d)", authLogMax), http.StatusRequestEntityTooLarge)
			return
		}
		host := ""
		if h := r.URL.Query().Get("host"); h != "" {
			host = "auth:" + strings.ToLower(webTruncate(webSanitise(h), 120))
		}
		rep, findings := AnalyzeAuthLogs(recs, host)
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
