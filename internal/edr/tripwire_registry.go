// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Deception tripwire registry (observation only). You declare decoys that already exist in your
// environment (honey accounts, planted token values, decoy host names, decoy IPs, decoy URL paths,
// for example from a Canarytokens or honeypot deployment). Kavach matches the declarations against
// the logs you send it, offline, and raises a finding when a decoy shows up. It never creates
// network listeners for these decoys, never contacts them and never blocks anyone. Decoy values must
// be non-functional: do not register a real credential.
const (
	twMaxExact     = 2000
	twMaxSubstring = 100
	twMaxFields    = 200
	twFieldMax     = 1024
	twBlobMax      = 4096
	twBudget       = 3 * time.Second
	twFindCap      = 25
	twMaxRecords   = 50000
	twMinLen       = 6
	twCoalesce     = 10 * time.Minute
)

var twRules = []struct {
	ID, Tactic, Technique, TechID, Sev string
}{
	{"tripwire-account-used", "Initial Access", "Valid Accounts", "T1078", "high"},
	{"tripwire-value-seen", "Credential Access", "Unsecured Credentials: Credentials In Files", "T1552.001", "high"},
	{"tripwire-decoy-touched", "Reconnaissance", "Active Scanning", "T1595", "high"},
}

func init() {
	for _, r := range twRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

// TripwireDef is one declared decoy.
type TripwireDef struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"` // account|ip|value|hostname|path
	Match   string    `json:"match"`
	Label   string    `json:"label"`
	Owner   string    `json:"owner,omitempty"`
	Created time.Time `json:"created"`
	Hits    int       `json:"hits"`
	LastHit time.Time `json:"last_hit,omitempty"`
}

type twRegistry struct {
	mu   sync.Mutex
	path string
	defs []TripwireDef
}

var twReg = &twRegistry{}

func twNewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func twNorm(kind, s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if kind == "account" {
		s = twAccount(s)
	}
	return s
}

// twAccount strips a DOMAIN\ prefix and an @domain suffix so DOM\svc, svc@corp and svc compare equal.
func twAccount(s string) string {
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	return s
}

func (r *twRegistry) load(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path, r.defs = p, nil
	if p == "" {
		return
	}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &r.defs)
	}
}

func (r *twRegistry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	b, err := json.Marshal(r.defs)
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func twMask(d TripwireDef) string {
	if d.Kind == "value" && len(d.Match) > 4 {
		return d.Match[:4] + strings.Repeat("*", 6)
	}
	return d.Match
}

// Add validates and stores a tripwire.
func (r *twRegistry) Add(kind, match, label, owner string) (TripwireDef, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	match = twNorm(kind, webSanitise(match))
	switch kind {
	case "account":
		if len(match) < 3 || len(match) > 128 {
			return TripwireDef{}, fmt.Errorf("account must be 3..128 characters")
		}
	case "ip":
		if net.ParseIP(match) == nil {
			return TripwireDef{}, fmt.Errorf("ip must be a valid address")
		}
		match = net.ParseIP(match).String()
	case "value", "hostname", "path":
		if len(match) < twMinLen || len(match) > 200 {
			return TripwireDef{}, fmt.Errorf("%s must be %d..200 characters", kind, twMinLen)
		}
	default:
		return TripwireDef{}, fmt.Errorf("kind must be account, ip, value, hostname or path")
	}
	label = webTruncate(webSanitise(strings.TrimSpace(label)), 100)
	if label == "" {
		return TripwireDef{}, fmt.Errorf("label required")
	}
	d := TripwireDef{ID: twNewID(), Kind: kind, Match: match, Label: label, Owner: webTruncate(webSanitise(owner), 100), Created: time.Now().UTC()}
	r.mu.Lock()
	defer r.mu.Unlock()
	exact, sub := 0, 0
	for _, x := range r.defs {
		if x.Kind == kind && x.Match == match {
			return TripwireDef{}, fmt.Errorf("already registered")
		}
		if x.Kind == "account" || x.Kind == "ip" {
			exact++
		} else {
			sub++
		}
	}
	if (kind == "account" || kind == "ip") && exact >= twMaxExact {
		return TripwireDef{}, fmt.Errorf("limit of %d account/ip tripwires reached", twMaxExact)
	}
	if kind != "account" && kind != "ip" && sub >= twMaxSubstring {
		return TripwireDef{}, fmt.Errorf("limit of %d value/hostname/path tripwires reached", twMaxSubstring)
	}
	r.defs = append(r.defs, d)
	if err := r.saveLocked(); err != nil {
		r.defs = r.defs[:len(r.defs)-1]
		return TripwireDef{}, fmt.Errorf("storage error")
	}
	return d, nil
}

func (r *twRegistry) Delete(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, d := range r.defs {
		if d.ID == id {
			r.defs = append(r.defs[:i], r.defs[i+1:]...)
			_ = r.saveLocked()
			return true
		}
	}
	return false
}

// TripwireScanReport is the scan summary.
type TripwireScanReport struct {
	Mode      string         `json:"mode"`
	Records   int            `json:"records"`
	Matched   int            `json:"matched_records"`
	ByTrip    map[string]int `json:"by_tripwire"`
	Findings  int            `json:"findings"`
	Truncated bool           `json:"budget_exceeded,omitempty"`
	Note      string         `json:"note"`
}

func twUserKey(k string) bool {
	for _, s := range []string{"user", "account", "principal", "actor", "alternateid", "login", "upn", "email", "target"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func twIPKey(k string) bool {
	for _, s := range []string{"ip", "addr", "src", "dst", "source", "dest", "client", "remote", "host", "server", "target"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// twScan matches the declared tripwires against records. host labels the finding; src names the log type.
func twScan(recs []map[string]any, src, hostLabel string) (*TripwireScanReport, []Finding) {
	rep := &TripwireScanReport{Mode: "observe-only", Records: len(recs), ByTrip: map[string]int{},
		Note: "matches your declared decoys against the logs you sent; nothing is blocked or contacted. Decoy values must be non-functional."}
	twReg.mu.Lock()
	defs := append([]TripwireDef(nil), twReg.defs...)
	twReg.mu.Unlock()
	if len(defs) == 0 {
		return rep, nil
	}
	accounts, ips := map[string]int{}, map[string]int{}
	var subs []int
	for i, d := range defs {
		switch d.Kind {
		case "account":
			accounts[d.Match] = i
		case "ip":
			ips[d.Match] = i
		default:
			subs = append(subs, i)
		}
	}
	if hostLabel == "" {
		hostLabel = "tripwire:" + src
	}
	var out []Finding
	perRule := map[string]int{}
	seen := map[string]time.Time{}
	hits := map[int]int{}
	last := map[int]time.Time{}
	start := time.Now()
	for _, m := range recs {
		if m == nil {
			continue
		}
		if time.Since(start) > twBudget {
			rep.Truncated = true
			break
		}
		flat := map[string]string{}
		webFlatten(m, "", 0, flat)
		t, ok := parseWebTime(webPick(flat, "time", "timestamp", "@timestamp", "published", "createddatetime", "activitydatetime", "eventtime", "_time"))
		if !ok {
			t = time.Now().UTC()
		}
		matched := map[int]string{}
		var blob strings.Builder
		n := 0
		user := ""
		for k, v := range flat {
			if n++; n > twMaxFields {
				break
			}
			if len(v) > twFieldMax {
				v = v[:twFieldMax]
			}
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv == "" {
				continue
			}
			if blob.Len() < twBlobMax {
				blob.WriteString(lv)
				blob.WriteByte('\n')
			}
			if twUserKey(k) {
				if i, ok := accounts[twAccount(lv)]; ok {
					matched[i] = k
					user = lv
				}
			}
			if twIPKey(k) {
				if i, ok := ips[lv]; ok {
					matched[i] = k
				}
			}
		}
		if b := blob.String(); b != "" {
			for _, i := range subs {
				if strings.Contains(b, defs[i].Match) {
					matched[i] = "text"
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		rep.Matched++
		ip := webPick(flat, "client.ipaddress", "ipaddress", "ip", "source_ip", "src_ip", "source.ip", "client_ip", "remote_addr", "clientip")
		outcome := ""
		if o, ok := authOutcome(webPick(flat, "outcome.result", "outcome", "result", "status", "event.outcome", "success")); ok {
			outcome = "failed"
			if o {
				outcome = "successful"
			}
		}
		for i := range matched {
			d := defs[i]
			hits[i]++
			last[i] = t
			rule := "tripwire-decoy-touched"
			switch d.Kind {
			case "account":
				rule = "tripwire-account-used"
			case "value":
				rule = "tripwire-value-seen"
			}
			key := d.ID + "|" + ip + "|" + user
			if prev, ok := seen[key]; ok && t.Sub(prev) < twCoalesce && t.After(prev) {
				continue
			}
			seen[key] = t
			if perRule[rule] >= twFindCap {
				continue
			}
			perRule[rule]++
			rep.ByTrip[d.ID]++
			sev := "high"
			if outcome == "successful" && d.Kind == "account" {
				sev = "critical"
			}
			desc := fmt.Sprintf("decoy %q (%s) appeared in %s logs", d.Label, d.Kind, src)
			if outcome != "" {
				desc += ", " + outcome + " event"
			}
			if ip != "" && d.Kind != "ip" {
				desc += " from " + webTruncate(webSanitise(ip), 64)
			}
			mt := ruleMITRE[rule]
			out = append(out, Finding{ID: fmt.Sprintf("%s:%s:%s:%d", hostLabel, rule, d.ID, t.UnixNano()), Time: t, Host: hostLabel, Rule: rule, Severity: sev,
				Description: desc + " (a declared decoy should never be used; investigate who touched it)", Destination: webTruncate(webSanitise(ip), 64),
				Tags:     []string{mt.ID, "deception", "tripwire", "observe-only"},
				Evidence: Event{Time: t, Host: hostLabel, Executable: "tripwire:" + src, Command: webTruncate("tripwire "+d.ID+" "+d.Kind+" matched in field "+matched[i], 200)}})
		}
	}
	if len(hits) > 0 {
		twReg.mu.Lock()
		for i, n := range hits {
			for j := range twReg.defs {
				if twReg.defs[j].ID == defs[i].ID {
					twReg.defs[j].Hits += n
					if last[i].After(twReg.defs[j].LastHit) {
						twReg.defs[j].LastHit = last[i]
					}
				}
			}
		}
		_ = twReg.saveLocked()
		twReg.mu.Unlock()
	}
	rep.Findings = len(out)
	return rep, out
}

// twRecords parses a JSON array/object/JSON-lines body, or plain text lines, into records.
func twRecords(raw []byte) []map[string]any {
	if recs, err := authUnwrap(raw); err == nil && len(recs) > 0 {
		ok := false
		for _, r := range recs {
			if r != nil {
				ok = true
				break
			}
		}
		if ok {
			return recs
		}
	}
	var out []map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > webLineMax {
			line = line[:webLineMax]
		}
		out = append(out, map[string]any{"_line": webSanitise(line)})
		if len(out) > twMaxRecords {
			break
		}
	}
	return out
}

// RegisterTripwires mounts the /v1/deception/tripwires routes.
func RegisterTripwires(mux *http.ServeMux, token string, store *Store) {
	if store != nil && store.path != "" {
		twReg.load(store.path + ".tripwires.json")
	} else {
		twReg.load("")
	}
	jsonOut := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/deception/tripwires", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		twReg.mu.Lock()
		out := make([]TripwireDef, len(twReg.defs))
		for i, d := range twReg.defs {
			d.Match = twMask(d)
			out[i] = d
		}
		twReg.mu.Unlock()
		jsonOut(w, 200, map[string]any{"tripwires": out, "limits": map[string]int{"account_ip": twMaxExact, "value_hostname_path": twMaxSubstring}, "rules": twRuleList()})
	})
	mux.HandleFunc("POST /v1/deception/tripwires", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
		var in struct{ Kind, Match, Label, Owner string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		d, err := twReg.Add(in.Kind, in.Match, in.Label, in.Owner)
		if err != nil {
			code := 400
			if err.Error() == "storage error" {
				code = 500
			} else if strings.HasPrefix(err.Error(), "already") || strings.HasPrefix(err.Error(), "limit") {
				code = 409
			}
			http.Error(w, err.Error(), code)
			return
		}
		AppendAudit(token, "deception.tripwire.create", d.ID)
		d.Match = twMask(d)
		jsonOut(w, 201, d)
	})
	mux.HandleFunc("DELETE /v1/deception/tripwires/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		id := r.PathValue("id")
		if !twReg.Delete(id) {
			http.Error(w, "not found", 404)
			return
		}
		AppendAudit(token, "deception.tripwire.delete", id)
		jsonOut(w, 200, map[string]any{"deleted": id})
	})
	mux.HandleFunc("POST /v1/deception/tripwires/scan", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		recs := twRecords(raw)
		if len(recs) == 0 {
			http.Error(w, "empty log", 400)
			return
		}
		if len(recs) > twMaxRecords {
			http.Error(w, fmt.Sprintf("too many records (max %d)", twMaxRecords), 413)
			return
		}
		src := "scan"
		if s := r.URL.Query().Get("source"); s != "" {
			src = strings.ToLower(webTruncate(webSanitise(s), 40))
		}
		rep, fs := twScan(recs, src, "")
		stored, err := webStoreFindings(store, fs)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		rep.Findings = stored
		jsonOut(w, 200, rep)
	})
}

func twRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(twRules))
	for _, a := range twRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

// twMerge scans records during another analyser's ingest and returns extra findings and the hit count.
func twMerge(recs []map[string]any, src string) ([]Finding, int) {
	_, fs := twScan(recs, src, "")
	return fs, len(fs)
}
