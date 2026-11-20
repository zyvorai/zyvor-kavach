// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Data governance (DPDP / GDPR-minded helpers). Observation only: nothing here
// acts on a host. Limits are stated honestly in docs/observability.md: this is a
// triage and hygiene aid, not a certified compliance control.

const (
	govMaxLine      = 1024 * 1024
	govMaxIDs       = 200
	govMaxDays      = 36500
	govMaxRedactIn  = 16 * 1024
	govMinSubject   = 3
	govMaxSubject   = 128
	govMaxBody      = 8 * 1024
	govRetentionExt = ".retention.json"
	govRedactionExt = ".redaction.json"
	govAuditExt     = ".governance.audit.jsonl"
)

// govRetentionClasses are the classes retention can purge. The hash-chained
// journal, alert rules, saved searches, notes and the credential registry are
// deliberately excluded (notes/searches are owned by the workspace's in-memory
// state; purging them behind its back would be unsafe).
var govRetentionClasses = []string{"findings", "process_events", "network_events", "file_events"}

var govMu sync.Mutex // serialises policy/redaction file writes and audit appends

// ---------------- redaction ----------------

type govRule struct {
	ID   string
	Desc string
	Re   *regexp.Regexp
	Repl string
}

// All patterns are RE2 (Go regexp): linear time, no backtracking.
var govRules = []govRule{
	{"bearer", "Authorization bearer tokens", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}`), "Bearer [REDACTED:token]"},
	{"password", "password=/--password/-p style values", regexp.MustCompile(`(?i)(--?pass(?:word|wd)?(?:=|\s+)|\bpass(?:word|wd)?=|\b(?:secret|token|api[_-]?key)=)("[^"]*"|'[^']*'|\S+)`), "${1}[REDACTED:secret]"},
	{"aws_key", "AWS access key ids", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b`), "[REDACTED:aws-key]"},
	{"email", "Email addresses", regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}`), "[REDACTED:email]"},
	{"ipv4", "IPv4 addresses", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "[REDACTED:ip]"},
	{"ipv6", "IPv6 addresses (4+ groups or :: compressed)", regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4})?|::(?:[0-9A-Fa-f]{1,4}:?){1,6}`), "[REDACTED:ip]"},
	{"hex_secret", "Long hex strings (32+ chars; also hides file hashes)", regexp.MustCompile(`\b[0-9A-Fa-f]{32,}\b`), "[REDACTED:hex]"},
}

// govRedact masks likely personal data and secrets in free text.
func govRedact(s string) string {
	out, _ := govRedactCount(s)
	return out
}

func govRedactCount(s string) (string, map[string]int) {
	counts := map[string]int{}
	for _, r := range govRules {
		n := len(r.Re.FindAllStringIndex(s, -1))
		if n == 0 {
			continue
		}
		counts[r.ID] = n
		s = r.Re.ReplaceAllString(s, r.Repl)
	}
	return s, counts
}

func govRedactionEnabled(store *Store) bool {
	b, err := os.ReadFile(store.path + govRedactionExt)
	if err != nil {
		return false
	}
	var v struct {
		Enabled bool `json:"enabled"`
	}
	return json.Unmarshal(b, &v) == nil && v.Enabled
}

// govMaybeRedact is the export hook: when the persisted toggle is on it returns
// redacted copies of findings; otherwise the input unchanged.
func govMaybeRedact(store *Store, fs []Finding) []Finding {
	if !govRedactionEnabled(store) {
		return fs
	}
	out := make([]Finding, len(fs))
	for i, f := range fs {
		f.Description = govRedact(f.Description)
		f.Destination = govRedact(f.Destination)
		f.Evidence.Command = govRedact(f.Evidence.Command)
		f.Evidence.ParentExe = govRedact(f.Evidence.ParentExe)
		if f.Tags != nil {
			tags := make([]string, len(f.Tags))
			for j, t := range f.Tags {
				tags[j] = govRedact(t)
			}
			f.Tags = tags
		}
		out[i] = f
	}
	return out
}

// ---------------- persistence helpers ----------------

func govWriteAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

type govPolicy struct {
	Days map[string]int `json:"days"` // class -> max age in days; absent = unlimited
}

func govLoadPolicy(store *Store) govPolicy {
	p := govPolicy{Days: map[string]int{}}
	if b, err := os.ReadFile(store.path + govRetentionExt); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	if p.Days == nil {
		p.Days = map[string]int{}
	}
	return p
}

func govAudit(store *Store, actor, action, detail string) {
	govMu.Lock()
	defer govMu.Unlock()
	line, _ := json.Marshal(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "actor": actor, "action": action, "detail": detail})
	f, err := os.OpenFile(store.path+govAuditExt, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
	_ = f.Sync()
}

// ---------------- scanning ----------------

type govStat struct {
	Class   string     `json:"class"`
	Where   string     `json:"where"`
	Records int        `json:"records"`
	Bytes   int64      `json:"approx_bytes"`
	Oldest  *time.Time `json:"oldest,omitempty"`
	Newest  *time.Time `json:"newest,omitempty"`
	Purge   bool       `json:"retention_supported"`
	Note    string     `json:"note,omitempty"`
}

// span widens the oldest/newest window without touching the record count.
func (g *govStat) span(t time.Time) {
	if t.IsZero() {
		return
	}
	if g.Oldest == nil || t.Before(*g.Oldest) {
		tt := t
		g.Oldest = &tt
	}
	if g.Newest == nil || t.After(*g.Newest) {
		tt := t
		g.Newest = &tt
	}
}

func (g *govStat) see(t time.Time, n int) {
	g.Records++
	g.Bytes += int64(n)
	g.span(t)
}

type govTime struct {
	Time time.Time `json:"time"`
}

type govLedgerLine struct {
	Process *govTime `json:"process"`
	Network *govTime `json:"network"`
	File    *govTime `json:"file"`
}

func govEachLine(path string, fn func(line []byte)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), govMaxLine)
	for sc.Scan() {
		fn(sc.Bytes())
	}
}

func govInventory(store *Store, registry *CredentialRegistry) []govStat {
	rel := func(p string) string { return filepath.Base(p) }
	fnd := &govStat{Class: "findings", Where: rel(store.path), Purge: true}
	proc := &govStat{Class: "process_events", Where: rel(store.eventPath), Purge: true, Note: "includes full command lines; may contain personal data"}
	net := &govStat{Class: "network_events", Where: rel(store.eventPath), Purge: true}
	file := &govStat{Class: "file_events", Where: rel(store.eventPath), Purge: true, Note: "paths may contain usernames"}
	store.mu.Lock()
	govEachLine(store.path, func(l []byte) {
		var x govTime
		if json.Unmarshal(l, &x) == nil {
			fnd.see(x.Time, len(l)+1)
		}
	})
	govEachLine(store.eventPath, func(l []byte) {
		var x govLedgerLine
		if json.Unmarshal(l, &x) != nil {
			return
		}
		switch {
		case x.Process != nil:
			proc.see(x.Process.Time, len(l)+1)
		case x.Network != nil:
			net.see(x.Network.Time, len(l)+1)
		case x.File != nil:
			file.see(x.File.Time, len(l)+1)
		}
	})
	store.mu.Unlock()

	out := []govStat{*fnd, *proc, *net, *file}

	var ws workspaceData
	wsPath := store.path + ".workspace.json"
	if b, err := os.ReadFile(wsPath); err == nil {
		_ = json.Unmarshal(b, &ws)
	}
	size := func(v any) int64 { b, _ := json.Marshal(v); return int64(len(b)) }
	notes := govStat{Class: "notes", Where: rel(wsPath), Records: len(ws.Notes), Bytes: size(ws.Notes), Note: "analyst free text; not purged by retention"}
	for _, n := range ws.Notes {
		notes.span(n.Created)
	}
	journal := govStat{Class: "journal", Where: rel(wsPath), Records: len(ws.Journal), Bytes: size(ws.Journal), Note: "hash-chained audit journal; never purged"}
	for _, j := range ws.Journal {
		journal.span(j.Time)
	}
	searches := govStat{Class: "saved_searches", Where: rel(wsPath), Records: len(ws.Searches), Bytes: size(ws.Searches)}
	for _, s := range ws.Searches {
		searches.span(s.Created)
	}
	out = append(out, notes, journal, searches)

	alerts := govStat{Class: "alert_rules", Where: rel(store.path + ".alerts.json"), Note: "webhook destinations; not purged by retention"}
	if b, err := os.ReadFile(store.path + ".alerts.json"); err == nil {
		var rs []json.RawMessage
		if json.Unmarshal(b, &rs) == nil {
			alerts.Records = len(rs)
		}
		alerts.Bytes = int64(len(b))
	}
	out = append(out, alerts)

	creds := govStat{Class: "credentials_registry", Where: "(credential registry file)", Note: "hashed agent credentials only; not purged by retention"}
	if registry != nil {
		registry.mu.Lock()
		creds.Records = len(registry.agents)
		creds.Where = rel(registry.path)
		for _, a := range registry.agents {
			creds.span(a.Created)
		}
		registry.mu.Unlock()
		if fi, err := os.Stat(registry.path); err == nil {
			creds.Bytes = fi.Size()
		}
	}
	out = append(out, creds)
	return out
}

// ---------------- retention purge ----------------

// govPurge applies (or, with dryRun, counts) retention against the store's
// jsonl files. It runs under Store.mu and rewrites files atomically
// (tmp + fsync + rename). Unparseable lines are always kept. The in-memory
// dedupe set is left alone so replayed old events are not re-ingested.
func govPurge(store *Store, p govPolicy, now time.Time, dryRun bool) (map[string]int, error) {
	cut := map[string]time.Time{}
	for c, d := range p.Days {
		if d >= 1 {
			cut[c] = now.Add(-time.Duration(d) * 24 * time.Hour)
		}
	}
	res := map[string]int{}
	for _, c := range govRetentionClasses {
		res[c] = 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	if c, ok := cut["findings"]; ok {
		_, n, err := govRewrite(store.path, dryRun, func(l []byte) bool {
			var x govTime
			return json.Unmarshal(l, &x) == nil && !x.Time.IsZero() && x.Time.Before(c)
		})
		if err != nil {
			return nil, err
		}
		res["findings"] = n
		if !dryRun && n > 0 {
			f := store.findings[:0:0]
			for _, x := range store.findings {
				if !x.Time.Before(c) {
					f = append(f, x)
				}
			}
			store.findings = f
		}
	}
	cp, hasP := cut["process_events"]
	cn, hasN := cut["network_events"]
	cf, hasF := cut["file_events"]
	if hasP || hasN || hasF {
		counts := map[string]int{}
		_, _, err := govRewrite(store.eventPath, dryRun, func(l []byte) bool {
			var x govLedgerLine
			if json.Unmarshal(l, &x) != nil {
				return false
			}
			old := func(has bool, c time.Time, t *govTime) bool {
				return has && t != nil && !t.Time.IsZero() && t.Time.Before(c)
			}
			switch {
			case x.Process != nil:
				if old(hasP, cp, x.Process) {
					counts["process_events"]++
					return true
				}
			case x.Network != nil:
				if old(hasN, cn, x.Network) {
					counts["network_events"]++
					return true
				}
			case x.File != nil:
				if old(hasF, cf, x.File) {
					counts["file_events"]++
					return true
				}
			}
			return false
		})
		if err != nil {
			return nil, err
		}
		for k, v := range counts {
			res[k] = v
		}
		if !dryRun {
			if hasP {
				v := store.recentEvents[:0:0]
				for _, e := range store.recentEvents {
					if !e.Time.Before(cp) {
						v = append(v, e)
					}
				}
				store.recentEvents = v
			}
			if hasN {
				v := store.networkEvents[:0:0]
				for _, e := range store.networkEvents {
					if !e.Time.Before(cn) {
						v = append(v, e)
					}
				}
				store.networkEvents = v
			}
			if hasF {
				v := store.fileEvents[:0:0]
				for _, e := range store.fileEvents {
					if !e.Time.Before(cf) {
						v = append(v, e)
					}
				}
				store.fileEvents = v
			}
		}
	}
	return res, nil
}

// govRewrite streams path, dropping lines for which drop returns true. With
// dryRun it only counts. Caller holds Store.mu.
func govRewrite(path string, dryRun bool, drop func([]byte) bool) (kept, dropped int, err error) {
	in, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer in.Close()
	var tmp *os.File
	var bw *bufio.Writer
	tmpName := path + ".gov.tmp"
	if !dryRun {
		if tmp, err = os.OpenFile(tmpName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
			return 0, 0, err
		}
		bw = bufio.NewWriter(tmp)
	}
	fail := func(e error) (int, int, error) {
		if tmp != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
		return 0, 0, e
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 4096), govMaxLine)
	for sc.Scan() {
		l := sc.Bytes()
		if drop(l) {
			dropped++
			continue
		}
		kept++
		if bw != nil {
			if _, e := bw.Write(l); e != nil {
				return fail(e)
			}
			if e := bw.WriteByte('\n'); e != nil {
				return fail(e)
			}
		}
	}
	if e := sc.Err(); e != nil {
		return fail(e)
	}
	if dryRun {
		return kept, dropped, nil
	}
	if dropped == 0 {
		tmp.Close()
		os.Remove(tmpName)
		return kept, 0, nil
	}
	if e := bw.Flush(); e != nil {
		return fail(e)
	}
	if e := tmp.Sync(); e != nil {
		return fail(e)
	}
	if e := tmp.Close(); e != nil {
		os.Remove(tmpName)
		return 0, 0, e
	}
	if e := os.Rename(tmpName, path); e != nil {
		os.Remove(tmpName)
		return 0, 0, e
	}
	return kept, dropped, nil
}

// ---------------- subject lookup ----------------

func govSubject(store *Store, q string) map[string]any {
	needle := strings.ToLower(q)
	has := func(ss ...string) bool {
		for _, s := range ss {
			if strings.Contains(strings.ToLower(s), needle) {
				return true
			}
		}
		return false
	}
	fids, nids := []string{}, []string{}
	fcount, ncount := 0, 0
	store.mu.Lock()
	govEachLine(store.path, func(l []byte) {
		var f Finding
		if json.Unmarshal(l, &f) != nil {
			return
		}
		if has(f.Host, f.Description, f.Destination, f.Evidence.Host, f.Evidence.Command, f.Evidence.Executable, f.Evidence.ParentExe, strings.Join(f.Tags, " ")) {
			fcount++
			if len(fids) < govMaxIDs {
				fids = append(fids, f.ID)
			}
		}
	})
	store.mu.Unlock()
	if b, err := os.ReadFile(store.path + ".workspace.json"); err == nil {
		var ws workspaceData
		if json.Unmarshal(b, &ws) == nil {
			for _, n := range ws.Notes {
				if has(n.Text, n.Author) {
					ncount++
					if len(nids) < govMaxIDs {
						nids = append(nids, n.ID)
					}
				}
			}
		}
	}
	return map[string]any{
		"query":    html.EscapeString(q),
		"findings": map[string]any{"count": fcount, "ids": fids, "truncated": fcount > len(fids)},
		"notes":    map[string]any{"count": ncount, "ids": nids, "truncated": ncount > len(nids)},
		"scope":    "findings and analyst notes only (case-insensitive substring); process/network/file ledgers are not searched",
		"limits":   "ids only; no record bodies. Triage aid, not a complete DSAR response",
	}
}

// ---------------- routes ----------------

func govJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func govActor(admin bool) string {
	if admin {
		return "admin"
	}
	return "session"
}

func govParsePolicy(r *http.Request, w http.ResponseWriter) (govPolicy, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, govMaxBody)
	var in struct {
		Days map[string]*int `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", 400)
		return govPolicy{}, false
	}
	p := govPolicy{Days: map[string]int{}}
	for c, d := range in.Days {
		known := false
		for _, k := range govRetentionClasses {
			known = known || k == c
		}
		if !known {
			http.Error(w, "unknown class (allowed: "+strings.Join(govRetentionClasses, ", ")+")", 400)
			return govPolicy{}, false
		}
		if d == nil {
			continue // null = unlimited
		}
		if *d < 1 || *d > govMaxDays {
			http.Error(w, fmt.Sprintf("days must be 1..%d", govMaxDays), 400)
			return govPolicy{}, false
		}
		p.Days[c] = *d
	}
	return p, true
}

// RegisterDataGovernance wires /v1/governance/*.
func RegisterDataGovernance(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/governance/inventory", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		govJSON(w, map[string]any{"mode": "observe-only", "generated": time.Now().UTC().Format(time.RFC3339), "classes": govInventory(store, registry),
			"note": "record counts are read from disk (not the in-memory window); bytes are approximate"})
	})
	mux.HandleFunc("GET /v1/governance/retention", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		govJSON(w, map[string]any{"classes": govRetentionClasses, "days": govLoadPolicy(store).Days, "default": "unlimited"})
	})
	mux.HandleFunc("POST /v1/governance/retention", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		p, ok := govParsePolicy(r, w)
		if !ok {
			return
		}
		govMu.Lock()
		err := govWriteAtomic(store.path+govRetentionExt, p)
		govMu.Unlock()
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		b, _ := json.Marshal(p.Days)
		govAudit(store, govActor(admin), "retention.set", string(b))
		govJSON(w, map[string]any{"days": p.Days})
	})
	mux.HandleFunc("POST /v1/governance/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		p := govLoadPolicy(store)
		if r.ContentLength != 0 {
			var ok bool
			if p, ok = govParsePolicy(r, w); !ok {
				return
			}
		}
		res, err := govPurge(store, p, time.Now(), true)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		govJSON(w, map[string]any{"dry_run": true, "would_purge": res, "days": p.Days})
	})
	mux.HandleFunc("POST /v1/governance/retention/apply", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !admin {
			http.Error(w, "admin token required", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var in struct {
			Confirm string `json:"confirm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Confirm != "purge" {
			http.Error(w, `body must be {"confirm":"purge"}`, 400)
			return
		}
		p := govLoadPolicy(store)
		res, err := govPurge(store, p, time.Now(), false)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		b, _ := json.Marshal(res)
		govAudit(store, "admin", "retention.apply", string(b))
		govJSON(w, map[string]any{"dry_run": false, "purged": res, "days": p.Days})
	})
	mux.HandleFunc("GET /v1/governance/redaction", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rules := make([]map[string]string, 0, len(govRules))
		for _, x := range govRules {
			rules = append(rules, map[string]string{"id": x.ID, "description": x.Desc, "pattern": x.Re.String()})
		}
		govJSON(w, map[string]any{"enabled": govRedactionEnabled(store), "applies_to": "GET /v1/export/findings", "rules": rules})
	})
	mux.HandleFunc("POST /v1/governance/redaction", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Enabled == nil {
			http.Error(w, `body must be {"enabled":true|false}`, 400)
			return
		}
		govMu.Lock()
		err := govWriteAtomic(store.path+govRedactionExt, map[string]bool{"enabled": *in.Enabled})
		govMu.Unlock()
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		govAudit(store, govActor(admin), "redaction.set", fmt.Sprint(*in.Enabled))
		govJSON(w, map[string]any{"enabled": *in.Enabled})
	})
	mux.HandleFunc("POST /v1/governance/redact/preview", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, govMaxRedactIn*2+1024)
		var in struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Text) > govMaxRedactIn {
			http.Error(w, "invalid json or text over 16KB", 400)
			return
		}
		out, counts := govRedactCount(in.Text)
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		govJSON(w, map[string]any{"redacted": out, "matches": counts, "rules_hit": keys})
	})
	mux.HandleFunc("GET /v1/governance/subject", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(q) < govMinSubject || len(q) > govMaxSubject {
			http.Error(w, fmt.Sprintf("q must be %d..%d chars", govMinSubject, govMaxSubject), 400)
			return
		}
		govJSON(w, govSubject(store, q))
	})
}
