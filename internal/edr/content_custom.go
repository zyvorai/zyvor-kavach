// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Customer-authored detection content. Custom rules use the same JSON schema and the same harness
// checks as embedded packs (own positive/negative samples plus a benign-baseline guard), persist
// next to the findings store, evaluate on the live path and count toward the ATT&CK matrix with
// source=custom. They can never shadow an embedded or built-in rule id. Observation only.

const (
	customMaxRules = 500
	customMaxBody  = 4 * 1024 * 1024
	customMaxDry   = 1000
	customSource   = "custom"
)

// customBenignBaseline mirrors the harness baseline (content_framework_test.go): everyday events no
// rule may match. Each event is tried under the rule's event kind and process/file/network.
var customBenignBaseline = []LabEvent{
	{Executable: "/bin/ls", Command: "ls -la /home/dev"},
	{Executable: "/bin/cat", Command: "cat /etc/hostname"},
	{Executable: "/bin/bash", ParentExe: "/usr/sbin/sshd", Command: "bash -c echo hi"},
	{Executable: "/usr/lib/systemd/systemd", Command: "/sbin/init splash"},
	{Executable: "/usr/bin/curl", Command: "curl https://example.com"},
	{Executable: "/usr/bin/ssh-agent", Command: "ssh-agent -s"},
	{Executable: "/usr/local/go/bin/go", Command: "go build ./..."},
	{Executable: "/usr/bin/python3", Command: "python3 script.py"},
	{Executable: "/usr/bin/apt", Command: "apt update"},
	{Executable: "/usr/bin/git", Command: "git status"},
	{Executable: "/usr/bin/tar", Command: "tar czf backup.tgz /var/www"},
	{Executable: "/usr/bin/vim", Command: "vim notes.txt"},
	{Executable: "C:\\Windows\\explorer.exe", Command: "explorer.exe C:\\Users\\ann\\Documents"},
	{Executable: "C:\\Windows\\System32\\cmd.exe", Command: "cmd.exe /c dir"},
	{Executable: "/usr/bin/open", Command: "open -a Safari https://example.com"},
	{Path: "/home/dev/project/main.go", Operation: "modify"},
	{Path: "/var/log/syslog", Operation: "modify"},
	{Path: "/tmp/build.log", Operation: "create"},
	{Path: "/Users/ann/Documents/report.docx", Operation: "create"},
	{Path: "C:\\Users\\ann\\Documents\\report.docx", Operation: "modify"},
	{Path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"},
	{Destination: "example.com:443"},
	{Destination: "93.184.216.34:443"},
	{Destination: "github.com:22"},
	{Destination: "registry.npmjs.org:443"},
}

var (
	customIDs     atomic.Pointer[map[string]bool] // ids of the custom rules currently merged into the registry
	customApplyMu sync.Mutex

	embeddedOnce sync.Once
	embeddedByID map[string]bool
)

// contentIsCustom reports whether a rule id is a customer-authored rule in the live registry.
func contentIsCustom(id string) bool {
	m := customIDs.Load()
	return m != nil && (*m)[id]
}

func embeddedRuleIDs() map[string]bool {
	embeddedOnce.Do(func() {
		embeddedByID = map[string]bool{}
		if packs, err := embeddedContentPacks(); err == nil {
			reg, _ := buildContentRegistry(packs)
			for id := range reg.byID {
				embeddedByID[id] = true
			}
		}
	})
	return embeddedByID
}

// validateCustomRule runs the full harness against one rule: schema + compile, no id collision with
// embedded or built-in rules, positive/negative samples, and the benign-baseline guard.
func validateCustomRule(r *ContentRule) error {
	r.Source = ""
	if err := r.validateAndCompile(); err != nil {
		return err
	}
	if embeddedRuleIDs()[r.ID] {
		return fmt.Errorf("rule %q: id collides with an embedded content rule; custom rules cannot override embedded ids", r.ID)
	}
	for i, ev := range r.Tests.Positive {
		ev.Kind = r.EventType
		if !r.Matches(ev) {
			return fmt.Errorf("rule %q: positive sample #%d does not match the rule", r.ID, i)
		}
	}
	for i, ev := range r.Tests.Negative {
		ev.Kind = r.EventType
		if r.Matches(ev) {
			return fmt.Errorf("rule %q: negative sample #%d matches the rule but must not", r.ID, i)
		}
	}
	for i, ev := range customBenignBaseline {
		for _, kind := range []string{r.EventType, "process", "file", "network"} {
			ev.Kind = kind
			if r.Matches(ev) {
				return fmt.Errorf("rule %q: matches benign baseline event #%d (%s) as kind %s; tighten the pattern", r.ID, i, customBaselineLabel(customBenignBaseline[i]), kind)
			}
		}
	}
	r.Source = customSource
	return nil
}

func customBaselineLabel(e LabEvent) string {
	for _, s := range []string{e.Command, e.Path, e.Destination, e.Executable} {
		if s != "" {
			return s
		}
	}
	return "event"
}

// customStore holds the persisted custom rules.
type customStore struct {
	mu    sync.Mutex
	path  string
	rules map[string]*ContentRule
}

func (c *customStore) load() {
	c.rules = map[string]*ContentRule{}
	b, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var list []ContentRule
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for i := range list {
		r := list[i]
		if len(c.rules) < customMaxRules && validateCustomRule(&r) == nil {
			c.rules[r.ID] = &r
		}
	}
}

func (c *customStore) sorted() []*ContentRule {
	out := make([]*ContentRule, 0, len(c.rules))
	for _, r := range c.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (c *customStore) save() error {
	list := make([]ContentRule, 0, len(c.rules))
	for _, r := range c.sorted() {
		list = append(list, *r)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// apply merges the custom rules into the live registry (embedded rules are kept as loaded).
func (c *customStore) apply() {
	customApplyMu.Lock()
	defer customApplyMu.Unlock()
	old := map[string]bool{}
	if m := customIDs.Load(); m != nil {
		old = *m
	}
	reg := &ContentRegistry{byID: map[string]*ContentRule{}, byType: map[string][]*ContentRule{}}
	taken := map[string]bool{}
	if base := contentReg.Load(); base != nil {
		for _, r := range base.rules {
			if !old[r.ID] {
				reg.rules = append(reg.rules, r)
				taken[r.ID] = true
			}
		}
	}
	ids := map[string]bool{}
	for _, r := range c.sorted() {
		if taken[r.ID] {
			continue // never override an embedded id
		}
		cp := *r
		reg.rules = append(reg.rules, &cp)
		ids[r.ID] = true
	}
	sort.Slice(reg.rules, func(i, j int) bool { return reg.rules[i].ID < reg.rules[j].ID })
	for _, r := range reg.rules {
		reg.byID[r.ID] = r
		if !r.PendingTelemetry {
			reg.byType[r.EventType] = append(reg.byType[r.EventType], r)
		}
	}
	customIDs.Store(&ids)
	contentReg.Store(reg)
}

type customImportItem struct {
	ID          string   `json:"id"`
	Status      string   `json:"status"` // imported | valid (validate-only) | rejected | unsupported
	Errors      []string `json:"errors,omitempty"`
	Unsupported []string `json:"unsupported,omitempty"`
}

// put validates rules and, unless validateOnly, stores every valid one (rejected rules are reported).
func (c *customStore) put(rules []ContentRule, validateOnly bool) []customImportItem {
	return c.putAs("", rules, validateOnly)
}

// putAs is put with the acting principal recorded in the rule change history (rule_health.go).
func (c *customStore) putAs(actor string, rules []ContentRule, validateOnly bool) []customImportItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	items := make([]customImportItem, len(rules))
	staged := map[string]*ContentRule{}
	count := len(c.rules)
	for i := range rules {
		r := rules[i]
		it := customImportItem{ID: r.ID}
		_, exists := c.rules[r.ID]
		if err := validateCustomRule(&r); err != nil {
			it.Status, it.Errors = "rejected", []string{err.Error()}
		} else if !exists && staged[r.ID] == nil && count >= customMaxRules {
			it.Status, it.Errors = "rejected", []string{fmt.Sprintf("custom rule cap of %d reached", customMaxRules)}
		} else {
			if !exists && staged[r.ID] == nil {
				count++
			}
			staged[r.ID] = &r
			it.Status = "valid"
		}
		items[i] = it
	}
	if validateOnly || len(staged) == 0 {
		return items
	}
	prev := c.rules
	next := make(map[string]*ContentRule, len(prev)+len(staged))
	for k, v := range prev {
		next[k] = v
	}
	for k, v := range staged {
		next[k] = v
	}
	c.rules = next
	if err := c.save(); err != nil {
		c.rules = prev
		for i := range items {
			if items[i].Status == "valid" {
				items[i].Status, items[i].Errors = "rejected", []string{"persist failed: " + err.Error()}
			}
		}
		return items
	}
	c.apply()
	for i := range items {
		if items[i].Status == "valid" {
			items[i].Status = "imported"
			if staged[items[i].ID] != nil {
				ruleChanged(actor, items[i].ID, prev[items[i].ID], staged[items[i].ID])
			}
		}
	}
	return items
}

func customJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func customDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}

func customSummary(items []customImportItem) (imported, valid, rejected, unsupported int) {
	for _, it := range items {
		switch it.Status {
		case "imported":
			imported++
		case "valid":
			valid++
		case "rejected":
			rejected++
		case "unsupported":
			unsupported++
		}
	}
	return
}

// RegisterCustomContent wires the custom content lifecycle endpoints (all authenticated).
func RegisterCustomContent(mux *http.ServeMux, token string, store *Store) {
	cs := &customStore{path: store.path + ".customcontent.json"}
	cs.load()
	if contentReg.Load() == nil {
		_ = LoadContentPacks()
	}
	cs.apply()

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			h(w, r)
		}
	}
	body := func(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, customMaxBody))
		if err != nil {
			customJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large or unreadable"})
			return nil, false
		}
		return b, true
	}

	mux.HandleFunc("GET /v1/content/custom", auth(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		list := cs.sorted()
		out := make([]ContentRule, len(list))
		for i, x := range list {
			out[i] = *x
			if r.URL.Query().Get("tests") != "1" {
				out[i].Tests = nil
			}
		}
		cs.mu.Unlock()
		customJSON(w, 200, map[string]any{"mode": "observe-only", "source": customSource, "count": len(out), "rules": out})
	}))

	mux.HandleFunc("POST /v1/content/custom", auth(func(w http.ResponseWriter, r *http.Request) {
		b, ok := body(w, r)
		if !ok {
			return
		}
		var rule ContentRule
		if err := customDecode(b, &rule); err != nil {
			customJSON(w, 400, map[string]any{"error": "invalid rule JSON: " + err.Error(), "errors": []string{err.Error()}})
			return
		}
		it := cs.putAs(customActor(r), []ContentRule{rule}, false)[0]
		if it.Status != "imported" {
			code := 400
			if strings.Contains(strings.Join(it.Errors, " "), "embedded content rule") {
				code = 409
			}
			customJSON(w, code, map[string]any{"error": strings.Join(it.Errors, "; "), "errors": it.Errors})
			return
		}
		cs.mu.Lock()
		saved := *cs.rules[rule.ID]
		cs.mu.Unlock()
		customJSON(w, 200, map[string]any{"status": "saved", "mode": "observe-only", "rule": saved})
	}))

	mux.HandleFunc("DELETE /v1/content/custom/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		cs.mu.Lock()
		defer cs.mu.Unlock()
		if _, ok := cs.rules[id]; !ok {
			if embeddedRuleIDs()[id] {
				customJSON(w, 400, map[string]any{"error": "embedded rules cannot be deleted"})
				return
			}
			customJSON(w, 404, map[string]any{"error": "custom rule not found"})
			return
		}
		prev := cs.rules
		next := make(map[string]*ContentRule, len(prev))
		for k, v := range prev {
			if k != id {
				next[k] = v
			}
		}
		cs.rules = next
		if err := cs.save(); err != nil {
			cs.rules = prev
			customJSON(w, 500, map[string]any{"error": "persist failed: " + err.Error()})
			return
		}
		cs.apply()
		ruleChanged(customActor(r), id, prev[id], nil)
		customJSON(w, 200, map[string]any{"status": "deleted", "id": id})
	}))

	mux.HandleFunc("POST /v1/content/custom/{id}/dryrun", auth(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		rule := cs.rules[r.PathValue("id")]
		cs.mu.Unlock()
		if rule == nil {
			customJSON(w, 404, map[string]any{"error": "custom rule not found"})
			return
		}
		b, ok := body(w, r)
		if !ok {
			return
		}
		var req struct {
			Events []LabEvent `json:"events"`
		}
		if err := customDecode(b, &req); err != nil {
			customJSON(w, 400, map[string]any{"error": "invalid body (want {\"events\":[...]}): " + err.Error()})
			return
		}
		if len(req.Events) == 0 || len(req.Events) > customMaxDry {
			customJSON(w, 400, map[string]any{"error": fmt.Sprintf("events: 1..%d required", customMaxDry)})
			return
		}
		type match struct {
			Index int      `json:"index"`
			Event LabEvent `json:"event"`
		}
		matches := []match{}
		for i, ev := range req.Events {
			ev.Kind = rule.EventType
			if rule.matchCtx(newEvalCtx(ev), true) {
				matches = append(matches, match{i, req.Events[i]})
			}
		}
		customJSON(w, 200, map[string]any{"mode": "observe-only", "rule": rule.ID, "event_type": rule.EventType,
			"evaluated": len(req.Events), "matched": len(matches), "matches": matches, "findings_recorded": 0})
	}))

	mux.HandleFunc("POST /v1/content/export", auth(func(w http.ResponseWriter, r *http.Request) {
		b, ok := body(w, r)
		if !ok {
			return
		}
		var f struct {
			Source    string   `json:"source"` // custom (default) | embedded | all
			IDs       []string `json:"ids"`
			Tactic    string   `json:"tactic"`
			Technique string   `json:"technique"`
			OS        string   `json:"os"`
			Batch     string   `json:"batch"`
			Q         string   `json:"q"`
			EventType string   `json:"event_type"`
		}
		if len(bytes.TrimSpace(b)) > 0 {
			if err := customDecode(b, &f); err != nil {
				customJSON(w, 400, map[string]any{"error": "invalid filter: " + err.Error()})
				return
			}
		}
		if f.Source == "" {
			f.Source = customSource
		}
		if f.Source != customSource && f.Source != "embedded" && f.Source != "all" {
			customJSON(w, 400, map[string]any{"error": "source must be custom|embedded|all"})
			return
		}
		reg := contentReg.Load()
		if reg == nil {
			reg = &ContentRegistry{}
		}
		q := map[string][]string{"tactic": {f.Tactic}, "technique": {f.Technique}, "os": {f.OS}, "batch": {f.Batch}, "q": {f.Q}}
		want := map[string]bool{}
		for _, id := range f.IDs {
			want[id] = true
		}
		rules := []ContentRule{}
		for _, x := range contentFilter(reg, q) {
			isCustom := contentIsCustom(x.ID)
			if (f.Source == customSource && !isCustom) || (f.Source == "embedded" && isCustom) {
				continue
			}
			if len(want) > 0 && !want[x.ID] {
				continue
			}
			if f.EventType != "" && x.EventType != f.EventType {
				continue
			}
			rules = append(rules, *x)
		}
		customJSON(w, 200, map[string]any{"pack": "export", "rules": rules})
	}))

	mux.HandleFunc("POST /v1/content/import", auth(func(w http.ResponseWriter, r *http.Request) {
		b, ok := body(w, r)
		if !ok {
			return
		}
		qv := r.URL.Query()
		validateOnly := qv.Get("validate_only") == "true" || qv.Get("validate_only") == "1"
		var items []customImportItem
		switch qv.Get("format") {
		case "", "kavach":
			var p contentPack
			if err := customDecode(b, &p); err != nil {
				customJSON(w, 400, map[string]any{"error": "invalid pack (want {\"pack\":...,\"rules\":[...]}): " + err.Error()})
				return
			}
			if len(p.Rules) == 0 {
				customJSON(w, 400, map[string]any{"error": "pack has no rules"})
				return
			}
			items = cs.putAs(customActor(r), p.Rules, validateOnly)
		case "sigma":
			res, err := sigmaConvertDocument(b)
			if err != nil {
				customJSON(w, 400, map[string]any{"error": "invalid Sigma input: " + err.Error()})
				return
			}
			var rules []ContentRule
			var idx []int
			items = make([]customImportItem, len(res))
			for i, s := range res {
				items[i] = customImportItem{ID: s.ID, Errors: s.Errors, Unsupported: s.Unsupported}
				switch {
				case len(s.Unsupported) > 0:
					items[i].Status = "unsupported"
				case len(s.Errors) > 0 || s.Rule == nil:
					items[i].Status = "rejected"
				default:
					rules, idx = append(rules, *s.Rule), append(idx, i)
				}
			}
			if len(rules) > 0 {
				for k, it := range cs.putAs(customActor(r), rules, validateOnly) {
					i := idx[k]
					items[i].Status, items[i].Errors = it.Status, it.Errors
				}
			}
		default:
			customJSON(w, 400, map[string]any{"error": "format must be kavach or sigma"})
			return
		}
		imp, val, rej, uns := customSummary(items)
		code := 200
		if len(items) > 0 && imp+val == 0 {
			code = 400
		}
		customJSON(w, code, map[string]any{"mode": "observe-only", "validate_only": validateOnly, "imported": imp,
			"valid": val, "rejected": rej, "unsupported": uns, "results": items})
	}))
}
