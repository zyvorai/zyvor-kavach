// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Detection-as-code lab. Rules here are a SANDBOX: they are validated, tested against samples and
// backtested against stored telemetry, but are never promoted into live detection or ruleMITRE.
// Observation-only: nothing here contains, kills or blocks.

const (
	labMode          = "sandbox"
	labMaxEvents     = 50000
	labMaxSamples    = 1000
	labMaxRules      = 200
	labMaxBody       = 256 * 1024
	labMaxTestBody   = 4 * 1024 * 1024
	labMaxRegexLen   = 256
	labMaxValueLen   = 512
	labMaxInValues   = 100
	labMaxNodes      = 50
	labMaxDepth      = 6
	labMaxInputLen   = 4096
	labMaxWindowSecs = 7 * 86400
	labMaxCount      = 100000
	labHitSampleMax  = 20
)

var labFields = map[string]bool{
	"executable": true, "command": true, "parent_exe": true, "host": true, "uid": true,
	"path": true, "destination": true, "kind": true, "rule": true, "severity": true, "operation": true,
}
var labOps = map[string]bool{"equals": true, "contains": true, "startswith": true, "endswith": true, "regex": true, "in": true}
var labIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var labTechRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// LabEvent is the flattened event the DSL matches against (process, file, network or finding).
type LabEvent struct {
	Kind        string    `json:"kind,omitempty"`
	Time        time.Time `json:"time"`
	Host        string    `json:"host,omitempty"`
	UID         *int      `json:"uid,omitempty"`
	Executable  string    `json:"executable,omitempty"`
	ParentExe   string    `json:"parent_exe,omitempty"`
	Command     string    `json:"command,omitempty"`
	Path        string    `json:"path,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Rule        string    `json:"rule,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Operation   string    `json:"operation,omitempty"`
	// Attrs carries type-specific fields (telemetry: key, query, method, module_path, ...). Content
	// rules may reference them by name; the lab DSL (labFields) does not.
	Attrs map[string]string `json:"attrs,omitempty"`
}

func (e LabEvent) field(name string) (string, bool) {
	var v string
	switch name {
	case "executable":
		v = e.Executable
	case "command":
		v = e.Command
	case "parent_exe":
		v = e.ParentExe
	case "host":
		v = e.Host
	case "path":
		v = e.Path
	case "destination":
		v = e.Destination
	case "kind":
		v = e.Kind
	case "rule":
		v = e.Rule
	case "severity":
		v = e.Severity
	case "operation":
		v = e.Operation
	case "uid":
		if e.UID == nil {
			return "", false
		}
		return strconv.Itoa(*e.UID), true
	}
	if v == "" && e.Attrs != nil {
		v = e.Attrs[name]
	}
	return v, v != ""
}

// LabNode is a boolean tree node: a leaf (field/op/value) or all / any / not.
type LabNode struct {
	Field         string    `json:"field,omitempty"`
	Op            string    `json:"op,omitempty"`
	Value         string    `json:"value,omitempty"`
	Values        []string  `json:"values,omitempty"`
	CaseSensitive bool      `json:"case_sensitive,omitempty"`
	All           []LabNode `json:"all,omitempty"`
	Any           []LabNode `json:"any,omitempty"`
	Not           *LabNode  `json:"not,omitempty"`

	re  *regexp.Regexp
	set map[string]struct{}
}

type LabThreshold struct {
	Count         int      `json:"count"`
	WithinSeconds int      `json:"within_seconds"`
	GroupBy       []string `json:"group_by,omitempty"`
}

type LabRule struct {
	ID          string        `json:"id,omitempty"`
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	Technique   string        `json:"technique,omitempty"`
	Enabled     bool          `json:"enabled"`
	Mode        string        `json:"mode"`
	Condition   LabNode       `json:"condition"`
	Threshold   *LabThreshold `json:"threshold,omitempty"`
	Updated     time.Time     `json:"updated,omitempty"`
}

// ParseLabRule strictly decodes and validates a rule. Errors name the offending field.
func ParseLabRule(raw []byte) (*LabRule, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r LabRule
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("rule: %v", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *LabRule) Validate() error {
	r.Mode = labMode // always sandbox, regardless of input
	if r.ID != "" && !labIDRe.MatchString(r.ID) {
		return fmt.Errorf("id: must match %s", labIDRe)
	}
	if len(r.Name) > 120 {
		return fmt.Errorf("name: longer than 120 chars")
	}
	if len(r.Description) > 1000 {
		return fmt.Errorf("description: longer than 1000 chars")
	}
	if r.Technique != "" && !labTechRe.MatchString(r.Technique) {
		return fmt.Errorf("technique: %q is not an ATT&CK id like T1059 or T1059.004", r.Technique)
	}
	nodes := 0
	if err := r.Condition.validate("condition", 0, &nodes); err != nil {
		return err
	}
	if t := r.Threshold; t != nil {
		if t.Count < 1 || t.Count > labMaxCount {
			return fmt.Errorf("threshold.count: must be 1..%d", labMaxCount)
		}
		if t.WithinSeconds < 1 || t.WithinSeconds > labMaxWindowSecs {
			return fmt.Errorf("threshold.within_seconds: must be 1..%d", labMaxWindowSecs)
		}
		if len(t.GroupBy) > 3 {
			return fmt.Errorf("threshold.group_by: at most 3 fields")
		}
		for i, g := range t.GroupBy {
			if !labFields[g] {
				return fmt.Errorf("threshold.group_by[%d]: unknown field %q", i, g)
			}
		}
	}
	return nil
}

func (n *LabNode) validate(path string, depth int, nodes *int) error {
	return n.validateFields(path, depth, nodes, labFields)
}

// validateFields is validate with a caller-chosen set of allowed field names (content rules for
// telemetry event types accept extra fields).
func (n *LabNode) validateFields(path string, depth int, nodes *int, fields map[string]bool) error {
	if depth > labMaxDepth {
		return fmt.Errorf("%s: nesting deeper than %d", path, labMaxDepth)
	}
	*nodes++
	if *nodes > labMaxNodes {
		return fmt.Errorf("%s: more than %d condition nodes", path, labMaxNodes)
	}
	kinds := 0
	if n.Field != "" || n.Op != "" || n.Value != "" || len(n.Values) > 0 {
		kinds++
	}
	if len(n.All) > 0 {
		kinds++
	}
	if len(n.Any) > 0 {
		kinds++
	}
	if n.Not != nil {
		kinds++
	}
	if kinds != 1 {
		return fmt.Errorf("%s: must be exactly one of a field condition, all, any or not", path)
	}
	switch {
	case len(n.All) > 0:
		for i := range n.All {
			if err := n.All[i].validateFields(fmt.Sprintf("%s.all[%d]", path, i), depth+1, nodes, fields); err != nil {
				return err
			}
		}
		return nil
	case len(n.Any) > 0:
		for i := range n.Any {
			if err := n.Any[i].validateFields(fmt.Sprintf("%s.any[%d]", path, i), depth+1, nodes, fields); err != nil {
				return err
			}
		}
		return nil
	case n.Not != nil:
		return n.Not.validateFields(path+".not", depth+1, nodes, fields)
	}
	if !fields[n.Field] {
		return fmt.Errorf("%s.field: unknown field %q", path, n.Field)
	}
	if !labOps[n.Op] {
		return fmt.Errorf("%s.op: unknown operator %q (use equals|contains|startswith|endswith|regex|in)", path, n.Op)
	}
	if n.Op == "in" {
		if n.Value != "" {
			return fmt.Errorf("%s.value: use values with operator in", path)
		}
		if len(n.Values) == 0 || len(n.Values) > labMaxInValues {
			return fmt.Errorf("%s.values: need 1..%d entries", path, labMaxInValues)
		}
		n.set = make(map[string]struct{}, len(n.Values))
		for i, v := range n.Values {
			if len(v) > labMaxValueLen {
				return fmt.Errorf("%s.values[%d]: longer than %d chars", path, i, labMaxValueLen)
			}
			if !n.CaseSensitive {
				v = strings.ToLower(v)
			}
			n.set[v] = struct{}{}
		}
		return nil
	}
	if len(n.Values) > 0 {
		return fmt.Errorf("%s.values: only valid with operator in", path)
	}
	if n.Value == "" {
		return fmt.Errorf("%s.value: required", path)
	}
	if n.Op == "regex" {
		if len(n.Value) > labMaxRegexLen {
			return fmt.Errorf("%s.value: regex longer than %d chars", path, labMaxRegexLen)
		}
		p := n.Value
		if !n.CaseSensitive {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p) // RE2: linear time, no backtracking
		if err != nil {
			return fmt.Errorf("%s.value: invalid regex: %v", path, err)
		}
		n.re = re
	} else if len(n.Value) > labMaxValueLen {
		return fmt.Errorf("%s.value: longer than %d chars", path, labMaxValueLen)
	}
	return nil
}

// LabTrace is one step of a per-condition evaluation trace.
type LabTrace struct {
	Cond     string     `json:"cond"`
	Matched  bool       `json:"matched"`
	Actual   string     `json:"actual,omitempty"`
	Missing  bool       `json:"missing,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Children []LabTrace `json:"children,omitempty"`
}

func (n *LabNode) eval(ev LabEvent, trace bool) (bool, *LabTrace) {
	switch {
	case len(n.All) > 0:
		ok := true
		t := &LabTrace{Cond: "all"}
		for i := range n.All {
			m, c := n.All[i].eval(ev, trace)
			if trace {
				t.Children = append(t.Children, *c)
			}
			if !m {
				ok = false
				if !trace {
					break
				}
			}
		}
		t.Matched = ok
		return ok, t
	case len(n.Any) > 0:
		ok := false
		t := &LabTrace{Cond: "any"}
		for i := range n.Any {
			m, c := n.Any[i].eval(ev, trace)
			if trace {
				t.Children = append(t.Children, *c)
			}
			if m {
				ok = true
				if !trace {
					break
				}
			}
		}
		t.Matched = ok
		return ok, t
	case n.Not != nil:
		m, c := n.Not.eval(ev, trace)
		t := &LabTrace{Cond: "not", Matched: !m}
		if trace {
			t.Children = []LabTrace{*c}
		}
		return !m, t
	}
	actual, present := ev.field(n.Field)
	t := &LabTrace{}
	if trace {
		if n.Op == "in" {
			t.Cond = fmt.Sprintf("%s in %v", n.Field, n.Values)
		} else {
			t.Cond = fmt.Sprintf("%s %s %q", n.Field, n.Op, n.Value)
		}
		t.Actual = labTruncate(actual, 200)
		t.Missing = !present
	}
	if !present {
		t.Reason = "field absent on event"
		return false, t
	}
	if len(actual) > labMaxInputLen {
		actual = actual[:labMaxInputLen]
	}
	a, v := actual, n.Value
	if !n.CaseSensitive {
		a, v = strings.ToLower(a), strings.ToLower(v)
	}
	var m bool
	switch n.Op {
	case "equals":
		m = a == v
	case "contains":
		m = strings.Contains(a, v)
	case "startswith":
		m = strings.HasPrefix(a, v)
	case "endswith":
		m = strings.HasSuffix(a, v)
	case "regex":
		m = n.re.MatchString(actual)
	case "in":
		_, m = n.set[a]
	}
	t.Matched = m
	return m, t
}

func labTruncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// LabHit is a rule match, possibly aggregated by a threshold.
type LabHit struct {
	Event LabEvent `json:"event"`
	Why   string   `json:"why"`
	Count int      `json:"count,omitempty"`
}

// Run evaluates the rule across events (sorted by time) and returns hits. Rule must be validated.
func (r *LabRule) Run(events []LabEvent) []LabHit {
	sorted := make([]LabEvent, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Time.Before(sorted[j].Time) })
	var hits []LabHit
	win := map[string][]time.Time{}
	for _, ev := range sorted {
		if m, _ := r.Condition.eval(ev, false); !m {
			continue
		}
		t := r.Threshold
		if t == nil {
			hits = append(hits, LabHit{Event: ev, Why: "condition matched"})
			continue
		}
		key := labGroupKey(t.GroupBy, ev)
		w := append(win[key], ev.Time)
		cut := ev.Time.Add(-time.Duration(t.WithinSeconds) * time.Second)
		i := 0
		for i < len(w) && w[i].Before(cut) {
			i++
		}
		w = w[i:]
		if len(w) >= t.Count {
			hits = append(hits, LabHit{Event: ev, Count: len(w), Why: fmt.Sprintf("%d matches within %ds for group %q", len(w), t.WithinSeconds, key)})
			w = nil
		}
		win[key] = w
	}
	return hits
}

func labGroupKey(by []string, ev LabEvent) string {
	if len(by) == 0 {
		return "*"
	}
	parts := make([]string, len(by))
	for i, f := range by {
		parts[i], _ = ev.field(f)
	}
	return strings.Join(parts, "|")
}

// labEventsFromStore flattens stored process/file/network events and findings, capped at labMaxEvents.
func labEventsFromStore(s *Store) ([]LabEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []LabEvent
	truncated := false
	add := func(e LabEvent) bool {
		if len(out) >= labMaxEvents {
			truncated = true
			return false
		}
		out = append(out, e)
		return true
	}
	for _, e := range s.recentEvents {
		uid := e.UID
		if !add(LabEvent{Kind: "process", Time: e.Time, Host: e.Host, UID: &uid, Executable: e.Executable, ParentExe: e.ParentExe, Command: e.Command}) {
			return out, truncated
		}
	}
	for _, e := range s.fileEvents {
		if !add(LabEvent{Kind: "file", Time: e.Time, Host: e.Host, Path: e.Path, Operation: e.Operation}) {
			return out, truncated
		}
	}
	for _, e := range s.networkEvents {
		if !add(LabEvent{Kind: "network", Time: e.Time, Host: e.Host, Destination: e.Destination}) {
			return out, truncated
		}
	}
	for _, f := range s.findings {
		uid := f.Evidence.UID
		if !add(LabEvent{Kind: "finding", Time: f.Time, Host: f.Host, UID: &uid, Executable: f.Evidence.Executable,
			ParentExe: f.Evidence.ParentExe, Command: f.Evidence.Command, Destination: f.Destination, Rule: f.Rule, Severity: f.Severity}) {
			return out, truncated
		}
	}
	return out, truncated
}

type labStore struct {
	mu    sync.Mutex
	path  string
	rules []LabRule
}

func (l *labStore) load() {
	if b, err := os.ReadFile(l.path); err == nil {
		_ = json.Unmarshal(b, &l.rules)
		for i := range l.rules {
			l.rules[i].Mode = labMode
			if l.rules[i].Validate() != nil {
				l.rules[i].Enabled = false
			}
		}
	}
}

func (l *labStore) save() error {
	b, err := json.MarshalIndent(l.rules, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

func labJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func labReadBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		labJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large or unreadable"})
		return nil, false
	}
	return b, true
}

// RegisterDetectionLab wires the sandbox detection-as-code endpoints.
func RegisterDetectionLab(mux *http.ServeMux, token string, store *Store) {
	ls := &labStore{path: store.path + ".labrules.json"}
	ls.load()

	// envelope accepts {"rule": {...}, "events": [...]} or {"rule_id": "..."} for stored rules.
	type envelope struct {
		Rule   json.RawMessage `json:"rule"`
		RuleID string          `json:"rule_id"`
		Events []LabEvent      `json:"events"`
	}
	resolve := func(w http.ResponseWriter, env envelope) (*LabRule, bool) {
		if len(env.Rule) > 0 {
			rule, err := ParseLabRule(env.Rule)
			if err != nil {
				labJSON(w, 400, map[string]any{"valid": false, "error": err.Error(), "mode": labMode})
				return nil, false
			}
			return rule, true
		}
		if env.RuleID != "" {
			ls.mu.Lock()
			defer ls.mu.Unlock()
			for i := range ls.rules {
				if ls.rules[i].ID == env.RuleID {
					c := ls.rules[i]
					return &c, true
				}
			}
			labJSON(w, 404, map[string]any{"error": "lab rule not found"})
			return nil, false
		}
		labJSON(w, 400, map[string]any{"valid": false, "error": "rule: required (or rule_id)", "mode": labMode})
		return nil, false
	}

	mux.HandleFunc("POST /v1/lab/rules/validate", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		b, ok := labReadBody(w, r, labMaxBody)
		if !ok {
			return
		}
		rule, err := ParseLabRule(b)
		if err != nil {
			labJSON(w, 400, map[string]any{"valid": false, "error": err.Error(), "mode": labMode})
			return
		}
		labJSON(w, 200, map[string]any{"valid": true, "mode": labMode, "rule": rule})
	})

	mux.HandleFunc("POST /v1/lab/rules/test", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		b, ok := labReadBody(w, r, labMaxTestBody)
		if !ok {
			return
		}
		var env envelope
		if err := json.Unmarshal(b, &env); err != nil {
			labJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if len(env.Events) == 0 || len(env.Events) > labMaxSamples {
			labJSON(w, 400, map[string]any{"error": fmt.Sprintf("events: need 1..%d sample events", labMaxSamples)})
			return
		}
		rule, ok := resolve(w, env)
		if !ok {
			return
		}
		type result struct {
			Index   int       `json:"index"`
			Matched bool      `json:"matched"`
			Trace   *LabTrace `json:"trace"`
		}
		results := make([]result, len(env.Events))
		matched := 0
		for i, ev := range env.Events {
			m, tr := rule.Condition.eval(ev, true)
			results[i] = result{i, m, tr}
			if m {
				matched++
			}
		}
		hits := rule.Run(env.Events)
		labJSON(w, 200, map[string]any{"mode": labMode, "events": len(env.Events), "condition_matched": matched,
			"results": results, "hits": hits, "threshold": rule.Threshold})
	})

	mux.HandleFunc("POST /v1/lab/rules/backtest", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		b, ok := labReadBody(w, r, labMaxBody)
		if !ok {
			return
		}
		var env envelope
		if err := json.Unmarshal(b, &env); err != nil {
			labJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		rule, ok := resolve(w, env)
		if !ok {
			return
		}
		events, truncated := labEventsFromStore(store)
		labJSON(w, 200, labBacktest(rule, events, truncated))
	})

	mux.HandleFunc("GET /v1/lab/rules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ls.mu.Lock()
		out := append([]LabRule{}, ls.rules...)
		ls.mu.Unlock()
		labJSON(w, 200, map[string]any{"mode": labMode, "rules": out, "max_rules": labMaxRules})
	})

	mux.HandleFunc("POST /v1/lab/rules", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		b, ok := labReadBody(w, r, labMaxBody)
		if !ok {
			return
		}
		rule, err := ParseLabRule(b)
		if err != nil {
			labJSON(w, 400, map[string]any{"valid": false, "error": err.Error(), "mode": labMode})
			return
		}
		ls.mu.Lock()
		defer ls.mu.Unlock()
		if rule.ID == "" {
			rule.ID = "lab-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		rule.Updated = time.Now().UTC()
		replaced := false
		for i := range ls.rules {
			if ls.rules[i].ID == rule.ID {
				ls.rules[i] = *rule
				replaced = true
			}
		}
		if !replaced {
			if len(ls.rules) >= labMaxRules {
				labJSON(w, 409, map[string]any{"error": fmt.Sprintf("rule cap of %d reached", labMaxRules)})
				return
			}
			ls.rules = append(ls.rules, *rule)
		}
		if err := ls.save(); err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		labJSON(w, 200, map[string]any{"mode": labMode, "rule": rule})
	})

	mux.HandleFunc("DELETE /v1/lab/rules", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.URL.Query().Get("id")
		ls.mu.Lock()
		defer ls.mu.Unlock()
		for i := range ls.rules {
			if ls.rules[i].ID == id {
				ls.rules = append(ls.rules[:i], ls.rules[i+1:]...)
				if err := ls.save(); err != nil {
					http.Error(w, "storage error", 500)
					return
				}
				labJSON(w, 200, map[string]any{"deleted": id, "mode": labMode})
				return
			}
		}
		labJSON(w, 404, map[string]any{"error": "lab rule not found"})
	})
}

type labHostCount struct {
	Host string `json:"host"`
	Hits int    `json:"hits"`
}

func labBacktest(rule *LabRule, events []LabEvent, truncated bool) map[string]any {
	hits := rule.Run(events)
	hosts := map[string]int{}
	perDay := map[string]int{}
	for _, h := range hits {
		hosts[h.Event.Host]++
		perDay[h.Event.Time.UTC().Format("2006-01-02")]++
	}
	top := make([]labHostCount, 0, len(hosts))
	for h, c := range hosts {
		top = append(top, labHostCount{h, c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Hits != top[j].Hits {
			return top[i].Hits > top[j].Hits
		}
		return top[i].Host < top[j].Host
	})
	if len(top) > 10 {
		top = top[:10]
	}
	keys := make([]string, 0, len(perDay))
	for d := range perDay {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	days := make([]map[string]any, 0, len(keys))
	for _, d := range keys {
		days = append(days, map[string]any{"day": d, "hits": perDay[d]})
	}
	// Noise estimate: hits / distinct hosts observed / days spanned by the scanned telemetry.
	allHosts := map[string]struct{}{}
	var minT, maxT time.Time
	for _, e := range events {
		allHosts[e.Host] = struct{}{}
		if e.Time.IsZero() {
			continue
		}
		if minT.IsZero() || e.Time.Before(minT) {
			minT = e.Time
		}
		if e.Time.After(maxT) {
			maxT = e.Time
		}
	}
	spanDays := 1.0
	if !minT.IsZero() {
		if d := maxT.Sub(minT).Hours() / 24; d > 1 {
			spanDays = d
		}
	}
	noise := 0.0
	if n := len(allHosts); n > 0 {
		noise = float64(len(hits)) / float64(n) / spanDays
	}
	sample := hits
	if len(sample) > labHitSampleMax {
		sample = sample[:labHitSampleMax]
	}
	return map[string]any{
		"mode": labMode, "events_scanned": len(events), "truncated": truncated, "event_cap": labMaxEvents,
		"hit_count": len(hits), "hit_sample": sample, "top_hosts": top, "hits_per_day": days,
		"hosts_observed": len(allHosts), "span_days": spanDays, "noise_per_host_per_day": noise,
	}
}
