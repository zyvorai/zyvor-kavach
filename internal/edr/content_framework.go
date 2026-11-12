// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

// Data-driven detection CONTENT framework. Rules are JSON packs embedded from content/*.json,
// validated at load, matched with the detection-lab matcher (LabNode) and evaluated on the live
// ingest path. Observation-only: a match produces a Finding, never a containment action.

//go:embed content/*.json
var contentFS embed.FS

const (
	contentMaxRules     = 5000
	contentMaxPerEvent  = 10 // cap findings one event can raise from content rules
	contentMaxTags      = 16
	contentMaxSamples   = 20
	contentMaxPackBytes = 4 * 1024 * 1024
)

var (
	contentIDRe       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	contentBatchRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	contentSeverities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	contentOSes       = map[string]bool{"linux": true, "macos": true, "windows": true, "any": true}
	// Evaluated on the live path today: process, network, file. The rest are accepted by the schema
	// and flagged pending_telemetry until a sensor emits them.
	contentLiveTypes = map[string]bool{"process": true, "network": true, "file": true}
	contentAllTypes  = map[string]bool{"process": true, "network": true, "file": true, "registry": true, "dns": true, "auth": true, "module": true}
	contentOps       = map[string]string{"equals": "equals", "contains": "contains", "regex": "regex", "prefix": "startswith", "suffix": "endswith", "in": "in"}
)

// ContentMatch is the JSON match tree: a leaf (field/op/pattern|patterns) or all / any / not.
type ContentMatch struct {
	Field         string         `json:"field,omitempty"`
	Op            string         `json:"op,omitempty"`
	Pattern       string         `json:"pattern,omitempty"`
	Patterns      []string       `json:"patterns,omitempty"`
	CaseSensitive bool           `json:"case_sensitive,omitempty"`
	All           []ContentMatch `json:"all,omitempty"`
	Any           []ContentMatch `json:"any,omitempty"`
	Not           *ContentMatch  `json:"not,omitempty"`
}

// ContentTests holds sample events: every positive must match the rule, every negative must not.
type ContentTests struct {
	Positive []LabEvent `json:"positive"`
	Negative []LabEvent `json:"negative"`
}

// ContentRule is one detection content rule.
type ContentRule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	Description      string        `json:"description"`
	Tactic           string        `json:"tactic"`
	Technique        string        `json:"technique"`
	TechniqueName    string        `json:"technique_name,omitempty"`
	Severity         string        `json:"severity"`
	OS               string        `json:"os"`
	EventType        string        `json:"event_type"`
	Match            ContentMatch  `json:"match"`
	Tags             []string      `json:"tags,omitempty"`
	Batch            string        `json:"batch,omitempty"`
	Tests            *ContentTests `json:"tests,omitempty"`
	PendingTelemetry bool          `json:"pending_telemetry"` // computed at load; ignored in pack input

	node *LabNode // compiled matcher (shared with the detection lab)
}

type contentPack struct {
	Pack  string        `json:"pack,omitempty"`
	Rules []ContentRule `json:"rules"`
}

// ContentRegistry is the immutable, indexed result of loading the packs.
type ContentRegistry struct {
	rules  []*ContentRule // sorted by id
	byID   map[string]*ContentRule
	byType map[string][]*ContentRule // live (non-pending) rules per event type
}

var contentReg atomic.Pointer[ContentRegistry]

// Matches reports whether the compiled rule matches the event (event kind is not enforced here).
func (r *ContentRule) Matches(ev LabEvent) bool {
	if r.node == nil {
		return false
	}
	m, _ := r.node.eval(ev, false)
	return m
}

func (m *ContentMatch) toLab(path string) (LabNode, error) {
	kinds := 0
	if m.Field != "" || m.Op != "" || m.Pattern != "" || len(m.Patterns) > 0 {
		kinds++
	}
	if len(m.All) > 0 {
		kinds++
	}
	if len(m.Any) > 0 {
		kinds++
	}
	if m.Not != nil {
		kinds++
	}
	if kinds != 1 {
		return LabNode{}, fmt.Errorf("%s: must be exactly one of a field condition, all, any or not", path)
	}
	conv := func(list []ContentMatch, sub string) ([]LabNode, error) {
		out := make([]LabNode, 0, len(list))
		for i := range list {
			n, err := list[i].toLab(fmt.Sprintf("%s.%s[%d]", path, sub, i))
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	}
	switch {
	case len(m.All) > 0:
		l, err := conv(m.All, "all")
		return LabNode{All: l}, err
	case len(m.Any) > 0:
		l, err := conv(m.Any, "any")
		return LabNode{Any: l}, err
	case m.Not != nil:
		n, err := m.Not.toLab(path + ".not")
		return LabNode{Not: &n}, err
	}
	op, ok := contentOps[m.Op]
	if !ok {
		return LabNode{}, fmt.Errorf("%s.op: unknown operator %q (use equals|contains|regex|prefix|suffix|in)", path, m.Op)
	}
	if op == "in" {
		vals := m.Patterns
		if len(vals) == 0 && m.Pattern != "" {
			vals = []string{m.Pattern}
		}
		return LabNode{Field: m.Field, Op: op, Values: vals, CaseSensitive: m.CaseSensitive}, nil
	}
	if m.Pattern != "" && len(m.Patterns) > 0 {
		return LabNode{}, fmt.Errorf("%s: use pattern or patterns, not both", path)
	}
	if len(m.Patterns) > 0 { // any-of shorthand
		alts := make([]LabNode, 0, len(m.Patterns))
		for _, p := range m.Patterns {
			alts = append(alts, LabNode{Field: m.Field, Op: op, Value: p, CaseSensitive: m.CaseSensitive})
		}
		if len(alts) == 1 {
			return alts[0], nil
		}
		return LabNode{Any: alts}, nil
	}
	return LabNode{Field: m.Field, Op: op, Value: m.Pattern, CaseSensitive: m.CaseSensitive}, nil
}

// validateAndCompile checks the schema and builds the matcher. Errors name the rule id.
func (r *ContentRule) validateAndCompile() error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("rule %q: %s", r.ID, fmt.Sprintf(format, a...))
	}
	if len(r.ID) == 0 || len(r.ID) > 64 || !contentIDRe.MatchString(r.ID) {
		return fail("id must be kebab-case (a-z0-9 and single dashes, max 64 chars)")
	}
	if _, clash := ruleMITRE[r.ID]; clash {
		return fail("id collides with a built-in detection rule")
	}
	if n := len(strings.TrimSpace(r.Name)); n == 0 || len(r.Name) > 120 {
		return fail("name: required, max 120 chars")
	}
	if n := len(strings.TrimSpace(r.Description)); n == 0 || len(r.Description) > 1000 {
		return fail("description: required, max 1000 chars")
	}
	okTactic := false
	for _, t := range attackTactics {
		if t == r.Tactic {
			okTactic = true
		}
	}
	if !okTactic {
		return fail("tactic %q is not an ATT&CK Enterprise tactic name", r.Tactic)
	}
	if !labTechRe.MatchString(r.Technique) {
		return fail("technique %q is not an ATT&CK id like T1059 or T1059.004", r.Technique)
	}
	if len(r.TechniqueName) > 120 {
		return fail("technique_name: max 120 chars")
	}
	if !contentSeverities[r.Severity] {
		return fail("severity %q must be low|medium|high|critical", r.Severity)
	}
	if !contentOSes[r.OS] {
		return fail("os %q must be linux|macos|windows|any", r.OS)
	}
	if !contentAllTypes[r.EventType] {
		return fail("event_type %q must be process|network|file|registry|dns|auth|module", r.EventType)
	}
	if len(r.Tags) > contentMaxTags {
		return fail("tags: at most %d", contentMaxTags)
	}
	for _, t := range r.Tags {
		if t == "" || len(t) > 32 {
			return fail("tags: each tag must be 1..32 chars")
		}
	}
	if r.Batch != "" && !contentBatchRe.MatchString(r.Batch) {
		return fail("batch %q must match %s", r.Batch, contentBatchRe)
	}
	if r.Tests == nil || len(r.Tests.Positive) == 0 || len(r.Tests.Negative) == 0 {
		return fail("tests: at least one positive and one negative sample are required")
	}
	if len(r.Tests.Positive) > contentMaxSamples || len(r.Tests.Negative) > contentMaxSamples {
		return fail("tests: at most %d samples per list", contentMaxSamples)
	}
	node, err := r.Match.toLab("match")
	if err != nil {
		return fail("%v", err)
	}
	nodes := 0
	if err := node.validate("match", 0, &nodes); err != nil {
		return fail("%v", err)
	}
	r.node = &node
	r.PendingTelemetry = !contentLiveTypes[r.EventType]
	return nil
}

func buildContentRegistry(packs map[string][]byte) (*ContentRegistry, error) {
	names := make([]string, 0, len(packs))
	for n := range packs {
		names = append(names, n)
	}
	sort.Strings(names)
	reg := &ContentRegistry{byID: map[string]*ContentRule{}, byType: map[string][]*ContentRule{}}
	var errs []error
	for _, name := range names {
		raw := packs[name]
		if len(raw) > contentMaxPackBytes {
			errs = append(errs, fmt.Errorf("pack %s: larger than %d bytes", name, contentMaxPackBytes))
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var p contentPack
		if err := dec.Decode(&p); err != nil {
			errs = append(errs, fmt.Errorf("pack %s: %v", name, err))
			continue
		}
		for i := range p.Rules {
			r := p.Rules[i]
			if err := r.validateAndCompile(); err != nil {
				errs = append(errs, fmt.Errorf("pack %s: %v", name, err))
				continue
			}
			if _, dup := reg.byID[r.ID]; dup {
				errs = append(errs, fmt.Errorf("pack %s: rule %q: duplicate id", name, r.ID))
				continue
			}
			if len(reg.rules) >= contentMaxRules {
				errs = append(errs, fmt.Errorf("pack %s: rule cap of %d reached", name, contentMaxRules))
				break
			}
			rp := &r
			reg.rules = append(reg.rules, rp)
			reg.byID[r.ID] = rp
		}
	}
	sort.Slice(reg.rules, func(i, j int) bool { return reg.rules[i].ID < reg.rules[j].ID })
	for _, r := range reg.rules {
		if !r.PendingTelemetry {
			reg.byType[r.EventType] = append(reg.byType[r.EventType], r)
		}
	}
	return reg, errors.Join(errs...)
}

func embeddedContentPacks() (map[string][]byte, error) {
	entries, err := contentFS.ReadDir("content")
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := contentFS.ReadFile("content/" + e.Name())
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}

// LoadContentPacks validates and indexes every embedded pack and installs the registry.
// Invalid rules are skipped and reported in the returned error; valid rules stay active.
func LoadContentPacks() error {
	packs, err := embeddedContentPacks()
	if err != nil {
		return err
	}
	reg, lerr := buildContentRegistry(packs)
	contentReg.Store(reg)
	return lerr
}

// ContentRules returns all loaded rules sorted by id (nil when no packs are loaded).
func ContentRules() []ContentRule {
	reg := contentReg.Load()
	if reg == nil {
		return nil
	}
	out := make([]ContentRule, len(reg.rules))
	for i, r := range reg.rules {
		out[i] = *r
	}
	return out
}

// contentMITRE resolves a content rule id to its ATT&CK mapping (fallback for MapDetection etc.).
func contentMITRE(rule string) (struct{ Tactic, Technique, ID string }, bool) {
	reg := contentReg.Load()
	if reg == nil {
		return struct{ Tactic, Technique, ID string }{}, false
	}
	r := reg.byID[rule]
	if r == nil {
		return struct{ Tactic, Technique, ID string }{}, false
	}
	name := r.TechniqueName
	if name == "" {
		name = r.Technique
	}
	return struct{ Tactic, Technique, ID string }{r.Tactic, name, r.Technique}, true
}

// mitreFor looks up built-in rules first, then content rules.
func mitreFor(rule string) (struct{ Tactic, Technique, ID string }, bool) {
	if m, ok := ruleMITRE[rule]; ok {
		return m, true
	}
	return contentMITRE(rule)
}

// contentMITREAll lists live content rules for ATT&CK matrix coverage (pending rules are excluded:
// they cannot fire yet, so counting them would overstate coverage).
func contentMITREAll() map[string]struct{ Tactic, Technique, ID string } {
	reg := contentReg.Load()
	if reg == nil {
		return nil
	}
	out := map[string]struct{ Tactic, Technique, ID string }{}
	for _, r := range reg.rules {
		if r.PendingTelemetry {
			continue
		}
		if m, ok := contentMITRE(r.ID); ok {
			out[r.ID] = m
		}
	}
	return out
}

// contentEvaluate runs the live rules for one event kind. No-op (nil) when no packs are loaded.
func contentEvaluate(kind string, ev LabEvent, base Finding) []Finding {
	reg := contentReg.Load()
	if reg == nil {
		return nil
	}
	rules := reg.byType[kind]
	if len(rules) == 0 {
		return nil
	}
	ev.Kind = kind
	var out []Finding
	for _, r := range rules {
		if !r.Matches(ev) {
			continue
		}
		f := base
		f.ID = fmt.Sprintf("%s:%d:%s:%d", base.Host, base.PID, r.ID, base.Time.UnixNano())
		f.Rule, f.Severity, f.Description = r.ID, r.Severity, r.Name+": "+r.Description
		f.Tags = append([]string{"content", r.Technique}, r.Tags...)
		if r.Batch != "" {
			f.Tags = append(f.Tags, "batch:"+r.Batch)
		}
		out = append(out, f)
		if len(out) >= contentMaxPerEvent {
			break
		}
	}
	return out
}

func contentProcessFindings(e Event) []Finding {
	uid := e.UID
	return contentEvaluate("process", LabEvent{Time: e.Time, Host: e.Host, UID: &uid, Executable: e.Executable,
		ParentExe: e.ParentExe, Command: e.Command},
		Finding{Time: e.Time, Host: e.Host, PID: e.PID, Evidence: e})
}

func contentNetworkFindings(n NetworkEvent) []Finding {
	return FilterExcluded(contentEvaluate("network", LabEvent{Time: n.Time, Host: n.Host, Destination: n.Destination},
		Finding{Time: n.Time, Host: n.Host, PID: n.PID, Destination: n.Destination,
			Evidence: Event{Time: n.Time, Host: n.Host, PID: n.PID}}))
}

func contentFileFindings(e FileEvent) []Finding {
	return FilterExcluded(contentEvaluate("file", LabEvent{Time: e.Time, Host: e.Host, Path: e.Path, Operation: e.Operation},
		Finding{Time: e.Time, Host: e.Host, PID: e.PID, Evidence: Event{Time: e.Time, Host: e.Host, PID: e.PID, Command: e.Operation + " " + e.Path}}))
}

// ---- HTTP API ----

func contentFilter(reg *ContentRegistry, q map[string][]string) []*ContentRule {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	tactic, osf, batch, tech, text := strings.ToLower(get("tactic")), strings.ToLower(get("os")), get("batch"), strings.ToUpper(get("technique")), strings.ToLower(get("q"))
	out := []*ContentRule{}
	for _, r := range reg.rules {
		if tactic != "" && strings.ToLower(r.Tactic) != tactic {
			continue
		}
		if osf != "" && r.OS != osf && r.OS != "any" {
			continue
		}
		if batch != "" && r.Batch != batch {
			continue
		}
		if tech != "" && r.Technique != tech && !strings.HasPrefix(r.Technique, tech+".") {
			continue
		}
		if text != "" {
			blob := strings.ToLower(r.ID + " " + r.Name + " " + r.Description + " " + strings.Join(r.Tags, " "))
			if !strings.Contains(blob, text) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// ContentCoverage summarizes the loaded content (counts by tactic/technique/os/batch).
func ContentCoverage() map[string]any {
	reg := contentReg.Load()
	if reg == nil {
		reg = &ContentRegistry{}
	}
	byTactic, byTech, byOS, byBatch, bySev, byType := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	pending := []string{}
	for _, r := range reg.rules {
		byTactic[r.Tactic]++
		byTech[r.Technique]++
		byOS[r.OS]++
		b := r.Batch
		if b == "" {
			b = "(none)"
		}
		byBatch[b]++
		bySev[r.Severity]++
		byType[r.EventType]++
		if r.PendingTelemetry {
			pending = append(pending, r.ID)
		}
	}
	techs := make([]string, 0, len(byTech))
	for t := range byTech {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	return map[string]any{
		"mode": "observe-only", "total_rules": len(reg.rules), "active_rules": len(reg.rules) - len(pending),
		"by_tactic": byTactic, "by_technique": byTech, "by_os": byOS, "by_batch": byBatch,
		"by_severity": bySev, "by_event_type": byType,
		"techniques_covered": techs, "techniques_covered_count": len(techs),
		"pending_telemetry": map[string]any{"count": len(pending), "rules": pending},
	}
}

// RegisterContentFramework loads the embedded packs and wires the read-only content endpoints.
func RegisterContentFramework(mux *http.ServeMux, token string) {
	if contentReg.Load() == nil {
		_ = LoadContentPacks() // invalid rules are skipped; the harness test gates the shipped packs
	}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/content/rules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		reg := contentReg.Load()
		if reg == nil {
			reg = &ContentRegistry{}
		}
		list := contentFilter(reg, r.URL.Query())
		out := make([]ContentRule, len(list))
		for i, x := range list {
			c := *x
			c.Tests = nil // samples are served on the detail endpoint
			out[i] = c
		}
		writeJSON(w, 200, map[string]any{"mode": "observe-only", "count": len(out), "rules": out})
	})
	mux.HandleFunc("GET /v1/content/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if reg := contentReg.Load(); reg != nil {
			if x := reg.byID[r.PathValue("id")]; x != nil {
				writeJSON(w, 200, x)
				return
			}
		}
		writeJSON(w, 404, map[string]any{"error": "content rule not found"})
	})
	mux.HandleFunc("GET /v1/content/coverage", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, 200, ContentCoverage())
	})
}
