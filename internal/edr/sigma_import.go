// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Detection-as-code: staging of converted Sigma rules (harness, benign corpus guard, lifecycle) and the
// admin-only POST /v1/content/import/sigma route. Observation-only: an imported rule raises Findings, it
// never blocks or contains anything, and a noisy rule is never imported.

//go:embed testdata/benign_corpus.json
var sigmaCorpusJSON []byte

var (
	sigmaCorpusOnce sync.Once
	sigmaCorpus     []LabEvent
)

func sigmaBenignCorpus() []LabEvent {
	sigmaCorpusOnce.Do(func() { _ = json.Unmarshal(sigmaCorpusJSON, &sigmaCorpus) })
	return sigmaCorpus
}

// sigmaCorpusHits evaluates the rule against every benign-corpus event of its event type and returns
// the hit count and a few examples.
func sigmaCorpusHits(r *ContentRule) (n int, samples []string) {
	for _, ev := range sigmaBenignCorpus() {
		if ev.Kind != r.EventType {
			continue
		}
		if r.Matches(ev) {
			n++
			if len(samples) < 3 {
				samples = append(samples, customBaselineLabel(ev))
			}
		}
	}
	return
}

// sigmaItem is one rule's outcome in an import report.
type sigmaItem struct {
	ID          string     `json:"id"`
	Title       string     `json:"title,omitempty"`
	Status      string     `json:"status"` // converted (dry run) | imported | skipped | noisy | rejected
	Errors      []string   `json:"errors,omitempty"`
	Gaps        []sigmaGap `json:"gaps,omitempty"`
	Samples     string     `json:"samples,omitempty"`   // provided | derived | none
	Lifecycle   string     `json:"lifecycle,omitempty"` // testing when the rule has no verifiable samples
	NoisyHits   int        `json:"benign_hits,omitempty"`
	NoisyEvents []string   `json:"benign_hit_examples,omitempty"`
	Replaces    bool       `json:"replaces_existing,omitempty"`
}

// sigmaStage runs converted rules through the harness and benign guards and, when apply is true,
// imports the clean ones. Noisy rules are reported and never imported or enabled.
func sigmaStage(cs *customStore, actor string, res []sigmaResult, apply bool) []sigmaItem {
	items := make([]sigmaItem, len(res))
	var rules []ContentRule
	var idx []int
	for i, s := range res {
		it := sigmaItem{ID: s.ID, Title: s.Title, Errors: s.Errors, Gaps: s.Gaps, Samples: s.Samples}
		if len(s.Unsupported) > 0 {
			it.Status = "skipped"
			it.Errors = append(append([]string(nil), s.Errors...), s.Unsupported...)
			items[i] = it
			continue
		}
		if len(s.Errors) > 0 || s.Rule == nil {
			it.Status = "rejected"
			items[i] = it
			continue
		}
		r := *s.Rule
		if err := validateCustomRule(&r); err != nil {
			it.Errors = []string{err.Error()}
			it.Status = "rejected"
			if strings.Contains(err.Error(), "benign baseline") {
				it.Status = "noisy"
			}
			items[i] = it
			continue
		}
		if n, ex := sigmaCorpusHits(&r); n > 0 {
			it.Status, it.NoisyHits, it.NoisyEvents = "noisy", n, ex
			it.Errors = []string{fmt.Sprintf("matches %d event(s) of the benign corpus; not imported. Tighten the rule", n)}
			items[i] = it
			continue
		}
		if r.Unverified {
			it.Lifecycle = "testing"
		}
		cs.mu.Lock()
		_, it.Replaces = cs.rules[r.ID]
		cs.mu.Unlock()
		items[i] = it
		rules, idx = append(rules, *s.Rule), append(idx, i)
	}
	if len(rules) == 0 {
		return items
	}
	for k, p := range cs.putAs(actor, rules, !apply) {
		i := idx[k]
		switch p.Status {
		case "imported":
			items[i].Status = "imported"
		case "valid":
			items[i].Status = "converted"
		default:
			items[i].Status, items[i].Errors = "rejected", p.Errors
			items[i].Lifecycle = ""
		}
	}
	return items
}

// ruleSetTesting records the "testing" lifecycle state for a rule (hits become shadow findings).
func ruleSetTesting(actor, id, note string) {
	s := ruleSvc.Load()
	if s == nil {
		return
	}
	if actor == "" {
		actor = "unknown"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Lifecycle == nil {
		s.d.Lifecycle = map[string]RuleLifecycle{}
	}
	old := s.state(id).State
	s.d.Lifecycle[id] = RuleLifecycle{Rule: id, State: "testing", Since: s.now().UTC(), By: actor, Note: note}
	s.appendLocked(actor, id, "lifecycle", fmt.Sprintf("%s -> testing note=%q", old, note))
	_ = s.saveLocked()
}

func sigmaSummarize(items []sigmaItem) (map[string]any, map[string]map[string]int) {
	count := map[string]int{}
	testing, derived := 0, 0
	gaps := map[string]map[string]int{}
	for _, it := range items {
		count[it.Status]++
		if it.Lifecycle == "testing" {
			testing++
		}
		if it.Samples == "derived" {
			derived++
		}
		for _, g := range it.Gaps {
			if g.Name == "" {
				continue
			}
			if gaps[g.Kind] == nil {
				gaps[g.Kind] = map[string]int{}
			}
			gaps[g.Kind][g.Name]++
		}
	}
	return map[string]any{"rules": len(items), "converted": count["converted"], "imported": count["imported"], "skipped": count["skipped"],
		"noisy": count["noisy"], "rejected": count["rejected"], "starts_in_testing": testing, "samples_derived": derived}, gaps
}

// sigmaLimits are echoed in every report so callers see the bounds that applied.
func sigmaLimits() map[string]any {
	return map[string]any{"max_bytes": sigmaMaxBytes, "max_rules": sigmaMaxRules, "max_regex_len": sigmaMaxRegexLen, "max_values_per_field": sigmaMaxVariants}
}

// registerSigmaImport wires POST /v1/content/import/sigma and POST /v1/content/export/sigma.
func registerSigmaImport(mux *http.ServeMux, token string, cs *customStore) {
	mux.HandleFunc("POST /v1/content/import/sigma", func(w http.ResponseWriter, r *http.Request) {
		isAdmin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !isAdmin {
			customJSON(w, http.StatusForbidden, map[string]any{"error": "admin token required"})
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sigmaMaxBytes))
		if err != nil {
			customJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": fmt.Sprintf("body too large or unreadable (limit %d bytes)", sigmaMaxBytes), "limits": sigmaLimits()})
			return
		}
		dry := true
		// Envelope form {"sigma": "<yaml>", "dry_run": bool}, for clients that can only send JSON fields.
		if t := strings.TrimSpace(string(b)); strings.HasPrefix(t, "{") {
			var env struct {
				Sigma  *string `json:"sigma"`
				DryRun *bool   `json:"dry_run"`
			}
			if json.Unmarshal(b, &env) == nil && env.Sigma != nil {
				b = []byte(*env.Sigma)
				if env.DryRun != nil {
					dry = *env.DryRun
				}
			}
		}
		switch r.URL.Query().Get("dry_run") { // the query string wins over the body
		case "false", "0":
			dry = false
		case "true", "1":
			dry = true
		case "":
		default:
			customJSON(w, 400, map[string]any{"error": "dry_run must be true or false"})
			return
		}
		res, err := sigmaConvertDocument(b)
		if err != nil {
			customJSON(w, 400, map[string]any{"error": "invalid Sigma input: " + err.Error(), "limits": sigmaLimits()})
			return
		}
		items := sigmaStage(cs, customActor(r), res, !dry)
		sum, gaps := sigmaSummarize(items)
		customJSON(w, 200, map[string]any{"mode": "observe-only", "dry_run": dry, "summary": sum, "gap_summary": gaps,
			"limits": sigmaLimits(), "results": items,
			"caveats": "Sigma subset only; unsupported rules are skipped, never guessed. Derived samples prove the conversion is self-consistent, not that the detection is right for your telemetry."})
	})

	mux.HandleFunc("POST /v1/content/export/sigma", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, customMaxBody))
		if err != nil {
			customJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large or unreadable"})
			return
		}
		var f struct {
			IDs []string `json:"ids"`
		}
		if len(strings.TrimSpace(string(b))) > 0 {
			if err := customDecode(b, &f); err != nil {
				customJSON(w, 400, map[string]any{"error": "invalid filter (want {\"ids\":[...]}): " + err.Error()})
				return
			}
		}
		want := map[string]bool{}
		for _, id := range f.IDs {
			want[id] = true
		}
		cs.mu.Lock()
		var list []*ContentRule
		for _, x := range cs.sorted() {
			if len(want) == 0 || want[x.ID] {
				list = append(list, x)
			}
		}
		cs.mu.Unlock()
		yaml, exported, skipped := sigmaExportAll(list)
		customJSON(w, 200, map[string]any{"mode": "observe-only", "format": "sigma", "yaml": yaml, "exported": exported, "skipped": skipped,
			"note": "only rules expressible without loss are exported; skipped rules say why"})
	})
}
