// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Draft-rule synthesis: from one observed event, propose a candidate ContentRule that is a
// conjunction of 2-4 "contains" conditions chosen to match the source event and none of the benign
// events known to the product (testdata/benign_corpus.json embedded below, the negative samples of
// the embedded content packs and the custom-content benign baseline). No LLM, no network. The
// endpoint is read-only: it never saves or enables a rule. The analyst reviews the draft and saves
// it through POST /v1/content/custom, which re-runs the same validation.

//go:embed testdata/benign_corpus.json
var synthBenignRaw []byte

const (
	synthMaxBody       = 1 << 20
	synthMaxConditions = 4
	synthMinConditions = 2
	synthMaxPattern    = 80
	synthMinPattern    = 3
)

type synthCand struct {
	Field string
	Pat   string // lower-cased
	Prio  int    // tie-break: higher is preferred
}

var (
	synthBenignOnce sync.Once
	synthBenign     []LabEvent
	synthBenignSrc  map[string]int
)

// synthBenignSet returns every benign event the synthesizer protects against, with per-source counts.
func synthBenignSet() ([]LabEvent, map[string]int) {
	synthBenignOnce.Do(func() {
		synthBenignSrc = map[string]int{}
		var corpus []LabEvent
		if json.Unmarshal(synthBenignRaw, &corpus) == nil {
			synthBenign = append(synthBenign, corpus...)
			synthBenignSrc["benign_corpus"] = len(corpus)
		}
		if packs, err := embeddedContentPacks(); err == nil {
			names := make([]string, 0, len(packs))
			for n := range packs {
				names = append(names, n)
			}
			sort.Strings(names)
			n := 0
			for _, name := range names {
				var p contentPack
				if json.Unmarshal(packs[name], &p) != nil {
					continue
				}
				for _, r := range p.Rules {
					if r.Tests == nil {
						continue
					}
					for _, ev := range r.Tests.Negative {
						ev.Kind = r.EventType
						synthBenign = append(synthBenign, ev)
						n++
					}
				}
			}
			synthBenignSrc["embedded_pack_negatives"] = n
		}
		synthBenign = append(synthBenign, customBenignBaseline...)
		synthBenignSrc["custom_baseline"] = len(customBenignBaseline)
	})
	return synthBenign, synthBenignSrc
}

func synthBase(p string) string {
	p = strings.TrimSpace(strings.Trim(p, `"'`))
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

var synthIPRe = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

var synthSplitRe = regexp.MustCompile(`[=:;|&,()<>{}\[\]]+`)

func synthOK(s string) bool {
	if len(s) < synthMinPattern || len(s) > synthMaxPattern {
		return false
	}
	digits := true
	for _, c := range s {
		if c < '0' || c > '9' {
			digits = false
			break
		}
	}
	return !digits // bare numbers (pids, ports, sizes) are instance noise
}

// synthCandidates tokenises the source event into candidate substrings per field.
func synthCandidates(src LabEvent) []synthCand {
	seen := map[string]bool{}
	var out []synthCand
	add := func(field, pat string, prio int) {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if !synthOK(pat) || seen[field+"\x00"+pat] {
			return
		}
		v, _ := src.field(field)
		if !strings.Contains(strings.ToLower(v), pat) {
			return
		}
		seen[field+"\x00"+pat] = true
		if synthIPRe.MatchString(pat) {
			prio = 0 // instance-bound literal: least preferred
		}
		out = append(out, synthCand{field, pat, prio})
	}
	text := func(field, s string) {
		toks := strings.Fields(s)
		for i, tk := range toks {
			tk = strings.Trim(tk, `"'`)
			prio := 1
			if strings.HasPrefix(tk, "-") || strings.HasPrefix(tk, "/") || strings.Contains(tk, `\`) || strings.Contains(tk, "/") {
				prio = 2
			}
			add(field, tk, prio)
			if i+1 < len(toks) {
				add(field, tk+" "+strings.Trim(toks[i+1], `"'`), 1)
			}
			if j := strings.LastIndexAny(tk, `/\`); j > 0 {
				add(field, tk[:j+1], 2)
				add(field, tk[j+1:], 1)
			}
			for _, sub := range synthSplitRe.Split(tk, -1) {
				add(field, sub, prio)
			}
		}
	}
	switch src.Kind {
	case "process":
		if b := synthBase(src.Executable); b != "" {
			add("executable", b, 3)
		}
		if b := synthBase(src.ParentExe); b != "" {
			add("parent_exe", b, 1)
		}
		text("command", src.Command)
	case "file":
		p := strings.ToLower(src.Path)
		add("path", synthBase(p), 2)
		if i := strings.LastIndex(synthBase(p), "."); i > 0 {
			add("path", synthBase(p)[i:], 1)
		}
		text("path", strings.NewReplacer("/", " /", `\`, ` \`).Replace(p))
		add("path", p, 1)
	case "network":
		host, port := beaconSplitDest(src.Destination)
		add("destination", host, 3)
		if port != "" {
			add("destination", ":"+port, 1)
		}
		labels := strings.Split(host, ".")
		for i := 0; net.ParseIP(host) == nil && i+2 <= len(labels) && len(labels) > 2; i++ {
			add("destination", strings.Join(labels[i:], "."), 2)
		}
	}
	return out
}

func synthHit(c synthCand, ev LabEvent) bool {
	v, ok := ev.field(c.Field)
	return ok && strings.Contains(strings.ToLower(v), c.Pat)
}

type synthCondition struct {
	Field         string `json:"field"`
	Pattern       string `json:"pattern"`
	BenignHitsAlo int    `json:"benign_hits_alone"` // benign events this condition matches on its own (rarity)
	BenignTotal   int    `json:"benign_events"`
}

// synthChoose picks a minimal conjunction. ok=false returns the benign events that still match.
func synthChoose(src LabEvent, benign []LabEvent) (conds []synthCand, leftover []LabEvent) {
	cands := synthCandidates(src)
	hits := make([][]bool, len(cands))
	for i, c := range cands {
		hits[i] = make([]bool, len(benign))
		for j, ev := range benign {
			hits[i][j] = synthHit(c, ev)
		}
	}
	cur := make([]bool, len(benign))
	for i := range cur {
		cur[i] = true
	}
	used := make([]bool, len(cands))
	count := func() int {
		n := 0
		for _, b := range cur {
			if b {
				n++
			}
		}
		return n
	}
	redundant := func(c synthCand) bool {
		for _, o := range conds {
			if o.Field == c.Field && (strings.Contains(o.Pat, c.Pat) || strings.Contains(c.Pat, o.Pat)) {
				return true
			}
		}
		return false
	}
	take := func(i int) {
		used[i] = true
		conds = append(conds, cands[i])
		for j := range cur {
			cur[j] = cur[j] && hits[i][j]
		}
	}
	for i, c := range cands { // seed: the executable name anchors process rules
		if c.Field == "executable" {
			take(i)
			break
		}
	}
	for len(conds) < synthMaxConditions && (count() > 0 || len(conds) < synthMinConditions) {
		best, bestN := -1, 0
		for i, c := range cands {
			if used[i] || redundant(c) {
				continue
			}
			n := 0
			for j := range cur {
				if cur[j] && hits[i][j] {
					n++
				}
			}
			better := best < 0 || n < bestN ||
				(n == bestN && (c.Prio > cands[best].Prio ||
					(c.Prio == cands[best].Prio && (len(c.Pat) > len(cands[best].Pat) ||
						(len(c.Pat) == len(cands[best].Pat) && c.Field+c.Pat < cands[best].Field+cands[best].Pat)))))
			if better {
				best, bestN = i, n
			}
		}
		if best < 0 {
			break
		}
		take(best)
	}
	// prune: drop conditions that are not needed to keep zero benign hits (keep at least 2).
	for k := len(conds) - 1; k >= 0 && len(conds) > synthMinConditions; k-- {
		rest := append(append([]synthCand{}, conds[:k]...), conds[k+1:]...)
		if synthCount(rest, benign) == 0 {
			conds = rest
		}
	}
	for j, ev := range benign {
		if synthAll(conds, ev) {
			leftover = append(leftover, benign[j])
		}
	}
	return conds, leftover
}

func synthAll(conds []synthCand, ev LabEvent) bool {
	for _, c := range conds {
		if !synthHit(c, ev) {
			return false
		}
	}
	return len(conds) > 0
}

func synthCount(conds []synthCand, benign []LabEvent) int {
	n := 0
	for _, ev := range benign {
		if synthAll(conds, ev) {
			n++
		}
	}
	return n
}

func synthSeverity(src string) string {
	switch src {
	case "medium", "high", "critical":
		return "medium" // conservative cap
	}
	return "low"
}

// synthesizeRule builds the candidate rule and runs the shared custom-content validation on it.
func synthesizeRule(src LabEvent, srcSeverity, srcRule, srcID string) (map[string]any, int) {
	benign, srcCounts := synthBenignSet()
	conds, leftover := synthChoose(src, benign)
	if len(conds) < synthMinConditions || len(leftover) > 0 {
		lo := []LabEvent{}
		for i, ev := range leftover {
			if i < 5 {
				lo = append(lo, ev)
			}
		}
		return map[string]any{
			"mode": "observe-only", "saved": false, "error": "no conjunction of 2-4 discriminative substrings separates this event from the benign events; the event is too generic or too sparse to synthesize safely",
			"conditions_tried": len(conds), "benign_events_still_matching": len(leftover), "benign_examples": lo,
		}, http.StatusUnprocessableEntity
	}

	kind := src.Kind
	ids := kind
	for _, c := range conds {
		ids += "|" + c.Field + "|" + c.Pat
	}
	h := sha256.Sum256([]byte(ids))
	id := "synth-" + hex.EncodeToString(h[:])[:10]

	node := ContentMatch{}
	crs := make([]synthCondition, 0, len(conds))
	for _, c := range conds {
		node.All = append(node.All, ContentMatch{Field: c.Field, Op: "contains", Pattern: c.Pat})
		n := 0
		for _, ev := range benign {
			if synthHit(c, ev) {
				n++
			}
		}
		crs = append(crs, synthCondition{c.Field, c.Pat, n, len(benign)})
	}
	tactic, tech, techName := "Execution", "T1059", "Command and Scripting Interpreter"
	if kind == "network" {
		tactic, tech, techName = "Command and Control", "T1071", "Application Layer Protocol"
	}
	if m, ok := ruleMITRE[srcRule]; ok && srcRule != "" {
		tactic, tech, techName = m.Tactic, m.ID, m.Technique
	} else if reg := contentReg.Load(); reg != nil && srcRule != "" {
		if r := reg.byID[srcRule]; r != nil {
			tactic, tech, techName = r.Tactic, r.Technique, r.TechniqueName
		}
	}
	osName := "any"
	if strings.Contains(src.Executable, `\`) || strings.Contains(src.Path, `\`) || strings.HasSuffix(strings.ToLower(src.Executable), ".exe") {
		osName = "windows"
	}
	desc := "Draft synthesized from one observed " + kind + " event"
	if srcID != "" {
		desc += " (finding " + srcID + ")"
	}
	desc += ". Matches events containing all of: "
	for i, c := range conds {
		if i > 0 {
			desc += "; "
		}
		desc += c.Field + " ~ \"" + c.Pat + "\""
	}
	desc += ". Statistically chosen against the benign corpus; analyst review required."
	if len(desc) > 1000 {
		desc = desc[:1000]
	}
	name := "Synthesized: " + strings.TrimSpace(strings.Join(func() []string {
		var p []string
		for _, c := range conds {
			p = append(p, c.Pat)
		}
		return p
	}(), " + "))
	if len(name) > 120 {
		name = name[:120]
	}
	rule := ContentRule{
		ID: id, Name: name, Description: desc, Tactic: tactic, Technique: tech, TechniqueName: techName,
		Severity: synthSeverity(srcSeverity), OS: osName, EventType: kind, Match: node,
		Tags: []string{"synthesized", "needs-review"}, Batch: "synthesized",
	}

	// samples
	src.Kind = kind
	pos := []LabEvent{src}
	v := src
	v.Host = "variant-host"
	pos = append(pos, v)
	neg := []LabEvent{}
	type scored struct {
		ev  LabEvent
		hit int
	}
	var near []scored
	for _, ev := range benign {
		if ev.Kind != kind {
			continue
		}
		n := 0
		for _, c := range conds {
			if synthHit(c, ev) {
				n++
			}
		}
		near = append(near, scored{ev, n})
	}
	sort.SliceStable(near, func(i, j int) bool { return near[i].hit > near[j].hit })
	nearest := []map[string]any{}
	for i, s := range near {
		if i >= 6 {
			break
		}
		neg = append(neg, s.ev)
		nearest = append(nearest, map[string]any{"event": s.ev, "conditions_matched": s.hit, "of": len(conds), "matched_rule": false})
	}
	for _, c := range conds { // mutated source with one condition broken must not match
		m := src
		re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(c.Pat))
		switch c.Field {
		case "executable":
			m.Executable = re.ReplaceAllString(m.Executable, "zz")
		case "parent_exe":
			m.ParentExe = re.ReplaceAllString(m.ParentExe, "zz")
		case "command":
			m.Command = re.ReplaceAllString(m.Command, "zz")
		case "path":
			m.Path = re.ReplaceAllString(m.Path, "zz")
		case "destination":
			m.Destination = re.ReplaceAllString(m.Destination, "zz")
		}
		neg = append(neg, m)
	}
	rule.Tests = &ContentTests{Positive: pos, Negative: neg}
	// keep only negatives the compiled rule really rejects, so samples never contradict the rule
	if err := rule.validateAndCompile(); err == nil {
		keep := neg[:0]
		for _, ev := range neg {
			e := ev
			e.Kind = kind
			if !rule.Matches(e) {
				keep = append(keep, ev)
			}
		}
		rule.Tests.Negative = keep
	}

	verdict := map[string]any{"valid": true, "harness": "validateCustomRule (the checks behind POST /v1/content/custom: schema, id collisions, own samples, benign baseline)"}
	if err := validateCustomRule(&rule); err != nil {
		verdict["valid"], verdict["error"] = false, err.Error()
	}
	rule.Source = ""
	srcMatches := rule.Matches(src)
	total := len(benign)
	return map[string]any{
		"mode": "observe-only", "model": "synthesis-conjunction-v1", "saved": false, "enabled": false,
		"rule": rule, "validation": verdict, "source_event": src, "source_event_matches": srcMatches,
		"conditions": crs,
		"benign_check": map[string]any{
			"events_checked": total, "sources": srcCounts, "events_matched": synthCount(conds, benign),
			"nearest_benign": nearest,
		},
		"recommended_initial_lifecycle": "testing",
		"next_steps": []string{
			"Review the conditions and the nearest benign events above; widen or tighten as needed.",
			"Save the draft yourself: POST /v1/content/custom with the \"rule\" JSON as the body. Nothing has been saved or enabled by this call.",
			"Then set the lifecycle to testing: PUT /v1/rules/lifecycle/" + id + " {\"state\":\"testing\"} and watch GET /v1/rules/health/" + id + " before promoting to production.",
		},
	}, http.StatusOK
}

type synthRequest struct {
	FindingID string    `json:"finding_id"`
	Command   string    `json:"command"`
	Event     *LabEvent `json:"event"`
}

func inferSynthKind(e LabEvent) string {
	switch {
	case e.Kind != "":
		return e.Kind
	case e.Path != "":
		return "file"
	case e.Command != "" || e.Executable != "":
		return "process"
	case e.Destination != "":
		return "network"
	}
	return ""
}

func registerMLSynth(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/ml/synthesize", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, synthMaxBody))
		if err != nil {
			customJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large or unreadable"})
			return
		}
		var req synthRequest
		if err := customDecode(b, &req); err != nil {
			customJSON(w, 400, map[string]any{"error": "invalid body (want {\"finding_id\"|\"command\"|\"event\"}): " + err.Error()})
			return
		}
		n := 0
		for _, set := range []bool{req.FindingID != "", req.Command != "", req.Event != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			customJSON(w, 400, map[string]any{"error": "provide exactly one of finding_id, command, event"})
			return
		}
		var src LabEvent
		sev, rule, fid := "", "", ""
		switch {
		case req.FindingID != "":
			var f *Finding
			for _, x := range store.List() {
				if x.ID == req.FindingID {
					c := x
					f = &c
				}
			}
			if f == nil {
				customJSON(w, 404, map[string]any{"error": "finding not found"})
				return
			}
			src = LabEvent{Host: f.Host, Executable: f.Evidence.Executable, ParentExe: f.Evidence.ParentExe, Command: f.Evidence.Command}
			if f.Evidence.Executable == "" && f.Evidence.Command == "" && f.Destination != "" {
				src = LabEvent{Host: f.Host, Destination: f.Destination, Kind: "network"}
			}
			sev, rule, fid = f.Severity, f.Rule, f.ID
		case req.Command != "":
			if len(req.Command) > 4096 {
				customJSON(w, 400, map[string]any{"error": "command too long"})
				return
			}
			exe := ""
			if tk := strings.Fields(req.Command); len(tk) > 0 {
				exe = tk[0]
			}
			src = LabEvent{Executable: exe, Command: req.Command}
		default:
			src = *req.Event
		}
		src.Kind = inferSynthKind(src)
		if src.Kind != "process" && src.Kind != "file" && src.Kind != "network" {
			customJSON(w, 400, map[string]any{"error": "synthesis supports process, file and network events (need executable/command, path or destination)"})
			return
		}
		out, code := synthesizeRule(src, sev, rule, fid)
		if code == http.StatusOK && out["error"] == nil {
			if v, _ := out["validation"].(map[string]any); v != nil && v["valid"] == false {
				code = http.StatusUnprocessableEntity
			}
		}
		customJSON(w, code, out)
	})
}
