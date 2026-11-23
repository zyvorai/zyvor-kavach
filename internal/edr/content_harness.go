// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Detection-as-code harness (observation only, offline). A test file in the kavach-content-tests/1
// format names an input (raw log lines, JSON records, content-rule events, generated lines or a
// file next to the test file), the rule ids that MUST fire and the rule ids that MUST NOT fire. The
// input goes through the same detection code the server uses; nothing is fetched, nothing is
// contacted and no state is kept (the tripwire registry is swapped for the case and restored).
//
// File format: JSON lines. Blank lines and lines starting with # or // are ignored. The first
// content line is the header {"schema":"kavach-content-tests/1","name":"..."}; every later line is
// one case (see HarnessCaseSpec). Unknown fields and unknown rule ids are errors so a typo can never
// make a test pass silently.

// HarnessSchema is the version string a test file must declare.
const HarnessSchema = "kavach-content-tests/1"

const (
	harnessMaxFileBytes = 4 << 20
	harnessMaxCases     = 2000
	harnessMaxInput     = 8 << 20
	harnessMaxRecords   = 50000
	harnessMaxGen       = 50000
	harnessMaxList      = 64
	harnessMaxName      = 160
	harnessBudget       = 20 * time.Second
	harnessAttrMax      = 8
)

var (
	harnessKinds   = map[string]bool{"web": true, "auth": true, "idp": true, "ransom": true, "tripwire": true, "event": true}
	harnessFormats = map[string]bool{"": true, "auto": true, "combined": true, "common": true, "clf": true, "json": true, "logfmt": true, "f5": true}
	harnessRuleRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	harnessTokenRe = regexp.MustCompile(`\{(i|t|clf)(?:([%/])(\d{1,6}))?\}`)
)

// HarnessTripwire declares one decoy for a case (the real registry is not touched).
type HarnessTripwire struct {
	Kind  string `json:"kind"`
	Match string `json:"match"`
	Label string `json:"label,omitempty"`
}

// HarnessGen generates Count lines or records from Template. Template is a JSON string (a raw log
// line) or a JSON object (a record). Tokens in string values: {i} index, {i%K} index modulo K,
// {i/K} index divided by K, {t} RFC 3339 time, {clf} common-log time. Time is Start + i*StepMS.
type HarnessGen struct {
	Count    int             `json:"count"`
	Start    string          `json:"start,omitempty"`
	StepMS   *int            `json:"step_ms,omitempty"`
	Template json.RawMessage `json:"template"`
}

// HarnessCaseSpec is one test case line.
type HarnessCaseSpec struct {
	Case        string            `json:"case"`
	Kind        string            `json:"kind"`
	Format      string            `json:"format,omitempty"`
	Host        string            `json:"host,omitempty"`
	Lines       []string          `json:"lines,omitempty"`
	Records     []map[string]any  `json:"records,omitempty"`
	Events      []LabEvent        `json:"events,omitempty"`
	Gen         []HarnessGen      `json:"gen,omitempty"`
	Input       string            `json:"input,omitempty"`
	Tripwires   []HarnessTripwire `json:"tripwires,omitempty"`
	DormantDays int               `json:"dormant_days,omitempty"`
	Expect      []string          `json:"expect,omitempty"`
	Forbid      []string          `json:"forbid,omitempty"`
	Exact       bool              `json:"exact,omitempty"`
	Rule        string            `json:"rule,omitempty"`
	Polarity    string            `json:"polarity,omitempty"`
	Note        string            `json:"note,omitempty"`
}

// HarnessFired is one rule that fired in a case.
type HarnessFired struct {
	Rule       string `json:"rule"`
	Count      int    `json:"count"`
	InputLines []int  `json:"input_lines,omitempty"`
}

// HarnessCaseResult is the outcome of one case.
type HarnessCaseResult struct {
	Case     string         `json:"case"`
	File     string         `json:"file"`
	Line     int            `json:"line"`
	Kind     string         `json:"kind,omitempty"`
	Rule     string         `json:"rule,omitempty"`
	Polarity string         `json:"polarity,omitempty"`
	Pass     bool           `json:"pass"`
	Error    string         `json:"error,omitempty"`
	Records  int            `json:"records"`
	Fired    []HarnessFired `json:"fired"`
	Diff     []string       `json:"diff,omitempty"`
}

// HarnessReport is the result of running one or more test files.
type HarnessReport struct {
	Schema  string              `json:"schema"`
	Mode    string              `json:"mode"`
	Files   []string            `json:"files"`
	Cases   int                 `json:"cases"`
	Passed  int                 `json:"passed"`
	Failed  int                 `json:"failed"`
	Results []HarnessCaseResult `json:"results"`
	Note    string              `json:"note"`
}

// HarnessOptions tunes a run. Registry nil means the embedded packs.
type HarnessOptions struct {
	Registry *ContentRegistry
	Known    map[string]bool // extra rule ids that may be named (custom packs)
}

type harnessSpec struct {
	HarnessCaseSpec
	line int
	perr string
}

var (
	harnessRegOnce sync.Once
	harnessReg     *ContentRegistry
	harnessRegErr  error
	harnessTW      sync.Mutex
)

// HarnessRegistry returns the registry built from the embedded content packs.
func HarnessRegistry() (*ContentRegistry, error) {
	harnessRegOnce.Do(func() {
		packs, err := embeddedContentPacks()
		if err != nil {
			harnessRegErr = err
			return
		}
		harnessReg, harnessRegErr = buildContentRegistry(packs)
	})
	return harnessReg, harnessRegErr
}

// HarnessRegistryWithPacks builds a registry from the embedded packs plus extra pack JSON documents
// (the same schema as content/*.json; every rule must carry positive and negative samples).
func HarnessRegistryWithPacks(extra map[string][]byte) (*ContentRegistry, error) {
	packs, err := embeddedContentPacks()
	if err != nil {
		return nil, err
	}
	for k, v := range extra {
		packs["extra-"+k] = v
	}
	return buildContentRegistry(packs)
}

func (o HarnessOptions) reg() (*ContentRegistry, error) {
	if o.Registry != nil {
		return o.Registry, nil
	}
	return HarnessRegistry()
}

// HarnessKnownRules returns every rule id a test may name.
func HarnessKnownRules(reg *ContentRegistry) map[string]bool {
	known := map[string]bool{}
	for k := range ruleMITRE {
		known[k] = true
	}
	if reg != nil {
		for id := range reg.byID {
			known[id] = true
		}
	}
	for _, r := range harnessAnalytics() {
		known[r.ID] = true
	}
	return known
}

// ReadHarnessFile reads a file with a size cap (never trusts the length reported by stat).
func harnessReadCapped(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("%s is over the %d byte limit", filepath.Base(path), max)
	}
	return b, nil
}

// harnessParse splits and validates a test file. A bad header is a hard error; a bad case line
// becomes a failing case so one typo does not hide the rest of the file.
func harnessParse(data []byte, known map[string]bool) ([]harnessSpec, error) {
	if len(data) > harnessMaxFileBytes {
		return nil, fmt.Errorf("test file is over the %d byte limit", harnessMaxFileBytes)
	}
	var specs []harnessSpec
	headerSeen := false
	for n, raw := range bytes.Split(data, []byte("\n")) {
		ln := n + 1
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' || bytes.HasPrefix(line, []byte("//")) {
			continue
		}
		if !headerSeen {
			var h struct {
				Schema      string `json:"schema"`
				Name        string `json:"name"`
				Description string `json:"description"`
			}
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&h); err != nil {
				return nil, fmt.Errorf("line %d: the first line must be the header {\"schema\":%q}: %v", ln, HarnessSchema, err)
			}
			if h.Schema != HarnessSchema {
				return nil, fmt.Errorf("line %d: unsupported schema %q (this build reads %q)", ln, h.Schema, HarnessSchema)
			}
			headerSeen = true
			continue
		}
		if len(specs) >= harnessMaxCases {
			return specs, fmt.Errorf("line %d: more than %d cases; split the file", ln, harnessMaxCases)
		}
		sp := harnessSpec{line: ln}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sp.HarnessCaseSpec); err != nil {
			sp.perr = "malformed case: " + webTruncate(webSanitise(err.Error()), 200)
		} else if dec.More() {
			sp.perr = "malformed case: more than one JSON value on the line"
		} else {
			sp.perr = harnessValidateSpec(&sp.HarnessCaseSpec, known)
		}
		specs = append(specs, sp)
	}
	if !headerSeen {
		return nil, fmt.Errorf("no header: the file must start with {\"schema\":%q}", HarnessSchema)
	}
	return specs, nil
}

func harnessValidateIDs(kind string, ids []string, known map[string]bool) string {
	if len(ids) > harnessMaxList {
		return fmt.Sprintf("%s lists more than %d rule ids", kind, harnessMaxList)
	}
	for _, id := range ids {
		if !harnessRuleRe.MatchString(id) || len(id) > 96 {
			return fmt.Sprintf("%s: %q is not a rule id", kind, webTruncate(webSanitise(id), 60))
		}
		if known != nil && !known[id] {
			return fmt.Sprintf("%s: unknown rule id %q (typo?)", kind, id)
		}
	}
	return ""
}

func harnessValidateSpec(s *HarnessCaseSpec, known map[string]bool) string {
	if s.Case == "" || len(s.Case) > harnessMaxName {
		return fmt.Sprintf("case needs a name of 1..%d characters", harnessMaxName)
	}
	s.Case = webSanitise(s.Case)
	if !harnessKinds[s.Kind] {
		return `kind must be one of web, auth, idp, ransom, tripwire, event`
	}
	if !harnessFormats[s.Format] {
		return "unknown format (auto|combined|json|logfmt)"
	}
	if s.Kind != "web" && s.Format != "" {
		return "format only applies to kind web"
	}
	if s.Kind != "event" && len(s.Events) > 0 {
		return "events only apply to kind event"
	}
	if s.Kind == "event" && (len(s.Lines) > 0 || len(s.Records) > 0 || len(s.Gen) > 0) {
		return "kind event takes events (or input), not lines, records or gen"
	}
	if s.Input != "" && (len(s.Lines) > 0 || len(s.Records) > 0 || len(s.Events) > 0 || len(s.Gen) > 0) {
		return "input is exclusive: do not combine it with lines, records, events or gen"
	}
	if s.Input == "" && len(s.Lines) == 0 && len(s.Records) == 0 && len(s.Events) == 0 && len(s.Gen) == 0 {
		return "case has no input (lines, records, events, gen or input)"
	}
	if len(s.Tripwires) > 0 && s.Kind != "auth" && s.Kind != "idp" && s.Kind != "ransom" && s.Kind != "tripwire" {
		return "tripwires apply to kinds auth, idp, ransom and tripwire"
	}
	if len(s.Tripwires) > 16 {
		return "at most 16 tripwires per case"
	}
	if s.DormantDays != 0 && (s.Kind != "idp" || s.DormantDays < 7 || s.DormantDays > 730) {
		return "dormant_days applies to kind idp and must be 7..730"
	}
	if len(s.Gen) > 8 {
		return "at most 8 gen blocks per case"
	}
	for _, g := range s.Gen {
		if g.Count < 1 || g.Count > harnessMaxGen {
			return fmt.Sprintf("gen count must be 1..%d", harnessMaxGen)
		}
		if len(g.Template) == 0 || (g.Template[0] != '"' && g.Template[0] != '{') {
			return "gen template must be a JSON string or object"
		}
		if g.Start != "" {
			if _, err := time.Parse(time.RFC3339, g.Start); err != nil {
				return "gen start must be RFC 3339"
			}
		}
		if g.StepMS != nil && (*g.StepMS < 0 || *g.StepMS > 86400000) {
			return "gen step_ms must be 0..86400000"
		}
	}
	if s.Polarity != "" && s.Polarity != "positive" && s.Polarity != "negative" {
		return "polarity must be positive or negative"
	}
	if (s.Rule == "") != (s.Polarity == "") {
		return "rule and polarity must be given together"
	}
	if s.Rule != "" {
		if m := harnessValidateIDs("rule", []string{s.Rule}, known); m != "" {
			return m
		}
	}
	if m := harnessValidateIDs("expect", s.Expect, known); m != "" {
		return m
	}
	if m := harnessValidateIDs("forbid", s.Forbid, known); m != "" {
		return m
	}
	if len(s.Expect) == 0 && len(s.Forbid) == 0 && s.Rule == "" && !s.Exact {
		return "case asserts nothing (give expect, forbid, rule+polarity or exact)"
	}
	for _, t := range s.Tripwires {
		if len(t.Match) > 200 || len(t.Label) > 100 {
			return "tripwire match or label too long"
		}
	}
	return ""
}

// harnessExpectations folds rule+polarity into expect/forbid.
func (s *HarnessCaseSpec) expectations() (expect, forbid []string) {
	expect = append(expect, s.Expect...)
	forbid = append(forbid, s.Forbid...)
	switch s.Polarity {
	case "positive":
		expect = append(expect, s.Rule)
	case "negative":
		forbid = append(forbid, s.Rule)
	}
	return
}

// harnessResolveInput reads an input file that must live inside baseDir (no absolute paths, no .., no
// symlink escape).
func harnessResolveInput(baseDir, rel string) ([]byte, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("input files need a test file on disk")
	}
	if !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("input must be a relative path inside the test file's directory")
	}
	full := filepath.Join(baseDir, rel)
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, fmt.Errorf("input not readable")
	}
	rb, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("test directory not readable")
	}
	if r, err := filepath.Rel(rb, real); err != nil || !filepath.IsLocal(r) {
		return nil, fmt.Errorf("input resolves outside the test file's directory")
	}
	return harnessReadCapped(real, harnessMaxInput)
}

func harnessGenStart(g HarnessGen) time.Time {
	if g.Start != "" {
		if t, err := time.Parse(time.RFC3339, g.Start); err == nil {
			return t.UTC()
		}
	}
	return time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
}

func harnessGenSub(s string, i int, t time.Time) string {
	if !strings.Contains(s, "{") {
		return s
	}
	return harnessTokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		m := harnessTokenRe.FindStringSubmatch(tok)
		switch m[1] {
		case "t":
			return t.Format(time.RFC3339)
		case "clf":
			return t.Format("02/Jan/2006:15:04:05 -0700")
		}
		v := i
		if m[2] != "" {
			k, _ := strconv.Atoi(m[3])
			if k <= 0 {
				k = 1
			}
			if m[2] == "%" {
				v = i % k
			} else {
				v = i / k
			}
		}
		return strconv.Itoa(v)
	})
}

func harnessGenWalk(v any, i int, t time.Time) any {
	switch x := v.(type) {
	case string:
		return harnessGenSub(x, i, t)
	case map[string]any:
		o := make(map[string]any, len(x))
		for k, e := range x {
			o[k] = harnessGenWalk(e, i, t)
		}
		return o
	case []any:
		o := make([]any, len(x))
		for j, e := range x {
			o[j] = harnessGenWalk(e, i, t)
		}
		return o
	}
	return v
}

// harnessBuildText assembles the case input as newline-separated text and its record count.
func harnessBuildText(s *HarnessCaseSpec, baseDir string) (string, error) {
	if s.Input != "" {
		b, err := harnessResolveInput(baseDir, s.Input)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	var b strings.Builder
	n := 0
	add := func(line string) error {
		n++
		if n > harnessMaxRecords || b.Len() > harnessMaxInput {
			return fmt.Errorf("case input is over %d lines or %d bytes", harnessMaxRecords, harnessMaxInput)
		}
		b.WriteString(strings.ReplaceAll(line, "\n", " "))
		b.WriteByte('\n')
		return nil
	}
	for _, l := range s.Lines {
		if err := add(l); err != nil {
			return "", err
		}
	}
	for _, r := range s.Records {
		j, err := json.Marshal(r)
		if err != nil {
			return "", fmt.Errorf("record not encodable")
		}
		if err := add(string(j)); err != nil {
			return "", err
		}
	}
	for _, g := range s.Gen {
		step := 1000
		if g.StepMS != nil {
			step = *g.StepMS
		}
		var tmpl any
		if err := json.Unmarshal(g.Template, &tmpl); err != nil {
			return "", fmt.Errorf("gen template is not valid JSON")
		}
		start := harnessGenStart(g)
		for i := 0; i < g.Count; i++ {
			t := start.Add(time.Duration(i) * time.Duration(step) * time.Millisecond)
			var line string
			switch x := tmpl.(type) {
			case string:
				line = harnessGenSub(x, i, t)
			default:
				j, err := json.Marshal(harnessGenWalk(x, i, t))
				if err != nil {
					return "", fmt.Errorf("gen record not encodable")
				}
				line = string(j)
			}
			if err := add(line); err != nil {
				return "", err
			}
		}
	}
	return b.String(), nil
}

// harnessWithTripwires runs fn with the tripwire registry replaced by defs and restores it afterwards.
func harnessWithTripwires(defs []HarnessTripwire, fn func()) error {
	tmp := &twRegistry{}
	for _, d := range defs {
		label := d.Label
		if label == "" {
			label = "harness decoy"
		}
		if _, err := tmp.Add(d.Kind, d.Match, label, "harness"); err != nil {
			return fmt.Errorf("tripwire %s %q: %v", d.Kind, webTruncate(webSanitise(d.Match), 40), err)
		}
	}
	harnessTW.Lock()
	defer harnessTW.Unlock()
	twReg.mu.Lock()
	saveDefs, savePath := twReg.defs, twReg.path
	twReg.defs, twReg.path = tmp.defs, ""
	twReg.mu.Unlock()
	defer func() {
		twReg.mu.Lock()
		twReg.defs, twReg.path = saveDefs, savePath
		twReg.mu.Unlock()
	}()
	fn()
	return nil
}

// harnessRun is what one analysis pass produced.
type harnessRun struct {
	fired     map[string]int
	lines     map[string][]int
	samples   map[string][]string
	parsed    int
	rejected  int
	total     int
	truncated bool
	err       string
}

func newHarnessRun() *harnessRun {
	return &harnessRun{fired: map[string]int{}, lines: map[string][]int{}, samples: map[string][]string{}}
}

func (r *harnessRun) note(rule string, line int, sample string) {
	r.fired[rule]++
	if line > 0 && len(r.lines[rule]) < harnessAttrMax {
		r.lines[rule] = append(r.lines[rule], line)
	}
	if sample != "" && len(r.samples[rule]) < 3 {
		r.samples[rule] = append(r.samples[rule], sample)
	}
}

func harnessSample(s string) string {
	return webTruncate(govRedact(webSanitise(s)), 200)
}

// harnessRunKind runs one input through the detection path named by kind.
func harnessRunKind(kind, text, format, host string, dormant int, reg *ContentRegistry) *harnessRun {
	run := newHarnessRun()
	switch kind {
	case "web":
		harnessRunWeb(run, text, format, host, reg)
	case "event":
		harnessRunEvents(run, text, reg)
	default:
		recs, err := authUnwrap([]byte(text))
		if kind == "tripwire" {
			recs = twRecords([]byte(text))
			err = nil
		}
		if err != nil || len(recs) == 0 {
			run.err = "no records could be read (expect a JSON array, object or JSON lines)"
			return run
		}
		if len(recs) > harnessMaxRecords {
			run.err = fmt.Sprintf("more than %d records", harnessMaxRecords)
			return run
		}
		run.total = len(recs)
		var fs []Finding
		src := kind
		switch kind {
		case "auth":
			lbl := ""
			if host != "" {
				lbl = "auth:" + host
			}
			rep, f := AnalyzeAuthLogs(recs, lbl)
			run.parsed, run.rejected, fs = rep.Parsed, rep.Rejected, f
		case "idp":
			rep, f := AnalyzeIdpLogs(recs, "", dormant)
			run.parsed, run.rejected, fs = rep.Parsed, rep.Rejected, f
		case "ransom":
			rep, f := AnalyzeRansomLogs(recs, "")
			run.parsed, run.rejected, fs = rep.Parsed, rep.Rejected, f
		case "tripwire":
			rep, f := twScan(recs, "log", "")
			run.parsed, fs = rep.Records, f
			src = ""
		}
		if src != "" {
			tw, _ := twMerge(recs, src)
			fs = append(fs, tw...)
		}
		for _, f := range fs {
			run.note(f.Rule, 0, harnessSample(f.Description))
		}
		if run.parsed == 0 && kind != "tripwire" {
			run.err = "no record could be parsed"
		}
	}
	return run
}

func harnessRunWeb(run *harnessRun, text, format, host string, reg *ContentRegistry) {
	if strings.TrimSpace(text) == "" {
		run.err = "empty input"
		return
	}
	if strings.Count(text, "\n") > webLinesMax {
		run.err = fmt.Sprintf("more than %d lines", webLinesMax)
		return
	}
	rep, fs, err := AnalyzeWebLogs(text, format, host, nil, reg)
	if err != nil {
		run.err = webTruncate(webSanitise(err.Error()), 200)
		return
	}
	run.parsed, run.rejected, run.total = rep.Parsed, rep.Rejected, rep.Lines
	if rep.Parsed == 0 {
		run.err = "no line could be parsed"
		return
	}
	for _, f := range fs {
		run.note(f.Rule, 0, "")
	}
	// per-line attribution for the per-event web- rules
	for i, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" || len(line) > webLineMax {
			continue
		}
		rec, err := ParseWebLine(line, format)
		if err != nil {
			continue
		}
		for _, f := range WebEvaluate(reg, NormalizeWebRecord(rec, host)) {
			if len(run.lines[f.Rule]) < harnessAttrMax {
				run.lines[f.Rule] = append(run.lines[f.Rule], i+1)
			}
			if len(run.samples[f.Rule]) < 3 {
				run.samples[f.Rule] = append(run.samples[f.Rule], harnessSample(f.Evidence.Command))
			}
		}
	}
}

func harnessDecodeEvents(text string) ([]LabEvent, error) {
	t := strings.TrimSpace(text)
	var evs []LabEvent
	if strings.HasPrefix(t, "[") {
		if err := json.Unmarshal([]byte(t), &evs); err != nil {
			return nil, fmt.Errorf("events are not a valid JSON array")
		}
		return evs, nil
	}
	for _, l := range strings.Split(t, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var e LabEvent
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			return nil, fmt.Errorf("an event line is not valid JSON")
		}
		evs = append(evs, e)
		if len(evs) > harnessMaxRecords {
			break
		}
	}
	return evs, nil
}

func harnessRunEvents(run *harnessRun, text string, reg *ContentRegistry) {
	evs, err := harnessDecodeEvents(text)
	if err != nil {
		run.err = err.Error()
		return
	}
	harnessEvents(run, evs, reg)
}

func harnessEvents(run *harnessRun, evs []LabEvent, reg *ContentRegistry) {
	if len(evs) == 0 {
		run.err = "no events"
		return
	}
	if len(evs) > harnessMaxRecords {
		run.err = fmt.Sprintf("more than %d events", harnessMaxRecords)
		return
	}
	run.total = len(evs)
	deadline := time.Now().Add(harnessBudget)
	for i, ev := range evs {
		if i&127 == 0 && time.Now().After(deadline) {
			run.truncated = true
			run.err = "time budget reached; events after #" + strconv.Itoa(i) + " were not evaluated"
			break
		}
		if !contentAllTypes[ev.Kind] {
			run.rejected++
			continue
		}
		run.parsed++
		for _, r := range reg.byType[ev.Kind] {
			if r.Matches(ev) {
				run.note(r.ID, i+1, "")
				if len(run.samples[r.ID]) < 3 {
					run.samples[r.ID] = append(run.samples[r.ID], harnessSample(ev.Command+" "+ev.Path+" "+ev.Destination))
				}
			}
		}
	}
	if run.parsed == 0 {
		run.err = "no event had a valid kind (process, network, file, registry, dns, auth, module)"
	}
}

func harnessRunSpec(sp harnessSpec, file, baseDir string, reg *ContentRegistry) HarnessCaseResult {
	res := HarnessCaseResult{Case: sp.Case, File: file, Line: sp.line, Kind: sp.Kind, Rule: sp.Rule, Polarity: sp.Polarity, Fired: []HarnessFired{}}
	fail := func(msg string) HarnessCaseResult {
		res.Error = msg
		res.Diff = append(res.Diff, fmt.Sprintf("! %s", msg))
		return res
	}
	if sp.perr != "" {
		if res.Case == "" {
			res.Case = fmt.Sprintf("(line %d)", sp.line)
		}
		return fail(sp.perr)
	}
	expect, forbid := sp.expectations()
	var run *harnessRun
	if sp.Kind == "event" && sp.Input == "" {
		run = newHarnessRun()
		harnessEvents(run, sp.Events, reg)
	} else {
		text, err := harnessBuildText(&sp.HarnessCaseSpec, baseDir)
		if err != nil {
			return fail(err.Error())
		}
		do := func() { run = harnessRunKind(sp.Kind, text, sp.Format, sp.Host, sp.DormantDays, reg) }
		if sp.Kind == "web" || sp.Kind == "event" {
			do()
		} else if err := harnessWithTripwires(sp.Tripwires, do); err != nil {
			return fail(err.Error())
		}
	}
	res.Records = run.total
	if run.err != "" {
		return fail(run.err)
	}
	names := make([]string, 0, len(run.fired))
	for r := range run.fired {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		res.Fired = append(res.Fired, HarnessFired{Rule: r, Count: run.fired[r], InputLines: run.lines[r]})
	}
	where := func(r string) string {
		if l := run.lines[r]; len(l) > 0 {
			ss := make([]string, len(l))
			for i, x := range l {
				ss[i] = strconv.Itoa(x)
			}
			return " (input line " + strings.Join(ss, ", ") + ")"
		}
		return ""
	}
	for _, r := range expect {
		if run.fired[r] == 0 {
			res.Diff = append(res.Diff, fmt.Sprintf("- %s:%d expected rule %s did not fire", file, sp.line, r))
		}
	}
	for _, r := range forbid {
		if run.fired[r] > 0 {
			res.Diff = append(res.Diff, fmt.Sprintf("+ %s:%d forbidden rule %s fired %dx%s", file, sp.line, r, run.fired[r], where(r)))
		}
	}
	if sp.Exact {
		allow := map[string]bool{}
		for _, r := range expect {
			allow[r] = true
		}
		for _, r := range names {
			if !allow[r] {
				res.Diff = append(res.Diff, fmt.Sprintf("+ %s:%d unexpected rule %s fired %dx%s (exact mode)", file, sp.line, r, run.fired[r], where(r)))
			}
		}
	}
	res.Pass = len(res.Diff) == 0
	return res
}

// RunHarnessData parses and runs one test file's bytes. baseDir resolves "input" paths ("" disables them).
func RunHarnessData(name string, data []byte, baseDir string, opts HarnessOptions) (*HarnessReport, error) {
	reg, err := opts.reg()
	if reg == nil {
		return nil, fmt.Errorf("content packs unavailable: %v", err)
	}
	known := HarnessKnownRules(reg)
	for k := range opts.Known {
		known[k] = true
	}
	specs, perr := harnessParse(data, known)
	if perr != nil && specs == nil {
		return nil, fmt.Errorf("%s: %v", name, perr)
	}
	rep := newHarnessReport([]string{name})
	for _, sp := range specs {
		rep.add(harnessRunSpec(sp, name, baseDir, reg))
	}
	if perr != nil {
		rep.add(HarnessCaseResult{Case: "(file)", File: name, Error: perr.Error(), Diff: []string{"! " + perr.Error()}, Fired: []HarnessFired{}})
	}
	return rep, nil
}

func newHarnessReport(files []string) *HarnessReport {
	return &HarnessReport{Schema: HarnessSchema, Mode: "observe-only", Files: files, Results: []HarnessCaseResult{},
		Note: "offline: inputs are read from the test files you name and analysed in memory; nothing is fetched, contacted, blocked or stored."}
}

func (r *HarnessReport) add(c HarnessCaseResult) {
	r.Cases++
	if c.Pass {
		r.Passed++
	} else {
		r.Failed++
	}
	r.Results = append(r.Results, c)
}

// Merge appends another report's results.
func (r *HarnessReport) Merge(o *HarnessReport) {
	r.Files = append(r.Files, o.Files...)
	for _, c := range o.Results {
		r.add(c)
	}
}

// RunHarnessFile reads a test file (size capped) and runs it; input paths resolve next to it.
func RunHarnessFile(path string, opts HarnessOptions) (*HarnessReport, error) {
	b, err := harnessReadCapped(path, harnessMaxFileBytes)
	if err != nil {
		return nil, err
	}
	return RunHarnessData(filepath.Base(path), b, filepath.Dir(path), opts)
}
