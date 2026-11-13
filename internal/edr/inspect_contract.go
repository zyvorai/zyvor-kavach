// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Artifact inspector: shared contract.
//
// The inspector statically analyses things an analyst submits: file bytes,
// scripts, command lines and domains. It parses only. It never executes the
// input, never opens a network connection on its behalf and never persists the
// submitted bytes (only the resulting report and the sha256 are kept, in a
// capped in-memory ring). Kavach stays observation-only.
//
// Analyzers live in their own files and register themselves from init() with
// RegisterAnalyzer; nobody edits another analyzer's file. RunAnalyzers wraps
// every analyzer in a time budget and recover(), caps findings, IOCs and
// layers, and builds the verdict from the findings' weights.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hard limits shared by every analyzer. Analyzers must also honour ctx.
const (
	InspectMaxBytes     = 32 << 20 // largest accepted input
	InspectMaxTextBytes = 4 << 20  // largest accepted script/cmdline/domain text
	InspectAnalyzerTime = 5 * time.Second
	InspectTotalTime    = 20 * time.Second
	InspectMaxFindings  = 200
	InspectMaxIOCs      = 500
	InspectMaxLayers    = 16
	InspectMaxStringLen = 512 // longest evidence/preview string kept in a report
	InspectRingCapacity = 200
	inspectMaxRecursion = 8
)

// Inspect kinds.
const (
	InspectKindFile    = "file"
	InspectKindScript  = "script"
	InspectKindCmdline = "cmdline"
	InspectKindDomain  = "domain"
)

var inspectKinds = []string{InspectKindFile, InspectKindScript, InspectKindCmdline, InspectKindDomain}

// InspectMaxDepth is the deepest decoder/archive recursion analyzers may use.
const InspectMaxDepth = inspectMaxRecursion

// InspectInput is what analyzers receive. Data is set for files, Text for the
// other kinds. Analyzers must treat both as hostile and read-only.
type InspectInput struct {
	Kind string
	Name string // client-supplied label; never trusted as a path
	Data []byte
	Text string
}

// InspectFinding is one observation with a weight used by the verdict.
type InspectFinding struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"` // info|low|medium|high|critical
	Technique string `json:"technique,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
	Weight    int    `json:"weight"` // 0-100 contribution to the score
	Analyzer  string `json:"analyzer,omitempty"`
}

// InspectIOC is an indicator extracted from the input.
type InspectIOC struct {
	Type  string `json:"type"` // url|ipv4|ipv6|domain|email|sha256|md5|registry|path|wallet
	Value string `json:"value"`
}

// InspectLayer records one decoding or unpacking step.
type InspectLayer struct {
	Depth   int    `json:"depth"`
	Method  string `json:"method"`
	Bytes   int    `json:"bytes"`
	Preview string `json:"preview,omitempty"`
}

// InspectReport is the result of one inspection.
type InspectReport struct {
	ID        string           `json:"id"`
	Time      time.Time        `json:"time"`
	Kind      string           `json:"kind"`
	Name      string           `json:"name,omitempty"`
	SHA256    string           `json:"sha256"`
	Size      int64            `json:"size"`
	Format    string           `json:"format,omitempty"`
	Findings  []InspectFinding `json:"findings"`
	IOCs      []InspectIOC     `json:"iocs"`
	Layers    []InspectLayer   `json:"layers,omitempty"`
	Meta      map[string]any   `json:"meta,omitempty"`
	Score     int              `json:"score"`
	Level     string           `json:"level"` // clean|low|suspicious|malicious-likely
	Factors   []string         `json:"factors"`
	KnownIOCs []string         `json:"known_iocs,omitempty"` // ids of IOC-store entries that matched
	Analyzers []string         `json:"analyzers"`
	LimitsHit []string         `json:"limits_hit,omitempty"`
	Errors    []string         `json:"errors,omitempty"`
	Mode      string           `json:"mode"`
	Note      string           `json:"note"`
}

// Builder is handed to analyzers to add results; it enforces the caps so an
// analyzer cannot grow a report without bound.
type InspectBuilder struct {
	mu       sync.Mutex
	r        *InspectReport
	analyzer string
	seenIOC  map[string]bool
}

func (b *InspectBuilder) limit(name string) {
	for _, x := range b.r.LimitsHit {
		if x == name {
			return
		}
	}
	b.r.LimitsHit = append(b.r.LimitsHit, name)
}

// Finding adds a finding (truncating long strings, capping the count).
func (b *InspectBuilder) Finding(f InspectFinding) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.r.Findings) >= InspectMaxFindings {
		b.limit("findings")
		return
	}
	f.Title = truncInspect(f.Title)
	f.Evidence = truncInspect(f.Evidence)
	if f.Weight < 0 {
		f.Weight = 0
	}
	if f.Weight > 100 {
		f.Weight = 100
	}
	switch f.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		f.Severity = "info"
	}
	f.Analyzer = b.analyzer
	b.r.Findings = append(b.r.Findings, f)
}

// IOC adds a de-duplicated indicator.
func (b *InspectBuilder) IOC(typ, value string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	key := typ + "\x00" + value
	if b.seenIOC[key] {
		return
	}
	if len(b.r.IOCs) >= InspectMaxIOCs {
		b.limit("iocs")
		return
	}
	b.seenIOC[key] = true
	b.r.IOCs = append(b.r.IOCs, InspectIOC{Type: typ, Value: truncInspect(value)})
}

// Layer records a decode/unpack step.
func (b *InspectBuilder) Layer(l InspectLayer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.r.Layers) >= InspectMaxLayers {
		b.limit("layers")
		return
	}
	l.Preview = truncInspect(l.Preview)
	b.r.Layers = append(b.r.Layers, l)
}

// Format sets the detected format (first non-empty wins).
func (b *InspectBuilder) Format(f string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.r.Format == "" {
		b.r.Format = f
	}
}

// Meta stores a structured detail under key (last writer wins per key).
func (b *InspectBuilder) Meta(key string, v any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.r.Meta == nil {
		b.r.Meta = map[string]any{}
	}
	b.r.Meta[b.analyzer+"."+key] = v
}

// LimitHit lets an analyzer report that it stopped early on a limit.
func (b *InspectBuilder) LimitHit(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.limit(b.analyzer + ":" + name)
}

func truncInspect(s string) string {
	if len(s) <= InspectMaxStringLen {
		return s
	}
	return s[:InspectMaxStringLen] + "..."
}

// AnalyzerFunc inspects in and records results on b. It must return promptly
// when ctx is done, and must never execute, write or fetch anything.
type AnalyzerFunc func(ctx context.Context, in InspectInput, b *InspectBuilder) error

type inspectAnalyzer struct {
	name  string
	kinds map[string]bool
	fn    AnalyzerFunc
}

var (
	inspectMu        sync.RWMutex
	inspectAnalyzers []inspectAnalyzer
)

// RegisterAnalyzer adds an analyzer for the given kinds. Call from init().
func RegisterAnalyzer(name string, kinds []string, fn AnalyzerFunc) {
	inspectMu.Lock()
	defer inspectMu.Unlock()
	m := map[string]bool{}
	for _, k := range kinds {
		m[k] = true
	}
	inspectAnalyzers = append(inspectAnalyzers, inspectAnalyzer{name: name, kinds: m, fn: fn})
	sort.SliceStable(inspectAnalyzers, func(i, j int) bool { return inspectAnalyzers[i].name < inspectAnalyzers[j].name })
}

// InspectAnalyzerNames lists registered analyzers per kind.
func InspectAnalyzerNames() map[string][]string {
	inspectMu.RLock()
	defer inspectMu.RUnlock()
	out := map[string][]string{}
	for _, k := range inspectKinds {
		out[k] = []string{}
	}
	for _, a := range inspectAnalyzers {
		for k := range a.kinds {
			out[k] = append(out[k], a.name)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func runSafely(ctx context.Context, a inspectAnalyzer, in InspectInput, b *InspectBuilder) (err error) {
	actx, cancel := context.WithTimeout(ctx, InspectAnalyzerTime)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- fmt.Errorf("panic: %v", rec)
			}
		}()
		done <- a.fn(actx, in, b)
	}()
	select {
	case e := <-done:
		return e
	case <-actx.Done():
		// The goroutine may still be running; the builder is mutex-guarded and
		// results already added are kept.
		return errors.New("timed out")
	}
}

// RunAnalyzers runs every analyzer registered for in.Kind and builds the report.
func RunAnalyzers(ctx context.Context, in InspectInput) *InspectReport {
	r := &InspectReport{
		ID:       fmt.Sprintf("insp-%d", time.Now().UnixNano()),
		Time:     time.Now().UTC(),
		Kind:     in.Kind,
		Name:     truncInspect(in.Name),
		Findings: []InspectFinding{},
		IOCs:     []InspectIOC{},
		Factors:  []string{},
		Mode:     "observe-only",
		Note:     "Static analysis only: the input was parsed, never executed, and its bytes were not stored. A low score is not proof the input is safe.",
	}
	var hashSrc []byte
	if in.Kind == InspectKindFile {
		hashSrc = in.Data
		r.Size = int64(len(in.Data))
	} else {
		hashSrc = []byte(in.Text)
		r.Size = int64(len(in.Text))
	}
	sum := sha256.Sum256(hashSrc)
	r.SHA256 = hex.EncodeToString(sum[:])

	tctx, cancel := context.WithTimeout(ctx, InspectTotalTime)
	defer cancel()
	inspectMu.RLock()
	list := make([]inspectAnalyzer, 0, len(inspectAnalyzers))
	for _, a := range inspectAnalyzers {
		if a.kinds[in.Kind] {
			list = append(list, a)
		}
	}
	inspectMu.RUnlock()

	b := &InspectBuilder{r: r, seenIOC: map[string]bool{}}
	for _, a := range list {
		if tctx.Err() != nil {
			b.mu.Lock()
			b.limit("total-time")
			b.mu.Unlock()
			break
		}
		b.analyzer = a.name
		r.Analyzers = append(r.Analyzers, a.name)
		if err := runSafely(tctx, a, in, b); err != nil {
			r.Errors = append(r.Errors, a.name+": "+err.Error())
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	crossCheckIOCs(r)
	scoreInspectReport(r)
	return r
}

// crossCheckIOCs matches the sha256 and extracted indicators against the IOC
// store (read-only; nothing is added to it).
func crossCheckIOCs(r *InspectReport) {
	hay := []string{r.SHA256}
	for _, i := range r.IOCs {
		hay = append(hay, i.Value)
	}
	seen := map[string]bool{}
	for _, h := range hay {
		for _, m := range MatchIOCs(h) {
			if !seen[m.ID] {
				seen[m.ID] = true
				r.KnownIOCs = append(r.KnownIOCs, m.ID)
			}
		}
	}
	sort.Strings(r.KnownIOCs)
}

// InspectObfuscationCap is the most that obfuscation-only findings (statistical
// scoring and the deobfuscation analyzer's "this looks obfuscated" findings)
// can add to a score together. It stays below the 40 "suspicious" line, so
// obfuscation alone never produces a verdict; a decoded layer that triggers a
// real detection rule is not obfuscation-only and is not capped here.
const InspectObfuscationCap = 35

// isObfuscationOnlyFinding reports whether a finding only says "the input
// looks obfuscated" (as opposed to saying what it does).
func isObfuscationOnlyFinding(id string) bool {
	if strings.HasPrefix(id, "obf-") {
		return true
	}
	switch id {
	case "deob-layers", "deob-mixed-techniques", "deob-xor-payload",
		"deob-compressed-payload", "deob-high-entropy-blob":
		return true
	}
	return false
}

// scoreInspectReport builds a transparent verdict: the score is the sum of the
// strongest findings' weights (capped at 100), a known IOC match adds 40, and
// every contributing finding is listed in Factors. There is no hidden model.
func scoreInspectReport(r *InspectReport) {
	fs := append([]InspectFinding(nil), r.Findings...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Weight > fs[j].Weight })
	score := 0
	obfSum := 0
	for i, f := range fs {
		if f.Weight == 0 {
			continue
		}
		if i < 10 { // only the top contributors count, so many weak hits cannot add up to a verdict
			w := f.Weight
			if isObfuscationOnlyFinding(f.ID) {
				// Obfuscation on its own is a weak signal and several analyzers
				// measure the same thing, so they share one budget.
				if room := InspectObfuscationCap - obfSum; w > room {
					w = room
				}
				if w <= 0 {
					continue
				}
				obfSum += w
			}
			score += w
			r.Factors = append(r.Factors, fmt.Sprintf("%s (+%d)", f.Title, w))
		}
	}
	if len(r.KnownIOCs) > 0 {
		score += 40
		r.Factors = append(r.Factors, fmt.Sprintf("matches %d known IOC(s) (+40)", len(r.KnownIOCs)))
	}
	if score > 100 {
		score = 100
	}
	r.Score = score
	switch {
	case score >= 70:
		r.Level = "malicious-likely"
	case score >= 40:
		r.Level = "suspicious"
	case score >= 15:
		r.Level = "low"
	default:
		r.Level = "clean"
	}
}

// Report ring: recent reports only (no input bytes), newest first.
var (
	inspectRingMu sync.Mutex
	inspectRing   []*InspectReport
)

func storeInspectReport(r *InspectReport) {
	inspectRingMu.Lock()
	defer inspectRingMu.Unlock()
	inspectRing = append([]*InspectReport{r}, inspectRing...)
	if len(inspectRing) > InspectRingCapacity {
		inspectRing = inspectRing[:InspectRingCapacity]
	}
}

// RecentInspectReports returns up to limit stored reports, newest first.
func RecentInspectReports(limit int) []*InspectReport {
	inspectRingMu.Lock()
	defer inspectRingMu.Unlock()
	if limit <= 0 || limit > len(inspectRing) {
		limit = len(inspectRing)
	}
	return append([]*InspectReport(nil), inspectRing[:limit]...)
}

// RegisterInspect serves the inspector endpoints:
//
//	POST /v1/inspect/file     raw bytes (application/octet-stream), ?name=
//	POST /v1/inspect/script   raw text or {"text": "..."}
//	POST /v1/inspect/cmdline  raw text or {"text": "..."}
//	POST /v1/inspect/domain   raw text or {"text": "..."} (one domain)
//	GET  /v1/inspect/reports  recent reports (no input bytes)
//	GET  /v1/inspect/analyzers
func RegisterInspect(mux *http.ServeMux, token string) {
	for _, kind := range inspectKinds {
		kind := kind
		mux.HandleFunc("POST /v1/inspect/"+kind, func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			in, code, msg := readInspectInput(w, r, kind)
			if msg != "" {
				http.Error(w, msg, code)
				return
			}
			rep := RunAnalyzers(r.Context(), in)
			storeInspectReport(rep)
			writeJSON(w, rep)
		})
	}
	mux.HandleFunc("GET /v1/inspect/reports", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		limit := 50
		fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
		reps := RecentInspectReports(limit)
		writeJSON(w, map[string]any{"count": len(reps), "reports": reps, "mode": "observe-only"})
	})
	mux.HandleFunc("GET /v1/inspect/analyzers", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, map[string]any{"analyzers": InspectAnalyzerNames(), "max_bytes": InspectMaxBytes, "mode": "observe-only"})
	})
}

func readInspectInput(w http.ResponseWriter, r *http.Request, kind string) (InspectInput, int, string) {
	in := InspectInput{Kind: kind, Name: r.URL.Query().Get("name")}
	max := int64(InspectMaxTextBytes)
	if kind == InspectKindFile {
		max = InspectMaxBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, max+1024)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return in, http.StatusRequestEntityTooLarge, fmt.Sprintf("input too large (max %d bytes)", max)
	}
	if int64(len(raw)) > max {
		return in, http.StatusRequestEntityTooLarge, fmt.Sprintf("input too large (max %d bytes)", max)
	}
	if len(raw) == 0 {
		return in, http.StatusBadRequest, "empty input"
	}
	if kind == InspectKindFile {
		in.Data = raw
		return in, 0, ""
	}
	if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Content-Type")), "application/json") {
		var body struct {
			Text string `json:"text"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return in, http.StatusBadRequest, "invalid JSON"
		}
		in.Text = body.Text
		if in.Name == "" {
			in.Name = body.Name
		}
	} else {
		in.Text = string(raw)
	}
	if strings.TrimSpace(in.Text) == "" {
		return in, http.StatusBadRequest, "empty input"
	}
	return in, 0, ""
}
