// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Evidence import cases. A case is built from analyst-supplied command output, replayed through the
// detection engines against the validation lab's private registry, and kept only in this manager.
// Nothing here writes to the live Store unless an admin calls promote.

const (
	evMaxCases      = 20
	evMaxEvents     = 20000
	evMaxFindings   = 2000
	evMaxTimeline   = 500
	evMaxIOCs       = 500
	evSynthStep     = 10 * time.Second
	evReplayTimeout = 60 * time.Second
	evCaseNote      = "Imported evidence: replayed in isolation through the detection engines. Nothing was executed and nothing was written to the live findings store. Listings lose timing and parent/child detail; see docs/evidence-import.md."
)

type EvEvidence struct {
	Host        string `json:"host"`
	PID         int    `json:"pid,omitempty"`
	Executable  string `json:"executable,omitempty"`
	Command     string `json:"command,omitempty"`
	Destination string `json:"destination,omitempty"`
	Path        string `json:"path,omitempty"`
}

type EvFinding struct {
	N             int        `json:"n"`
	Rule          string     `json:"rule"`
	Severity      string     `json:"severity"`
	Engine        string     `json:"engine"`
	TechniqueID   string     `json:"technique_id,omitempty"`
	Tactic        string     `json:"tactic,omitempty"`
	Mapped        bool       `json:"mapped"`
	Description   string     `json:"description,omitempty"`
	Artefact      string     `json:"artefact"`
	Line          int        `json:"line"`
	Time          time.Time  `json:"time"`
	TimeSynthetic bool       `json:"time_synthetic,omitempty"`
	Evidence      EvEvidence `json:"evidence"`
	Tags          []string   `json:"-"`
}

type EvTimelineEntry struct {
	Time          time.Time `json:"time"`
	TimeSynthetic bool      `json:"time_synthetic,omitempty"`
	Artefact      string    `json:"artefact"`
	Line          int       `json:"line"`
	Type          string    `json:"type"`
	Summary       string    `json:"summary"`
	Rules         []string  `json:"rules,omitempty"`
}

type EvIOC struct {
	Type     string `json:"type"` // ip | domain | url | hash
	Value    string `json:"value"`
	Artefact string `json:"artefact"`
	Line     int    `json:"line"`
	Count    int    `json:"count"`
}

type EvTotals struct {
	Events    int `json:"events"`
	Processes int `json:"processes"`
	Network   int `json:"network"`
	Files     int `json:"files"`
	Telemetry int `json:"telemetry"`
	Dropped   int `json:"dropped_over_cap,omitempty"`
	Rejected  int `json:"rejected_by_validation,omitempty"`
	Findings  int `json:"findings"`
}

type EvidenceCase struct {
	ID            string            `json:"id"`
	Label         string            `json:"case"`
	Host          string            `json:"host"`
	HostLabel     string            `json:"host_label"`
	CreatedAt     time.Time         `json:"created_at"`
	CollectedAt   time.Time         `json:"collected_at"`
	Artefacts     []evStat          `json:"artefacts"`
	Totals        EvTotals          `json:"totals"`
	Findings      []EvFinding       `json:"findings"`
	Timeline      []EvTimelineEntry `json:"timeline"`
	IOCs          []EvIOC           `json:"iocs"`
	Promoted      bool              `json:"promoted"`
	PromotedAt    *time.Time        `json:"promoted_at,omitempty"`
	PromotedCount int               `json:"promoted_count,omitempty"`
	MetadataOnly  bool              `json:"metadata_only,omitempty"`
	Note          string            `json:"note"`
}

type evInput struct {
	Name    string
	Hint    string
	Content []byte
	TooBig  bool
}

func evNewID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "ev-" + hex.EncodeToString(b)
}

var evLabelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// evValidLabel is the impersonation guard: labels cannot carry the namespace separator, so the
// composed host `import:<case>:<host>` can never equal an enrolled agent host name.
func evValidLabel(s string) bool { return evLabelRe.MatchString(s) }

func evSeverityOK(s string) bool { _, ok := valSevRank[s]; return ok }

// BuildEvidenceCase parses all inputs and replays the result. It has no side effects.
func BuildEvidenceCase(label, host string, collected time.Time, in []evInput) *EvidenceCase {
	now := time.Now().UTC()
	if collected.IsZero() {
		collected = now
	}
	id := evNewID()
	if label == "" {
		label = id
	}
	c := &EvidenceCase{ID: id, Label: label, Host: host, HostLabel: "import:" + label + ":" + host,
		CreatedAt: now, CollectedAt: collected, Artefacts: []evStat{}, Findings: []EvFinding{}, Timeline: []EvTimelineEntry{}, IOCs: []EvIOC{}, Note: evCaseNote}
	ctx := &evCtx{base: collected}
	var items []evItem
	for _, a := range in {
		if a.TooBig {
			c.Artefacts = append(c.Artefacts, evStat{Name: evClip(a.Name, 128), Format: "unknown", Bytes: len(a.Content), Status: "failed", Error: "artefact exceeds the per-artefact size cap"})
			continue
		}
		its, st := evParseArtefact(a.Name, a.Hint, a.Content, ctx)
		c.Artefacts = append(c.Artefacts, st)
		items = append(items, its...)
	}
	if len(items) > evMaxEvents {
		c.Totals.Dropped = len(items) - evMaxEvents
		items = items[:evMaxEvents]
	}
	evReplay(c, items)
	return c
}

func evAssignTimes(c *EvidenceCase, items []evItem) []bool {
	synth := make([]bool, len(items))
	k := 0
	for i := range items {
		if items[i].Time.IsZero() {
			items[i].Time = c.CollectedAt.Add(time.Duration(k) * evSynthStep)
			synth[i] = true
			k++
		}
	}
	return synth
}

// evReplay mirrors ReplayScenario (validate_replay.go): the same private registry, a fresh
// FileDetections window, and the pure Detect/contentEvaluateWith functions. The Store is never
// referenced.
func evReplay(c *EvidenceCase, items []evItem) {
	reg := valRegistry(ValOptions{})
	synth := evAssignTimes(c, items)
	detector := &FileDetections{}
	host := c.HostLabel
	deadline := time.Now().Add(evReplayTimeout)
	seen := map[string]bool{}
	firedAt := map[int][]string{}
	pidCounter := 4000
	record := func(i int, it *evItem, fs []Finding) {
		for _, f := range fs {
			id, tac, ok := valTechnique(reg, f)
			key := f.Rule + "|" + it.Exe + "|" + it.Cmd + "|" + it.Dest + "|" + it.Path
			if seen[key] || len(c.Findings) >= evMaxFindings {
				continue
			}
			seen[key] = true
			ef := EvFinding{N: len(c.Findings) + 1, Rule: f.Rule, Severity: f.Severity, Engine: engineOf(f), TechniqueID: id, Tactic: tac, Mapped: ok,
				Description: evClip(f.Description, 512), Artefact: it.Artefact, Line: it.Line, Time: it.Time, TimeSynthetic: synth[i],
				Evidence: EvEvidence{Host: host, PID: it.PID, Executable: evClip(it.Exe, 512), Command: evClip(it.Cmd, 1024), Destination: it.Dest, Path: it.Path}, Tags: f.Tags}
			c.Findings = append(c.Findings, ef)
			firedAt[i] = append(firedAt[i], f.Rule)
		}
	}
	for i := range items {
		it := &items[i]
		if i%256 == 0 && time.Now().After(deadline) {
			c.Artefacts = append(c.Artefacts, evStat{Name: "(replay)", Format: "internal", Status: "partial", Notes: []string{"replay stopped at the time budget; later events were not evaluated"}})
			break
		}
		t := it.Time
		pid := it.PID
		if pid == 0 {
			pid = pidCounter + i
		}
		switch it.Type {
		case "process":
			c.Totals.Processes++
			e := Event{Time: t, Host: host, PID: pid, PPID: it.PPID, UID: it.UID, Executable: it.Exe, ParentExe: it.Parent, Command: it.Cmd}
			if e.PPID == 0 {
				e.PPID = 1
			}
			fs := Detect(e)
			kept := fs[:0:0]
			for _, f := range fs {
				if g := engineOf(f); g == "content" || g == "custom" {
					continue
				}
				kept = append(kept, f)
			}
			uid := e.UID
			kept = append(kept, contentEvaluateWith(reg, "process", LabEvent{Time: t, Host: host, UID: &uid, Executable: e.Executable, ParentExe: e.ParentExe, Command: e.Command},
				Finding{Time: t, Host: host, PID: pid, Evidence: e})...)
			record(i, it, kept)
		case "network":
			c.Totals.Network++
			fs := contentEvaluateWith(reg, "network", LabEvent{Time: t, Host: host, Destination: it.Dest},
				Finding{Time: t, Host: host, PID: pid, Destination: it.Dest, Evidence: Event{Time: t, Host: host, PID: pid, Executable: it.Exe}})
			record(i, it, fs)
		case "file":
			c.Totals.Files++
			fe := FileEvent{Time: t, Host: host, Path: it.Path, Operation: "listed", Size: it.Size}
			fs := detector.Observe(fe)
			fs = append(fs, contentEvaluateWith(reg, "file", LabEvent{Time: t, Host: host, Path: it.Path, Operation: "listed"},
				Finding{Time: t, Host: host, Evidence: Event{Time: t, Host: host, Command: "listed " + it.Path}})...)
			record(i, it, fs)
		case "registry", "auth":
			te := it.Tel
			te.Time, te.Host = t, host
			if err := te.Validate(it.Type); err != nil {
				c.Totals.Rejected++
				continue
			}
			c.Totals.Telemetry++
			it.Cmd = telemetrySummary(it.Type, te)
			base := Finding{Time: t, Host: host, Evidence: Event{Time: t, Host: host, Command: it.Cmd}}
			record(i, it, contentEvaluateWith(reg, it.Type, contentTelemetryEvent(it.Type, te), base))
		}
	}
	c.Totals.Events = len(items)
	c.Totals.Findings = len(c.Findings)
	c.Timeline = evTimeline(items, synth, firedAt)
	c.IOCs = evIOCs(items)
	sort.SliceStable(c.Findings, func(a, b int) bool { return valSevRank[c.Findings[a].Severity] > valSevRank[c.Findings[b].Severity] })
	for i := range c.Findings {
		c.Findings[i].N = i + 1
	}
}

func evSummary(it *evItem) string {
	switch it.Type {
	case "process":
		return evClip(it.Cmd, 200)
	case "network":
		s := "connection to " + it.Dest
		if it.Exe != "" {
			s = it.Exe + " " + s
		}
		return s
	case "file":
		return "listed " + it.Path
	}
	return evClip(it.Cmd, 200)
}

func evTimeline(items []evItem, synth []bool, fired map[int][]string) []EvTimelineEntry {
	var out []EvTimelineEntry
	add := func(i int) {
		it := &items[i]
		out = append(out, EvTimelineEntry{Time: it.Time, TimeSynthetic: synth[i], Artefact: it.Artefact, Line: it.Line, Type: it.Type, Summary: evSummary(it), Rules: dedupSorted(fired[i])})
	}
	for i := range items {
		if len(fired[i]) > 0 && len(out) < evMaxTimeline {
			add(i)
		}
	}
	for i := range items { // real-timestamped events (history, auth) next, then the rest
		if len(fired[i]) == 0 && !synth[i] && len(out) < evMaxTimeline {
			add(i)
		}
	}
	for i := range items {
		if len(fired[i]) == 0 && synth[i] && len(out) < evMaxTimeline {
			add(i)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Time.Before(out[b].Time) })
	return out
}

var (
	evURLRe  = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>|;)]{3,300}`)
	evIPv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	evHashRe = regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)
)

func evPublicIP(s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	if a.IsPrivate() || a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return "", false
	}
	return a.String(), true
}

func evHostOf(dest string) string {
	if strings.HasPrefix(dest, "[") {
		if i := strings.Index(dest, "]"); i > 0 {
			return dest[1:i]
		}
	}
	if strings.Count(dest, ":") == 1 {
		return dest[:strings.IndexByte(dest, ':')]
	}
	return dest
}

func evIOCs(items []evItem) []EvIOC {
	idx := map[string]int{}
	var out []EvIOC
	add := func(typ, val string, it *evItem) {
		k := typ + "|" + val
		if i, ok := idx[k]; ok {
			out[i].Count++
			return
		}
		if len(out) >= evMaxIOCs {
			return
		}
		idx[k] = len(out)
		out = append(out, EvIOC{Type: typ, Value: evClip(val, 400), Artefact: it.Artefact, Line: it.Line, Count: 1})
	}
	for i := range items {
		it := &items[i]
		if it.Type == "network" {
			if ip, ok := evPublicIP(evHostOf(it.Dest)); ok {
				add("ip", ip, it)
			}
		}
		text := it.Cmd
		if it.Type == "registry" {
			text = it.Tel.ValueData
		}
		if text == "" {
			continue
		}
		for _, u := range evURLRe.FindAllString(text, 5) {
			add("url", u, it)
			if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
				h := strings.ToLower(pu.Hostname())
				if ip, ok := evPublicIP(h); ok {
					add("ip", ip, it)
				} else if strings.Contains(h, ".") && !strings.HasSuffix(h, ".local") {
					if _, err := netip.ParseAddr(h); err != nil {
						add("domain", h, it)
					}
				}
			}
		}
		for _, ip := range evIPv4Re.FindAllString(text, 5) {
			if p, ok := evPublicIP(ip); ok {
				add("ip", p, it)
			}
		}
		for _, h := range evHashRe.FindAllString(text, 3) {
			add("hash", strings.ToLower(h), it)
		}
	}
	return out
}

// ---- manager ----

type evManager struct {
	mu      sync.Mutex
	cases   []*EvidenceCase // oldest first, capped at evMaxCases
	path    string          // "" disables persistence
	slots   chan struct{}   // bounds concurrent imports
	persist bool
}

func newEvManager(storePath string) *evManager {
	m := &evManager{slots: make(chan struct{}, 2)}
	v := strings.ToLower(os.Getenv("KAVACH_EVIDENCE_PERSIST"))
	if storePath != "" && (v == "1" || v == "on" || v == "true" || v == "yes") {
		m.path = storePath + ".evidence.json"
		m.persist = true
		m.load()
	}
	return m
}

type evPersisted struct {
	Version int             `json:"version"`
	Note    string          `json:"note"`
	Cases   []*EvidenceCase `json:"cases"`
}

// metadataOnly strips every field derived from raw artefact text.
func (c *EvidenceCase) metadataOnly() *EvidenceCase {
	cp := *c
	cp.MetadataOnly = true
	cp.Timeline, cp.IOCs = []EvTimelineEntry{}, []EvIOC{}
	cp.Findings = make([]EvFinding, len(c.Findings))
	for i, f := range c.Findings {
		f.Description, f.Evidence, f.Tags = "", EvEvidence{Host: f.Evidence.Host}, nil
		cp.Findings[i] = f
	}
	cp.Artefacts = make([]evStat, len(c.Artefacts))
	for i, a := range c.Artefacts {
		a.Notes, a.Error = nil, ""
		cp.Artefacts[i] = a
	}
	return &cp
}

func (m *evManager) load() {
	b, err := os.ReadFile(m.path)
	if err != nil || len(b) > 64<<20 {
		return
	}
	var p evPersisted
	if json.Unmarshal(b, &p) != nil {
		return
	}
	for _, c := range p.Cases {
		if c == nil || c.ID == "" || !evValidLabel(c.Host) {
			continue
		}
		c.MetadataOnly = true
		m.cases = append(m.cases, c)
	}
	if len(m.cases) > evMaxCases {
		m.cases = m.cases[len(m.cases)-evMaxCases:]
	}
}

func (m *evManager) saveLocked() {
	if !m.persist {
		return
	}
	p := evPersisted{Version: 1, Note: "metadata only: no raw artefact text, commands, paths or IOC values", Cases: make([]*EvidenceCase, 0, len(m.cases))}
	for _, c := range m.cases {
		p.Cases = append(p.Cases, c.metadataOnly())
	}
	_ = govWriteAtomic(m.path, p)
}

func (m *evManager) add(c *EvidenceCase) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cases = append(m.cases, c)
	if len(m.cases) > evMaxCases {
		m.cases = m.cases[len(m.cases)-evMaxCases:]
	}
	m.saveLocked()
}

func (m *evManager) get(id string) *EvidenceCase {
	for _, c := range m.cases {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (m *evManager) remove(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.cases {
		if c.ID == id {
			m.cases = append(m.cases[:i], m.cases[i+1:]...)
			m.saveLocked()
			return true
		}
	}
	return false
}

// promote ingests the would-fire findings into the live store. Explicit, admin only, once per case.
func (m *evManager) promote(id string, store *Store) (int, error, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.get(id)
	if c == nil {
		return 0, fmt.Errorf("case not found"), 404
	}
	if c.Promoted {
		return c.PromotedCount, fmt.Errorf("case already promoted"), 409
	}
	if c.MetadataOnly {
		return 0, fmt.Errorf("case was restored from metadata only; the findings' evidence is not retained, re-import the artefacts"), 409
	}
	if len(c.Findings) == 0 {
		return 0, fmt.Errorf("case has no findings to promote"), 409
	}
	now := time.Now().UTC()
	n := 0
	for _, f := range c.Findings {
		if !strings.HasPrefix(f.Evidence.Host, "import:") {
			continue // never ingest anything outside the import namespace
		}
		ev := Event{Time: now, Host: f.Evidence.Host, PID: f.Evidence.PID, PPID: 1, Executable: f.Evidence.Executable, Command: f.Evidence.Command}
		tags := append([]string{"evidence-import", "case:" + c.ID, "artefact:" + f.Artefact}, f.Tags...)
		if f.TechniqueID != "" {
			tags = append(tags, f.TechniqueID)
		}
		fin := Finding{ID: fmt.Sprintf("evidence:%s:%d:%s", c.ID, f.N, f.Rule), Time: now, Host: f.Evidence.Host, PID: f.Evidence.PID, Rule: f.Rule,
			Severity: f.Severity, Description: fmt.Sprintf("[evidence-import %s %s:%d] %s", c.ID, f.Artefact, f.Line, f.Description),
			Evidence: ev, Tags: tags, Destination: f.Evidence.Destination}
		if err := store.Append(fin); err != nil {
			c.PromotedCount = n
			return n, fmt.Errorf("store write failed after %d findings: %v", n, err), 500
		}
		n++
	}
	t := now
	c.Promoted, c.PromotedAt, c.PromotedCount = true, &t, n
	m.saveLocked()
	return n, nil, 200
}
