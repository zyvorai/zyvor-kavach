package edr

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scheduled report engine. PULL-ONLY: reports are rendered in-process from
// data Kavach already holds and written to <store>.reports/. This file (and the
// rest of report_sched_*.go) opens no network connection and sends nothing
// anywhere; operators fetch artefacts over the authenticated API. A test scans
// the source for outbound primitives to keep it that way.

const (
	rsTick          = 30 * time.Second
	rsRunTimeout    = 30 * time.Second
	rsMaxRunBytes   = 2 << 20
	rsMaxArchive    = 500
	rsMaxArchiveSz  = 64 << 20
	rsMaxRunRecords = 2000
	rsMaxPerTick    = 5
)

var (
	rsRunIDRe  = regexp.MustCompile(`^r[0-9a-z]{6,40}$`)
	rsSchedRe  = regexp.MustCompile(`^s[0-9a-z]{6,40}$`)
	errRSBusy  = errors.New("schedule is already running")
	errRSNoSch = errors.New("schedule not found")
)

type rsRun struct {
	RunID       string            `json:"run_id"`
	ScheduleID  string            `json:"schedule_id"`
	Template    string            `json:"template"`
	Params      map[string]string `json:"params,omitempty"`
	Format      string            `json:"format"`
	Trigger     string            `json:"trigger"` // scheduled | catchup | manual
	Status      string            `json:"status"`  // ok | failed | timeout
	Error       string            `json:"error,omitempty"`
	GeneratedAt time.Time         `json:"generated_at"`
	DurationMS  int64             `json:"duration_ms"`
	Bytes       int               `json:"bytes"`
	SHA256      string            `json:"sha256,omitempty"`
	Redacted    bool              `json:"redacted"`
	File        string            `json:"-"`
}

type rsEngine struct {
	mu       sync.Mutex
	path     string
	dir      string
	scheds   map[string]*rsSchedule
	running  map[string]bool
	runs     []rsRun // oldest first
	seq      int
	clock    func() time.Time
	render   func(s rsSchedule, now time.Time) ([]byte, bool, error)
	sem      chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	timeout  time.Duration
	maxBytes int
	maxFiles int
	maxTotal int64
}

func newRSEngine(storePath string, clock func() time.Time) *rsEngine {
	e := &rsEngine{path: storePath + ".reportschedules.json", dir: storePath + ".reports",
		scheds: map[string]*rsSchedule{}, running: map[string]bool{}, clock: clock,
		sem: make(chan struct{}, 1), stop: make(chan struct{}), timeout: rsRunTimeout,
		maxBytes: rsMaxRunBytes, maxFiles: rsMaxArchive, maxTotal: rsMaxArchiveSz}
	e.load()
	return e
}

func (e *rsEngine) load() {
	if b, err := os.ReadFile(e.path); err == nil {
		var l []rsSchedule
		if json.Unmarshal(b, &l) == nil {
			for i := range l {
				s := l[i]
				if rsSchedRe.MatchString(s.ID) && rsNormalize(&s) == nil && len(e.scheds) < rsMaxSchedules {
					e.scheds[s.ID] = &s
				}
			}
		}
	}
	ents, _ := os.ReadDir(e.dir)
	for _, en := range ents {
		n := en.Name()
		if !strings.HasSuffix(n, ".meta.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(e.dir, n))
		var r rsRun
		if err != nil || json.Unmarshal(b, &r) != nil || !rsRunIDRe.MatchString(r.RunID) {
			continue
		}
		if r.Bytes > 0 {
			r.File = r.RunID + rsExt(r.Format)
			if _, err := os.Stat(filepath.Join(e.dir, r.File)); err != nil {
				continue
			}
		}
		e.runs = append(e.runs, r)
	}
	sort.Slice(e.runs, func(i, j int) bool { return e.runs[i].GeneratedAt.Before(e.runs[j].GeneratedAt) })
}

func rsExt(f string) string {
	switch f {
	case rsFormatJSON:
		return ".json"
	case rsFormatCSV:
		return ".csv"
	}
	return ".md"
}

func rsContentType(f string) string {
	switch f {
	case rsFormatJSON:
		return "application/json"
	case rsFormatCSV:
		return "text/csv; charset=utf-8"
	}
	return "text/markdown; charset=utf-8"
}

func (e *rsEngine) saveLocked() {
	l := make([]rsSchedule, 0, len(e.scheds))
	for _, s := range e.scheds {
		l = append(l, *s)
	}
	sort.Slice(l, func(i, j int) bool { return l[i].ID < l[j].ID })
	_ = os.MkdirAll(filepath.Dir(e.path), 0o700)
	_ = govWriteAtomic(e.path, l)
}

func (e *rsEngine) newID(prefix string) string {
	e.seq++
	return prefix + strconv.FormatInt(e.clock().UnixNano(), 36) + strconv.Itoa(e.seq)
}

// Create stores a new schedule.
func (e *rsEngine) Create(s rsSchedule) (rsSchedule, error) {
	if err := rsNormalize(&s); err != nil {
		return s, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.scheds) >= rsMaxSchedules {
		return s, fmt.Errorf("schedule limit of %d reached", rsMaxSchedules)
	}
	now := e.clock().UTC()
	s.ID, s.CreatedAt, s.NextRun = e.newID("s"), now, rsNext(s, now)
	s.LastRun, s.LastStatus, s.LastRunID = time.Time{}, "", ""
	e.scheds[s.ID] = &s
	e.saveLocked()
	return s, nil
}

func (e *rsEngine) Update(id string, s rsSchedule) (rsSchedule, error) {
	if err := rsNormalize(&s); err != nil {
		return s, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.scheds[id]
	if old == nil {
		return s, errRSNoSch
	}
	s.ID, s.CreatedAt, s.LastRun, s.LastStatus, s.LastRunID = old.ID, old.CreatedAt, old.LastRun, old.LastStatus, old.LastRunID
	s.NextRun = rsNext(s, e.clock().UTC())
	e.scheds[id] = &s
	e.pruneLocked()
	e.saveLocked()
	return s, nil
}

// Delete removes a schedule together with its stored reports.
func (e *rsEngine) Delete(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scheds[id] == nil {
		return errRSNoSch
	}
	delete(e.scheds, id)
	keep := e.runs[:0]
	for _, r := range e.runs {
		if r.ScheduleID == id {
			e.removeFilesLocked(r)
			continue
		}
		keep = append(keep, r)
	}
	e.runs = keep
	e.saveLocked()
	return nil
}

func (e *rsEngine) List() []rsSchedule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]rsSchedule, 0, len(e.scheds))
	for _, s := range e.scheds {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (e *rsEngine) Runs(id string) []rsRun {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []rsRun
	for i := len(e.runs) - 1; i >= 0; i-- {
		if e.runs[i].ScheduleID == id {
			out = append(out, e.runs[i])
		}
	}
	return out
}

func (e *rsEngine) Archive(runID string) (rsRun, []byte, error) {
	if !rsRunIDRe.MatchString(runID) {
		return rsRun{}, nil, errors.New("not found")
	}
	e.mu.Lock()
	var r rsRun
	found := false
	for _, x := range e.runs {
		if x.RunID == runID {
			r, found = x, true
		}
	}
	e.mu.Unlock()
	if !found || r.File == "" {
		return r, nil, errors.New("not found")
	}
	b, err := os.ReadFile(filepath.Join(e.dir, r.File))
	return r, b, err
}

// tick runs every enabled schedule that is due. A schedule that is overdue
// (process was down, or the host was busy) runs ONCE and its next run is
// computed from now, so a long outage never produces a backlog. At most
// rsMaxPerTick runs start per tick; the rest stay due for the next tick.
func (e *rsEngine) tick(now time.Time) int {
	e.mu.Lock()
	type due struct {
		id   string
		next time.Time
	}
	var ds []due
	for _, s := range e.scheds {
		if s.Enabled && !s.NextRun.IsZero() && !s.NextRun.After(now) {
			ds = append(ds, due{s.ID, s.NextRun})
		}
	}
	e.mu.Unlock()
	sort.Slice(ds, func(i, j int) bool { return ds[i].next.Before(ds[j].next) })
	n := 0
	for _, d := range ds {
		if n >= rsMaxPerTick {
			break
		}
		trig := "scheduled"
		if now.Sub(d.next) > 2*rsTick {
			trig = "catchup"
		}
		if _, err := e.execute(d.id, trig, now); err == nil {
			n++
		}
	}
	return n
}

// execute renders one schedule. It never overlaps with another run: a single
// slot is shared by all schedules, and a schedule cannot run twice at once.
func (e *rsEngine) execute(id, trigger string, now time.Time) (rsRun, error) {
	e.mu.Lock()
	s := e.scheds[id]
	if s == nil {
		e.mu.Unlock()
		return rsRun{}, errRSNoSch
	}
	if e.running[id] {
		e.mu.Unlock()
		return rsRun{}, errRSBusy
	}
	select {
	case e.sem <- struct{}{}:
	default:
		e.mu.Unlock()
		return rsRun{}, errRSBusy
	}
	e.running[id] = true
	sc := *s
	e.mu.Unlock()
	release := func() {
		e.mu.Lock()
		delete(e.running, id)
		e.mu.Unlock()
		<-e.sem
	}

	type result struct {
		b   []byte
		red bool
		err error
	}
	ch := make(chan result, 1)
	start := time.Now()
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- result{err: fmt.Errorf("render panic: %v", p)}
			}
		}()
		b, red, err := e.render(sc, now)
		ch <- result{b, red, err}
	}()
	run := rsRun{ScheduleID: id, Template: sc.Template, Params: sc.Params, Format: sc.Format, Trigger: trigger, GeneratedAt: now.UTC()}
	var res result
	timer := time.NewTimer(e.timeout)
	select {
	case res = <-ch:
		timer.Stop()
		defer release()
	case <-timer.C:
		res.err = fmt.Errorf("run exceeded %s limit", e.timeout)
		run.Status = "timeout"
		// keep the slot until the render goroutine really finishes: no overlap
		go func() { <-ch; release() }()
	}
	run.DurationMS = time.Since(start).Milliseconds()
	run.Redacted = res.red
	e.mu.Lock()
	defer e.mu.Unlock()
	run.RunID = e.newID("r")
	switch {
	case res.err != nil:
		if run.Status == "" {
			run.Status = "failed"
		}
		run.Error = res.err.Error()
	case len(res.b) > e.maxBytes:
		run.Status, run.Error = "failed", fmt.Sprintf("rendered report is %d bytes, over the %d byte limit; not stored", len(res.b), e.maxBytes)
	default:
		sum := sha256.Sum256(res.b)
		run.Status, run.Bytes, run.SHA256 = "ok", len(res.b), hex.EncodeToString(sum[:])
		run.File = run.RunID + rsExt(run.Format)
		_ = os.MkdirAll(e.dir, 0o700)
		if err := os.WriteFile(filepath.Join(e.dir, run.File), res.b, 0o600); err != nil {
			run.Status, run.Error, run.Bytes, run.SHA256, run.File = "failed", "write failed: "+err.Error(), 0, "", ""
		}
	}
	_ = os.MkdirAll(e.dir, 0o700)
	_ = govWriteAtomic(filepath.Join(e.dir, run.RunID+".meta.json"), run)
	e.runs = append(e.runs, run)
	if cur := e.scheds[id]; cur != nil {
		cur.LastRun, cur.LastStatus, cur.LastRunID = run.GeneratedAt, run.Status, run.RunID
		if trigger != "manual" {
			cur.NextRun = rsNext(*cur, now)
		}
	}
	e.pruneLocked()
	e.saveLocked()
	return run, nil
}

func (e *rsEngine) removeFilesLocked(r rsRun) {
	if r.File != "" {
		_ = os.Remove(filepath.Join(e.dir, r.File))
	}
	_ = os.Remove(filepath.Join(e.dir, r.RunID+".meta.json"))
}

// pruneLocked applies per-schedule retention (newest N runs), then the global
// caps on record count, artefact count and total bytes (oldest dropped first).
func (e *rsEngine) pruneLocked() {
	per := map[string]int{}
	drop := map[string]bool{}
	for i := len(e.runs) - 1; i >= 0; i-- {
		r := e.runs[i]
		per[r.ScheduleID]++
		limit := rsDefaultRetain
		if s := e.scheds[r.ScheduleID]; s != nil {
			limit = s.Retention
		}
		if per[r.ScheduleID] > limit {
			drop[r.RunID] = true
		}
	}
	files, total := 0, int64(0)
	for _, r := range e.runs {
		if !drop[r.RunID] && r.File != "" {
			files++
			total += int64(r.Bytes)
		}
	}
	recs := len(e.runs) - len(drop)
	for _, r := range e.runs { // oldest first
		if drop[r.RunID] {
			continue
		}
		if files <= e.maxFiles && total <= e.maxTotal && recs <= rsMaxRunRecords {
			break
		}
		drop[r.RunID] = true
		recs--
		if r.File != "" {
			files--
			total -= int64(r.Bytes)
		}
	}
	if len(drop) == 0 {
		return
	}
	keep := e.runs[:0]
	for _, r := range e.runs {
		if drop[r.RunID] {
			e.removeFilesLocked(r)
			continue
		}
		keep = append(keep, r)
	}
	e.runs = keep
}

// Start runs one catch-up tick immediately, then ticks every rsTick on a
// single goroutine. Stop ends it.
func (e *rsEngine) Start() {
	go func() {
		e.tick(e.clock().UTC())
		t := time.NewTicker(rsTick)
		defer t.Stop()
		for {
			select {
			case <-e.stop:
				return
			case <-t.C:
				e.tick(e.clock().UTC())
			}
		}
	}()
}

// Stop ends the scheduler goroutine.
func (e *rsEngine) Stop() { e.stopOnce.Do(func() { close(e.stop) }) }

// ---------------- rendering ----------------

type rsSectionOut struct {
	Heading string   `json:"heading"`
	Source  string   `json:"source"`
	Lines   []string `json:"lines"`
}

// rsHostTemplates lists templates whose output can contain host names (a
// "hosts" section lists the most active hosts).
func rsHostTemplates() []string {
	var out []string
	for _, t := range ReportTemplates() {
		for _, s := range t.Sections {
			if s.Source == "hosts" {
				out = append(out, t.ID)
				break
			}
		}
	}
	return out
}

func rsFilterData(d *reportData, p map[string]string, now time.Time) {
	since, minSev := 0, -1
	if v := p["since_hours"]; v != "" {
		since, _ = strconv.Atoi(v)
	}
	if v := p["min_severity"]; v != "" {
		minSev = rsSeverityRank[strings.ToLower(v)]
	}
	if since == 0 && minSev < 0 {
		return
	}
	cut := now.Add(-time.Duration(since) * time.Hour)
	out := make([]Finding, 0, len(d.findings))
	for _, f := range d.findings {
		if since > 0 && f.Time.Before(cut) {
			continue
		}
		if minSev >= 0 && rsSeverityRank[strings.ToLower(f.Severity)] < minSev {
			continue
		}
		out = append(out, f)
	}
	d.findings = out
}

func rsCSVSafe(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r") {
		return "'" + s
	}
	return s
}

// rsRenderTemplate renders t. Redaction mirrors the findings export: when the
// data-governance toggle is on, findings pass through govMaybeRedact and every
// section body through govRedact before formatting.
func rsRenderTemplate(t ReportTemplate, s rsSchedule, now time.Time, store *Store, registry *CredentialRegistry) ([]byte, bool, error) {
	d := gatherReportData(store, registry)
	redact := store != nil && govRedactionEnabled(store)
	if redact {
		d.findings = govMaybeRedact(store, d.findings)
	}
	rsFilterData(&d, s.Params, now)
	var secs []rsSectionOut
	for _, sc := range t.Sections {
		body := renderSection(sc, d)
		if redact {
			body = govRedact(body)
		}
		secs = append(secs, rsSectionOut{sc.Heading, sc.Source, strings.Split(body, "\n")})
	}
	gen := now.UTC().Format(time.RFC3339)
	switch s.Format {
	case rsFormatJSON:
		b, err := json.MarshalIndent(map[string]any{"template": t.ID, "title": t.Title, "audience": t.Audience, "params": s.Params,
			"generated_at": gen, "redacted": redact, "sections": secs, "note": "Kavach is observation-only; this report requests nothing automatically."}, "", "  ")
		return b, redact, err
	case rsFormatCSV:
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		_ = w.Write([]string{"section", "item", "value"})
		for _, so := range secs {
			if so.Source == "manual" {
				continue
			}
			for _, l := range so.Lines {
				l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
				if l == "" || strings.HasPrefix(l, "_") {
					continue
				}
				k, v := l, ""
				if i := strings.LastIndex(l, ": "); i >= 0 {
					k, v = l[:i], l[i+2:]
				}
				_ = w.Write([]string{rsCSVSafe(so.Heading), rsCSVSafe(k), rsCSVSafe(v)})
			}
		}
		w.Flush()
		return []byte(sb.String()), redact, w.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\nAudience: %s  \nGenerated: %s\n", t.Title, t.Audience, gen)
	if len(s.Params) > 0 {
		keys := make([]string, 0, len(s.Params))
		for k := range s.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("Parameters:")
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", k, s.Params[k])
		}
		b.WriteString("  \n")
	}
	fmt.Fprintf(&b, "\n%s\n\n", t.Summary)
	for _, so := range secs {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", so.Heading, strings.Join(so.Lines, "\n"))
	}
	b.WriteString("_Kavach is observation-only; this report records what was seen and requests nothing automatically._\n")
	return []byte(b.String()), redact, nil
}
