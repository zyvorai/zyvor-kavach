// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SOC operations analytics. Observation only: nothing here changes workflow
// state or touches a host; it reads findings, analyst transitions and events.

// Transition is one append-only analyst status change.
type Transition struct {
	FindingID string    `json:"finding_id"`
	Source    string    `json:"source"` // "detection" or "incident"
	Status    string    `json:"status"`
	Actor     string    `json:"actor,omitempty"`
	Time      time.Time `json:"time"`
}

var socLog = struct {
	mu   sync.Mutex
	path string
	list []Transition
}{}

// recordDetectionTransition is the hook called by the detection triage
// handler. Detection state keeps no timestamps, so this log supplies them.
func recordDetectionTransition(detectionID, status string) {
	recordTransitionAt(Transition{
		FindingID: strings.TrimPrefix(detectionID, "det-"), Source: "detection",
		Status: status, Time: time.Now().UTC(),
	})
}

func recordTransitionAt(t Transition) {
	socLog.mu.Lock()
	defer socLog.mu.Unlock()
	socLog.list = append(socLog.list, t)
	if socLog.path != "" {
		_ = appendRecord(socLog.path, t)
	}
}

func loadSOCLog(path string) {
	socLog.mu.Lock()
	defer socLog.mu.Unlock()
	socLog.path = path
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	have := map[Transition]bool{}
	for _, t := range socLog.list {
		have[t] = true
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var t Transition
		if json.Unmarshal(sc.Bytes(), &t) == nil && !have[t] {
			socLog.list = append(socLog.list, t)
		}
	}
}

// allTransitions merges the detection log with the incident ledger history.
func allTransitions(store *Store) map[string][]Transition {
	out := map[string][]Transition{}
	socLog.mu.Lock()
	for _, t := range socLog.list {
		out[t.FindingID] = append(out[t.FindingID], t)
	}
	socLog.mu.Unlock()
	if f, err := os.Open(store.path + ".incidents"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var a IncidentAction
			if json.Unmarshal(sc.Bytes(), &a) == nil && a.FindingID != "" {
				out[a.FindingID] = append(out[a.FindingID], Transition{
					FindingID: a.FindingID, Source: "incident", Status: a.Status, Actor: a.Actor, Time: a.Time})
			}
		}
		f.Close()
	}
	for k := range out {
		sort.SliceStable(out[k], func(i, j int) bool { return out[k][i].Time.Before(out[k][j].Time) })
	}
	return out
}

func terminalStatus(s string) bool {
	switch s {
	case "closed", "true_positive", "false_positive", "resolved":
		return true
	}
	return false
}

var socSeverities = []string{"critical", "high", "medium", "low"}

var defaultAckMin = map[string]float64{"critical": 15, "high": 60, "medium": 240, "low": 1440}
var defaultResolveHours = map[string]float64{"critical": 4, "high": 24, "medium": 72, "low": 168}

// slaTargets parses an env var holding either one number (all severities) or
// "critical=15,high=60" pairs layered over the defaults.
func slaTargets(env string, def map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range def {
		out[k] = v
	}
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return out
	}
	if n, err := strconv.ParseFloat(raw, 64); err == nil && n > 0 {
		for k := range out {
			out[k] = n
		}
		return out
	}
	for _, kv := range strings.Split(raw, ",") {
		p := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(p) != 2 {
			continue
		}
		if n, err := strconv.ParseFloat(strings.TrimSpace(p[1]), 64); err == nil && n > 0 {
			out[strings.ToLower(strings.TrimSpace(p[0]))] = n
		}
	}
	return out
}

type socTicket struct {
	F         Finding
	Sev       string
	Acked     *time.Time
	Resolved  *time.Time
	State     string
	Open      bool
	FPositive bool
}

func buildTickets(findings []Finding, tr map[string][]Transition) []socTicket {
	out := make([]socTicket, 0, len(findings))
	for _, f := range findings {
		t := socTicket{F: f, Sev: strings.ToLower(f.Severity), State: "new", Open: true}
		for _, x := range tr[f.ID] {
			x := x
			if t.Acked == nil && x.Status != "new" && x.Status != "open" {
				tm := x.Time
				t.Acked = &tm
			}
			if t.Resolved == nil && terminalStatus(x.Status) {
				tm := x.Time
				t.Resolved = &tm
			}
			t.State = x.Status
		}
		if terminalStatus(t.State) || t.State == "ignored" {
			t.Open = false
		}
		t.FPositive = t.State == "false_positive"
		out = append(out, t)
	}
	return out
}

func queryInt(r *http.Request, key string, def, max int) int {
	if n, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil && n > 0 {
		if n > max {
			return max
		}
		return n
	}
	return def
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func ageBucket(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "lt_1h"
	case d < 24*time.Hour:
		return "1h_24h"
	case d < 7*24*time.Hour:
		return "1d_7d"
	}
	return "gt_7d"
}

func avgMinutes(xs []float64) *float64 {
	if len(xs) == 0 {
		return nil
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	v := round1(s / float64(len(xs)))
	return &v
}

type socBreach struct {
	Ack     int `json:"ack"`
	Resolve int `json:"resolve"`
}

type socRuleRow struct {
	Rule              string  `json:"rule"`
	Total             int     `json:"total"`
	FalsePositives    int     `json:"false_positives"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
}

// SOCMetrics computes the analytics document for tickets created since now-days.
func SOCMetrics(findings []Finding, tr map[string][]Transition, now time.Time, days int) map[string]any {
	cut := now.Add(-time.Duration(days) * 24 * time.Hour)
	var in []Finding
	for _, f := range findings {
		if !f.Time.Before(cut) {
			in = append(in, f)
		}
	}
	tickets := buildTickets(in, tr)
	ackT := slaTargets("KAVACH_SLA_ACK_MIN", defaultAckMin)
	resT := slaTargets("KAVACH_SLA_RESOLVE_HOURS", defaultResolveHours)

	var ack, res []float64
	backlog := map[string]map[string]int{}
	newBuckets := func() map[string]int { return map[string]int{"lt_1h": 0, "1h_24h": 0, "1d_7d": 0, "gt_7d": 0} }
	for _, s := range socSeverities {
		backlog[s] = newBuckets()
	}
	breaches := map[string]*socBreach{}
	type ruleAcc struct{ total, fp int }
	rules := map[string]*ruleAcc{}
	openTotal := 0
	for _, t := range tickets {
		ra := rules[t.F.Rule]
		if ra == nil {
			ra = &ruleAcc{}
			rules[t.F.Rule] = ra
		}
		ra.total++
		if t.FPositive {
			ra.fp++
		}
		if t.Acked != nil {
			ack = append(ack, t.Acked.Sub(t.F.Time).Minutes())
		}
		if t.Resolved != nil {
			res = append(res, t.Resolved.Sub(t.F.Time).Minutes())
		}
		if t.Open {
			openTotal++
			if backlog[t.Sev] == nil {
				backlog[t.Sev] = newBuckets()
			}
			backlog[t.Sev][ageBucket(now.Sub(t.F.Time))]++
		}
		b := breaches[t.Sev]
		if b == nil {
			b = &socBreach{}
			breaches[t.Sev] = b
		}
		if at, ok := ackT[t.Sev]; ok {
			end := now
			if t.Acked != nil {
				end = *t.Acked
			}
			if end.Sub(t.F.Time).Minutes() > at {
				b.Ack++
			}
		}
		if rt, ok := resT[t.Sev]; ok {
			end := now
			if t.Resolved != nil {
				end = *t.Resolved
			}
			// Tickets dismissed as ignored are out of resolve-SLA scope.
			if t.State != "ignored" && end.Sub(t.F.Time).Hours() > rt {
				b.Resolve++
			}
		}
	}
	rows := make([]socRuleRow, 0, len(rules))
	for r, a := range rules {
		rows = append(rows, socRuleRow{r, a.total, a.fp, round1(float64(a.fp) * 100 / float64(a.total))})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total != rows[j].Total {
			return rows[i].Total > rows[j].Total
		}
		return rows[i].Rule < rows[j].Rule
	})
	noisy := rows
	if len(noisy) > 10 {
		noisy = noisy[:10]
	}
	fpRows := append([]socRuleRow(nil), rows...)
	sort.Slice(fpRows, func(i, j int) bool {
		if fpRows[i].FalsePositiveRate != fpRows[j].FalsePositiveRate {
			return fpRows[i].FalsePositiveRate > fpRows[j].FalsePositiveRate
		}
		return fpRows[i].Rule < fpRows[j].Rule
	})
	return map[string]any{
		"days":                 days,
		"generated_at":         now.UTC(),
		"tickets":              len(tickets),
		"mtta_minutes":         avgMinutes(ack),
		"mttr_minutes":         avgMinutes(res),
		"acknowledged":         len(ack),
		"resolved":             len(res),
		"open_backlog":         openTotal,
		"backlog_by_severity":  backlog,
		"false_positive_rules": fpRows,
		"top_noisy_rules":      noisy,
		"sla_breaches":         breaches,
		"sla_targets":          map[string]any{"ack_minutes": ackT, "resolve_hours": resT},
	}
}

// ---- storyline ----

var tacticOrder = []string{
	"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
	"Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
	"Collection", "Command and Control", "Exfiltration", "Impact",
}

func tacticPhase(t string) int {
	for i, x := range tacticOrder {
		if x == t {
			return i + 1
		}
	}
	return 0
}

const burstGap = 15 * time.Minute

type StorylineStep struct {
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"` // finding|process|network|file
	Burst        int       `json:"burst"`
	GapSeconds   int       `json:"gap_seconds,omitempty"`
	Tactic       string    `json:"tactic"`
	TacticSource string    `json:"tactic_source"` // rule|pid-correlation|default
	Phase        int       `json:"phase"`
	Technique    string    `json:"technique_id,omitempty"`
	Severity     string    `json:"severity,omitempty"`
	Rule         string    `json:"rule,omitempty"`
	PID          int       `json:"pid,omitempty"`
	Summary      string    `json:"summary"`
}

type storyBurst struct {
	ID    int       `json:"id"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Steps int       `json:"steps"`
}

// BuildStoryline merges one host's findings and events into a kill-chain timeline.
func BuildStoryline(store *Store, host string, since time.Time) map[string]any {
	steps := []StorylineStep{}
	pidTactic := map[int]StorylineStep{}
	for _, f := range store.List() {
		if !strings.EqualFold(f.Host, host) || f.Time.Before(since) {
			continue
		}
		d := MapDetection(f)
		s := StorylineStep{Time: f.Time, Kind: "finding", Tactic: d.Tactic, TacticSource: "rule", Phase: tacticPhase(d.Tactic),
			Technique: d.TechniqueID, Severity: f.Severity, Rule: f.Rule, PID: f.PID, Summary: f.Description}
		steps = append(steps, s)
		if f.PID != 0 {
			pidTactic[f.PID] = s
		}
	}
	store.mu.Lock()
	procs := append([]Event(nil), store.recentEvents...)
	nets := append([]NetworkEvent(nil), store.networkEvents...)
	files := append([]FileEvent(nil), store.fileEvents...)
	store.mu.Unlock()
	tag := func(s StorylineStep, def string) StorylineStep {
		if p, ok := pidTactic[s.PID]; ok && s.PID != 0 {
			s.Tactic, s.TacticSource, s.Technique = p.Tactic, "pid-correlation", p.Technique
		} else {
			s.Tactic, s.TacticSource = def, "default"
		}
		s.Phase = tacticPhase(s.Tactic)
		return s
	}
	for _, e := range procs {
		if strings.EqualFold(e.Host, host) && !e.Time.Before(since) {
			steps = append(steps, tag(StorylineStep{Time: e.Time, Kind: "process", PID: e.PID, Summary: e.Command}, "Execution"))
		}
	}
	for _, n := range nets {
		if strings.EqualFold(n.Host, host) && !n.Time.Before(since) {
			sum := "connection to " + n.Destination
			if n.Verdict != "" {
				sum += " (" + n.Verdict + ")"
			}
			steps = append(steps, tag(StorylineStep{Time: n.Time, Kind: "network", PID: n.PID, Summary: sum}, "Command and Control"))
		}
	}
	for _, e := range files {
		if strings.EqualFold(e.Host, host) && !e.Time.Before(since) {
			steps = append(steps, tag(StorylineStep{Time: e.Time, Kind: "file", PID: e.PID, Summary: e.Operation + " " + e.Path}, "Collection"))
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Time.Before(steps[j].Time) })
	bursts := []storyBurst{}
	seen := map[string]bool{}
	tactics := []string{}
	for i := range steps {
		if i == 0 || steps[i].Time.Sub(steps[i-1].Time) > burstGap {
			if i > 0 {
				steps[i].GapSeconds = int(steps[i].Time.Sub(steps[i-1].Time).Seconds())
			}
			bursts = append(bursts, storyBurst{ID: len(bursts) + 1, Start: steps[i].Time})
		}
		b := &bursts[len(bursts)-1]
		b.End, b.Steps = steps[i].Time, b.Steps+1
		steps[i].Burst = b.ID
		if !seen[steps[i].Tactic] {
			seen[steps[i].Tactic] = true
			tactics = append(tactics, steps[i].Tactic)
		}
	}
	sort.SliceStable(tactics, func(i, j int) bool { return tacticPhase(tactics[i]) < tacticPhase(tactics[j]) })
	return map[string]any{"host": host, "since": since.UTC(), "steps": steps, "bursts": bursts, "tactics": tactics,
		"burst_gap_minutes": int(burstGap.Minutes())}
}

// ---- shift report ----

type shiftCritical struct {
	FindingID string    `json:"finding_id"`
	Host      string    `json:"host"`
	Rule      string    `json:"rule"`
	Time      time.Time `json:"time"`
	State     string    `json:"state"`
}

// BuildShiftReport produces a deterministic, template-based handoff summary.
func BuildShiftReport(store *Store, tr map[string][]Transition, now time.Time, hours int) map[string]any {
	since := now.Add(-time.Duration(hours) * time.Hour)
	findings := store.List()
	tickets := buildTickets(findings, tr)
	newN, openN, closedN := 0, 0, 0
	crits := []shiftCritical{}
	for _, t := range tickets {
		if !t.F.Time.Before(since) {
			newN++
		}
		if t.Open {
			openN++
			if t.Sev == "critical" {
				crits = append(crits, shiftCritical{t.F.ID, t.F.Host, t.F.Rule, t.F.Time, t.State})
			}
		}
		if t.Resolved != nil && !t.Resolved.Before(since) {
			closedN++
		}
	}
	sort.Slice(crits, func(i, j int) bool { return crits[i].Time.Before(crits[j].Time) })
	if len(crits) > 20 {
		crits = crits[:20]
	}
	risks := ComputeHostRisks(findings, now)
	if len(risks) > 5 {
		risks = risks[:5]
	}
	qs := []string{}
	if len(crits) > 0 {
		qs = append(qs, "Who owns the "+strconv.Itoa(len(crits))+" unresolved critical finding(s), and has the owner acknowledged them?")
	}
	if len(risks) > 0 {
		qs = append(qs, "Why is "+risks[0].Host+" the highest-risk host (risk "+strconv.Itoa(risks[0].Risk)+"), and is its activity expected?")
		if len(risks[0].TopRules) > 0 {
			qs = append(qs, "Is rule '"+risks[0].TopRules[0].Rule+"' on "+risks[0].Host+" a true positive or tuning noise?")
		}
	}
	if openN > 0 && closedN == 0 {
		qs = append(qs, "Nothing was closed this shift; is the backlog of "+strconv.Itoa(openN)+" open findings blocked on anyone?")
	}
	if newN > 0 {
		qs = append(qs, "Do the "+strconv.Itoa(newN)+" new finding(s) share a host, rule or tactic that suggests one campaign?")
	}
	if len(qs) == 0 {
		qs = append(qs, "No open work this shift; are all expected telemetry sources still reporting?")
	}
	return map[string]any{
		"hours": hours, "generated_at": now.UTC(), "since": since.UTC(),
		"counts":                map[string]int{"new": newN, "open": openN, "closed": closedN},
		"highest_risk_hosts":    risks,
		"unresolved_criticals":  crits,
		"recommended_questions": qs,
	}
}

func RegisterSOCOps(mux *http.ServeMux, token string, store *Store) {
	loadSOCLog(store.path + ".transitions")
	mux.HandleFunc("GET /v1/soc/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, SOCMetrics(store.List(), allTransitions(store), time.Now().UTC(), queryInt(r, "days", 30, 365)))
	})
	mux.HandleFunc("GET /v1/storyline/host", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" || len(host) > 253 {
			http.Error(w, "host required", http.StatusBadRequest)
			return
		}
		hours := queryInt(r, "hours", 24, 720)
		writeJSON(w, BuildStoryline(store, host, time.Now().UTC().Add(-time.Duration(hours)*time.Hour)))
	})
	mux.HandleFunc("GET /v1/soc/shift-report", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, BuildShiftReport(store, allTransitions(store), time.Now().UTC(), queryInt(r, "hours", 12, 168)))
	})
}
