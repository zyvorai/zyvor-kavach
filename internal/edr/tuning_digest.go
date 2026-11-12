// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// Rule-tuning advisor and scheduled digests. Observation only: suggestions are
// advisory and a human must apply them; digests are notifications carrying
// aggregates and ids, never evidence, command lines or tokens.

const (
	tuneMinHits       = 10   // a rule is "noisy" at this many hits in the window
	tuneMinFPHits     = 3    // ... or this many false positives
	tuneFPRate        = 50.0 // ... with at least this false-positive rate (%)
	tuneMinShare      = 20.0 // a host must drive this % of a rule to be proposed
	tuneMinPattern    = 6    // shortest allowed exclusion pattern
	tuneMaxHistory    = 500
	tuneMaxDigests    = 20
	tuneMaxDeliveries = 100
	tuneTopN          = 5
)

// ---- advisor ----

type TuningCount struct {
	Name    string  `json:"name"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

type TuningProposal struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule"`
}

type TuningSuggestion struct {
	Rule              string          `json:"rule"`
	Severity          string          `json:"severity"`
	Hits              int             `json:"hits"`
	FalsePositives    int             `json:"false_positives"`
	FalsePositiveRate float64         `json:"false_positive_rate"`
	TopHosts          []TuningCount   `json:"top_hosts"`
	TopExecutables    []TuningCount   `json:"top_executables"`
	TopCommands       []TuningCount   `json:"top_command_prefixes"`
	Action            string          `json:"action"` // propose_exclusion | review_rule
	Proposal          *TuningProposal `json:"proposed_exclusion,omitempty"`
	RemovesHits       int             `json:"would_remove_hits"`
	RemovesPercent    float64         `json:"would_remove_percent"`
	CollateralHits    int             `json:"collateral_hits"`
	Risk              string          `json:"risk"` // low|medium|high|blocked
	RiskNotes         []string        `json:"risk_notes"`
}

func tuneBlob(f Finding) string {
	return strings.ToLower(f.Rule + " " + f.Host + " " + f.Description + " " + f.Evidence.Command)
}

// tunePatternOK rejects broad or wildcard patterns: it must be a rule + host
// style pattern (contains a space) with no wildcard characters.
func tunePatternOK(p string) bool {
	p = strings.TrimSpace(p)
	return len(p) >= tuneMinPattern && len(p) <= 256 && !strings.ContainsAny(p, "*?%") && strings.Contains(p, " ")
}

func tuneTop(m map[string]int, total int) []TuningCount {
	out := make([]TuningCount, 0, len(m))
	for k, v := range m {
		out = append(out, TuningCount{k, v, round1(float64(v) * 100 / float64(total))})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > tuneTopN {
		out = out[:tuneTopN]
	}
	return out
}

// tuneCmdPrefix keeps only the program name of a command line (no arguments).
func tuneCmdPrefix(cmd string) string {
	fs := strings.Fields(cmd)
	if len(fs) == 0 {
		return ""
	}
	s := path.Base(fs[0])
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// tuneSimulate counts window findings a pattern would hide: same-rule hits and
// collateral hits on other rules, plus whether any matched finding is critical.
func tuneSimulate(window []Finding, pattern, rule string) (same, other int, critical bool) {
	p := strings.ToLower(pattern)
	for _, f := range window {
		if !strings.Contains(tuneBlob(f), p) {
			continue
		}
		if f.Rule == rule {
			same++
		} else {
			other++
		}
		if severityRank(f.Severity) == 4 {
			critical = true
		}
	}
	return
}

// BuildTuningSuggestions is deterministic: same stores and clock, same output.
func BuildTuningSuggestions(findings []Finding, tr map[string][]Transition, now time.Time, days int) []TuningSuggestion {
	cut := now.Add(-time.Duration(days) * 24 * time.Hour)
	var window []Finding
	for _, f := range findings {
		if !f.Time.Before(cut) {
			window = append(window, f)
		}
	}
	fp := map[string]bool{}
	for _, t := range buildTickets(window, tr) {
		if t.FPositive {
			fp[t.F.ID] = true
		}
	}
	byRule := map[string][]Finding{}
	for _, f := range window {
		byRule[f.Rule] = append(byRule[f.Rule], f)
	}
	out := []TuningSuggestion{}
	for rule, fs := range byRule {
		nfp := 0
		hosts, exes, cmds := map[string]int{}, map[string]int{}, map[string]int{}
		maxSev := 0
		sev := ""
		for _, f := range fs {
			if fp[f.ID] {
				nfp++
			}
			hosts[f.Host]++
			if f.Evidence.Executable != "" {
				exes[path.Base(f.Evidence.Executable)]++
			}
			if c := tuneCmdPrefix(f.Evidence.Command); c != "" {
				cmds[c]++
			}
			if r := severityRank(f.Severity); r > maxSev {
				maxSev, sev = r, strings.ToLower(f.Severity)
			}
		}
		rate := round1(float64(nfp) * 100 / float64(len(fs)))
		if len(fs) < tuneMinHits && !(nfp >= tuneMinFPHits && rate >= tuneFPRate) {
			continue
		}
		s := TuningSuggestion{Rule: rule, Severity: sev, Hits: len(fs), FalsePositives: nfp, FalsePositiveRate: rate,
			TopHosts: tuneTop(hosts, len(fs)), TopExecutables: tuneTop(exes, len(fs)), TopCommands: tuneTop(cmds, len(fs)),
			Action: "review_rule", Risk: "low", RiskNotes: []string{}}
		if maxSev == 4 {
			s.Risk = "blocked"
			s.RiskNotes = append(s.RiskNotes, "critical severity rules are never suppressed; tune the rule logic or threshold instead")
			out = append(out, s)
			continue
		}
		if maxSev == 3 {
			s.Risk = "high"
			s.RiskNotes = append(s.RiskNotes, "high severity rule: suppression can hide real attacks on the excluded host")
		} else if maxSev == 2 {
			s.Risk = "medium"
		}
		top := s.TopHosts[0]
		pat := rule + " " + top.Name
		if top.Percent < tuneMinShare || top.Name == "" || !tunePatternOK(pat) {
			s.RiskNotes = append(s.RiskNotes, "no single host drives enough volume for a narrow exclusion; review the rule itself")
			out = append(out, s)
			continue
		}
		same, other, crit := tuneSimulate(window, pat, rule)
		if crit {
			s.Risk = "blocked"
			s.RiskNotes = append(s.RiskNotes, "pattern would also hide critical findings; not proposed")
			out = append(out, s)
			continue
		}
		s.Action = "propose_exclusion"
		s.Proposal = &TuningProposal{Pattern: pat, Rule: rule, Reason: "tuning: " + rule + " noise from host " + top.Name}
		s.RemovesHits, s.CollateralHits = same, other
		s.RemovesPercent = round1(float64(same) * 100 / float64(len(fs)))
		s.RiskNotes = append(s.RiskNotes, "scoped to one rule and one host (no wildcards); exclusions match by substring")
		if other > 0 {
			s.Risk = "high"
			s.RiskNotes = append(s.RiskNotes, "pattern also matches findings of other rules; review before applying")
		}
		if nfp == 0 {
			s.RiskNotes = append(s.RiskNotes, "no analyst false-positive verdicts yet; volume alone drives this suggestion")
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// TuningRecord is one human-applied exclusion with who/when.
type TuningRecord struct {
	ID          string     `json:"id"`
	ExclusionID string     `json:"exclusion_id"`
	Rule        string     `json:"rule"`
	Pattern     string     `json:"pattern"`
	Reason      string     `json:"reason"`
	AppliedBy   string     `json:"applied_by"`
	AppliedAt   time.Time  `json:"applied_at"`
	RevertedBy  string     `json:"reverted_by,omitempty"`
	RevertedAt  *time.Time `json:"reverted_at,omitempty"`
	Status      string     `json:"status"` // active | reverted
}

// ---- digests ----

type Digest struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Schedule   string    `json:"schedule"` // daily | weekly (Mondays)
	Hour       int       `json:"hour_utc"`
	Content    string    `json:"content"` // shift-report | soc-metrics | top-risks
	Type       string    `json:"type"`    // webhook | slack
	URL        string    `json:"url,omitempty"`
	Created    time.Time `json:"created"`
	LastRun    time.Time `json:"last_run,omitempty"`
	LastPeriod string    `json:"last_period,omitempty"`
}

type DigestDelivery struct {
	Time     time.Time `json:"time"`
	DigestID string    `json:"digest_id"`
	Period   string    `json:"period"`
	Trigger  string    `json:"trigger"` // schedule | manual
	Type     string    `json:"type"`
	Host     string    `json:"destination_host"`
	Status   string    `json:"status"`
	Attempts int       `json:"attempts"`
	Code     int       `json:"http_status,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type tuneState struct {
	Digests []Digest       `json:"digests"`
	History []TuningRecord `json:"history"`
}

type tuneService struct {
	store *Store
	disp  *Dispatcher
	path  string
	now   func() time.Time

	mu         sync.Mutex
	st         tuneState
	deliveries []DigestDelivery
}

func tunePeriod(d Digest, now time.Time) string {
	now = now.UTC()
	if d.Schedule == "weekly" {
		y, w := now.ISOWeek()
		return fmt.Sprintf("%d-W%02d", y, w)
	}
	return now.Format("2006-01-02")
}

// tuneDue reports whether a digest should fire now and for which period.
func tuneDue(d Digest, now time.Time) (string, bool) {
	now = now.UTC()
	if now.Hour() < d.Hour {
		return "", false
	}
	if d.Schedule == "weekly" && now.Weekday() != time.Monday {
		return "", false
	}
	p := tunePeriod(d, now)
	return p, p != d.LastPeriod
}

func newTuneService(store *Store, disp *Dispatcher) *tuneService {
	s := &tuneService{store: store, disp: disp, path: store.path + ".tuning.json", now: func() time.Time { return time.Now().UTC() }}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.st)
	}
	// Exclusions live in memory; re-apply active tuning exclusions after restart.
	worldMu.Lock()
	for _, h := range s.st.History {
		if h.Status == "active" && !tuneHasExclusion(h.ExclusionID) {
			exclusions = append(exclusions, map[string]any{"id": h.ExclusionID, "pattern": h.Pattern, "reason": h.Reason, "source": "tuning"})
		}
	}
	worldMu.Unlock()
	return s
}

func tuneHasExclusion(id string) bool { // caller holds worldMu
	for _, e := range exclusions {
		if e["id"] == id {
			return true
		}
	}
	return false
}

func (s *tuneService) saveLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func tuneID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// content builds an aggregates-only payload (ids, counts, host names, rule names).
func (s *tuneService) content(kind string, now time.Time) map[string]any {
	tr := allTransitions(s.store)
	switch kind {
	case "soc-metrics":
		m := SOCMetrics(s.store.List(), tr, now, 7)
		return map[string]any{"days": m["days"], "tickets": m["tickets"], "mtta_minutes": m["mtta_minutes"],
			"mttr_minutes": m["mttr_minutes"], "open_backlog": m["open_backlog"], "sla_breaches": m["sla_breaches"]}
	case "top-risks":
		return map[string]any{"hosts": tuneRiskRows(s.store.List(), now, 10)}
	}
	r := BuildShiftReport(s.store, tr, now, 12)
	return map[string]any{"hours": r["hours"], "counts": r["counts"],
		"highest_risk_hosts": tuneRiskRows(s.store.List(), now, 5), "unresolved_critical_ids": r["unresolved_criticals"]}
}

func tuneRiskRows(findings []Finding, now time.Time, n int) []map[string]any {
	rs := ComputeHostRisks(findings, now)
	if len(rs) > n {
		rs = rs[:n]
	}
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		out = append(out, map[string]any{"host": r.Host, "rank": r.Rank, "risk": r.Risk, "band": r.Band, "findings": r.Findings})
	}
	return out
}

func (s *tuneService) payload(d Digest, period string, now time.Time) []byte {
	if d.Type == "slack" {
		b, _ := json.Marshal(map[string]string{"text": "[Kavach digest] " + d.Name + " (" + d.Content + ", " + period + ")"})
		return b
	}
	b, _ := json.Marshal(map[string]any{"event": "digest", "digest_id": d.ID, "name": d.Name, "content": d.Content,
		"period": period, "generated_at": now.UTC(), "data": s.content(d.Content, now)})
	return b
}

func (s *tuneService) send(ctx context.Context, d Digest, period, trigger string) DigestDelivery {
	now := s.now()
	rec := DigestDelivery{Time: now, DigestID: d.ID, Period: period, Trigger: trigger, Type: d.Type}
	u, err := validateAlertURL(d.URL)
	if err != nil {
		rec.Status, rec.Error = "failed", err.Error()
		s.record(rec)
		return rec
	}
	rec.Host = u.Host
	body := s.payload(d, period, now)
	wait := s.disp.Backoff
	for i := 1; i <= deliveryTries; i++ {
		rec.Attempts = i
		code, err := s.disp.post(ctx, u, d.Type, body)
		rec.Code = code
		if err == nil {
			rec.Status, rec.Error = "delivered", ""
			s.record(rec)
			return rec
		}
		rec.Error = err.Error()
		if i == deliveryTries {
			break
		}
		select {
		case <-ctx.Done():
			rec.Status = "failed"
			s.record(rec)
			return rec
		case <-time.After(wait):
		}
		wait *= 2
	}
	rec.Status = "failed"
	s.record(rec)
	return rec
}

func (s *tuneService) record(x DigestDelivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, x)
	if len(s.deliveries) > tuneMaxDeliveries {
		s.deliveries = s.deliveries[len(s.deliveries)-tuneMaxDeliveries:]
	}
}

// tick fires every due digest at most once per period. The period is persisted
// before sending, so a crash or restart never double-sends (at-most-once).
func (s *tuneService) tick(ctx context.Context) {
	now := s.now()
	type job struct {
		d      Digest
		period string
	}
	var jobs []job
	s.mu.Lock()
	for i := range s.st.Digests {
		d := &s.st.Digests[i]
		if p, ok := tuneDue(*d, now); ok {
			d.LastPeriod, d.LastRun = p, now
			jobs = append(jobs, job{*d, p})
		}
	}
	if len(jobs) > 0 {
		_ = s.saveLocked()
	}
	s.mu.Unlock()
	for _, j := range jobs {
		s.send(ctx, j.d, j.period, "schedule")
	}
}

func (s *tuneService) start(ctx context.Context, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.tick(ctx)
			}
		}
	}()
}

func tuneRedact(d Digest) Digest {
	if u, err := url.Parse(d.URL); err == nil && u.Host != "" {
		d.URL = u.Scheme + "://" + u.Host + "/..."
	} else {
		d.URL = ""
	}
	return d
}

func tuneActor(admin bool) string {
	if admin {
		return "admin-token"
	}
	return "session"
}

// RegisterTuningDigest wires the tuning advisor and digest routes and starts the scheduler.
func RegisterTuningDigest(mux *http.ServeMux, token string, store *Store, disp *Dispatcher) {
	s := newTuneService(store, disp)
	s.start(context.Background(), time.Minute)
	s.routes(mux, token)
}

func (s *tuneService) routes(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/tuning/suggestions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		days := queryInt(r, "days", 14, 90)
		writeJSON(w, map[string]any{"days": days, "advisory_only": true,
			"suggestions": BuildTuningSuggestions(s.store.List(), allTransitions(s.store), s.now(), days)})
	})
	mux.HandleFunc("GET /v1/tuning/history", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		h := append([]TuningRecord{}, s.st.History...)
		s.mu.Unlock()
		writeJSON(w, map[string]any{"history": h})
	})
	mux.HandleFunc("POST /v1/tuning/apply", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		var in TuningProposal
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		in.Pattern, in.Rule = strings.TrimSpace(in.Pattern), strings.TrimSpace(in.Rule)
		if in.Rule == "" || !tunePatternOK(in.Pattern) || len(in.Reason) > 256 {
			http.Error(w, "rule and a specific pattern (rule + host, no wildcards) required", 400)
			return
		}
		if !strings.Contains(strings.ToLower(in.Pattern), strings.ToLower(in.Rule)) {
			http.Error(w, "pattern must contain the rule name", 400)
			return
		}
		all := s.store.List()
		for _, f := range all {
			if f.Rule == in.Rule && severityRank(f.Severity) == 4 {
				http.Error(w, "critical severity rules are never suppressed", http.StatusUnprocessableEntity)
				return
			}
		}
		if _, _, crit := tuneSimulate(all, in.Pattern, in.Rule); crit {
			http.Error(w, "pattern would hide critical findings", http.StatusUnprocessableEntity)
			return
		}
		if in.Reason == "" {
			in.Reason = "tuning: " + in.Rule
		}
		rec := TuningRecord{ID: tuneID("tun-"), ExclusionID: tuneID("ex-tune-"), Rule: in.Rule, Pattern: in.Pattern,
			Reason: in.Reason, AppliedBy: tuneActor(admin), AppliedAt: s.now(), Status: "active"}
		s.mu.Lock()
		if len(s.st.History) >= tuneMaxHistory {
			s.mu.Unlock()
			http.Error(w, "history full", 400)
			return
		}
		worldMu.Lock()
		exclusions = append(exclusions, map[string]any{"id": rec.ExclusionID, "pattern": rec.Pattern, "reason": rec.Reason, "source": "tuning"})
		worldMu.Unlock()
		s.st.History = append(s.st.History, rec)
		err := s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		AppendAudit(token, "tuning.apply", rec.ID+" "+rec.Rule)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rec)
	})
	mux.HandleFunc("POST /v1/tuning/revert", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.URL.Query().Get("id")
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range s.st.History {
			h := &s.st.History[i]
			if h.ID != id {
				continue
			}
			if h.Status == "reverted" {
				http.Error(w, "already reverted", http.StatusConflict)
				return
			}
			worldMu.Lock()
			kept := make([]map[string]any, 0, len(exclusions))
			for _, e := range exclusions {
				if e["id"] != h.ExclusionID {
					kept = append(kept, e)
				}
			}
			exclusions = kept
			worldMu.Unlock()
			now := s.now()
			h.Status, h.RevertedAt, h.RevertedBy = "reverted", &now, tuneActor(admin)
			if err := s.saveLocked(); err != nil {
				http.Error(w, "storage error", 500)
				return
			}
			AppendAudit(token, "tuning.revert", h.ID)
			writeJSON(w, h)
			return
		}
		http.Error(w, "not found", 404)
	})

	mux.HandleFunc("GET /v1/digests", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		out := make([]Digest, 0, len(s.st.Digests))
		for _, d := range s.st.Digests {
			out = append(out, tuneRedact(d))
		}
		s.mu.Unlock()
		writeJSON(w, map[string]any{"digests": out})
	})
	mux.HandleFunc("POST /v1/digests", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		var in Digest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		in.Schedule, in.Content, in.Type = strings.ToLower(in.Schedule), strings.ToLower(in.Content), strings.ToLower(in.Type)
		if in.Name == "" || len(in.Name) > 80 {
			http.Error(w, "name required (max 80)", 400)
			return
		}
		if in.Schedule != "daily" && in.Schedule != "weekly" {
			http.Error(w, "schedule must be daily or weekly", 400)
			return
		}
		if in.Hour < 0 || in.Hour > 23 {
			http.Error(w, "hour_utc must be 0-23", 400)
			return
		}
		if in.Content != "shift-report" && in.Content != "soc-metrics" && in.Content != "top-risks" {
			http.Error(w, "content must be shift-report, soc-metrics or top-risks", 400)
			return
		}
		if in.Type != "webhook" && in.Type != "slack" {
			http.Error(w, "type must be webhook or slack", 400)
			return
		}
		if _, err := validateAlertURL(in.URL); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		in.ID, in.Created = tuneID("dg-"), s.now()
		in.LastRun, in.LastPeriod = time.Time{}, ""
		// A digest created after this period's hour waits for the next period.
		if p, due := tuneDue(in, in.Created); due {
			in.LastPeriod = p
		}
		s.mu.Lock()
		if len(s.st.Digests) >= tuneMaxDigests {
			s.mu.Unlock()
			http.Error(w, "too many digests", 400)
			return
		}
		s.st.Digests = append(s.st.Digests, in)
		err := s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tuneRedact(in))
	})
	mux.HandleFunc("DELETE /v1/digests", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.URL.Query().Get("id")
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, d := range s.st.Digests {
			if d.ID == id {
				s.st.Digests = append(s.st.Digests[:i:i], s.st.Digests[i+1:]...)
				if s.saveLocked() != nil {
					http.Error(w, "storage error", 500)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "not found", 404)
	})
	mux.HandleFunc("POST /v1/digests/send-now", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.URL.Query().Get("id")
		var found *Digest
		s.mu.Lock()
		for _, d := range s.st.Digests {
			if d.ID == id {
				d := d
				found = &d
			}
		}
		s.mu.Unlock()
		if found == nil {
			http.Error(w, "not found", 404)
			return
		}
		writeJSON(w, s.send(r.Context(), *found, tunePeriod(*found, s.now()), "manual"))
	})
	mux.HandleFunc("GET /v1/digests/deliveries", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		out := make([]DigestDelivery, 0, len(s.deliveries))
		for i := len(s.deliveries) - 1; i >= 0; i-- {
			out = append(out, s.deliveries[i])
		}
		s.mu.Unlock()
		writeJSON(w, map[string]any{"deliveries": out})
	})
}
