package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Incident and case management. Observation only: nothing here acts on a host.

const incidentWindow = time.Hour

var caseStatuses = map[string]bool{"open": true, "investigating": true, "contained": true, "closed": true}
var caseSeverities = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// slaMinutes: severity -> {respond, resolve}.
var slaMinutes = map[string][2]int{"critical": {15, 240}, "high": {60, 480}, "medium": {240, 1440}, "low": {1440, 4320}}

type TimelineEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

type CaseComment struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Author string    `json:"author"`
	Text   string    `json:"text"`
}

type SLAClock struct {
	RespondDue    time.Time `json:"respond_due"`
	ResolveDue    time.Time `json:"resolve_due"`
	RespondBreach bool      `json:"respond_breached"`
	ResolveBreach bool      `json:"resolve_breached"`
	RemainingMins int       `json:"resolve_remaining_minutes"`
}

type IncCase struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Severity    string          `json:"severity"`
	Status      string          `json:"status"`
	Assignee    string          `json:"assignee,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	FindingIDs  []string        `json:"finding_ids,omitempty"`
	IncidentID  string          `json:"incident_id,omitempty"`
	Notes       string          `json:"notes,omitempty"`
	Resolution  string          `json:"resolution,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	RespondedAt *time.Time      `json:"responded_at,omitempty"`
	ClosedAt    *time.Time      `json:"closed_at,omitempty"`
	Timeline    []TimelineEntry `json:"timeline"`
	Comments    []CaseComment   `json:"comments"`
	SLA         *SLAClock       `json:"sla,omitempty"`
}

type Incident struct {
	ID         string    `json:"id"`
	Hosts      []string  `json:"hosts"`
	Techniques []string  `json:"techniques"`
	Severity   string    `json:"severity"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Count      int       `json:"count"`
	FindingIDs []string  `json:"finding_ids"`
	Rules      []string  `json:"rules"`
	CaseID     string    `json:"case_id,omitempty"`
}

func findingTechnique(f Finding) string {
	if m, ok := mitreForFinding(f); ok {
		return m.ID
	}
	return ""
}

// CorrelateIncidents groups findings by same host or shared technique within a time window.
func CorrelateIncidents(fs []Finding, window time.Duration) []Incident {
	n := len(fs)
	idx := make([]int, n)
	parent := make([]int, n)
	for i := range idx {
		idx[i], parent[i] = i, i
	}
	sort.SliceStable(idx, func(a, b int) bool { return fs[idx[a]].Time.Before(fs[idx[b]].Time) })
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	lastHost, lastTech := map[string]int{}, map[string]int{}
	for _, i := range idx {
		f := fs[i]
		if j, ok := lastHost[f.Host]; ok && f.Host != "" && f.Time.Sub(fs[j].Time) <= window {
			parent[find(i)] = find(j)
		}
		lastHost[f.Host] = i
		if t := findingTechnique(f); t != "" {
			if j, ok := lastTech[t]; ok && f.Time.Sub(fs[j].Time) <= window {
				parent[find(i)] = find(j)
			}
			lastTech[t] = i
		}
	}
	groups := map[int][]int{}
	for _, i := range idx {
		groups[find(i)] = append(groups[find(i)], i)
	}
	out := []Incident{}
	for _, g := range groups {
		inc := Incident{Start: fs[g[0]].Time, End: fs[g[len(g)-1]].Time, Count: len(g)}
		hs, ts, rs := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, i := range g {
			f := fs[i]
			inc.FindingIDs = append(inc.FindingIDs, f.ID)
			hs[f.Host], rs[f.Rule] = true, true
			if t := findingTechnique(f); t != "" {
				ts[t] = true
			}
			if caseSeverities[f.Severity] > caseSeverities[inc.Severity] {
				inc.Severity = f.Severity
			}
		}
		inc.Hosts, inc.Techniques, inc.Rules = mapKeys(hs), mapKeys(ts), mapKeys(rs)
		inc.ID = "inc-" + shortID(inc.FindingIDs[0])
		out = append(out, inc)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].End.After(out[b].End) })
	return out
}

func mapKeys(m map[string]bool) []string {
	o := make([]string, 0, len(m))
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}

type caseManager struct {
	mu    sync.Mutex
	path  string
	ws    *Workspace
	cases []IncCase
}

func (m *caseManager) saveLocked() error {
	b, err := json.Marshal(m.cases)
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// journal records the change in the analyst workspace's hash-chained journal.
func (m *caseManager) journal(actor, action, target string) {
	if m.ws == nil {
		return
	}
	m.ws.mu.Lock()
	defer m.ws.mu.Unlock()
	m.ws.appendJournalLocked(actor, action, target)
	_ = m.ws.saveLocked()
}

func (c *IncCase) addTimeline(actor, kind, detail string) {
	c.Timeline = append(c.Timeline, TimelineEntry{Time: time.Now().UTC(), Actor: actor, Kind: kind, Detail: detail})
}

func computeSLA(c IncCase, now time.Time) *SLAClock {
	m, ok := slaMinutes[c.Severity]
	if !ok {
		return nil
	}
	s := &SLAClock{
		RespondDue: c.CreatedAt.Add(time.Duration(m[0]) * time.Minute),
		ResolveDue: c.CreatedAt.Add(time.Duration(m[1]) * time.Minute),
	}
	respEnd, resEnd := now, now
	if c.RespondedAt != nil {
		respEnd = *c.RespondedAt
	}
	if c.ClosedAt != nil {
		resEnd = *c.ClosedAt
		if c.RespondedAt == nil {
			respEnd = *c.ClosedAt
		}
	}
	s.RespondBreach = respEnd.After(s.RespondDue)
	s.ResolveBreach = resEnd.After(s.ResolveDue)
	s.RemainingMins = int(s.ResolveDue.Sub(resEnd).Minutes())
	return s
}

func (m *caseManager) view(c IncCase) IncCase {
	c.SLA = computeSLA(c, time.Now().UTC())
	if c.Timeline == nil {
		c.Timeline = []TimelineEntry{}
	}
	if c.Comments == nil {
		c.Comments = []CaseComment{}
	}
	return c
}

func (m *caseManager) find(id string) int {
	for i := range m.cases {
		if m.cases[i].ID == id {
			return i
		}
	}
	return -1
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func caseMarkdown(c IncCase, fs map[string]Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Case %s: %s\n\n- Status: %s\n- Severity: %s\n- Assignee: %s\n- Created: %s\n",
		c.ID, c.Title, c.Status, c.Severity, orDash(c.Assignee), c.CreatedAt.Format(time.RFC3339))
	if len(c.Tags) > 0 {
		fmt.Fprintf(&b, "- Tags: %s\n", strings.Join(c.Tags, ", "))
	}
	if c.SLA != nil {
		fmt.Fprintf(&b, "- SLA respond due %s (breached: %t), resolve due %s (breached: %t)\n",
			c.SLA.RespondDue.Format(time.RFC3339), c.SLA.RespondBreach, c.SLA.ResolveDue.Format(time.RFC3339), c.SLA.ResolveBreach)
	}
	if c.Resolution != "" {
		fmt.Fprintf(&b, "\n## Resolution\n\n%s\n", c.Resolution)
	}
	b.WriteString("\n## Linked findings\n\n")
	for _, id := range c.FindingIDs {
		if f, ok := fs[id]; ok {
			fmt.Fprintf(&b, "- `%s` [%s] %s on %s: %s\n", f.ID, f.Severity, f.Rule, f.Host, f.Description)
		} else {
			fmt.Fprintf(&b, "- `%s`\n", id)
		}
	}
	b.WriteString("\n## Timeline\n\n")
	for _, t := range c.Timeline {
		fmt.Fprintf(&b, "- %s %s (%s): %s\n", t.Time.Format(time.RFC3339), t.Kind, t.Actor, t.Detail)
	}
	b.WriteString("\n## Comments\n\n")
	for _, cm := range c.Comments {
		fmt.Fprintf(&b, "- %s **%s**: %s\n", cm.Time.Format(time.RFC3339), cm.Author, strings.ReplaceAll(cm.Text, "\n", " "))
	}
	return b.String()
}

func cleanTags(in []string) []string {
	var out []string
	for _, t := range in {
		if t = cleanText(t, false); t != "" && len(out) < 20 {
			out = append(out, t)
		}
	}
	return out
}

// RegisterCaseManagement wires incidents, cases, comments and export.
// Auto-correlated incidents are served at /v1/incidents/correlated because
// GET /v1/incidents is the legacy per-finding workflow list.
func RegisterCaseManagement(mux *http.ServeMux, token string, store *Store, ws *Workspace) {
	m := &caseManager{path: store.path + ".cases.json", ws: ws}
	if b, err := os.ReadFile(m.path); err == nil {
		_ = json.Unmarshal(b, &m.cases)
	}

	mux.HandleFunc("GET /v1/incidents/correlated", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		window := incidentWindow
		if v, err := time.ParseDuration(r.URL.Query().Get("window")); err == nil && v > 0 && v <= 72*time.Hour {
			window = v
		}
		incs := CorrelateIncidents(store.List(), window)
		m.mu.Lock()
		for i := range incs {
			for _, c := range m.cases {
				if c.IncidentID == incs[i].ID {
					incs[i].CaseID = c.ID
				}
			}
		}
		m.mu.Unlock()
		wsJSON(w, 200, incs)
	})

	mux.HandleFunc("GET /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		m.mu.Lock()
		out := []IncCase{}
		for _, c := range m.cases {
			if (q.Get("status") != "" && c.Status != q.Get("status")) || (q.Get("assignee") != "" && c.Assignee != q.Get("assignee")) {
				continue
			}
			out = append(out, m.view(c))
		}
		m.mu.Unlock()
		wsJSON(w, 200, out)
	})

	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		var in struct {
			Title      string   `json:"title"`
			Severity   string   `json:"severity"`
			Assignee   string   `json:"assignee"`
			Tags       []string `json:"tags"`
			FindingIDs []string `json:"finding_ids"`
			IncidentID string   `json:"incident_id"`
			Notes      string   `json:"notes"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if in.IncidentID != "" {
			for _, inc := range CorrelateIncidents(store.List(), incidentWindow) {
				if inc.ID == in.IncidentID {
					in.FindingIDs = append(in.FindingIDs, inc.FindingIDs...)
					if in.Severity == "" {
						in.Severity = inc.Severity
					}
					if in.Title == "" {
						in.Title = fmt.Sprintf("Incident on %s (%d findings)", strings.Join(inc.Hosts, ","), inc.Count)
					}
				}
			}
		}
		in.Title = cleanText(in.Title, false)
		if in.Title == "" || len(in.Title) > 200 {
			http.Error(w, "invalid title", 400)
			return
		}
		if in.Severity == "" {
			in.Severity = "medium"
		}
		if caseSeverities[in.Severity] == 0 {
			http.Error(w, "invalid severity", 400)
			return
		}
		now := time.Now().UTC()
		c := IncCase{ID: newWSID("case-"), Title: in.Title, Severity: in.Severity, Status: "open",
			Assignee: cleanText(in.Assignee, false), IncidentID: in.IncidentID, Notes: cleanText(in.Notes, true),
			FindingIDs: in.FindingIDs, Tags: cleanTags(in.Tags), CreatedAt: now, UpdatedAt: now}
		c.addTimeline(wsActor(admin), "created", c.Title)
		for _, id := range c.FindingIDs {
			c.addTimeline(wsActor(admin), "finding_linked", id)
		}
		m.mu.Lock()
		m.cases = append(m.cases, c)
		err := m.saveLocked()
		v := m.view(c)
		m.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		m.journal(wsActor(admin), "case.create", c.ID+" "+c.Title)
		wsJSON(w, 201, v)
	})

	mux.HandleFunc("GET /v1/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		i := m.find(r.PathValue("id"))
		if i < 0 {
			http.Error(w, "not found", 404)
			return
		}
		wsJSON(w, 200, m.view(m.cases[i]))
	})

	mux.HandleFunc("PATCH /v1/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		var in struct {
			Status     *string  `json:"status"`
			Severity   *string  `json:"severity"`
			Assignee   *string  `json:"assignee"`
			Tags       []string `json:"tags"`
			AddFinding []string `json:"link_findings"`
			Resolution *string  `json:"resolution"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if in.Status != nil && !caseStatuses[*in.Status] {
			http.Error(w, "invalid status", 400)
			return
		}
		if in.Severity != nil && caseSeverities[*in.Severity] == 0 {
			http.Error(w, "invalid severity", 400)
			return
		}
		m.mu.Lock()
		i := m.find(r.PathValue("id"))
		if i < 0 {
			m.mu.Unlock()
			http.Error(w, "not found", 404)
			return
		}
		c := m.cases[i]
		c.Timeline = append([]TimelineEntry{}, c.Timeline...)
		actor, now := wsActor(admin), time.Now().UTC()
		if in.Status != nil && *in.Status != c.Status {
			if *in.Status == "closed" {
				res := ""
				if in.Resolution != nil {
					res = cleanText(*in.Resolution, true)
				}
				if res == "" {
					m.mu.Unlock()
					http.Error(w, "resolution required to close", 400)
					return
				}
				c.Resolution, c.ClosedAt = res, &now
			} else {
				c.ClosedAt = nil
			}
			if c.RespondedAt == nil {
				c.RespondedAt = &now
			}
			c.addTimeline(actor, "status", c.Status+" -> "+*in.Status)
			c.Status = *in.Status
		}
		if in.Severity != nil && *in.Severity != c.Severity {
			c.addTimeline(actor, "severity", c.Severity+" -> "+*in.Severity)
			c.Severity = *in.Severity
		}
		if in.Assignee != nil {
			a := cleanText(*in.Assignee, false)
			c.addTimeline(actor, "assignee", orDash(c.Assignee)+" -> "+orDash(a))
			c.Assignee = a
			if a != "" && c.RespondedAt == nil {
				c.RespondedAt = &now
			}
		}
		if in.Tags != nil {
			c.Tags = cleanTags(in.Tags)
			c.addTimeline(actor, "tags", strings.Join(c.Tags, ","))
		}
		for _, id := range in.AddFinding {
			id = cleanText(id, false)
			dup := id == ""
			for _, e := range c.FindingIDs {
				dup = dup || e == id
			}
			if !dup {
				c.FindingIDs = append(append([]string{}, c.FindingIDs...), id)
				c.addTimeline(actor, "finding_linked", id)
			}
		}
		c.UpdatedAt = now
		m.cases[i] = c
		err := m.saveLocked()
		v := m.view(c)
		m.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		m.journal(actor, "case.update", c.ID+" status="+c.Status)
		wsJSON(w, 200, v)
	})

	mux.HandleFunc("POST /v1/cases/{id}/comments", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		var in struct {
			Author string `json:"author"`
			Text   string `json:"text"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		text := cleanText(in.Text, true)
		if text == "" || len(text) > 8000 {
			http.Error(w, "invalid text", 400)
			return
		}
		author := cleanText(in.Author, false)
		if author == "" {
			author = wsActor(admin)
		}
		m.mu.Lock()
		i := m.find(r.PathValue("id"))
		if i < 0 {
			m.mu.Unlock()
			http.Error(w, "not found", 404)
			return
		}
		now := time.Now().UTC()
		cm := CaseComment{ID: newWSID("cm-"), Time: now, Author: author, Text: text}
		c := m.cases[i]
		c.Comments = append(append([]CaseComment{}, c.Comments...), cm)
		c.Timeline = append(append([]TimelineEntry{}, c.Timeline...), TimelineEntry{Time: now, Actor: author, Kind: "comment", Detail: cm.ID})
		c.UpdatedAt = now
		m.cases[i] = c
		err := m.saveLocked()
		m.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		m.journal(wsActor(admin), "case.comment", c.ID+" "+cm.ID)
		wsJSON(w, 201, cm)
	})

	mux.HandleFunc("GET /v1/cases/{id}/export", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		m.mu.Lock()
		i := m.find(r.PathValue("id"))
		if i < 0 {
			m.mu.Unlock()
			http.Error(w, "not found", 404)
			return
		}
		c := m.view(m.cases[i])
		m.mu.Unlock()
		fs := map[string]Finding{}
		for _, f := range store.List() {
			fs[f.ID] = f
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(caseMarkdown(c, fs)))
	})
}
