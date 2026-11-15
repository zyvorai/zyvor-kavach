package edr

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const ctAssigneeNote = "Assignee is a free-text analyst label. Kavach has no per-analyst identity; the actor recorded in the journal is only 'admin' or 'session'."

func ctIsAdmin(r *http.Request, token string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// requireCTAdmin allows only the admin bearer token.
func requireCTAdmin(w http.ResponseWriter, r *http.Request, token string) bool {
	if ctIsAdmin(r, token) {
		return true
	}
	if bearerOrSession(r, token) {
		http.Error(w, "admin token required", http.StatusForbidden)
		return false
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

type ctTemplateIn struct {
	Name      string         `json:"name"`
	CaseType  string         `json:"case_type"`
	Severity  string         `json:"default_severity"`
	Checklist []string       `json:"checklist"`
	SLAHours  map[string]int `json:"sla_hours"`
	Tags      []string       `json:"default_tags"`
}

func ctValidate(in ctTemplateIn) (CaseTemplate, string) {
	t := CaseTemplate{Name: cleanText(in.Name, false), CaseType: cleanText(in.CaseType, false), Severity: in.Severity}
	if t.Name == "" || len(t.Name) > 100 {
		return t, "invalid name"
	}
	if t.CaseType == "" || len(t.CaseType) > 60 {
		return t, "invalid case_type"
	}
	if t.Severity == "" {
		t.Severity = "medium"
	}
	if caseSeverities[t.Severity] == 0 {
		return t, "invalid default_severity"
	}
	if len(in.Checklist) == 0 || len(in.Checklist) > 30 {
		return t, "checklist needs 1-30 steps"
	}
	for _, s := range in.Checklist {
		s = cleanText(s, false)
		if s == "" || len(s) > 300 {
			return t, "invalid checklist step"
		}
		t.Checklist = append(t.Checklist, s)
	}
	t.SLAHours = map[string]int{}
	for k, v := range in.SLAHours {
		if caseSeverities[k] == 0 || v < 1 || v > 8760 {
			return t, "invalid sla_hours"
		}
		t.SLAHours[k] = v
	}
	t.Tags = cleanTags(in.Tags)
	return t, ""
}

type ctSLAView struct {
	ResolveHours     int        `json:"resolve_hours"`
	ResolveDue       *time.Time `json:"resolve_due,omitempty"`
	Overdue          bool       `json:"overdue"`
	RemainingMinutes int        `json:"remaining_minutes"`
}

// computeWorkflow is pure so tests can drive it with a fake clock.
func computeWorkflow(c IncCase, wf *CaseWorkflow, now time.Time) map[string]any {
	out := map[string]any{"case_id": c.ID, "assignee": c.Assignee, "assignee_note": ctAssigneeNote,
		"severity": c.Severity, "status": c.Status}
	done, total := 0, 0
	items := []ChecklistItem{}
	if wf != nil {
		items = wf.Checklist
		out["template_id"], out["template_name"], out["applied_at"] = wf.TemplateID, wf.Template, wf.AppliedAt
	}
	for _, it := range items {
		total++
		if it.Done {
			done++
		}
	}
	out["checklist"] = items
	out["checklist_progress"] = map[string]any{"done": done, "total": total}
	if wf != nil {
		if h, ok := wf.SLAHours[c.Severity]; ok && h > 0 {
			due := c.CreatedAt.Add(time.Duration(h) * time.Hour)
			end := now
			if c.ClosedAt != nil {
				end = *c.ClosedAt
			}
			out["template_sla"] = ctSLAView{ResolveHours: h, ResolveDue: &due, Overdue: end.After(due), RemainingMinutes: int(due.Sub(end).Minutes())}
		}
	}
	if c.SLA != nil {
		out["builtin_sla"] = c.SLA
	}
	return out
}

func ctCaseIDOK(id string) bool { return id != "" && len(id) <= 64 }

func registerCaseTemplates(mux *http.ServeMux, token string, st *ctState) {
	allTemplates := func() []CaseTemplate {
		out := append([]CaseTemplate{}, ctDefaults...)
		st.mu.Lock()
		out = append(out, st.d.Templates...)
		st.mu.Unlock()
		return out
	}
	findTpl := func(id string) (CaseTemplate, bool) {
		for _, t := range allTemplates() {
			if t.ID == id {
				return t, true
			}
		}
		return CaseTemplate{}, false
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		if json.NewDecoder(r.Body).Decode(v) != nil {
			http.Error(w, "invalid", 400)
			return false
		}
		return true
	}

	mux.HandleFunc("GET /v1/case-templates", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		wsJSON(w, 200, allTemplates())
	})
	mux.HandleFunc("POST /v1/case-templates", func(w http.ResponseWriter, r *http.Request) {
		if !requireCTAdmin(w, r, token) {
			return
		}
		var in ctTemplateIn
		if !decode(w, r, &in) {
			return
		}
		t, msg := ctValidate(in)
		if msg != "" {
			http.Error(w, msg, 400)
			return
		}
		t.ID, t.UpdatedAt = newWSID("tpl-"), ctNow()
		st.mu.Lock()
		if len(st.d.Templates) >= 200 {
			st.mu.Unlock()
			http.Error(w, "too many templates", 400)
			return
		}
		st.d.Templates = append(st.d.Templates, t)
		st.journalLocked("admin", "template.create", t.ID+" "+t.Name)
		err := st.saveLocked()
		st.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		wsJSON(w, 201, t)
	})
	mux.HandleFunc("GET /v1/case-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		t, ok := findTpl(r.PathValue("id"))
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		wsJSON(w, 200, t)
	})
	mux.HandleFunc("PUT /v1/case-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireCTAdmin(w, r, token) {
			return
		}
		id := r.PathValue("id")
		var in ctTemplateIn
		if !decode(w, r, &in) {
			return
		}
		t, msg := ctValidate(in)
		st.mu.Lock()
		defer st.mu.Unlock()
		for i := range st.d.Templates {
			if st.d.Templates[i].ID != id {
				continue
			}
			if msg != "" {
				http.Error(w, msg, 400)
				return
			}
			t.ID, t.UpdatedAt = id, ctNow()
			st.d.Templates[i] = t
			st.journalLocked("admin", "template.update", id+" "+t.Name)
			if st.saveLocked() != nil {
				http.Error(w, "persist failed", 500)
				return
			}
			wsJSON(w, 200, t)
			return
		}
		for _, d := range ctDefaults {
			if d.ID == id {
				http.Error(w, "built-in templates are read-only", 403)
				return
			}
		}
		http.Error(w, "not found", 404)
	})
	mux.HandleFunc("DELETE /v1/case-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireCTAdmin(w, r, token) {
			return
		}
		id := r.PathValue("id")
		st.mu.Lock()
		defer st.mu.Unlock()
		for i := range st.d.Templates {
			if st.d.Templates[i].ID == id {
				st.d.Templates = append(st.d.Templates[:i:i], st.d.Templates[i+1:]...)
				st.journalLocked("admin", "template.delete", id)
				if st.saveLocked() != nil {
					http.Error(w, "persist failed", 500)
					return
				}
				wsJSON(w, 200, map[string]any{"deleted": id})
				return
			}
		}
		for _, d := range ctDefaults {
			if d.ID == id {
				http.Error(w, "built-in templates are read-only", 403)
				return
			}
		}
		http.Error(w, "not found", 404)
	})

	// ---- per-case workflow ----
	view := func(w http.ResponseWriter, r *http.Request, id string, code int) {
		c, cc := ctGetCase(mux, r, id)
		if cc != 200 {
			http.Error(w, "case not found", 404)
			return
		}
		st.mu.Lock()
		wf := st.d.Workflows[id]
		var cp *CaseWorkflow
		if wf != nil {
			x := *wf
			x.Checklist = append([]ChecklistItem{}, wf.Checklist...)
			cp = &x
		}
		st.mu.Unlock()
		wsJSON(w, code, computeWorkflow(c, cp, ctNow()))
	}
	mux.HandleFunc("GET /v1/cases/{id}/workflow", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		view(w, r, r.PathValue("id"), 200)
	})
	mux.HandleFunc("POST /v1/cases/{id}/assign", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.PathValue("id")
		var in struct {
			Assignee string `json:"assignee"`
		}
		if !decode(w, r, &in) {
			return
		}
		a := cleanText(in.Assignee, false)
		if len(a) > 80 {
			http.Error(w, "assignee too long", 400)
			return
		}
		// Cases already carry a free-text assignee; reuse the existing update path.
		code, _ := internalCall(mux, r, "PATCH", "/v1/cases/"+id, map[string]any{"assignee": a})
		if code != 200 {
			http.Error(w, "case update failed", code)
			return
		}
		_ = st.record(wsActor(admin), "case.assign", id+" -> "+orDash(a))
		view(w, r, id, 200)
	})
	mux.HandleFunc("POST /v1/cases/{id}/apply-template", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.PathValue("id")
		var in struct {
			TemplateID string `json:"template_id"`
		}
		if !decode(w, r, &in) {
			return
		}
		t, found := findTpl(in.TemplateID)
		if !found {
			http.Error(w, "template not found", 404)
			return
		}
		c, cc := ctGetCase(mux, r, id)
		if cc != 200 {
			http.Error(w, "case not found", 404)
			return
		}
		st.mu.Lock()
		prev := map[string]ChecklistItem{}
		if old := st.d.Workflows[id]; old != nil {
			for _, it := range old.Checklist {
				prev[it.Text] = it
			}
		}
		wf := &CaseWorkflow{CaseID: id, TemplateID: t.ID, Template: t.Name, AppliedAt: ctNow(), SLAHours: t.SLAHours}
		for _, s := range t.Checklist {
			it := ChecklistItem{Text: s}
			if p, ok := prev[s]; ok {
				it = p
			}
			wf.Checklist = append(wf.Checklist, it)
		}
		st.d.Workflows[id] = wf
		st.journalLocked(wsActor(admin), "case.apply_template", id+" "+t.ID)
		err := st.saveLocked()
		st.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		// Record on the case itself through its comment and tag mechanisms.
		note := fmt.Sprintf("Template applied: %s (%s). Checklist of %d steps.", t.Name, t.CaseType, len(t.Checklist))
		if h, ok := t.SLAHours[c.Severity]; ok {
			note += fmt.Sprintf(" Resolve due %s (%dh from case creation, severity %s).", c.CreatedAt.Add(time.Duration(h)*time.Hour).Format(time.RFC3339), h, c.Severity)
		}
		internalCall(mux, r, "POST", "/v1/cases/"+id+"/comments", map[string]any{"text": note, "author": wsActor(admin)})
		if len(t.Tags) > 0 {
			merged := append([]string{}, c.Tags...)
			have := map[string]bool{}
			for _, x := range merged {
				have[x] = true
			}
			for _, x := range t.Tags {
				if !have[x] {
					merged = append(merged, x)
				}
			}
			internalCall(mux, r, "PATCH", "/v1/cases/"+id, map[string]any{"tags": merged})
		}
		view(w, r, id, 200)
	})
	mux.HandleFunc("POST /v1/cases/{id}/checklist/{n}", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.PathValue("id")
		n, err := strconv.Atoi(r.PathValue("n"))
		var in struct {
			Done *bool `json:"done"`
		}
		if err != nil || !decode(w, r, &in) || in.Done == nil {
			if err != nil {
				http.Error(w, "invalid step number", 400)
			} else if in.Done == nil {
				http.Error(w, "done required", 400)
			}
			return
		}
		st.mu.Lock()
		wf := st.d.Workflows[id]
		if wf == nil || n < 1 || n > len(wf.Checklist) {
			st.mu.Unlock()
			http.Error(w, "no such checklist step (apply a template first; steps are 1-based)", 404)
			return
		}
		it := wf.Checklist[n-1]
		it.Done = *in.Done
		if it.Done {
			now := ctNow()
			it.By, it.DoneAt = wsActor(admin), &now
		} else {
			it.By, it.DoneAt = "", nil
		}
		wf.Checklist[n-1] = it
		st.journalLocked(wsActor(admin), "case.checklist", fmt.Sprintf("%s step %d done=%v", id, n, it.Done))
		serr := st.saveLocked()
		st.mu.Unlock()
		if serr != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		view(w, r, id, 200)
	})
	mux.HandleFunc("GET /v1/case-workflow/journal", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		st.mu.Lock()
		seq, why := st.verifyLocked()
		j := append([]JournalEntry{}, st.d.Journal...)
		st.mu.Unlock()
		sort.Slice(j, func(a, b int) bool { return j[a].Seq > j[b].Seq })
		if len(j) > 200 {
			j = j[:200]
		}
		wsJSON(w, 200, map[string]any{"intact": seq == 0, "first_broken_seq": seq, "reason": why, "entries": j})
	})
}

// RegisterChainsAndTemplates wires attack chains and case templates/workflow.
func RegisterChainsAndTemplates(mux *http.ServeMux, token string, store *Store) {
	st := newCTState(store.path + ".casetemplates.json")
	registerCaseTemplates(mux, token, st)
	registerChains(mux, token, store, st)
}
