package edr

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type rsInput struct {
	Name       string            `json:"name"`
	Template   string            `json:"template"`
	Params     map[string]string `json:"params"`
	Frequency  string            `json:"frequency"`
	Time       string            `json:"time"`   // "HH:MM" UTC (daily, weekly, monthly)
	Minute     *int              `json:"minute"` // hourly: minute past the hour
	Weekday    string            `json:"weekday"`
	DayOfMonth int               `json:"day_of_month"`
	Retention  int               `json:"retention"`
	Format     string            `json:"format"`
	Enabled    *bool             `json:"enabled"`
}

func (in rsInput) schedule() (rsSchedule, error) {
	s := rsSchedule{Name: in.Name, Template: in.Template, Params: in.Params, Frequency: in.Frequency, Weekday: in.Weekday,
		DayOfMonth: in.DayOfMonth, Retention: in.Retention, Format: in.Format, Enabled: true}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if in.Frequency == rsFreqHourly {
		if in.Minute != nil {
			s.Minute = *in.Minute
		}
	} else {
		h, m, err := rsParseHHMM(in.Time)
		if err != nil {
			return s, err
		}
		s.Hour, s.Minute = h, m
	}
	return s, nil
}

// RegisterReportSched mounts scheduled report management and the fleet SLO
// views, and starts the single scheduler goroutine and SLO sampler.
func RegisterReportSched(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	if store == nil {
		return
	}
	eng := newRSEngine(store.path, time.Now)
	eng.render = func(s rsSchedule, now time.Time) ([]byte, bool, error) {
		t, ok := rsFindTemplate(s.Template)
		if !ok {
			return nil, false, errors.New("template no longer exists")
		}
		return rsRenderTemplate(t, s, now, store, registry)
	}
	eng.Start()
	RegisterFleetSLO(mux, token, store, registry)

	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	decode := func(w http.ResponseWriter, r *http.Request) (rsSchedule, bool) {
		var in rsInput
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), 400)
			return rsSchedule{}, false
		}
		s, err := in.schedule()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return s, false
		}
		return s, true
	}
	mux.HandleFunc("GET /v1/reports/scheduled", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out(w, 200, map[string]any{"schedules": eng.List(), "templates_with_host_names": rsHostTemplates(),
			"delivery": "pull-only: Kavach stores rendered reports locally and never emails or pushes them; fetch via GET /v1/reports/archive/{run_id}",
			"limits": map[string]any{"max_schedules": rsMaxSchedules, "max_retention": rsMaxRetention, "run_timeout_seconds": int(rsRunTimeout.Seconds()),
				"max_report_bytes": rsMaxRunBytes, "max_archived_reports": rsMaxArchive, "max_archive_bytes": rsMaxArchiveSz},
			"redaction": "when data-governance redaction is enabled, findings and section text are redacted as in findings export; host names in 'hosts' sections are only masked where they look like IP addresses"})
	})
	mux.HandleFunc("POST /v1/reports/scheduled", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		s, ok := decode(w, r)
		if !ok {
			return
		}
		c, err := eng.Create(s)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		out(w, 201, c)
	})
	mux.HandleFunc("PUT /v1/reports/scheduled/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		s, ok := decode(w, r)
		if !ok {
			return
		}
		u, err := eng.Update(r.PathValue("id"), s)
		if errors.Is(err, errRSNoSch) {
			http.Error(w, err.Error(), 404)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		out(w, 200, u)
	})
	mux.HandleFunc("DELETE /v1/reports/scheduled/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		if err := eng.Delete(r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v1/reports/scheduled/{id}/run", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		run, err := eng.execute(r.PathValue("id"), "manual", time.Now().UTC())
		switch {
		case errors.Is(err, errRSNoSch):
			http.Error(w, err.Error(), 404)
		case errors.Is(err, errRSBusy):
			http.Error(w, err.Error(), 409)
		case err != nil:
			http.Error(w, err.Error(), 500)
		default:
			out(w, 200, run)
		}
	})
	mux.HandleFunc("GET /v1/reports/scheduled/{id}/runs", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		found := false
		for _, s := range eng.List() {
			found = found || s.ID == id
		}
		if !found {
			http.Error(w, "schedule not found", 404)
			return
		}
		runs := eng.Runs(id)
		if runs == nil {
			runs = []rsRun{}
		}
		out(w, 200, map[string]any{"schedule_id": id, "runs": runs})
	})
	mux.HandleFunc("GET /v1/reports/archive/{run_id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		run, b, err := eng.Archive(r.PathValue("run_id"))
		if err != nil {
			http.Error(w, "report not found", 404)
			return
		}
		w.Header().Set("Content-Type", rsContentType(run.Format))
		w.Header().Set("X-Kavach-Report-SHA256", run.SHA256)
		w.Header().Set("Content-Disposition", `attachment; filename="`+run.RunID+rsExt(run.Format)+`"`)
		_, _ = w.Write(b)
	})
}
