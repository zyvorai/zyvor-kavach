// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Per-control scoring across every framework in the evidence catalog.
// Observation only. Controls Kavach cannot evidence are "not_observable" and
// are excluded from scores; they are never counted as met.

const (
	scoreMet           = "met"
	scorePartial       = "partial"
	scoreUnmet         = "unmet"
	scoreNotObservable = "not_observable"
)

// ScoredControl is one control with a score and a human-readable reason.
type ScoredControl struct {
	ID        string `json:"id"`
	Framework string `json:"framework"`
	Title     string `json:"title"`
	Status    string `json:"status"` // met | partial | unmet | not_observable
	Score     *int   `json:"score"`  // null when not_observable
	Reason    string `json:"reason"`
}

var signalLabels = map[string]string{
	sigDetect: "detection rule coverage", sigFleet: "agents online", sigAudit: "audit log",
	sigSBOM: "SBOM", sigFIM: "file-integrity events", sigWorkflow: "incident workflow activity",
	sigAlerts: "alert routing rules", sigTelem: "findings telemetry", sigTimely: "no overdue high/critical incidents",
}

func scoreControl(c evControl, s evSignals) ScoredControl {
	r := ScoredControl{ID: c.ID, Framework: c.Framework, Title: c.Title}
	if c.Kind != "" || len(c.Signals) == 0 {
		r.Status = scoreNotObservable
		r.Reason = c.Note
		if r.Reason == "" {
			r.Reason = "Kavach has no telemetry that evidences this control."
		}
		if c.Kind == "not_applicable" {
			r.Reason = "Out of Kavach scope: " + r.Reason
		}
		return r
	}
	var met, partial, missing []string
	for _, sg := range c.Signals {
		name := signalLabels[sg]
		if name == "" {
			name = sg
		}
		switch s.Level[sg] {
		case 2:
			met = append(met, name)
		case 1:
			partial = append(partial, name)
		default:
			missing = append(missing, name)
		}
	}
	pts := (len(met)*2 + len(partial)) * 100 / (2 * len(c.Signals))
	switch {
	case len(met) == len(c.Signals):
		r.Status = scoreMet
	case len(met) == 0 && len(partial) == 0:
		r.Status = scoreUnmet
	default:
		r.Status = scorePartial
	}
	r.Score = &pts
	var parts []string
	if len(met) > 0 {
		parts = append(parts, "evidenced: "+strings.Join(met, ", "))
	}
	if len(partial) > 0 {
		parts = append(parts, "partial: "+strings.Join(partial, ", "))
	}
	if len(missing) > 0 {
		parts = append(parts, "no evidence: "+strings.Join(missing, ", "))
	}
	r.Reason = strings.Join(parts, "; ")
	return r
}

// BuildComplianceScoreWith scores every framework in the catalog; framework
// ("" for all) optionally narrows the result and adds per-control rows.
func BuildComplianceScoreWith(store *Store, registry *CredentialRegistry, inc *IncidentStore, d *Dispatcher, framework string) map[string]any {
	s := gatherEvidence(store, registry, inc, d)
	s.Counts["content_rules"] = len(ContentRules())
	fwList := []map[string]any{}
	all := []ScoredControl{}
	sum, n := 0, 0
	for _, f := range evidenceFrameworks {
		if framework != "" && f.ID != framework {
			continue
		}
		var ctls []ScoredControl
		for _, c := range evidenceCatalog {
			if c.Framework == f.ID {
				ctls = append(ctls, scoreControl(c, s))
			}
		}
		cnt := map[string]int{}
		pts, obs := 0, 0
		for _, c := range ctls {
			cnt[c.Status]++
			if c.Score != nil {
				pts += *c.Score
				obs++
			}
		}
		entry := map[string]any{
			"id": f.ID, "framework": f.Name, "name": f.Name, "failing": cnt[scoreUnmet],
			"controls_total": len(ctls), "observable": obs,
			"met": cnt[scoreMet], "partial": cnt[scorePartial], "unmet": cnt[scoreUnmet], "not_observable": cnt[scoreNotObservable],
		}
		if obs > 0 {
			sc := pts / obs
			entry["score"], entry["grade"] = sc, gradeFor(sc)
			sum += sc
			n++
		} else {
			entry["score"], entry["grade"] = 0, "n/a"
		}
		fwList = append(fwList, entry)
		all = append(all, ctls...)
	}
	overall, grade := 0, "n/a"
	if n > 0 {
		overall = sum / n
		grade = gradeFor(overall)
	}
	out := map[string]any{
		"overall": overall, "grade": grade, "frameworks": fwList, "mode": "observe-only", "source": "evidence-catalog",
		"certification": false, "generated_at": time.Now().UTC(), "evidence": s.Counts,
		"note": "Scores cover observable controls only; not_observable controls are excluded, never counted as met.",
	}
	if framework != "" {
		out["framework"] = framework
		out["controls"] = all
	}
	return out
}

func RegisterComplianceScoreFull(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry, inc *IncidentStore, d *Dispatcher) {
	mux.HandleFunc("GET /v1/compliance/score", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fw := ""
		if q := r.URL.Query().Get("framework"); q != "" {
			f, ok := lookupFramework(q)
			if !ok {
				http.Error(w, "unknown framework", http.StatusBadRequest)
				return
			}
			fw = f.ID
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(BuildComplianceScoreWith(store, registry, inc, d, fw))
	})
}
