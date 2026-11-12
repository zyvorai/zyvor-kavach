// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
)

func gradeFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}

// BuildComplianceScore rolls derived framework scores into an overall posture grade.
func BuildComplianceScore(store *Store, registry *CredentialRegistry) map[string]any {
	fw := deriveCompliance(store, registry)
	sum := 0
	out := make([]map[string]any, 0, len(fw))
	for _, f := range fw {
		s, _ := f["score"].(int)
		sum += s
		out = append(out, map[string]any{"framework": f["framework"], "score": s, "grade": gradeFor(s), "failing": f["fail"]})
	}
	overall := 100
	if len(fw) > 0 {
		overall = sum / len(fw)
	}
	return map[string]any{"overall": overall, "grade": gradeFor(overall), "frameworks": out, "mode": "observe-only", "source": "derived"}
}

func RegisterComplianceScore(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/compliance/score", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(BuildComplianceScore(store, registry))
	})
}
