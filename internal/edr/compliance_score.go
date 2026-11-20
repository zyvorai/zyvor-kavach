// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
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

// BuildComplianceScore rolls per-framework control scores into an overall posture grade.
func BuildComplianceScore(store *Store, registry *CredentialRegistry) map[string]any {
	return BuildComplianceScoreWith(store, registry, nil, nil, "")
}

func RegisterComplianceScore(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	RegisterComplianceScoreFull(mux, token, store, registry, nil, nil)
}
