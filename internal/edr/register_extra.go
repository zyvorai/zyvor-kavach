// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import "net/http"

// RegisterAllExtra wires every observation-only surface added in the recent
// feature branches. Call this once from APIWithCredentials (after the other
// Register* calls) so the endpoints become live.
//
// Endpoints that become available:
//
//	GET  /v1/sse/casb|web|dlp|private|ai|summary
//	GET  /v1/finance/india
//	GET  /v1/ai/brief
//	GET  /v1/k8s/summary
//	GET  /v1/zscaler/zia|zpa|zdx|summary
//	GET  /v1/actions
//	POST /v1/actions
//	POST /v1/actions/suggest
//	GET  /v1/related
//	GET  /v1/posture/snapshot
//
// Nothing in this set executes containment or makes outbound calls.
func RegisterAllExtra(mux *http.ServeMux, token string, store *Store) {
	RegisterSSEObservation(mux, token, store)
	RegisterIndiaFinance(mux, token, store)
	RegisterAIBrief(mux, token, store)
	RegisterK8sObservation(mux, token, store)
	RegisterZscalerObservation(mux, token, store)
	RegisterSuggestedActions(mux, token, store)
	RegisterRelated(mux, token, store)
}
