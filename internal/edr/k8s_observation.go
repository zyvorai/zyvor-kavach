// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Kubernetes / Cilium / KubeVirt observation summary.
// Aggregates findings and events that look like container or VM activity.
// Observation-only.

func RegisterK8sObservation(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/k8s/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var container, vm, policy int
		for _, f := range store.List() {
			s := strings.ToLower(f.Rule + " " + f.Description)
			if strings.Contains(s, "pod") || strings.Contains(s, "container") || strings.Contains(s, "k8s") || strings.Contains(s, "kubernetes") {
				container++
			}
			if strings.Contains(s, "kubevirt") || strings.Contains(s, "virtualmachine") || strings.Contains(s, "vm ") {
				vm++
			}
			if strings.Contains(s, "networkpolicy") || strings.Contains(s, "cilium") || strings.Contains(s, "hubble") {
				policy++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"container_signals": container,
			"vm_signals":        vm,
			"policy_signals":    policy,
			"note":              "observation-only counts from existing findings. No live cluster calls.",
			"time":              time.Now().UTC(),
		})
	})
}
