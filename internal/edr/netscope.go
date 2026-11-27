// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// NetScope — observation-only network scoping.
// Summarises destinations, flow volume and simple risk signals from
// already-ingested network events. Nothing is blocked, dropped or contacted.
// Complements the XDR storyline and Netra poller.

type NetScopeDestination struct {
	Destination string    `json:"destination"`
	Count       int       `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Hosts       []string  `json:"hosts,omitempty"`
	Risk        string    `json:"risk,omitempty"` // info / low / medium / high (heuristic)
}

func RegisterNetScope(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/netscope/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		hostFilter := r.URL.Query().Get("host")
		dests := map[string]*NetScopeDestination{}
		store.mu.Lock()
		for _, n := range store.networkEvents {
			if hostFilter != "" && n.Host != hostFilter {
				continue
			}
			d := n.Destination
			if d == "" {
				continue
			}
			ent, ok := dests[d]
			if !ok {
				ent = &NetScopeDestination{Destination: d, FirstSeen: n.Time, LastSeen: n.Time}
				dests[d] = ent
			}
			ent.Count++
			if n.Time.Before(ent.FirstSeen) {
				ent.FirstSeen = n.Time
			}
			if n.Time.After(ent.LastSeen) {
				ent.LastSeen = n.Time
			}
			found := false
			for _, h := range ent.Hosts {
				if h == n.Host {
					found = true
					break
				}
			}
			if !found && n.Host != "" {
				ent.Hosts = append(ent.Hosts, n.Host)
			}
			ent.Risk = netscopeRisk(d, ent.Count)
		}
		store.mu.Unlock()

		list := make([]NetScopeDestination, 0, len(dests))
		for _, v := range dests {
			list = append(list, *v)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host_filter":  hostFilter,
			"destinations": len(list),
			"top":          list[:min(50, len(list))],
			"note":         "observation-only summary of ingested network events; no live capture or blocking",
		})
	})

	mux.HandleFunc("GET /v1/netscope/risk", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var high []NetScopeDestination
		store.mu.Lock()
		counts := map[string]int{}
		for _, n := range store.networkEvents {
			counts[n.Destination]++
		}
		for dest, c := range counts {
			risk := netscopeRisk(dest, c)
			if risk == "high" || risk == "medium" {
				high = append(high, NetScopeDestination{Destination: dest, Count: c, Risk: risk})
			}
		}
		store.mu.Unlock()
		sort.Slice(high, func(i, j int) bool { return high[i].Count > high[j].Count })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"risky": high[:min(30, len(high))],
			"note":  "heuristic only; review in context of your environment",
		})
	})
}

func netscopeRisk(dest string, count int) string {
	d := strings.ToLower(dest)
	if strings.Contains(d, "127.0.0.1") || strings.HasPrefix(d, "10.") || strings.HasPrefix(d, "192.168.") || strings.HasPrefix(d, "172.") {
		return "info"
	}
	if count > 100 {
		return "medium"
	}
	if count > 500 || strings.Contains(d, ".onion") || strings.Contains(d, "tor") {
		return "high"
	}
	return "low"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
