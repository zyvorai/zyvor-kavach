// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Case struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Assignee    string    `json:"assignee,omitempty"`
	FindingIDs  []string  `json:"finding_ids,omitempty"`
	DetectionIDs []string `json:"detection_ids,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Notes       string    `json:"notes,omitempty"`
}

type GraphNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type GraphEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Rel   string `json:"rel"`
}

type AuditEntry struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

type Connector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Endpoint string `json:"endpoint,omitempty"`
}

var (
	caseMu   sync.Mutex
	cases    []Case
	auditMu  sync.Mutex
	auditLog []AuditEntry
	connList = []Connector{
		{ID: "conn-netra", Name: "Netra Network XDR", Category: "network", Status: "available", Endpoint: "/v1/network-events"},
		{ID: "conn-siem", Name: "SIEM Webhook", Category: "siem", Status: "optional"},
		{ID: "conn-syslog", Name: "Syslog", Category: "siem", Status: "optional"},
		{ID: "conn-llm", Name: "Charlotte LLM", Category: "ai", Status: "optional"},
		{ID: "conn-okta", Name: "Identity (Okta/Entra)", Category: "identity", Status: "available"},
		{ID: "conn-cloud", Name: "Cloud CSPM", Category: "cloud", Status: "available"},
		{ID: "conn-inventory", Name: "Generic Inventory Ingest", Category: "inventory", Status: "available", Endpoint: "/v1/inventory"},
	}
)

func AppendAudit(_token, action, detail string) {
	auditMu.Lock()
	defer auditMu.Unlock()
	auditLog = append(auditLog, AuditEntry{
		ID: "aud-" + time.Now().UTC().Format("20060102150405.000000"),
		Time: time.Now().UTC(), Action: action, Detail: detail,
	})
	if len(auditLog) > 5000 {
		auditLog = auditLog[len(auditLog)-5000:]
	}
}

func RegisterCases(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		caseMu.Lock()
		out := append([]Case{}, cases...)
		caseMu.Unlock()
		if len(out) == 0 && store != nil {
			for _, f := range store.List() {
				if f.Severity != "high" && f.Severity != "critical" {
					continue
				}
				now := time.Now().UTC()
				out = append(out, Case{
					ID: "case-der-" + shortID(f.ID), Title: f.Rule + " on " + f.Host,
					Severity: f.Severity, Status: "open", FindingIDs: []string{f.ID},
					CreatedAt: now, UpdatedAt: now, Notes: "Auto-opened from finding (ledger)",
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		var c Case
		if json.NewDecoder(r.Body).Decode(&c) != nil || c.Title == "" {
			http.Error(w, "invalid", 400)
			return
		}
		now := time.Now().UTC()
		if c.ID == "" {
			c.ID = "case-" + now.Format("20060102150405")
		}
		if c.Status == "" {
			c.Status = "open"
		}
		if c.Severity == "" {
			c.Severity = "medium"
		}
		c.CreatedAt = now
		c.UpdatedAt = now
		caseMu.Lock()
		cases = append(cases, c)
		caseMu.Unlock()
		AppendAudit(token, "case.create", c.Title)
		_ = store
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	})
	mux.HandleFunc("POST /v1/cases/update", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		var body struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Assignee string `json:"assignee"`
			Notes    string `json:"notes"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.ID == "" {
			http.Error(w, "invalid", 400)
			return
		}
		caseMu.Lock()
		defer caseMu.Unlock()
		for i := range cases {
			if cases[i].ID == body.ID {
				if body.Status != "" {
					cases[i].Status = body.Status
				}
				if body.Assignee != "" {
					cases[i].Assignee = body.Assignee
				}
				if body.Notes != "" {
					cases[i].Notes = body.Notes
				}
				cases[i].UpdatedAt = time.Now().UTC()
				AppendAudit(token, "case.update", body.ID)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(cases[i])
				return
			}
		}
		http.Error(w, "not found", 404)
	})
}

func RegisterHunt(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/hunt/query", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body struct {
			Query string `json:"query"` // simple key:value filters, Falcon FQL-lite
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		filters := parseHuntQuery(body.Query)
		findings := []Finding{}
		for _, f := range store.List() {
			if matchHunt(f, filters) {
				findings = append(findings, f)
			}
		}
		store.mu.Lock()
		procs := []Event{}
		for _, e := range store.recentEvents {
			if matchHuntEvent(e, filters) {
				procs = append(procs, e)
			}
		}
		nets := []NetworkEvent{}
		for _, n := range store.networkEvents {
			if hostFilter, ok := filters["host"]; ok && !strings.Contains(strings.ToLower(n.Host), hostFilter) {
				continue
			}
			nets = append(nets, n)
		}
		store.mu.Unlock()
		AppendAudit(token, "hunt.query", body.Query)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"query": body.Query, "findings": findings, "processes": procs, "network": nets,
			"note": "FQL-lite: host:, rule:, severity:, exe: filters",
		})
	})
}

func parseHuntQuery(q string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Fields(q) {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.ToLower(kv[0])] = strings.ToLower(strings.Trim(kv[1], `"'`))
	}
	return out
}

func matchHunt(f Finding, filters map[string]string) bool {
	if v, ok := filters["host"]; ok && !strings.Contains(strings.ToLower(f.Host), v) {
		return false
	}
	if v, ok := filters["rule"]; ok && !strings.Contains(strings.ToLower(f.Rule), v) {
		return false
	}
	if v, ok := filters["severity"]; ok && strings.ToLower(f.Severity) != v {
		return false
	}
	if v, ok := filters["exe"]; ok && !strings.Contains(strings.ToLower(f.Evidence.Executable), v) {
		return false
	}
	return true
}

func matchHuntEvent(e Event, filters map[string]string) bool {
	if v, ok := filters["host"]; ok && !strings.Contains(strings.ToLower(e.Host), v) {
		return false
	}
	if v, ok := filters["exe"]; ok && !strings.Contains(strings.ToLower(e.Executable), v) {
		return false
	}
	if v, ok := filters["cmdline"]; ok && !strings.Contains(strings.ToLower(e.Command), v) {
		return false
	}
	return len(filters) == 0 || filters["host"] != "" || filters["exe"] != "" || filters["cmdline"] != ""
}

func RegisterThreatGraph(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/threat-graph", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		nodes := map[string]GraphNode{}
		edges := []GraphEdge{}
		add := func(id, typ, label string) {
			if _, ok := nodes[id]; !ok {
				nodes[id] = GraphNode{ID: id, Type: typ, Label: label}
			}
		}
		for _, f := range store.List() {
			hid := "host:" + f.Host
			fid := "finding:" + f.ID
			pid := "proc:" + f.Host + ":" + f.Evidence.Executable
			add(hid, "host", f.Host)
			add(fid, "finding", f.Rule)
			add(pid, "process", f.Evidence.Executable)
			edges = append(edges, GraphEdge{From: hid, To: fid, Rel: "triggered"})
			edges = append(edges, GraphEdge{From: fid, To: pid, Rel: "evidence"})
			if f.Evidence.ParentExe != "" {
				pp := "proc:" + f.Host + ":" + f.Evidence.ParentExe
				add(pp, "process", f.Evidence.ParentExe)
				edges = append(edges, GraphEdge{From: pp, To: pid, Rel: "parent_of"})
			}
			if f.Destination != "" {
				d := "net:" + f.Destination
				add(d, "network", f.Destination)
				edges = append(edges, GraphEdge{From: pid, To: d, Rel: "connected"})
			}
		}
		nodeList := make([]GraphNode, 0, len(nodes))
		for _, n := range nodes {
			nodeList = append(nodeList, n)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": nodeList, "edges": edges})
	})
}

func RegisterAudit(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		auditMu.Lock()
		out := append([]AuditEntry{}, auditLog...)
		auditMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

func RegisterReports(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/reports/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		findings := store.List()
		sev := map[string]int{}
		for _, f := range findings {
			sev[f.Severity]++
		}
		online := 0
		if registry != nil {
			for _, st := range registry.Status(time.Now(), 90*time.Second) {
				if st.State == "online" {
					online++
				}
			}
		}
		owMu.Lock()
		owOpen := 0
		for _, a := range owAlerts {
			if a.Status == "open" {
				owOpen++
			}
		}
		owMu.Unlock()
		vulnMu.Lock()
		critV := 0
		for _, v := range vulns {
			if v.Severity == "critical" {
				critV++
			}
		}
		vulnMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"findings": len(findings), "severities": sev, "fleet_online": online,
			"overwatch_open": owOpen, "critical_cves": critV,
			"detections": len(findings), "modules": len(FalconModules()),
			"product": "kavach", "parity": "crowdstrike-falcon",
		})
	})
}

func RegisterConnectors(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/connectors", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		live := deriveConnectors()
		// Include static registry entries that are not already represented.
		for _, c := range connList {
			live = append(live, map[string]any{
				"name": c.Name, "type": c.Category, "status": c.Status, "note": c.Endpoint, "source": "registry",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(live)
	})
	mux.HandleFunc("POST /v1/connectors", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		Live.Append("connectors", body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}

func RegisterCloudMobile(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/cloud/posture", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mergeLive("cloud", nil))
	})
	mux.HandleFunc("GET /v1/mobile/devices", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mergeLive("mobile", nil))
	})
}

var (
	deviceMu   sync.Mutex
	deviceInv  = defaultDeviceInventory()
)

func defaultDeviceInventory() []map[string]any {
	return []map[string]any{}
}

func RegisterDeviceControl(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/device-control", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		deviceMu.Lock()
		out := append([]map[string]any{}, deviceInv...)
		deviceMu.Unlock()
		if len(out) == 0 {
			out = mergeLive("device-control", nil)
		}
		if len(out) == 0 && store != nil {
			hosts := map[string]struct{}{}
			for _, f := range store.List() {
				hosts[f.Host] = struct{}{}
			}
			for h := range hosts {
				out = append(out, map[string]any{
					"id": "usb-obs-" + h, "host": h, "vendor": "unknown", "product": "no-recent-usb",
					"action": "observed", "time": time.Now().UTC(), "source": "derived",
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/device-control", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if body["id"] == nil {
			body["id"] = "usb-" + time.Now().UTC().Format("150405.000")
		}
		if body["action"] == nil {
			body["action"] = "observed"
		}
		body["time"] = time.Now().UTC()
		deviceMu.Lock()
		deviceInv = append(deviceInv, body)
		if len(deviceInv) > 500 {
			deviceInv = deviceInv[len(deviceInv)-500:]
		}
		deviceMu.Unlock()
		AppendAudit(token, "device-control.event", fmt.Sprint(body["id"]))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "device": body, "note": "observed only — never blocks USB"})
	})
}

func RegisterFirewall(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/firewall/rules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mergeLive("firewall", nil))
	})
}

func RegisterCharlotteAssist(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/ai/assist", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body struct {
			Question  string `json:"question"`
			FindingID string `json:"finding_id"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		answer := "Review process tree, Netra correlation, and MITRE mapping. Containment remains a request ledger only."
		if body.FindingID != "" {
			for _, f := range store.List() {
				if f.ID == body.FindingID {
					d := MapDetection(f)
					rs := ScoreFinding(f)
					answer = "Finding " + f.Rule + " on " + f.Host + " maps to " + d.TechniqueID + " (" + d.Technique + "). Risk " + rs.Level + ". " + answer
					if rs.LLMNote != "" {
						answer = rs.LLMNote
					}
					break
				}
			}
		}
		if body.Question != "" {
			answer = "Q: " + body.Question + " — " + answer
		}
		AppendAudit(token, "ai.assist", body.FindingID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"answer": answer, "assistive": true, "product": "charlotte-lite"})
	})
}
