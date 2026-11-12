// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Detection is an Insight-style detection enriched with MITRE ATT&CK.
type Detection struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	Time        time.Time `json:"time"`
	Host        string    `json:"host"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Assignee    string    `json:"assignee,omitempty"`
	Rule        string    `json:"rule"`
	Description string    `json:"description"`
	Tactic      string    `json:"tactic"`
	Technique   string    `json:"technique"`
	TechniqueID string    `json:"technique_id"`
	IOAs        []string  `json:"ioas,omitempty"`
	IOCs        []string  `json:"iocs,omitempty"`
	Score       int       `json:"score"`
	XDR         bool      `json:"xdr"`
}

var ruleMITRE = map[string]struct{ Tactic, Technique, ID string }{
	"shell-network-redirection":  {"Command and Control", "Ingress Tool Transfer", "T1105"},
	"download-execute":           {"Execution", "User Execution: Malicious File", "T1204.002"},
	"lolbin-netcat-shell":        {"Execution", "Command and Scripting Interpreter", "T1059"},
	"download-chmod-execute":     {"Defense Evasion", "Masquerading", "T1036"},
	"ransomware-burst":           {"Impact", "Data Encrypted for Impact", "T1486"},
	"ransomware-extension-burst": {"Impact", "Data Encrypted for Impact", "T1486"},
	"mass-file-activity":         {"Impact", "Data Destruction", "T1485"},
	"netra-denied-process":       {"Command and Control", "Application Layer Protocol", "T1071"},
	"ioc-hash-match":             {"Execution", "User Execution", "T1204"},
	"ioc-domain-match":           {"Command and Control", "Application Layer Protocol", "T1071"},
	"ioc-ip-match":               {"Command and Control", "Application Layer Protocol", "T1071"},
	"ioa-credential-dump":        {"Credential Access", "OS Credential Dumping", "T1003"},
	"ioa-lateral-smb":            {"Lateral Movement", "Remote Services: SMB/Windows Admin Shares", "T1021.002"},
	"identity-password-spray":    {"Credential Access", "Brute Force: Password Spraying", "T1110.003"},
	"identity-impossible-travel": {"Defense Evasion", "Use Alternate Authentication Material", "T1550"},
}

type detectionState struct {
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

var detectionMu sync.Mutex
var detectionStates = map[string]detectionState{}

func MapDetection(f Finding) Detection {
	m, ok := ruleMITRE[f.Rule]
	if !ok {
		m = struct{ Tactic, Technique, ID string }{"Discovery", "System Information Discovery", "T1082"}
	}
	xdr := false
	for _, t := range f.Tags {
		if strings.EqualFold(t, "xdr") || strings.EqualFold(t, "netra") {
			xdr = true
		}
	}
	if f.Destination != "" {
		xdr = true
	}
	score := ScoreFinding(f).Score
	d := Detection{
		ID: "det-" + f.ID, FindingID: f.ID, Time: f.Time, Host: f.Host, Severity: f.Severity,
		Status: "new", Rule: f.Rule, Description: f.Description, Tactic: m.Tactic,
		Technique: m.Technique, TechniqueID: m.ID, Score: score, XDR: xdr,
		IOAs: []string{f.Rule},
	}
	detectionMu.Lock()
	if st, ok := detectionStates[d.ID]; ok {
		d.Status = st.Status
		d.Assignee = st.Assignee
	}
	detectionMu.Unlock()
	return d
}

func RegisterDetections(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/detections", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		sev := strings.ToLower(r.URL.Query().Get("severity"))
		status := strings.ToLower(r.URL.Query().Get("status"))
		host := strings.ToLower(r.URL.Query().Get("host"))
		out := make([]Detection, 0)
		for _, f := range store.List() {
			d := MapDetection(f)
			if sev != "" && strings.ToLower(d.Severity) != sev {
				continue
			}
			if status != "" && strings.ToLower(d.Status) != status {
				continue
			}
			if host != "" && !strings.Contains(strings.ToLower(d.Host), host) {
				continue
			}
			out = append(out, d)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/detections/triage", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var body struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Assignee string `json:"assignee"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.ID == "" {
			http.Error(w, "invalid", 400)
			return
		}
		switch body.Status {
		case "new", "in_progress", "true_positive", "false_positive", "ignored", "closed":
		default:
			http.Error(w, "invalid status", 400)
			return
		}
		detectionMu.Lock()
		detectionStates[body.ID] = detectionState{Status: body.Status, Assignee: body.Assignee}
		detectionMu.Unlock()
		AppendAudit(token, "detections.triage", body.ID+" -> "+body.Status)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}
