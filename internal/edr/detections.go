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
	// Unmapped is true when the rule has no ATT&CK entry; Tactic/Technique/TechniqueID are then empty.
	Unmapped bool      `json:"unmapped,omitempty"`
	IOAs       []string  `json:"ioas,omitempty"`
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
	// Rules that previously fell through MapDetection's silent T1082 default. Each mapping is the
	// technique the rule's trigger actually describes (see docs/research-validation-lab.md).
	// chmod 777 on /etc/ paths: loosening permissions on sensitive config.
	"unsafe-permissions": {"Defense Evasion", "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification", "T1222.002"},
	// crontab / at / systemctl enable. T1053 (Scheduled Task/Job) is the parent covering cron and at;
	// it is also listed under Persistence in ATT&CK. systemctl enable is strictly T1543.002, which
	// the rule does not distinguish, so the parent is used rather than over-claiming a sub-technique.
	"persistence-attempt": {"Persistence", "Scheduled Task/Job", "T1053"},
	// python/perl/ruby/node/php with -c, base64 or /dev/tcp payloads: interpreter execution.
	"script-inline-execution": {"Execution", "Command and Scripting Interpreter", "T1059"},
	// root shell running `history -c`.
	"root-history-clear": {"Defense Evasion", "Indicator Removal: Clear Command History", "T1070.003"},
}

type mitreEntry = struct{ Tactic, Technique, ID string }

// iocRuleAlias maps the rule ids Detect emits for IOC matches ("ioc-"+type) onto the
// ruleMITRE keys. Operator-added IOC types without an alias stay unmapped.
var iocRuleAlias = map[string]string{
	"ioc-domain": "ioc-domain-match",
	"ioc-ipv4":   "ioc-ip-match", "ioc-ipv6": "ioc-ip-match",
	"ioc-sha256": "ioc-hash-match", "ioc-md5": "ioc-hash-match", "ioc-sha1": "ioc-hash-match",
}

// techniqueTactic resolves a technique id to name and tactic from the guidance technique table
// (falling back to the parent technique for an unknown sub-technique).
func techniqueTactic(id string) (name, tactic string, ok bool) {
	for _, d := range techniqueDefs {
		if d.id == id {
			return d.title, d.tactic, true
		}
	}
	if i := strings.IndexByte(id, '.'); i > 0 {
		return techniqueTactic(id[:i])
	}
	return "", "", false
}

// ioaMITRE resolves an IOA finding rule ("ioa-"+IOARule.ID) through the IOA's TechniqueID.
func ioaMITRE(rule string) (mitreEntry, bool) {
	if !strings.HasPrefix(rule, "ioa-") {
		return mitreEntry{}, false
	}
	ioaMu.Lock()
	defer ioaMu.Unlock()
	for _, r := range ioas {
		if "ioa-"+r.ID == rule && r.TechniqueID != "" {
			return ioaEntry(r.TechniqueID)
		}
	}
	return mitreEntry{}, false
}

func ioaEntry(tech string) (mitreEntry, bool) {
	name, tac, ok := techniqueTactic(tech)
	if !ok {
		return mitreEntry{}, false
	}
	return mitreEntry{tac, name, tech}, true
}

// mitreForFinding resolves a finding to its technique. Besides the rule id it understands IOA
// findings whose IOA has since been edited or removed (the technique rides in the tags).
// ok=false means unmapped: callers must not invent a technique.
func mitreForFinding(f Finding) (mitreEntry, bool) {
	if m, ok := mitreFor(f.Rule); ok {
		return m, true
	}
	if strings.HasPrefix(f.Rule, "ioa-") {
		for _, t := range f.Tags {
			if labTechRe.MatchString(t) {
				return ioaEntry(t)
			}
		}
	}
	return mitreEntry{}, false
}

// allRuleMITRE merges every rule-to-technique mapping that can fire: built-in rules, live content
// packs and enabled IOA rules that carry a technique. Shared by the ATT&CK matrix and TTP views.
func allRuleMITRE() map[string]mitreEntry {
	all := make(map[string]mitreEntry, len(ruleMITRE))
	for r, m := range ruleMITRE {
		all[r] = m
	}
	for r, m := range contentMITREAll() {
		all[r] = m
	}
	ioaMu.Lock()
	for _, r := range ioas {
		if !r.Enabled || r.TechniqueID == "" {
			continue
		}
		if m, ok := ioaEntry(r.TechniqueID); ok {
			if _, dup := all["ioa-"+r.ID]; !dup {
				all["ioa-"+r.ID] = m
			}
		}
	}
	ioaMu.Unlock()
	return all
}

type detectionState struct {
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

var detectionMu sync.Mutex
var detectionStates = map[string]detectionState{}

func MapDetection(f Finding) Detection {
	m, ok := mitreForFinding(f) // ok=false: explicit unmapped, never a guessed technique
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
		Technique: m.Technique, TechniqueID: m.ID, Unmapped: !ok, Score: score, XDR: xdr,
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
		recordDetectionTransition(body.ID, body.Status)
		AppendAudit(token, "detections.triage", body.ID+" -> "+body.Status)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}
