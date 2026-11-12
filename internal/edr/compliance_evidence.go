// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Control-level compliance evidence. Observation only: Kavach reports what it
// can evidence from live telemetry; it never certifies compliance and never
// takes enforcement action. Controls Kavach cannot evidence are "manual".

const certInWindow = 6 * time.Hour

type evidenceFramework struct {
	ID    string
	Name  string
	Scope string
}

var evidenceFrameworks = []evidenceFramework{
	{"cis-v8", "CIS Controls v8 (representative subset)", "Technical safeguards observable from endpoint telemetry."},
	{"nist-csf-2", "NIST CSF 2.0 (representative subset)", "Detect, Respond and Identify outcomes observable by Kavach."},
	{"soc2", "SOC 2 CC6/CC7", "Logical access monitoring and system operations criteria, observation evidence only."},
	{"iso27001", "ISO/IEC 27001:2022 Annex A (subset)", "Technological and organisational controls with observable evidence."},
	{"rbi", "RBI Cyber Security Framework (banks)", "Observation evidence for SOC, incident and logging expectations."},
	{"cert-in", "CERT-In Directions (6-hour reporting)", "Informational incident clock; Kavach does not file reports."},
	{"dpdp", "India DPDP Act breach notification", "Detection and tracking support only; notification decisions are manual."},
}

// Signal identifiers used by controls.
const (
	sigDetect   = "detections_coverage"
	sigFleet    = "fleet_agents_online"
	sigAudit    = "audit_log"
	sigSBOM     = "sbom_present"
	sigFIM      = "fim_present"
	sigWorkflow = "incident_workflow"
	sigAlerts   = "alert_routing"
	sigTelem    = "findings_telemetry"
	sigTimely   = "no_overdue_high"
)

type evControl struct {
	ID, Framework, Title string
	Signals              []string // evidence required; empty means manual / not applicable
	Kind                 string   // "" (evidence-based) | manual | not_applicable
	Note                 string
}

func ctl(fw, id, title, kind, note string, sig ...string) evControl {
	return evControl{ID: id, Framework: fw, Title: title, Signals: sig, Kind: kind, Note: note}
}

var evidenceCatalog = []evControl{
	// CIS Controls v8
	ctl("cis-v8", "CIS 1.1", "Establish and maintain detailed enterprise asset inventory", "", "Enrolled agents and heartbeat state.", sigFleet),
	ctl("cis-v8", "CIS 2.1", "Establish and maintain a software inventory", "", "SBOM / process inventory.", sigSBOM),
	ctl("cis-v8", "CIS 3.14", "Log sensitive data access", "", "File-integrity events on monitored paths.", sigFIM),
	ctl("cis-v8", "CIS 8.2", "Collect audit logs", "", "Kavach audit log and findings ledger.", sigAudit, sigTelem),
	ctl("cis-v8", "CIS 8.11", "Conduct audit log reviews", "", "Incident workflow records analyst review.", sigWorkflow),
	ctl("cis-v8", "CIS 10.7", "Use behavior-based anti-malware software", "", "Behavioural detections mapped to ATT&CK.", sigDetect, sigFleet),
	ctl("cis-v8", "CIS 13.1", "Centralize security event alerting", "", "Alert routing rules and findings.", sigAlerts, sigTelem),
	ctl("cis-v8", "CIS 17.4", "Establish and maintain an incident response process", "", "Incident workflow transitions recorded.", sigWorkflow),
	ctl("cis-v8", "CIS 14.1", "Establish a security awareness program", "manual", "Training is outside Kavach telemetry."),
	// NIST CSF 2.0
	ctl("nist-csf-2", "ID.AM-01", "Hardware inventories are maintained", "", "Enrolled agents.", sigFleet),
	ctl("nist-csf-2", "ID.AM-02", "Software inventories are maintained", "", "SBOM presence.", sigSBOM),
	ctl("nist-csf-2", "DE.CM-01", "Networks are monitored for adverse events", "", "Detections plus connected agents.", sigDetect, sigFleet),
	ctl("nist-csf-2", "DE.CM-09", "Computing hardware and software are monitored", "", "Endpoint sensors, FIM and SBOM.", sigFleet, sigFIM, sigSBOM),
	ctl("nist-csf-2", "DE.AE-06", "Adverse event information is provided to authorized staff", "", "Alert routing configured.", sigAlerts),
	ctl("nist-csf-2", "RS.MA-01", "Incident response plan is executed", "", "Incident workflow state transitions.", sigWorkflow),
	ctl("nist-csf-2", "RS.AN-03", "Analysis is performed to establish incident cause", "", "Findings with ATT&CK context.", sigTelem, sigDetect),
	ctl("nist-csf-2", "GV.PO-01", "Cybersecurity policy is established", "manual", "Policy governance is not evidenced by Kavach."),
	// SOC 2
	ctl("soc2", "CC6.1", "Logical access security software and architecture", "manual", "Access architecture is assessed by the auditor; Kavach only observes."),
	ctl("soc2", "CC6.8", "Controls to prevent or detect unauthorized or malicious software", "", "Detections and FIM coverage.", sigDetect, sigFIM),
	ctl("soc2", "CC7.1", "Detection and monitoring of configuration changes and vulnerabilities", "", "FIM, SBOM and fleet.", sigFIM, sigSBOM, sigFleet),
	ctl("soc2", "CC7.2", "Monitoring of system components for anomalies", "", "Detections, fleet and audit log.", sigDetect, sigFleet, sigAudit),
	ctl("soc2", "CC7.3", "Evaluation of security events", "", "Incident workflow records evaluation.", sigWorkflow, sigTelem),
	ctl("soc2", "CC7.4", "Incident response", "", "Workflow plus alert routing.", sigWorkflow, sigAlerts),
	ctl("soc2", "CC7.5", "Recovery from incidents", "manual", "Kavach is observation-only and does not perform recovery."),
	// ISO 27001 Annex A
	ctl("iso27001", "A.5.9", "Inventory of information and other associated assets", "", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	ctl("iso27001", "A.5.24", "Information security incident management planning", "", "Incident workflow.", sigWorkflow),
	ctl("iso27001", "A.5.26", "Response to information security incidents", "", "Workflow and alert routing.", sigWorkflow, sigAlerts),
	ctl("iso27001", "A.8.15", "Logging", "", "Audit log and findings ledger.", sigAudit, sigTelem),
	ctl("iso27001", "A.8.16", "Monitoring activities", "", "Detections and fleet.", sigDetect, sigFleet),
	ctl("iso27001", "A.8.7", "Protection against malware", "", "Behavioural detections (observation only).", sigDetect),
	ctl("iso27001", "A.8.9", "Configuration management", "", "FIM events.", sigFIM),
	ctl("iso27001", "A.7.1", "Physical security perimeters", "not_applicable", "Physical controls are outside Kavach scope."),
	// RBI
	ctl("rbi", "RBI-SOC", "Security Operations Centre monitoring and detection", "", "Detections, fleet, alert routing.", sigDetect, sigFleet, sigAlerts),
	ctl("rbi", "RBI-LOG", "Log retention and audit trail", "", "Audit log and findings ledger; retention period must be verified manually.", sigAudit, sigTelem),
	ctl("rbi", "RBI-INC", "Incident response and reporting workflow", "", "Incident workflow and timeliness of high severity items.", sigWorkflow, sigTimely),
	ctl("rbi", "RBI-INV", "Asset and software inventory", "", "Fleet and SBOM.", sigFleet, sigSBOM),
	ctl("rbi", "RBI-BOARD", "Board-approved cyber security policy", "manual", "Governance artefact; not evidenced by Kavach."),
	// CERT-In
	ctl("cert-in", "CI-6H", "Report cyber incidents within 6 hours of noticing", "", "Kavach tracks the 6-hour clock for open high/critical incidents; the report itself is filed manually.", sigWorkflow, sigTimely),
	ctl("cert-in", "CI-LOG", "Maintain ICT logs", "", "Audit log and findings ledger; 180-day retention must be verified manually.", sigAudit, sigTelem),
	ctl("cert-in", "CI-POC", "Designate a point of contact", "manual", "Organisational designation, not observable."),
	// DPDP
	ctl("dpdp", "DPDP-DET", "Ability to detect personal data breaches", "", "Detections and file-integrity monitoring.", sigDetect, sigFIM),
	ctl("dpdp", "DPDP-TRK", "Record and track breach-related incidents", "", "Incident workflow.", sigWorkflow, sigTelem),
	ctl("dpdp", "DPDP-NOT", "Notify the Board and affected Data Principals", "manual", "Notification and breach determination are legal decisions made by the Data Fiduciary."),
}

// evSignals holds live evidence counts and signal levels (0 unmet, 1 partial, 2 met).
type evSignals struct {
	Counts map[string]int
	Level  map[string]int
}

func gatherEvidence(store *Store, registry *CredentialRegistry, inc *IncidentStore, d *Dispatcher) evSignals {
	c := map[string]int{}
	lv := map[string]int{}
	findings := store.List()
	c["findings_total"] = len(findings)
	if len(findings) > 0 {
		lv[sigTelem] = 2
	}
	// Static detection coverage from the ATT&CK matrix (rules shipped).
	m := BuildATTACKMatrix(nil)
	cov, _ := m["covered"].(int)
	tot, _ := m["total"].(int)
	c["attack_tactics_covered"], c["attack_tactics_total"] = cov, tot
	switch {
	case tot > 0 && cov*2 >= tot:
		lv[sigDetect] = 2
	case cov > 0:
		lv[sigDetect] = 1
	}
	online, total := 0, 0
	if registry != nil {
		for _, st := range registry.Status(time.Now(), 90*time.Second) {
			if st.State == "revoked" {
				continue
			}
			total++
			if st.State == "online" {
				online++
			}
		}
	}
	c["agents_total"], c["agents_online"] = total, online
	switch {
	case total > 0 && online == total:
		lv[sigFleet] = 2
	case online > 0:
		lv[sigFleet] = 1
	}
	auditMu.Lock()
	c["audit_entries"] = len(auditLog)
	auditMu.Unlock()
	if c["audit_entries"] > 0 || len(findings) > 0 {
		lv[sigAudit] = 2 // findings ledger is itself an append-only audit trail
	}
	c["sbom_items"] = len(deriveSBOM())
	if c["sbom_items"] > 0 {
		lv[sigSBOM] = 2
	}
	c["fim_events"] = len(store.ListFiles())
	if c["fim_events"] > 0 {
		lv[sigFIM] = 2
	}
	// Incident workflow: capability always present; exercised when transitions exist.
	lv[sigWorkflow] = 1
	if inc != nil {
		store.mu.Lock()
		c["incident_transitions"] = len(inc.entries)
		store.mu.Unlock()
		if c["incident_transitions"] > 0 {
			lv[sigWorkflow] = 2
		}
	}
	if d != nil {
		d.mu.Lock()
		c["alert_rules"] = len(d.rules)
		c["alert_deliveries"] = len(d.deliveries)
		d.mu.Unlock()
		if c["alert_rules"] > 0 {
			lv[sigAlerts] = 2
		}
	}
	clock := certInClock(store, inc, time.Now().UTC())
	overdue := 0
	for _, e := range clock {
		if e.Overdue {
			overdue++
		}
	}
	c["open_high_critical"] = len(clock)
	c["open_high_critical_overdue"] = overdue
	if overdue == 0 {
		lv[sigTimely] = 2
	}
	return evSignals{Counts: c, Level: lv}
}

// ControlResult is one evaluated control with the evidence used.
type ControlResult struct {
	ID        string         `json:"id"`
	Framework string         `json:"framework"`
	Title     string         `json:"title"`
	Status    string         `json:"status"` // pass | partial | fail | manual | not_applicable
	Note      string         `json:"note,omitempty"`
	Signals   []string       `json:"signals,omitempty"`
	Evidence  map[string]int `json:"evidence,omitempty"`
}

func evaluateControl(c evControl, s evSignals) ControlResult {
	r := ControlResult{ID: c.ID, Framework: c.Framework, Title: c.Title, Note: c.Note, Signals: c.Signals}
	if c.Kind != "" || len(c.Signals) == 0 {
		r.Status = c.Kind
		if r.Status == "" {
			r.Status = "manual"
		}
		return r
	}
	met, none := 0, true
	for _, sg := range c.Signals {
		l := s.Level[sg]
		if l == 2 {
			met++
		}
		if l > 0 {
			none = false
		}
	}
	switch {
	case met == len(c.Signals):
		r.Status = "pass"
	case none:
		r.Status = "fail"
	default:
		r.Status = "partial"
	}
	r.Evidence = map[string]int{}
	for k, v := range s.Counts {
		r.Evidence[k] = v
	}
	return r
}

func lookupFramework(q string) (*evidenceFramework, bool) {
	q = strings.ToLower(strings.TrimSpace(q))
	for i := range evidenceFrameworks {
		if evidenceFrameworks[i].ID == q {
			return &evidenceFrameworks[i], true
		}
	}
	return nil, false
}

// BuildControlResults evaluates the catalog, optionally for a single framework id.
func BuildControlResults(s evSignals, framework string) []ControlResult {
	out := []ControlResult{}
	for _, c := range evidenceCatalog {
		if framework == "" || c.Framework == framework {
			out = append(out, evaluateControl(c, s))
		}
	}
	return out
}

// CertInEntry is an open high/critical incident against the 6-hour window.
type CertInEntry struct {
	FindingID        string    `json:"finding_id"`
	Rule             string    `json:"rule"`
	Host             string    `json:"host"`
	Severity         string    `json:"severity"`
	FirstDetected    time.Time `json:"first_detected"`
	Deadline         time.Time `json:"deadline"`
	RemainingSeconds int64     `json:"remaining_seconds"`
	Overdue          bool      `json:"overdue"`
	Status           string    `json:"status"`
}

func certInClock(store *Store, inc *IncidentStore, now time.Time) []CertInEntry {
	findings := store.List()
	states := map[string]string{}
	if inc != nil {
		store.mu.Lock()
		for id, a := range inc.entries {
			states[id] = a.Status
		}
		store.mu.Unlock()
	}
	out := []CertInEntry{}
	for _, f := range findings {
		if f.Severity != "high" && f.Severity != "critical" {
			continue
		}
		st := states[f.ID]
		if st == "" {
			st = "open"
		}
		if st == "resolved" || st == "false_positive" {
			continue
		}
		dl := f.Time.Add(certInWindow)
		rem := int64(dl.Sub(now).Seconds())
		out = append(out, CertInEntry{FindingID: f.ID, Rule: f.Rule, Host: f.Host, Severity: f.Severity,
			FirstDetected: f.Time.UTC(), Deadline: dl.UTC(), RemainingSeconds: rem, Overdue: rem < 0, Status: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemainingSeconds < out[j].RemainingSeconds })
	return out
}

var evidenceLimitations = []string{
	"Kavach is an observation-only platform. It does not certify, attest or guarantee compliance with any framework.",
	"Statuses are derived from live telemetry counts at the generated-at time and are indicative evidence, not an audit opinion.",
	"Controls marked manual or not_applicable cannot be evidenced by Kavach and require organisational evidence.",
	"The CERT-In clock is informational. Kavach does not file reports or notify any authority.",
	"Framework control lists are representative subsets and may not reflect the latest published revisions.",
}

var evidenceTmpl = template.Must(template.New("ev").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Kavach compliance evidence pack</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;color:#111}
table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #bbb;padding:.35rem .5rem;text-align:left;vertical-align:top}
.pass{color:#0a6b2b}.partial{color:#8a5a00}.fail{color:#b00020}.manual,.not_applicable{color:#555}
@media print{body{margin:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}</style></head><body>
<h1>Kavach compliance evidence pack</h1>
<p>Generated at: <strong>{{.Generated}}</strong> | Mode: observe-only</p>
<h2>Scope</h2><ul>{{range .Frameworks}}<li><strong>{{.Name}}</strong> ({{.ID}}): {{.Scope}}</li>{{end}}</ul>
<h2>Live evidence counts</h2><table><tr><th>Signal</th><th>Count</th></tr>{{range .Counts}}<tr><td>{{.K}}</td><td>{{.V}}</td></tr>{{end}}</table>
<h2>Controls</h2><table><tr><th>Framework</th><th>Control</th><th>Title</th><th>Status</th><th>Evidence / note</th></tr>
{{range .Controls}}<tr><td>{{.Framework}}</td><td>{{.ID}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{.Note}}{{if .Signals}}<br>Signals: {{range .Signals}}{{.}} {{end}}{{end}}</td></tr>{{end}}</table>
<h2>Limitations</h2><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
</body></html>`))

type kv struct {
	K string
	V int
}

// RegisterComplianceEvidence wires control-level compliance evidence routes (observe-only).
func RegisterComplianceEvidence(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry, inc *IncidentStore, d *Dispatcher) {
	parse := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		fw := strings.TrimSpace(r.URL.Query().Get("framework"))
		if fw == "" {
			return "", true
		}
		f, ok := lookupFramework(fw)
		if !ok {
			http.Error(w, "unknown framework", http.StatusBadRequest)
			return "", false
		}
		return f.ID, true
	}
	mux.HandleFunc("GET /v1/compliance/controls", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fw, ok := parse(w, r)
		if !ok {
			return
		}
		s := gatherEvidence(store, registry, inc, d)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generated_at": time.Now().UTC(), "framework": fw, "controls": BuildControlResults(s, fw),
			"counts": s.Counts, "mode": "observe-only", "certification": false,
		})
	})
	mux.HandleFunc("GET /v1/compliance/evidence", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fw, ok := parse(w, r)
		if !ok {
			return
		}
		format := strings.ToLower(r.URL.Query().Get("format"))
		if format == "" {
			format = "json"
		}
		if format != "json" && format != "html" {
			http.Error(w, "format must be json or html", http.StatusBadRequest)
			return
		}
		s := gatherEvidence(store, registry, inc, d)
		controls := BuildControlResults(s, fw)
		var fws []evidenceFramework
		for _, f := range evidenceFrameworks {
			if fw == "" || f.ID == fw {
				fws = append(fws, f)
			}
		}
		now := time.Now().UTC()
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"generated_at": now, "scope": fws, "controls": controls, "counts": s.Counts,
				"limitations": evidenceLimitations, "mode": "observe-only", "certification": false,
			})
			return
		}
		keys := make([]string, 0, len(s.Counts))
		for k := range s.Counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		counts := make([]kv, 0, len(keys))
		for _, k := range keys {
			counts = append(counts, kv{k, s.Counts[k]})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = evidenceTmpl.Execute(w, map[string]any{
			"Generated": now.Format(time.RFC3339), "Frameworks": fws, "Counts": counts,
			"Controls": controls, "Limitations": evidenceLimitations,
		})
	})
	mux.HandleFunc("GET /v1/compliance/cert-in-clock", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		now := time.Now().UTC()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generated_at": now, "window_hours": 6, "incidents": certInClock(store, inc, now),
			"informational": true, "note": "Kavach does not file CERT-In reports; this clock is informational only.",
		})
	})
}
