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

// WorldModule maps a global-vendor capability onto Kavach (observation-only).
type WorldModule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Vendors  []string `json:"vendors"` // who ships an analogue
	Status   string   `json:"status"`
	APIs     []string `json:"apis"`
	Note     string   `json:"note"`
}

func WorldModules() []WorldModule {
	return []WorldModule{
		{ID: "storyline", Name: "Attack Storyline", Vendors: []string{"SentinelOne Storyline", "Cortex Causality", "MDE Timeline"}, Status: "active", APIs: []string{"/v1/storyline"}, Note: "Reconstruct process/network chain"},
		{ID: "air", Name: "Automated Investigation", Vendors: []string{"Microsoft AIR", "S1 Purple Auto-Triage"}, Status: "active", APIs: []string{"/v1/air/investigations"}, Note: "Suggested investigation steps — never auto-remediates"},
		{ID: "advanced-hunt", Name: "Advanced Hunting (KQL-lite)", Vendors: []string{"Microsoft Advanced Hunting", "Elastic ES|QL", "S1 Purple PowerQuery"}, Status: "active", APIs: []string{"/v1/hunt/kql"}, Note: "Query language over findings/events"},
		{ID: "ranger", Name: "Network Discovery", Vendors: []string{"SentinelOne Ranger", "CrowdStrike Discover Network"}, Status: "active", APIs: []string{"/v1/network-discovery"}, Note: "Unmanaged / rogue device inventory"},
		{ID: "deception", Name: "Deception / Honeytokens", Vendors: []string{"Proofpoint", "Zscaler Deception", "Elastic Deception"}, Status: "active", APIs: []string{"/v1/deception"}, Note: "Decoy assets + tripwire events"},
		{ID: "casb", Name: "CASB / SaaS Security", Vendors: []string{"Microsoft Defender for Cloud Apps", "Netskope", "Prisma"}, Status: "active", APIs: []string{"/v1/casb/apps"}, Note: "SaaS app risk inventory"},
		{ID: "email", Name: "Email Security", Vendors: []string{"Proofpoint", "Mimecast", "Defender for Office"}, Status: "active", APIs: []string{"/v1/email/threats"}, Note: "Phish / BEC / malware mail signals"},
		{ID: "dlp", Name: "Data Loss Prevention", Vendors: []string{"Symantec DLP", "Forcepoint", "Microsoft Purview"}, Status: "active", APIs: []string{"/v1/dlp/events"}, Note: "Sensitive-data movement signals"},
		{ID: "cnapp", Name: "CNAPP / CWPP", Vendors: []string{"Wiz", "Prisma Cloud", "Defender for Cloud", "S1 Cloud"}, Status: "active", APIs: []string{"/v1/cnapp/workloads", "/v1/cnapp/misconfigs"}, Note: "Cloud workload + posture"},
		{ID: "asrm", Name: "Exposure / ASRM", Vendors: []string{"CrowdStrike ExPRT", "S1 Exposure", "Tenable"}, Status: "active", APIs: []string{"/v1/exposure"}, Note: "Attack-surface risk ranking"},
		{ID: "compliance", Name: "Compliance Posture", Vendors: []string{"Wiz Compliance", "Prisma", "Rapid7"}, Status: "active", APIs: []string{"/v1/compliance"}, Note: "CIS / NIST control mapping"},
		{ID: "forensics", Name: "Forensic Package", Vendors: []string{"CrowdStrike Falcon Forensics", "MDE investigation package"}, Status: "active", APIs: []string{"/v1/forensics"}, Note: "Collection requests — ledger only"},
		{ID: "fim", Name: "File Integrity Monitoring", Vendors: []string{"OSSEC/Wazuh", "Tripwire", "Elastic FIM"}, Status: "active", APIs: []string{"/v1/fim"}, Note: "Critical path change watch"},
		{ID: "persistence", Name: "Persistence Hunt", Vendors: []string{"MDE", "Elastic", "Velociraptor"}, Status: "active", APIs: []string{"/v1/persistence"}, Note: "Cron/systemd/autorun inventory"},
		{ID: "yara", Name: "YARA Rules", Vendors: []string{"Elastic", "CrowdStrike", "VirusTotal"}, Status: "active", APIs: []string{"/v1/yara"}, Note: "Custom YARA rule library"},
		{ID: "sigma", Name: "Sigma Rules", Vendors: []string{"Elastic", "Splunk", "SigmaHQ"}, Status: "active", APIs: []string{"/v1/sigma"}, Note: "Sigma detection rule library"},
		{ID: "watchlists", Name: "Watchlists", Vendors: []string{"Splunk", "Sentinel", "Elastic"}, Status: "active", APIs: []string{"/v1/watchlists"}, Note: "Entity watchlists"},
		{ID: "exclusions", Name: "Exclusions / Suppressions", Vendors: []string{"All major EDR"}, Status: "active", APIs: []string{"/v1/exclusions"}, Note: "Detection suppressions"},
		{ID: "sensor-health", Name: "Sensor Coverage Gaps", Vendors: []string{"S1 Ranger gaps", "Falcon sensor health"}, Status: "active", APIs: []string{"/v1/sensor-health"}, Note: "Coverage / stale / missing agents"},
		{ID: "sandbox", Name: "Sandbox Detonation", Vendors: []string{"CrowdStrike Falcon Sandbox", "Joe Sandbox", "Any.Run"}, Status: "active", APIs: []string{"/v1/sandbox"}, Note: "Detonation report stubs"},
		{ID: "itsm", Name: "ITSM Ticketing", Vendors: []string{"ServiceNow", "Jira", "PagerDuty"}, Status: "active", APIs: []string{"/v1/itsm/tickets"}, Note: "Ticket ledger / connectors"},
		{ID: "notify", Name: "Notification Channels", Vendors: []string{"Slack", "Teams", "PagerDuty", "Email"}, Status: "active", APIs: []string{"/v1/notify/channels"}, Note: "Alert channel registry"},
		{ID: "rbac", Name: "RBAC Roles", Vendors: []string{"All enterprise platforms"}, Status: "active", APIs: []string{"/v1/rbac/roles"}, Note: "Role catalog (auth still token/session)"},
		{ID: "tenants", Name: "Multi-site / Tenants", Vendors: []string{"MSSP multi-tenant consoles"}, Status: "active", APIs: []string{"/v1/tenants"}, Note: "Logical site inventory"},
		{ID: "retention", Name: "Data Retention", Vendors: []string{"Threat Graph retention", "Data Lake"}, Status: "active", APIs: []string{"/v1/retention"}, Note: "Retention policy"},
		{ID: "bas", Name: "Breach & Attack Simulation", Vendors: []string{"SafeBreach", "AttackIQ", "Cymulate"}, Status: "active", APIs: []string{"/v1/bas"}, Note: "Purple-team simulation ledger"},
		{ID: "zero-trust", Name: "Zero Trust Score", Vendors: []string{"Microsoft ZT", "Zscaler", "Cloudflare"}, Status: "active", APIs: []string{"/v1/zero-trust"}, Note: "ZT posture scorecard"},
		{ID: "dns-security", Name: "DNS Security", Vendors: []string{"Cisco Umbrella", "Infoblox", "Netra DNS"}, Status: "active", APIs: []string{"/v1/dns/threats"}, Note: "Malicious DNS / DoH signals"},
		{ID: "ot-iot", Name: "OT / IoT", Vendors: []string{"Nozomi", "Claroty", "Microsoft Defender for IoT"}, Status: "preview", APIs: []string{"/v1/ot/devices"}, Note: "OT/IoT asset inventory"},
		{ID: "sbom", Name: "Supply Chain / SBOM", Vendors: []string{"Snyk", "Anchore", "FOSSA"}, Status: "active", APIs: []string{"/v1/sbom"}, Note: "Component inventory + CVEs"},
		{ID: "hyperauto", Name: "Hyperautomation", Vendors: []string{"S1 Hyperautomation", "Cortex XSOAR", "Splunk SOAR"}, Status: "active", APIs: []string{"/v1/hyperautomation/workflows"}, Note: "No-code workflow catalog (ledger)"},
		{ID: "mdr", Name: "MDR / Vigilance Desk", Vendors: []string{"S1 Vigilance", "Falcon Complete", "MDE Experts"}, Status: "active", APIs: []string{"/v1/mdr/queue"}, Note: "Managed detection queue"},
		{ID: "geoip", Name: "Geo enrichment", Vendors: []string{"MaxMind", "CrowdStrike", "Elastic"}, Status: "active", APIs: []string{"/v1/enrich/geo"}, Note: "IP → geo stub enrichment"},
		{ID: "tls-inventory", Name: "TLS / Cert Inventory", Vendors: []string{"Censys", "Qualys SSL"}, Status: "active", APIs: []string{"/v1/tls/certs"}, Note: "Certificate inventory"},
		{ID: "rollback", Name: "Rollback Advisor", Vendors: []string{"SentinelOne Rollback"}, Status: "active", APIs: []string{"/v1/rollback"}, Note: "Guidance only — never restores files"},
		{ID: "custom-rules", Name: "Custom Detection Engine", Vendors: []string{"S1 STAR", "Elastic rules", "Splunk"}, Status: "active", APIs: []string{"/v1/rules"}, Note: "Custom detection rule store"},
		{ID: "browser", Name: "Browser / Extension Risk", Vendors: []string{"Island", "Chrome Enterprise", "Talon"}, Status: "preview", APIs: []string{"/v1/browser/extensions"}, Note: "Browser extension inventory"},
		{ID: "mfa-fatigue", Name: "MFA Fatigue / ITDR+", Vendors: []string{"CrowdStrike Identity", "Microsoft ITDR"}, Status: "active", APIs: []string{"/v1/itdr/mfa"}, Note: "MFA push-bomb / token abuse signals"},
		{ID: "world-catalog", Name: "Global Capability Catalog", Vendors: []string{"AMTSO XDR matrix", "IDC XDR 2025"}, Status: "active", APIs: []string{"/v1/world/modules"}, Note: "This catalog"},
	}
}

var (
	worldMu       sync.Mutex
	yaraRules     = defaultYARA()
	sigmaRules    = defaultSigma()
	watchlists    = []map[string]any{{"id": "wl-vip", "name": "VIP users", "entities": []string{"admin", "ceo"}, "type": "user"}}
	exclusions    = []map[string]any{}
	customRules   = defaultCustomRules()
	deceptionDecoys = defaultDeception()
	forensicReqs  []map[string]any
	basRuns       []map[string]any
	itsmTickets   []map[string]any
	hyperFlows    = defaultHyper()
)

func defaultYARA() []map[string]any {
	return []map[string]any{
		{"id": "yara-1", "name": "suspicious_packer", "rule": "rule SusPacker { strings: $a = \"UPX!\" condition: $a }", "enabled": true},
		{"id": "yara-2", "name": "webshell_php", "rule": "rule WebShell { strings: $a = \"eval($_\" condition: $a }", "enabled": true},
	}
}
func defaultSigma() []map[string]any {
	return []map[string]any{
		{"id": "sigma-1", "title": "Curl to Bash Pipe", "level": "high", "status": "stable", "logsource": "process_creation"},
		{"id": "sigma-2", "title": "Shadow Copy Delete", "level": "critical", "status": "stable", "logsource": "process_creation"},
	}
}
func defaultCustomRules() []map[string]any {
	return []map[string]any{
		{"id": "rule-1", "name": "star-lotl-shell", "engine": "star", "query": "process.cmd contains '/dev/tcp/'", "enabled": true},
		{"id": "rule-2", "name": "star-mass-encrypt", "engine": "star", "query": "file.ext in (encrypted,locked)", "enabled": true},
	}
}
func defaultDeception() []map[string]any {
	return []map[string]any{
		{"id": "dec-1", "type": "honeytoken", "name": "aws-keys-decoy", "host": "demo-host", "triggered": false},
		{"id": "dec-2", "type": "decoy_share", "name": "finance-q4.xlsx", "host": "demo-host", "triggered": false},
		{"id": "dec-3", "type": "decoy_account", "name": "svc-backup-decoy", "host": "id-plane", "triggered": false},
	}
}
func defaultHyper() []map[string]any {
	return []map[string]any{
		{"id": "ha-1", "name": "Notify Slack on critical", "trigger": "severity=critical", "actions": []string{"notify_slack", "create_case"}, "enabled": true},
		{"id": "ha-2", "name": "Open ITSM on ransomware family", "trigger": "family=ransomware", "actions": []string{"itsm_ticket", "mdr_escalate"}, "enabled": true},
		{"id": "ha-3", "name": "Enrich + hunt on C2", "trigger": "family=c2_network", "actions": []string{"enrich_geo", "nl_hunt", "ioc_detect_only"}, "enabled": true},
	}
}

// RegisterWorldPlatform adds global-vendor parity APIs beyond Falcon.
func RegisterWorldPlatform(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/world/modules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count": len(WorldModules()), "modules": WorldModules(),
			"note": "Global XDR/EDR/SIEM/SOAR/CNAPP/ITDR capability map — observation-only where peers enforce",
		})
	})

	// Storyline (SentinelOne)
	mux.HandleFunc("GET /v1/storyline", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(buildStoryline(store, id, host))
	})

	// AIR (Microsoft)
	mux.HandleFunc("GET /v1/air/investigations", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out := []map[string]any{}
		for _, f := range store.List() {
			out = append(out, map[string]any{
				"finding_id": f.ID, "status": "suggested",
				"steps": []string{"Collect process tree", "Run AI classify", "Check similarity", "NL hunt same host", "Draft case"},
				"verdict_hint": classifyBehavior(f).Family,
				"auto_remediate": false,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// Advanced hunting KQL-lite
	mux.HandleFunc("POST /v1/hunt/kql", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		var body struct {
			Query string `json:"query"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Query == "" {
			http.Error(w, "invalid", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runKQLLite(body.Query, store))
	})

	// Network discovery / Ranger
	mux.HandleFunc("GET /v1/network-discovery", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		managed := map[string]bool{}
		if registry != nil {
			for _, st := range registry.Status(time.Now(), 90*time.Second) {
				managed[st.Host] = true
			}
		}
		for _, f := range store.List() {
			managed[f.Host] = true
		}
		devices := []map[string]any{
			{"ip": "10.0.0.1", "hostname": "gateway", "type": "router", "managed": false, "risk": "medium"},
			{"ip": "10.0.0.50", "hostname": "printer-finance", "type": "iot", "managed": false, "risk": "low"},
			{"ip": "10.0.0.66", "hostname": "unknown-laptop", "type": "endpoint", "managed": false, "risk": "high"},
		}
		for h := range managed {
			devices = append(devices, map[string]any{"hostname": h, "type": "endpoint", "managed": true, "risk": "low"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": devices, "unmanaged": 3, "note": "Passive discovery seed + managed hosts"})
	})

	registerJSONList(mux, token, "GET /v1/deception", func() any {
		worldMu.Lock()
		defer worldMu.Unlock()
		return deceptionDecoys
	})
	mux.HandleFunc("POST /v1/deception/trigger", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var body struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		worldMu.Lock()
		for i := range deceptionDecoys {
			if deceptionDecoys[i]["id"] == body.ID {
				deceptionDecoys[i]["triggered"] = true
				deceptionDecoys[i]["triggered_at"] = time.Now().UTC()
			}
		}
		worldMu.Unlock()
		AppendAudit(token, "deception.trigger", body.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /v1/casb/apps", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"app": "Slack", "category": "collaboration", "risk": "medium", "users": 42, "sanctioned": true},
			{"app": "Dropbox", "category": "storage", "risk": "high", "users": 8, "sanctioned": false},
			{"app": "GitHub", "category": "dev", "risk": "low", "users": 30, "sanctioned": true},
			{"app": "ChatGPT", "category": "genai", "risk": "high", "users": 12, "sanctioned": false},
		})
	})

	mux.HandleFunc("GET /v1/email/threats", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "em-1", "type": "phishing", "subject": "Invoice overdue", "from": "billing@evil.example", "severity": "high"},
			{"id": "em-2", "type": "bec", "subject": "Wire transfer", "from": "ceo@lookalike.example", "severity": "critical"},
			{"id": "em-3", "type": "malware", "subject": "Resume.pdf.exe", "from": "hr@spam.example", "severity": "high"},
		})
	})

	mux.HandleFunc("GET /v1/dlp/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "dlp-1", "host": "demo-host", "channel": "usb", "label": "PII", "action": "observed", "severity": "medium"},
			{"id": "dlp-2", "host": "demo-host", "channel": "cloud_upload", "label": "source_code", "action": "observed", "severity": "high"},
		})
	})

	mux.HandleFunc("GET /v1/cnapp/workloads", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "wl-1", "provider": "aws", "type": "ec2", "name": "api-prod", "risk": "high", "public": true},
			{"id": "wl-2", "provider": "k8s", "type": "pod", "name": "kavach", "risk": "low", "public": false},
			{"id": "wl-3", "provider": "gcp", "type": "gke", "name": "batch", "risk": "medium", "public": false},
		})
	})
	mux.HandleFunc("GET /v1/cnapp/misconfigs", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "mc-1", "control": "s3-public", "severity": "critical", "resource": "logs-bucket"},
			{"id": "mc-2", "control": "sg-0.0.0.0/0:22", "severity": "high", "resource": "sg-prod"},
			{"id": "mc-3", "control": "k8s-privileged", "severity": "medium", "resource": "daemonset/agent"},
		})
	})

	mux.HandleFunc("GET /v1/exposure", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		findings := store.List()
		score := 20 + len(findings)*4
		if score > 95 {
			score = 95
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"exposure_score": score, "level": riskLevel(score),
			"top_exposures": []map[string]any{
				{"id": "exp-1", "title": "Internet-facing SSH", "score": 82},
				{"id": "exp-2", "title": "Unpatched openssl (Spotlight)", "score": 78},
				{"id": "exp-3", "title": "Unmanaged laptop (Ranger)", "score": 70},
			},
		})
	})

	mux.HandleFunc("GET /v1/compliance", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"framework": "CIS Kubernetes", "pass": 18, "fail": 4, "score": 82},
			{"framework": "NIST CSF", "pass": 40, "fail": 12, "score": 77},
			{"framework": "SOC2 CC6", "pass": 22, "fail": 3, "score": 88},
			{"framework": "ISO 27001", "pass": 55, "fail": 9, "score": 86},
		})
	})

	mux.HandleFunc("GET /v1/forensics", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		worldMu.Lock()
		out := append([]map[string]any{}, forensicReqs...)
		worldMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/forensics", func(w http.ResponseWriter, r *http.Request) {
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
		body["id"] = "for-" + time.Now().UTC().Format("20060102150405")
		body["status"] = "requested"
		body["collected"] = false
		body["note"] = "Observation-only: package request recorded, not collected automatically"
		body["time"] = time.Now().UTC()
		worldMu.Lock()
		forensicReqs = append(forensicReqs, body)
		worldMu.Unlock()
		AppendAudit(token, "forensics.request", fmt.Sprint(body["host"]))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("GET /v1/fim", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"path": "/etc/passwd", "host": "demo-host", "change": "hash_changed", "severity": "high"},
			{"path": "/etc/ssh/sshd_config", "host": "demo-host", "change": "modified", "severity": "critical"},
		})
	})

	mux.HandleFunc("GET /v1/persistence", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"host": "demo-host", "type": "systemd", "name": "kavach-agent.service", "risk": "low"},
			{"host": "demo-host", "type": "cron", "name": "*/5 * * * * curl evil", "risk": "critical"},
			{"host": "demo-host", "type": "bashrc", "name": "alias sudo=", "risk": "high"},
		})
	})

	registerJSONList(mux, token, "GET /v1/yara", func() any { worldMu.Lock(); defer worldMu.Unlock(); return yaraRules })
	registerJSONList(mux, token, "GET /v1/sigma", func() any { worldMu.Lock(); defer worldMu.Unlock(); return sigmaRules })
	registerJSONList(mux, token, "GET /v1/watchlists", func() any { worldMu.Lock(); defer worldMu.Unlock(); return watchlists })
	registerJSONList(mux, token, "GET /v1/exclusions", func() any { worldMu.Lock(); defer worldMu.Unlock(); return exclusions })
	registerJSONList(mux, token, "GET /v1/rules", func() any { worldMu.Lock(); defer worldMu.Unlock(); return customRules })

	mux.HandleFunc("POST /v1/watchlists", func(w http.ResponseWriter, r *http.Request) {
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
		if body["id"] == nil {
			body["id"] = "wl-" + time.Now().UTC().Format("150405")
		}
		worldMu.Lock()
		watchlists = append(watchlists, body)
		worldMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("POST /v1/exclusions", func(w http.ResponseWriter, r *http.Request) {
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
		body["id"] = "ex-" + time.Now().UTC().Format("150405")
		worldMu.Lock()
		exclusions = append(exclusions, body)
		worldMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("POST /v1/rules", func(w http.ResponseWriter, r *http.Request) {
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
		body["id"] = "rule-" + time.Now().UTC().Format("150405")
		body["enabled"] = true
		worldMu.Lock()
		customRules = append(customRules, body)
		worldMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("GET /v1/sensor-health", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out := []map[string]any{}
		if registry != nil {
			for _, st := range registry.Status(time.Now(), 90*time.Second) {
				out = append(out, map[string]any{"host": st.Host, "state": st.State, "sensor": st.Sensor, "coverage": st.State == "online"})
			}
		}
		out = append(out, map[string]any{"host": "unknown-laptop", "state": "missing", "sensor": "", "coverage": false, "gap": true})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("GET /v1/sandbox", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "sbx-1", "sha256": "deadbeef…", "verdict": "malicious", "family": "trojan.generic", "score": 92},
			{"id": "sbx-2", "sha256": "cafebabe…", "verdict": "suspicious", "family": "pua", "score": 61},
		})
	})

	mux.HandleFunc("GET /v1/itsm/tickets", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		worldMu.Lock()
		out := append([]map[string]any{}, itsmTickets...)
		worldMu.Unlock()
		if len(out) == 0 {
			out = []map[string]any{{"id": "INC001", "system": "jira", "title": "Seed: review OverWatch alert", "status": "open"}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/itsm/tickets", func(w http.ResponseWriter, r *http.Request) {
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
		body["id"] = "INC" + time.Now().UTC().Format("150405")
		body["status"] = "open"
		worldMu.Lock()
		itsmTickets = append(itsmTickets, body)
		worldMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("GET /v1/notify/channels", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "ch-slack", "type": "slack", "status": "configured"},
			{"id": "ch-teams", "type": "teams", "status": "optional"},
			{"id": "ch-email", "type": "email", "status": "optional"},
			{"id": "ch-pagerduty", "type": "pagerduty", "status": "optional"},
		})
	})

	mux.HandleFunc("GET /v1/rbac/roles", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "role-admin", "name": "Administrator", "permissions": []string{"*"}},
			{"id": "role-analyst", "name": "Analyst", "permissions": []string{"read", "triage", "hunt", "cases"}},
			{"id": "role-viewer", "name": "Viewer", "permissions": []string{"read"}},
			{"id": "role-mssp", "name": "MSSP Operator", "permissions": []string{"read", "triage", "tenants"}},
		})
	})

	mux.HandleFunc("GET /v1/tenants", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "site-default", "name": "Default", "hosts": len(store.List())},
			{"id": "site-lab", "name": "Lab", "hosts": 0},
			{"id": "site-prod", "name": "Production", "hosts": 0},
		})
	})

	mux.HandleFunc("GET /v1/retention", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"findings_days": 90, "events_days": 30, "ai_chat_days": 14, "audit_days": 365,
		})
	})

	mux.HandleFunc("GET /v1/bas", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		worldMu.Lock()
		out := append([]map[string]any{}, basRuns...)
		worldMu.Unlock()
		if len(out) == 0 {
			out = []map[string]any{{"id": "bas-1", "scenario": "ransomware_sim", "result": "detected", "coverage": "partial"}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/bas", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["id"] = "bas-" + time.Now().UTC().Format("150405")
		body["result"] = "scheduled"
		body["note"] = "Simulation ledger only — no live attack traffic generated"
		worldMu.Lock()
		basRuns = append(basRuns, body)
		worldMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("GET /v1/zero-trust", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score": 74, "level": "moderate",
			"pillars": map[string]int{"identity": 70, "device": 80, "network": 65, "application": 72, "data": 68},
		})
	})

	mux.HandleFunc("GET /v1/dns/threats", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"query": "evil-c2.example", "type": "A", "verdict": "malicious", "host": "demo-host"},
			{"query": "dns.google", "type": "DoH", "verdict": "doh_tunnel_suspect", "host": "demo-host"},
		})
	})

	mux.HandleFunc("GET /v1/ot/devices", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "ot-1", "name": "plc-line-1", "protocol": "modbus", "risk": "medium"},
			{"id": "ot-2", "name": "hmi-packaging", "protocol": "opcua", "risk": "low"},
		})
	})

	mux.HandleFunc("GET /v1/sbom", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"component": "openssl", "version": "3.0.12", "cves": []string{"CVE-2024-XXXX"}, "severity": "high"},
			{"component": "curl", "version": "8.5.0", "cves": []string{}, "severity": "low"},
		})
	})

	registerJSONList(mux, token, "GET /v1/hyperautomation/workflows", func() any {
		worldMu.Lock()
		defer worldMu.Unlock()
		return hyperFlows
	})

	mux.HandleFunc("GET /v1/mdr/queue", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "mdr-1", "title": "OverWatch seed: LOTL chain", "priority": "high", "status": "queued", "source": "overwatch"},
			{"id": "mdr-2", "title": "Identity spray review", "priority": "medium", "status": "in_progress", "source": "identity"},
		})
	})

	mux.HandleFunc("GET /v1/enrich/geo", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			ip = "203.0.113.66"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ip": ip, "country": "ZZ", "city": "Documentation Land", "asn": "AS64500", "risk": "medium",
			"note": "Stub geo enrichment for demos",
		})
	})

	mux.HandleFunc("GET /v1/tls/certs", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"host": "kavach.local", "not_after": "2027-01-01", "issuer": "self-signed", "risk": "medium"},
			{"host": "api.example", "not_after": "2026-06-01", "issuer": "Let's Encrypt", "risk": "low"},
		})
	})

	mux.HandleFunc("GET /v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"finding_id": id,
			"advice": []string{"Snapshot VSS/ZFS before changes", "Restore from known-good backup", "Do not rely on Kavach to rollback — observation only"},
			"enforced": false,
		})
	})

	mux.HandleFunc("GET /v1/browser/extensions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "uBlock", "risk": "low", "host": "demo-host"},
			{"name": "Unknown Wallet Helper", "risk": "high", "host": "demo-host"},
		})
	})

	mux.HandleFunc("GET /v1/itdr/mfa", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"user": "admin", "type": "mfa_fatigue", "pushes": 14, "severity": "high", "window_min": 10},
			{"user": "svc-backup", "type": "token_replay_suspect", "severity": "critical"},
		})
	})

	_ = store
}

func registerJSONList(mux *http.ServeMux, token, pattern string, list func() any) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list())
	})
}

func buildStoryline(store *Store, findingID, host string) map[string]any {
	nodes := []map[string]any{}
	edges := []map[string]any{}
	add := func(id, label, typ string) {
		nodes = append(nodes, map[string]any{"id": id, "label": label, "type": typ})
	}
	if f, ok := findByID(store, findingID); ok {
		host = f.Host
		root := "proc:" + f.Evidence.ParentExe
		child := "proc:" + f.Evidence.Executable
		add("host:"+f.Host, f.Host, "host")
		add(root, f.Evidence.ParentExe, "process")
		add(child, f.Evidence.Executable, "process")
		edges = append(edges, map[string]any{"from": "host:" + f.Host, "to": root, "rel": "runs"})
		edges = append(edges, map[string]any{"from": root, "to": child, "rel": "spawns"})
		if f.Destination != "" {
			add("net:"+f.Destination, f.Destination, "network")
			edges = append(edges, map[string]any{"from": child, "to": "net:" + f.Destination, "rel": "connects"})
		}
		add("finding:"+f.ID, f.Rule, "finding")
		edges = append(edges, map[string]any{"from": child, "to": "finding:" + f.ID, "rel": "triggers"})
	} else {
		store.mu.Lock()
		for i, e := range store.recentEvents {
			if host != "" && e.Host != host {
				continue
			}
			if i > 20 {
				break
			}
			id := fmt.Sprintf("e%d", i)
			add(id, e.Executable, "process")
			if i > 0 {
				edges = append(edges, map[string]any{"from": fmt.Sprintf("e%d", i-1), "to": id, "rel": "followed_by"})
			}
		}
		store.mu.Unlock()
	}
	return map[string]any{"host": host, "finding_id": findingID, "nodes": nodes, "edges": edges, "vendor_analogue": "SentinelOne Storyline"}
}

func runKQLLite(query string, store *Store) map[string]any {
	q := strings.ToLower(query)
	// Tiny subset: DeviceProcessEvents | where ... ; Findings | where ...
	rows := []map[string]any{}
	if strings.Contains(q, "finding") || strings.Contains(q, "alert") || strings.Contains(q, "detection") {
		for _, f := range store.List() {
			if matchKQLFinding(q, f) {
				rows = append(rows, map[string]any{"id": f.ID, "host": f.Host, "rule": f.Rule, "severity": f.Severity, "time": f.Time})
			}
		}
	} else {
		store.mu.Lock()
		for _, e := range store.recentEvents {
			if matchKQLEvent(q, e) {
				rows = append(rows, map[string]any{"host": e.Host, "exe": e.Executable, "cmd": e.Command, "pid": e.PID, "time": e.Time})
			}
		}
		store.mu.Unlock()
	}
	return map[string]any{"query": query, "rows": rows, "count": len(rows), "dialect": "kql-lite", "note": "Subset of MDE Advanced Hunting / ES|QL style"}
}

func matchKQLFinding(q string, f Finding) bool {
	hay := strings.ToLower(f.Host + " " + f.Rule + " " + f.Severity + " " + f.Description)
	if strings.Contains(q, "severity") && strings.Contains(q, "high") && f.Severity != "high" && f.Severity != "critical" {
		return false
	}
	for _, tok := range []string{"ransomware", "shell", "download", "curl", "root"} {
		if strings.Contains(q, tok) && !strings.Contains(hay, tok) && !strings.Contains(strings.ToLower(f.Evidence.Command), tok) {
			return false
		}
	}
	return true
}

func matchKQLEvent(q string, e Event) bool {
	hay := strings.ToLower(e.Host + " " + e.Executable + " " + e.Command)
	if strings.Contains(q, "where") {
		// require at least one keyword from query present
		hit := false
		for _, tok := range []string{"curl", "bash", "wget", "nc", "python", "ssh"} {
			if strings.Contains(q, tok) && strings.Contains(hay, tok) {
				hit = true
			}
		}
		if !hit && (strings.Contains(q, "curl") || strings.Contains(q, "bash") || strings.Contains(q, "wget")) {
			return false
		}
	}
	return true
}
