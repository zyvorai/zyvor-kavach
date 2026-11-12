// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
)

// FalconModule mirrors CrowdStrike Falcon console modules as Kavach capabilities.
// All response actions remain observation-only ledgers (no kill/isolate/enforce).
type FalconModule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CrowdStrike string   `json:"crowdstrike_analogue"`
	Status      string   `json:"status"`
	APIs        []string `json:"apis"`
	Note        string   `json:"note"`
}

func FalconModules() []FalconModule {
	return []FalconModule{
		{ID: "prevent", Name: "Prevent (NGAV)", CrowdStrike: "Falcon Prevent", Status: "active", APIs: []string{"/v1/prevention/policies", "/v1/ioc", "/v1/ioa"}, Note: "Detect-only ML/IOA/IOC; no quarantine"},
		{ID: "insight", Name: "Insight EDR/XDR", CrowdStrike: "Falcon Insight XDR", Status: "active", APIs: []string{"/v1/detections", "/v1/findings", "/v1/timeline"}, Note: "Detections with MITRE mapping"},
		{ID: "device-control", Name: "Device Control", CrowdStrike: "Falcon Device Control", Status: "active", APIs: []string{"/v1/device-control"}, Note: "USB/device visibility"},
		{ID: "firewall", Name: "Firewall Management", CrowdStrike: "Falcon Firewall Management", Status: "active", APIs: []string{"/v1/firewall/rules"}, Note: "Host firewall inventory"},
		{ID: "discover", Name: "Discover", CrowdStrike: "Falcon Discover", Status: "active", APIs: []string{"/v1/discover/assets", "/v1/discover/apps"}, Note: "IT hygiene / asset inventory"},
		{ID: "spotlight", Name: "Spotlight", CrowdStrike: "Falcon Spotlight", Status: "active", APIs: []string{"/v1/spotlight/vulnerabilities"}, Note: "CVE posture from sensor inventory"},
		{ID: "overwatch", Name: "OverWatch", CrowdStrike: "Falcon Adversary OverWatch", Status: "active", APIs: []string{"/v1/overwatch/alerts"}, Note: "Managed hunting alert feed"},
		{ID: "intel", Name: "Adversary Intel", CrowdStrike: "Falcon X / Adversary Intelligence", Status: "active", APIs: []string{"/v1/intel/actors", "/v1/intel/indicators"}, Note: "Actor profiles + IOC intel"},
		{ID: "identity", Name: "Identity Protection", CrowdStrike: "Falcon Identity", Status: "active", APIs: []string{"/v1/identity/events", "/v1/identity/entities"}, Note: "Identity anomalies + lateral movement signals"},
		{ID: "fusion", Name: "Fusion SOAR", CrowdStrike: "Falcon Fusion", Status: "active", APIs: []string{"/v1/fusion/playbooks", "/v1/fusion/runs"}, Note: "Playbook orchestration (notify/ledger only)"},
		{ID: "rtr", Name: "Real Time Response", CrowdStrike: "Falcon RTR", Status: "active", APIs: []string{"/v1/rtr/sessions", "/v1/rtr/commands"}, Note: "Read-only diagnostic queries from store"},
		{ID: "hosts", Name: "Host Management", CrowdStrike: "Host Management", Status: "active", APIs: []string{"/v1/hosts", "/v1/host-groups", "/v1/containment"}, Note: "Containment is a request ledger only"},
		{ID: "siem", Name: "Next-Gen SIEM", CrowdStrike: "Falcon Next-Gen SIEM", Status: "active", APIs: []string{"/v1/siem/status", "/v1/cases", "/v1/ueba"}, Note: "Export, cases, UEBA"},
		{ID: "hunt", Name: "Threat Hunting", CrowdStrike: "Falcon Hunt / FQL", Status: "active", APIs: []string{"/v1/hunt/query", "/v1/threat-graph"}, Note: "Structured hunt + correlation graph"},
		{ID: "charlotte", Name: "Charlotte AI", CrowdStrike: "Charlotte AI", Status: "active", APIs: []string{"/v1/ai/score", "/v1/ai/assist"}, Note: "Assistive triage (heuristic + optional LLM)"},
		{ID: "kavach-ai", Name: "Kavach AI Platform", CrowdStrike: "Beyond Charlotte / Complete", Status: "active", APIs: []string{"/v1/ai/capabilities"}, Note: "22+ AI capabilities beyond Falcon"},
		{ID: "multi-agent", Name: "Multi-Agent SOC", CrowdStrike: "Beyond Falcon Complete agents", Status: "active", APIs: []string{"/v1/ai/agents", "/v1/ai/agents/run"}, Note: "Triage/Hunt/Intel/IR/Reporter agents"},
		{ID: "nl-hunt", Name: "NL Threat Hunt", CrowdStrike: "Beyond FQL", Status: "active", APIs: []string{"/v1/ai/nl-hunt"}, Note: "Natural language → hunt"},
		{ID: "forecast", Name: "Breach Forecast", CrowdStrike: "Beyond ExPRT", Status: "active", APIs: []string{"/v1/ai/forecast"}, Note: "72h risk forecast"},
		{ID: "what-if", Name: "What-If Simulator", CrowdStrike: "n/a", Status: "active", APIs: []string{"/v1/ai/what-if"}, Note: "Adversary progression simulation"},
		{ID: "guardian-ai", Name: "AI Workload Guardian", CrowdStrike: "Falcon Guardian+", Status: "active", APIs: []string{"/v1/ai/guardian"}, Note: "Observe AI/agent processes"},
		{ID: "xdr-ai", Name: "Netra×Kavach AI Fusion", CrowdStrike: "Beyond Insight XDR", Status: "active", APIs: []string{"/v1/ai/xdr-fusion"}, Note: "Cross-domain AI correlation"},
		{ID: "cloud", Name: "Cloud Security", CrowdStrike: "Falcon Cloud / Horizon", Status: "active", APIs: []string{"/v1/cloud/posture"}, Note: "CSPM posture via POST /v1/inventory domain=cloud"},
		{ID: "mobile", Name: "Mobile", CrowdStrike: "Falcon for Mobile", Status: "active", APIs: []string{"/v1/mobile/devices"}, Note: "MDM inventory via POST /v1/inventory domain=mobile"},
		{ID: "audit", Name: "Audit & Reports", CrowdStrike: "Audit Logs / Dashboards", Status: "active", APIs: []string{"/v1/audit", "/v1/reports/summary"}, Note: "Console audit + SOC summary"},
		{ID: "connectors", Name: "Connectors", CrowdStrike: "Falcon Connectors", Status: "active", APIs: []string{"/v1/connectors"}, Note: "Third-party data source registry"},
		{ID: "world", Name: "Global XDR Catalog", CrowdStrike: "Beyond Falcon (world)", Status: "active", APIs: []string{"/v1/world/modules"}, Note: "SentinelOne/Defender/Cortex/Elastic/… parity map"},
	}
}

// RegisterFalconPlatform wires CrowdStrike-parity APIs onto the Kavach mux.
func RegisterFalconPlatform(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/modules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FalconModules())
	})
	RegisterDetections(mux, token, store)
	RegisterIOC(mux, token, store)
	RegisterIOA(mux, token, store)
	RegisterPrevention(mux, token)
	RegisterHostMgmt(mux, token, store, registry)
	RegisterRTR(mux, token, store, registry)
	RegisterDeviceControl(mux, token, store)
	RegisterFirewall(mux, token)
	RegisterDiscover(mux, token, store, registry)
	RegisterSpotlight(mux, token, store, registry)
	RegisterOverWatch(mux, token)
	RegisterIntel(mux, token)
	RegisterIdentity(mux, token, store)
	RegisterFusion(mux, token, store)
	RegisterUEBA(mux, token, store)
	RegisterCases(mux, token, store)
	RegisterHunt(mux, token, store)
	RegisterThreatGraph(mux, token, store)
	RegisterAudit(mux, token)
	RegisterReports(mux, token, store, registry)
	RegisterConnectors(mux, token)
	RegisterCloudMobile(mux, token)
	RegisterCharlotteAssist(mux, token, store)
	RegisterAIPlatform(mux, token, store)
	RegisterWorldPlatform(mux, token, store, registry)
}
