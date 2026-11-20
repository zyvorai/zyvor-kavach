// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
)

// KavachModule is a console capability (plain product names — no place lineage).
type KavachModule struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"`
	APIs   []string `json:"apis"`
	Note   string   `json:"note"`
}

// FalconModule is kept as a type alias for older tests/callers.
type FalconModule = KavachModule

// KavachModules (and FalconModules) returns the capability map.
func KavachModules() []KavachModule {
	return []KavachModule{
		{ID: "prevent", Name: "Prevent", Status: "active", APIs: []string{"/v1/prevention/policies", "/v1/ioc", "/v1/ioa"}, Note: "Detect-only IOA/IOC; no quarantine"},
		{ID: "insight", Name: "Insight", Status: "active", APIs: []string{"/v1/detections", "/v1/findings", "/v1/timeline"}, Note: "Detections with MITRE mapping"},
		{ID: "device-control", Name: "Device Control", Status: "active", APIs: []string{"/v1/device-control"}, Note: "USB/device visibility"},
		{ID: "firewall", Name: "Firewall", Status: "active", APIs: []string{"/v1/firewall/rules"}, Note: "Host firewall inventory"},
		{ID: "discover", Name: "Discover", Status: "active", APIs: []string{"/v1/discover/assets", "/v1/discover/apps"}, Note: "IT hygiene / asset inventory"},
		{ID: "spotlight", Name: "Spotlight", Status: "active", APIs: []string{"/v1/spotlight/vulnerabilities"}, Note: "CVE posture from sensor inventory"},
		{ID: "overwatch", Name: "OverWatch", Status: "active", APIs: []string{"/v1/overwatch/alerts"}, Note: "Managed hunting alert feed"},
		{ID: "intel", Name: "Intel", Status: "active", APIs: []string{"/v1/intel/actors", "/v1/intel/indicators"}, Note: "Actor profiles + IOC intel"},
		{ID: "identity", Name: "Identity", Status: "active", APIs: []string{"/v1/identity/events", "/v1/identity/entities"}, Note: "Identity anomalies + lateral movement signals"},
		{ID: "fusion", Name: "Fusion", Status: "active", APIs: []string{"/v1/fusion/playbooks", "/v1/fusion/runs"}, Note: "Playbook orchestration (notify/ledger only)"},
		{ID: "rtr", Name: "Response", Status: "active", APIs: []string{"/v1/rtr/sessions", "/v1/rtr/commands"}, Note: "Read-only diagnostic queries from store"},
		{ID: "hosts", Name: "Hosts", Status: "active", APIs: []string{"/v1/hosts", "/v1/host-groups", "/v1/containment"}, Note: "Containment is a request ledger only"},
		{ID: "siem", Name: "SIEM", Status: "active", APIs: []string{"/v1/siem/status", "/v1/cases", "/v1/ueba"}, Note: "Export, cases, UEBA"},
		{ID: "hunt", Name: "Hunt", Status: "active", APIs: []string{"/v1/hunt/query", "/v1/threat-graph"}, Note: "Structured hunt + correlation graph"},
		{ID: "ai-assist", Name: "AI assist", Status: "active", APIs: []string{"/v1/ai/score", "/v1/ai/assist"}, Note: "Assistive triage (heuristic + optional LLM)"},
		{ID: "kavach-ai", Name: "AI platform", Status: "active", APIs: []string{"/v1/ai/capabilities"}, Note: "22+ AI capabilities"},
		{ID: "multi-agent", Name: "Multi-agent", Status: "active", APIs: []string{"/v1/ai/agents", "/v1/ai/agents/run"}, Note: "Triage/Hunt/Intel/IR/Reporter agents"},
		{ID: "nl-hunt", Name: "NL Hunt", Status: "active", APIs: []string{"/v1/ai/nl-hunt"}, Note: "Natural language → hunt"},
		{ID: "forecast", Name: "Forecast", Status: "active", APIs: []string{"/v1/ai/forecast"}, Note: "72h risk forecast"},
		{ID: "what-if", Name: "What-If", Status: "active", APIs: []string{"/v1/ai/what-if"}, Note: "Adversary progression simulation"},
		{ID: "guardian-ai", Name: "Guardian", Status: "active", APIs: []string{"/v1/ai/guardian"}, Note: "Observe AI/agent processes"},
		{ID: "xdr-ai", Name: "XDR AI", Status: "active", APIs: []string{"/v1/ai/xdr-fusion"}, Note: "Netra×Kavach AI correlation"},
		{ID: "cloud", Name: "Cloud", Status: "active", APIs: []string{"/v1/cloud/posture"}, Note: "CSPM posture via POST /v1/inventory domain=cloud"},
		{ID: "mobile", Name: "Mobile", Status: "active", APIs: []string{"/v1/mobile/devices"}, Note: "MDM inventory via POST /v1/inventory domain=mobile"},
		{ID: "audit", Name: "Audit", Status: "active", APIs: []string{"/v1/audit", "/v1/reports/summary"}, Note: "Console audit + SOC summary"},
		{ID: "connectors", Name: "Connectors", Status: "active", APIs: []string{"/v1/connectors"}, Note: "Third-party data source registry"},
		{ID: "world", Name: "World catalog", Status: "active", APIs: []string{"/v1/world/modules"}, Note: "Global XDR/EDR capability map"},
		{ID: "ebpf", Name: "eBPF", Status: "active", APIs: []string{"/v1/ebpf/status", "/v1/ebpf/events", "/v1/ebpf/health"}, Note: "Observe-only CO-RE — never kill or drop"},
		{ID: "finance", Name: "Finance", Status: "active", APIs: []string{"/v1/finance/summary", "/v1/finance/modules"}, Note: "Banks, markets, UPI, insurance — never freezes money or cancels policies"},
		{ID: "sectors", Name: "Sectors", Status: "active", APIs: []string{"/v1/sectors/summary", "/v1/sectors/modules"}, Note: "Rail, aviation, public vehicles, industry, space — observe only"},
	}
}

// FalconModules is the historical name for KavachModules.
func FalconModules() []KavachModule { return KavachModules() }

// RegisterFalconPlatform wires platform APIs onto the Kavach mux.
func RegisterFalconPlatform(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/modules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(KavachModules())
	})
	RegisterDetections(mux, token, store)
	RegisterGuidance(mux, token, store)
	RegisterIOC(mux, token, store)
	RegisterIOA(mux, token, store)
	RegisterRansomwareCloud(mux, token, store)
	RegisterPrevention(mux, token)
	RegisterHostMgmt(mux, token, store, registry)
	RegisterRTR(mux, token, store, registry)
	RegisterDeviceControl(mux, token, store)
	RegisterFirewall(mux, token)
	RegisterDiscover(mux, token, store, registry)
	RegisterSpotlight(mux, token, store, registry)
	RegisterOverWatch(mux, token, store)
	RegisterIntel(mux, token)
	RegisterIdentity(mux, token, store)
	RegisterITDR(mux, token, store)
	RegisterFusion(mux, token, store)
	RegisterUEBA(mux, token, store)
	RegisterCases(mux, token, store)
	RegisterHunt(mux, token, store)
	RegisterThreatGraph(mux, token, store)
	RegisterAudit(mux, token)
	RegisterReports(mux, token, store, registry)
	RegisterReportTemplates(mux, token, store, registry)
	RegisterConnectors(mux, token)
	RegisterCloudMobile(mux, token)
	RegisterCharlotteAssist(mux, token, store)
	RegisterAIPlatform(mux, token, store)
	RegisterWorldPlatform(mux, token, store, registry)
	RegisterEBPFPlatform(mux, token, store, registry)
	RegisterFinancePlatform(mux, token, store, registry)
	RegisterSectorsPlatform(mux, token, store, registry)
	RegisterContentFramework(mux, token)
}
