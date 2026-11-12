// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Critical sectors — railways, government, energy, telecom, aviation, ports, health, …
// Observation / compliance posture only — never stops trains, takes sites offline, or blocks citizen services.

type SectorModule struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Sector string   `json:"sector"`
	Status string   `json:"status"`
	APIs   []string `json:"apis"`
	Note   string   `json:"note"`
}

func SectorModules() []SectorModule {
	return []SectorModule{
		{ID: "railways", Name: "Railways", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/railways"}, Note: "IR / metro / FOIS / stations — never stops trains"},
		{ID: "rail-signaling", Name: "Rail signaling & CTC", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/rail-signaling"}, Note: "Signaling host observe only"},
		{ID: "stations", Name: "Stations & terminals", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/stations"}, Note: "Station IT / CCTV / PA endpoints"},
		{ID: "passenger-apps", Name: "Passenger apps", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/passenger-apps"}, Note: "IRCTC / UTS / metro apps risk"},
		{ID: "freight", Name: "Freight / FOIS", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/freight"}, Note: "Freight ops systems"},
		{ID: "metro", Name: "Metro & urban rail", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/metro"}, Note: "Metro OCC / AFC observe"},
		{ID: "gov-portals", Name: "Government portals", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/gov-portals"}, Note: "Citizen-facing e-gov sites"},
		{ID: "ministries", Name: "Ministries & departments", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/ministries"}, Note: "Ministry IT inventory"},
		{ID: "e-office", Name: "e-Office / NIC", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/e-office"}, Note: "Workflow / file hosts"},
		{ID: "digital-id", Name: "Digital ID services", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/digital-id"}, Note: "DigiLocker / eSign posture — no identity writes"},
		{ID: "tax", Name: "Tax & GST", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/tax"}, Note: "GSTN / IT portal observe"},
		{ID: "customs", Name: "Customs / ICEGATE", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/customs"}, Note: "Trade portal health"},
		{ID: "elections", Name: "Elections systems", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/elections"}, Note: "ECI IT observe — never touches EVMs"},
		{ID: "courts", Name: "e-Courts / judiciary", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/courts"}, Note: "Case listing / eFiling hosts"},
		{ID: "postal", Name: "Postal / India Post", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/postal"}, Note: "Post office / parcel systems"},
		{ID: "cert-in", Name: "CERT-In / MeitY posture", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/cert-in"}, Note: "Directive checklist (observe)"},
		{ID: "power", Name: "Power & grid", Sector: "energy", Status: "active", APIs: []string{"/v1/sectors/power"}, Note: "SLDC / DISCOM IT — never trips breakers"},
		{ID: "scada", Name: "SCADA / OT bridges", Sector: "energy", Status: "active", APIs: []string{"/v1/sectors/scada"}, Note: "OT bridge hosts from fleet"},
		{ID: "oil-gas", Name: "Oil & gas / pipelines", Sector: "energy", Status: "active", APIs: []string{"/v1/sectors/oil-gas"}, Note: "Pipeline / refinery IT observe"},
		{ID: "telecom", Name: "Telecom / ISP", Sector: "telecom", Status: "active", APIs: []string{"/v1/sectors/telecom"}, Note: "Core / BSS / OSS inventory"},
		{ID: "spectrum", Name: "Spectrum & towers", Sector: "telecom", Status: "active", APIs: []string{"/v1/sectors/spectrum"}, Note: "Tower / NOC observe"},
		{ID: "aviation", Name: "Aviation overview", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/aviation"}, Note: "Airport / airline IT map — never controls ATC"},
		{ID: "airports", Name: "Airports", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/airports"}, Note: "Terminal / AODB / CUTE / BHS inventory"},
		{ID: "flights", Name: "Flights / AODB", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/flights"}, Note: "Flight board observe — never cancels or diversions"},
		{ID: "airlines", Name: "Airlines", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/airlines"}, Note: "PSS / DCS / crew IT observe"},
		{ID: "atc-it", Name: "ATC-adjacent IT", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/atc-it"}, Note: "Enterprise IT only — no voice/radar control"},
		{ID: "baggage", Name: "Baggage / BHS", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/baggage"}, Note: "BHS controllers & sortation IT"},
		{ID: "air-cargo", Name: "Air cargo", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/air-cargo"}, Note: "Cargo terminal / ICS observe"},
		{ID: "airport-security", Name: "Airport security IT", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/airport-security"}, Note: "CISF / screening IT — no access control writes"},
		{ID: "fids", Name: "FIDS / passenger info", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/fids"}, Note: "Display systems observe"},
		{ID: "ground-handling", Name: "Ground handling", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/ground-handling"}, Note: "GSE / ramp ops IT"},
		{ID: "dgca", Name: "DGCA / MoCA posture", Sector: "aviation", Status: "active", APIs: []string{"/v1/sectors/dgca"}, Note: "Regulatory portal checklist"},
		{ID: "ports", Name: "Ports & shipping", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/ports"}, Note: "Port community / TOS systems"},
		{ID: "highways", Name: "Highways / FASTag", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/highways"}, Note: "NHAI / FASTag / toll plazas"},
		{ID: "transport-reg", Name: "Vahan / Sarathi", Sector: "transport", Status: "active", APIs: []string{"/v1/sectors/transport-reg"}, Note: "RTO registration systems"},
		{ID: "health", Name: "Healthcare / ABDM", Sector: "health", Status: "active", APIs: []string{"/v1/sectors/health"}, Note: "Hospital / ABHA posture — no PHI mutation"},
		{ID: "pharma", Name: "Pharma / CDSCO", Sector: "health", Status: "active", APIs: []string{"/v1/sectors/pharma"}, Note: "Regulatory / plant IT"},
		{ID: "education", Name: "Education / DIKSHA", Sector: "education", Status: "active", APIs: []string{"/v1/sectors/education"}, Note: "EdTech / university hosts"},
		{ID: "smart-city", Name: "Smart city / municipal", Sector: "civic", Status: "active", APIs: []string{"/v1/sectors/smart-city"}, Note: "ICC / CCTV / civic apps"},
		{ID: "water", Name: "Water & irrigation", Sector: "civic", Status: "active", APIs: []string{"/v1/sectors/water"}, Note: "Utility SCADA IT observe"},
		{ID: "space", Name: "Space / ISRO adjacent", Sector: "science", Status: "active", APIs: []string{"/v1/sectors/space"}, Note: "Ground-segment IT inventory"},
		{ID: "defence-civil", Name: "Civil defence / disaster", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/defence-civil"}, Note: "NDMA / SDRF IT — observe only"},
		{ID: "defence", Name: "Defence enterprise IT", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/defence"}, Note: "MoD / service HQ enterprise IT — never weapons or C2"},
		{ID: "defence-portals", Name: "Defence portals", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/defence-portals"}, Note: "Recruitment / pension / public MoD sites"},
		{ID: "border", Name: "Border / immigration IT", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/border"}, Note: "ICP / immigration hosts — no clearance writes"},
		{ID: "coast-guard", Name: "Coast Guard IT", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/coast-guard"}, Note: "ICG enterprise / shore IT"},
		{ID: "paramilitary", Name: "Paramilitary IT", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/paramilitary"}, Note: "BSF / CRPF / CISF enterprise IT"},
		{ID: "drdo-labs", Name: "DRDO / lab IT", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/drdo-labs"}, Note: "Lab campus IT — no weapons design data plane"},
		{ID: "cantonment", Name: "Cantonment / MES", Sector: "defence", Status: "active", APIs: []string{"/v1/sectors/cantonment"}, Note: "Station / MES estate IT"},
		{ID: "critical-sites", Name: "Critical sites registry", Sector: "cross", Status: "active", APIs: []string{"/v1/sectors/critical-sites"}, Note: "Named critical locations"},
		{ID: "citizen-services", Name: "Citizen service desks", Sector: "government", Status: "active", APIs: []string{"/v1/sectors/citizen-services"}, Note: "CSC / Seva kendra endpoints"},
	}
}

var (
	sectorMu     sync.Mutex
	sectorEvents []map[string]any
)

func init() {
	seedSectorDemo()
}

func seedSectorDemo() {
	host, _ := os.Hostname()
	if host == "" {
		host = "controller"
	}
	now := time.Now().UTC()
	sectorMu.Lock()
	defer sectorMu.Unlock()
	sectorEvents = []map[string]any{
		{"id": "sec-evt-1", "type": "rail_tms_lag", "severity": "medium", "sector": "railways", "site": "Howrah", "host": host, "detail": "FOIS feed lag > 30s", "time": now.Add(-20 * time.Minute)},
		{"id": "sec-evt-2", "type": "portal_anomaly", "severity": "high", "sector": "government", "site": "DigiLocker", "host": host, "detail": "Auth burst from unusual ASN", "time": now.Add(-12 * time.Minute)},
		{"id": "sec-evt-3", "type": "scada_bridge", "severity": "high", "sector": "energy", "site": "SLDC", "host": "ot-bridge-01", "detail": "OT bridge host missing agent heartbeat", "time": now.Add(-9 * time.Minute)},
		{"id": "sec-evt-4", "type": "airport_cute", "severity": "medium", "sector": "aviation", "site": "DEL T3", "host": "cute-del-12", "detail": "CUTE workstation offline", "time": now.Add(-6 * time.Minute)},
		{"id": "sec-evt-5", "type": "fastag_plaza", "severity": "low", "sector": "highways", "site": "NH48 plaza", "host": "toll-nh48-03", "detail": "Plaza lane controller stale", "time": now.Add(-3 * time.Minute)},
		{"id": "sec-evt-6", "type": "metro_afc", "severity": "medium", "sector": "metro", "site": "DMRC OCC", "host": host, "detail": "AFC settlement job delayed", "time": now.Add(-2 * time.Minute)},
		{"id": "sec-evt-7", "type": "flight_board_lag", "severity": "medium", "sector": "flights", "site": "BOM T2", "host": "aodb-bom-01", "detail": "Departure board lag > 45s", "time": now.Add(-4 * time.Minute)},
		{"id": "sec-evt-8", "type": "bhs_sortation", "severity": "high", "sector": "baggage", "site": "BLR", "host": "bhs-blr-03", "detail": "Sortation PLC IT bridge heartbeat missed", "time": now.Add(-7 * time.Minute)},
		{"id": "sec-evt-9", "type": "airline_dcs", "severity": "medium", "sector": "airlines", "site": "DEL", "host": "dcs-ai-01", "detail": "DCS check-in pool latency spike", "time": now.Add(-5 * time.Minute)},
		{"id": "sec-evt-10", "type": "defence_portal", "severity": "low", "sector": "defence", "site": "joinindianarmy", "host": host, "detail": "Recruitment portal auth anomaly observe", "time": now.Add(-11 * time.Minute)},
		{"id": "sec-evt-11", "type": "border_icp", "severity": "high", "sector": "border", "site": "ICP Attari", "host": "icp-attari-02", "detail": "Immigration workstation offline", "time": now.Add(-8 * time.Minute)},
		{"id": "sec-evt-12", "type": "atc_it_mail", "severity": "medium", "sector": "atc-it", "site": "AAI", "host": "aai-mail-gw", "detail": "Enterprise mail gateway delayed (not ATC)", "time": now.Add(-1 * time.Minute)},
	}
}

func sectorRailways() []map[string]any {
	return []map[string]any{
		{"system": "FOIS", "org": "Indian Railways", "role": "freight_ops", "status": "observed"},
		{"system": "COA / TMS", "org": "Indian Railways", "role": "train_mgmt", "status": "observed"},
		{"system": "IRCTC", "org": "IRCTC", "role": "passenger_booking", "status": "observed"},
		{"system": "UTS", "org": "Indian Railways", "role": "unreserved", "status": "observed"},
		{"system": "PRS", "org": "CRIS", "role": "reservation", "status": "observed"},
		{"note": "Observe only — Kavach never issues signal aspects or stops rolling stock"},
	}
}

func sectorRailSignaling() []map[string]any {
	return []map[string]any{
		{"system": "CTC", "site": "Howrah", "status": "online", "risk": "critical"},
		{"system": "EI / interlocking IT", "site": "Vadodara", "status": "online", "risk": "critical"},
		{"system": "TMS interface", "site": "Secunderabad", "status": "degraded", "risk": "high"},
		{"note": "No control-plane writes; signaling remains with railway OT"},
	}
}

func sectorStations() []map[string]any {
	return []map[string]any{
		{"station": "NDLS", "name": "New Delhi", "endpoints": 48, "cctv": true},
		{"station": "CSTM", "name": "CSMT Mumbai", "endpoints": 52, "cctv": true},
		{"station": "HWH", "name": "Howrah", "endpoints": 44, "cctv": true},
		{"station": "MAS", "name": "Chennai Central", "endpoints": 36, "cctv": true},
		{"station": "SBC", "name": "KSR Bengaluru", "endpoints": 28, "cctv": true},
	}
}

func sectorPassengerApps() []map[string]any {
	return []map[string]any{
		{"app": "IRCTC Rail Connect", "risk": "medium", "note": "auth / payment observe"},
		{"app": "UTS On Mobile", "risk": "low"},
		{"app": "Where is my Train", "risk": "low"},
		{"app": "Metro apps (multi-city)", "risk": "medium"},
	}
}

func sectorFreight() []map[string]any {
	return []map[string]any{
		{"system": "FOIS", "status": "online"},
		{"system": "TMS wagon", "status": "online"},
		{"system": "e-payment freight", "status": "degraded"},
	}
}

func sectorMetro() []map[string]any {
	return []map[string]any{
		{"system": "OCC", "city": "Delhi", "operator": "DMRC", "status": "online"},
		{"system": "AFC", "city": "Mumbai", "operator": "MMRCL", "status": "online"},
		{"system": "OCC", "city": "Bengaluru", "operator": "BMRCL", "status": "online"},
		{"system": "OCC", "city": "Hyderabad", "operator": "HMRL", "status": "online"},
	}
}

func sectorGovPortals() []map[string]any {
	return []map[string]any{
		{"portal": "india.gov.in", "category": "national", "status": "observed"},
		{"portal": "DigiLocker", "category": "identity_docs", "status": "observed"},
		{"portal": "UMANG", "category": "citizen_apps", "status": "observed"},
		{"portal": "MyGov", "category": "engagement", "status": "observed"},
		{"portal": "eShram", "category": "labour", "status": "observed"},
		{"portal": "CoWIN / health portals", "category": "health", "status": "observed"},
		{"portal": "Passport Seva", "category": "mea", "status": "observed"},
		{"portal": "MCA21", "category": "corporate", "status": "observed"},
	}
}

func sectorMinistries() []map[string]any {
	return []map[string]any{
		{"org": "MeitY", "focus": "digital_infra", "status": "mapped"},
		{"org": "MoRTH", "focus": "highways", "status": "mapped"},
		{"org": "Ministry of Railways", "focus": "rail", "status": "mapped"},
		{"org": "Ministry of Power", "focus": "grid", "status": "mapped"},
		{"org": "MoHFW", "focus": "health", "status": "mapped"},
		{"org": "MoCA", "focus": "aviation", "status": "mapped"},
		{"org": "DoT", "focus": "telecom", "status": "mapped"},
	}
}

func sectorEOffice() []map[string]any {
	return []map[string]any{
		{"system": "e-Office", "provider": "NIC", "status": "online"},
		{"system": "NICNET edge", "status": "online"},
		{"system": "Government email", "status": "online"},
	}
}

func sectorDigitalID() []map[string]any {
	return []map[string]any{
		{"service": "DigiLocker", "posture": "observe", "note": "No document write/delete"},
		{"service": "eSign", "posture": "observe"},
		{"service": "eKYC connectors", "posture": "observe", "note": "Signal only — no identity mutation"},
	}
}

func sectorTax() []map[string]any {
	return []map[string]any{
		{"system": "GSTN", "status": "online", "risk": "high"},
		{"system": "Income Tax e-Filing", "status": "online", "risk": "high"},
		{"system": "TIN / NSDL bridges", "status": "online", "risk": "medium"},
	}
}

func sectorCustoms() []map[string]any {
	return []map[string]any{
		{"system": "ICEGATE", "status": "online"},
		{"system": "PCS / port community", "status": "online"},
		{"system": "Single Window", "status": "degraded"},
	}
}

func sectorElections() []map[string]any {
	return []map[string]any{
		{"system": "ECI IT", "note": "Observe hosts only — never touches EVMs or results tally", "status": "mapped"},
		{"system": "Voter services portal", "status": "observed"},
		{"system": "Candidate affidavit systems", "status": "observed"},
	}
}

func sectorCourts() []map[string]any {
	return []map[string]any{
		{"system": "eCourts", "status": "online"},
		{"system": "eFiling", "status": "online"},
		{"system": "Cause list", "status": "online"},
	}
}

func sectorPostal() []map[string]any {
	return []map[string]any{
		{"system": "India Post CMS", "status": "online"},
		{"system": "Speed Post tracking", "status": "online"},
		{"system": "IPP / banking counters", "status": "online"},
	}
}

func sectorCertIn() []map[string]any {
	return []map[string]any{
		{"directive": "Incident reporting", "status": "mapped", "note": "Observe logging posture"},
		{"directive": "Sync clocks / NTP", "status": "mapped"},
		{"directive": "Vulnerability disclosure", "status": "partial"},
		{"directive": "Log retention", "status": "mapped"},
	}
}

func sectorPower() []map[string]any {
	return []map[string]any{
		{"system": "NLDC / RLDC / SLDC IT", "status": "observed", "risk": "critical"},
		{"system": "DISCOM billing", "status": "observed", "risk": "high"},
		{"system": "Smart meter HES", "status": "observed", "risk": "high"},
		{"note": "Never trips breakers or writes protection settings"},
	}
}

func sectorSCADA(store *Store, registry *CredentialRegistry) []map[string]any {
	_ = store
	out := []map[string]any{}
	if registry != nil {
		for _, a := range registry.Status(time.Now(), 90*time.Second) {
			low := strings.ToLower(a.Host)
			if strings.Contains(low, "ot") || strings.Contains(low, "scada") || strings.Contains(low, "sldc") {
				out = append(out, map[string]any{"host": a.Host, "state": a.State, "role": "ot_bridge", "sensor": a.Sensor})
			}
		}
	}
	if len(out) == 0 {
		out = []map[string]any{
			{"host": "ot-bridge-01", "state": "stale", "role": "ot_bridge", "sensor": "derived"},
			{"host": "sldc-it-02", "state": "online", "role": "grid_it", "sensor": "derived"},
		}
	}
	out = append(out, map[string]any{"note": "OT control remains outside Kavach"})
	return out
}

func sectorOilGas() []map[string]any {
	return []map[string]any{
		{"system": "Pipeline SCADA IT", "status": "observed"},
		{"system": "Refinery MES", "status": "observed"},
		{"system": "Terminal automation", "status": "observed"},
	}
}

func sectorTelecom() []map[string]any {
	return []map[string]any{
		{"system": "BSS", "status": "online"},
		{"system": "OSS / NMS", "status": "online"},
		{"system": "Core signaling IT", "status": "online"},
		{"system": "CDN / peering edges", "status": "online"},
	}
}

func sectorSpectrum() []map[string]any {
	return []map[string]any{
		{"site": "NOC North", "towers_observe": 1200, "status": "online"},
		{"site": "NOC West", "towers_observe": 980, "status": "online"},
		{"site": "NOC South", "towers_observe": 1100, "status": "degraded"},
	}
}

func sectorAviation() []map[string]any {
	return []map[string]any{
		{"domain": "airports", "count": len(sectorAirports()), "apis": []string{"/v1/sectors/airports"}},
		{"domain": "flights", "count": len(sectorFlights()) - 1, "apis": []string{"/v1/sectors/flights"}},
		{"domain": "airlines", "count": len(sectorAirlines()) - 1, "apis": []string{"/v1/sectors/airlines"}},
		{"domain": "atc_it", "count": len(sectorATCIT()) - 1, "apis": []string{"/v1/sectors/atc-it"}},
		{"domain": "baggage", "count": len(sectorBaggage()) - 1, "apis": []string{"/v1/sectors/baggage"}},
		{"domain": "air_cargo", "count": len(sectorAirCargo()), "apis": []string{"/v1/sectors/air-cargo"}},
		{"note": "Observe only — never controls ATC, cancels flights, or writes access control"},
	}
}

func sectorAirports() []map[string]any {
	return []map[string]any{
		{"code": "DEL", "name": "Indira Gandhi International", "operator": "DIAL", "terminals": []string{"T1", "T2", "T3"}, "systems": []string{"AODB", "CUTE", "BHS", "FIDS", "ACS"}, "status": "online", "tier": "critical"},
		{"code": "BOM", "name": "Chhatrapati Shivaji Maharaj International", "operator": "MIAL", "terminals": []string{"T1", "T2"}, "systems": []string{"AODB", "CUTE", "BHS", "FIDS"}, "status": "online", "tier": "critical"},
		{"code": "BLR", "name": "Kempegowda International", "operator": "BIAL", "terminals": []string{"T1", "T2"}, "systems": []string{"AODB", "CUTE", "BHS", "FIDS"}, "status": "online", "tier": "critical"},
		{"code": "MAA", "name": "Chennai International", "operator": "AAI", "terminals": []string{"T1", "T4"}, "systems": []string{"AODB", "CUTE", "FIDS"}, "status": "online", "tier": "high"},
		{"code": "HYD", "name": "Rajiv Gandhi International", "operator": "GHIAL", "terminals": []string{"T1"}, "systems": []string{"AODB", "CUTE", "BHS"}, "status": "online", "tier": "high"},
		{"code": "CCU", "name": "Netaji Subhas Chandra Bose International", "operator": "AAI", "terminals": []string{"T1", "T2"}, "systems": []string{"AODB", "CUTE"}, "status": "online", "tier": "high"},
		{"code": "GOX", "name": "Manohar International", "operator": "GMR", "terminals": []string{"T1"}, "systems": []string{"AODB", "CUTE"}, "status": "online", "tier": "medium"},
		{"code": "AMD", "name": "Sardar Vallabhbhai Patel International", "operator": "AAI", "terminals": []string{"T1", "T2"}, "systems": []string{"AODB", "CUTE"}, "status": "online", "tier": "medium"},
	}
}

func sectorFlights() []map[string]any {
	now := time.Now().UTC()
	return []map[string]any{
		{"flight": "AI101", "airport": "DEL", "direction": "dep", "dest": "JFK", "std": now.Add(2 * time.Hour).Format(time.RFC3339), "status": "on_time", "gate": "A12", "observe": true},
		{"flight": "6E201", "airport": "BOM", "direction": "dep", "dest": "DEL", "std": now.Add(45 * time.Minute).Format(time.RFC3339), "status": "boarding", "gate": "B4", "observe": true},
		{"flight": "UK955", "airport": "BLR", "direction": "arr", "origin": "LHR", "sta": now.Add(30 * time.Minute).Format(time.RFC3339), "status": "expected", "belt": "5", "observe": true},
		{"flight": "SG815", "airport": "HYD", "direction": "dep", "dest": "DXB", "std": now.Add(90 * time.Minute).Format(time.RFC3339), "status": "delayed", "gate": "C2", "observe": true},
		{"flight": "AI570", "airport": "MAA", "direction": "arr", "origin": "SIN", "sta": now.Add(-10 * time.Minute).Format(time.RFC3339), "status": "landed", "belt": "3", "observe": true},
		{"note": "AODB-style board observe — Kavach never cancels, holds, or diversions"},
	}
}

func sectorAirlines() []map[string]any {
	return []map[string]any{
		{"airline": "Air India", "iata": "AI", "systems": []string{"PSS", "DCS", "crew", "loyalty"}, "status": "observed"},
		{"airline": "IndiGo", "iata": "6E", "systems": []string{"PSS", "DCS", "ops"}, "status": "observed"},
		{"airline": "Vistara / UK", "iata": "UK", "systems": []string{"PSS", "DCS"}, "status": "observed"},
		{"airline": "SpiceJet", "iata": "SG", "systems": []string{"PSS", "DCS"}, "status": "observed"},
		{"airline": "Akasa", "iata": "QP", "systems": []string{"PSS", "DCS"}, "status": "observed"},
		{"note": "No booking cancel / PNR mutation"},
	}
}

func sectorATCIT() []map[string]any {
	return []map[string]any{
		{"system": "AAI enterprise mail", "status": "online", "plane": "enterprise_it"},
		{"system": "AAI intranet / HR", "status": "online", "plane": "enterprise_it"},
		{"system": "ATFM briefing desktops", "status": "online", "plane": "enterprise_it"},
		{"system": "CNS inventory register", "status": "online", "plane": "inventory"},
		{"note": "Hard rule: no ATC voice, radar, or flight-data control plane access"},
	}
}

func sectorBaggage() []map[string]any {
	return []map[string]any{
		{"airport": "DEL", "system": "BHS sortation IT", "status": "online"},
		{"airport": "BOM", "system": "BHS sortation IT", "status": "degraded"},
		{"airport": "BLR", "system": "BHS sortation IT", "status": "online"},
		{"airport": "HYD", "system": "BHS early bag store", "status": "online"},
		{"note": "PLC/OT control remains with airport OT — Kavach observes IT bridges only"},
	}
}

func sectorAirCargo() []map[string]any {
	return []map[string]any{
		{"airport": "DEL", "system": "Cargo ICS", "status": "online"},
		{"airport": "BOM", "system": "Cargo ICS", "status": "online"},
		{"airport": "BLR", "system": "Freighter apron IT", "status": "online"},
		{"airport": "MAA", "system": "Cargo terminal", "status": "online"},
	}
}

func sectorAirportSecurity() []map[string]any {
	return []map[string]any{
		{"airport": "DEL", "system": "CISF IT desk", "status": "observed"},
		{"airport": "BOM", "system": "Screening queue IT", "status": "observed"},
		{"airport": "BLR", "system": "ACS / badge IT", "status": "observed"},
		{"note": "Never writes access control or screening decisions"},
	}
}

func sectorFIDS() []map[string]any {
	return []map[string]any{
		{"airport": "DEL", "system": "FIDS controllers", "status": "online"},
		{"airport": "BOM", "system": "FIDS controllers", "status": "online"},
		{"airport": "BLR", "system": "FIDS + gate displays", "status": "degraded"},
		{"airport": "HYD", "system": "FIDS controllers", "status": "online"},
	}
}

func sectorGroundHandling() []map[string]any {
	return []map[string]any{
		{"handler": "AIATSL", "airports": []string{"DEL", "BOM", "MAA"}, "status": "observed"},
		{"handler": "Bird / Celebi", "airports": []string{"DEL", "BLR"}, "status": "observed"},
		{"handler": "IndiGo ground", "airports": []string{"DEL", "BOM", "BLR", "HYD"}, "status": "observed"},
		{"system": "GSE tracking IT", "status": "observed"},
	}
}

func sectorDGCA() []map[string]any {
	return []map[string]any{
		{"portal": "DGCA eGCA", "status": "mapped"},
		{"portal": "MoCA", "status": "mapped"},
		{"control": "Safety reporting IT", "status": "mapped"},
		{"control": "License / medical IT", "status": "mapped"},
	}
}

func sectorPorts() []map[string]any {
	return []map[string]any{
		{"port": "JNPT", "systems": []string{"TOS", "PCS"}, "status": "online"},
		{"port": "Mundra", "systems": []string{"TOS"}, "status": "online"},
		{"port": "Chennai", "systems": []string{"PCS"}, "status": "online"},
		{"port": "Vizag", "systems": []string{"TOS"}, "status": "online"},
	}
}

func sectorHighways() []map[string]any {
	return []map[string]any{
		{"system": "FASTag issuer", "status": "online"},
		{"system": "NETC switch", "status": "online"},
		{"system": "Toll plaza controllers", "status": "degraded"},
		{"system": "NHAI IT", "status": "online"},
	}
}

func sectorTransportReg() []map[string]any {
	return []map[string]any{
		{"system": "Vahan", "status": "online"},
		{"system": "Sarathi", "status": "online"},
		{"system": "eChallan", "status": "online"},
	}
}

func sectorHealth() []map[string]any {
	return []map[string]any{
		{"system": "ABDM / ABHA connectors", "status": "observed", "note": "No PHI mutation"},
		{"system": "Hospital HIMS", "status": "observed"},
		{"system": "Blood bank IT", "status": "observed"},
		{"system": "Telemedicine gateways", "status": "observed"},
	}
}

func sectorPharma() []map[string]any {
	return []map[string]any{
		{"system": "CDSCO portals", "status": "observed"},
		{"system": "Plant MES", "status": "observed"},
		{"system": "Cold-chain monitors", "status": "observed"},
	}
}

func sectorEducation() []map[string]any {
	return []map[string]any{
		{"system": "DIKSHA", "status": "online"},
		{"system": "SWAYAM", "status": "online"},
		{"system": "University ERP", "status": "online"},
		{"system": "Exam portals", "status": "online"},
	}
}

func sectorSmartCity() []map[string]any {
	return []map[string]any{
		{"system": "Integrated Command Centre", "city": "multi", "status": "online"},
		{"system": "City CCTV VMS", "status": "online"},
		{"system": "Municipal apps", "status": "online"},
		{"system": "Smart lighting / parking", "status": "online"},
	}
}

func sectorWater() []map[string]any {
	return []map[string]any{
		{"system": "Water SCADA IT", "status": "observed"},
		{"system": "Irrigation canals IT", "status": "observed"},
		{"system": "Billing / AMR", "status": "observed"},
	}
}

func sectorSpace() []map[string]any {
	return []map[string]any{
		{"system": "Ground segment IT", "status": "observed"},
		{"system": "Mission support desktops", "status": "observed"},
		{"note": "No spacecraft command path"},
	}
}

func sectorDefenceCivil() []map[string]any {
	return []map[string]any{
		{"system": "NDMA IT", "status": "mapped"},
		{"system": "SDRF coordination", "status": "mapped"},
		{"system": "Early warning feeds", "status": "observed"},
		{"system": "NCMC support IT", "status": "mapped"},
	}
}

func sectorDefence() []map[string]any {
	return []map[string]any{
		{"org": "MoD", "system": "Enterprise IT / e-Office", "status": "observed", "plane": "enterprise"},
		{"org": "Army HQ", "system": "Enterprise intranet", "status": "observed", "plane": "enterprise"},
		{"org": "Naval HQ", "system": "Enterprise intranet", "status": "observed", "plane": "enterprise"},
		{"org": "Air HQ", "system": "Enterprise intranet", "status": "observed", "plane": "enterprise"},
		{"org": "IDS", "system": "HQ enterprise IT", "status": "observed", "plane": "enterprise"},
		{"note": "Hard rule: never weapons, C2, tactical radios, or munitions systems"},
	}
}

func sectorDefencePortals() []map[string]any {
	return []map[string]any{
		{"portal": "joinindianarmy.nic.in", "category": "recruitment", "status": "observed"},
		{"portal": "joinindiannavy.gov.in", "category": "recruitment", "status": "observed"},
		{"portal": "careerairforce.nic.in", "category": "recruitment", "status": "observed"},
		{"portal": "SPARSH / pension", "category": "pension", "status": "observed"},
		{"portal": "MyGov defence pages", "category": "public", "status": "observed"},
		{"portal": "DDP / MoD public sites", "category": "public", "status": "observed"},
	}
}

func sectorBorder() []map[string]any {
	return []map[string]any{
		{"site": "ICP Attari", "system": "Immigration IT", "status": "online"},
		{"site": "ICP Petrapole", "system": "Immigration IT", "status": "online"},
		{"site": "Airport immigration DEL", "system": "Immigration desks IT", "status": "online"},
		{"site": "Airport immigration BOM", "system": "Immigration desks IT", "status": "degraded"},
		{"note": "No visa / clearance decision writes"},
	}
}

func sectorCoastGuard() []map[string]any {
	return []map[string]any{
		{"system": "ICG shore enterprise IT", "status": "observed"},
		{"system": "ICG recruitment portal", "status": "observed"},
		{"system": "Maritime awareness desk IT", "status": "observed", "note": "Enterprise only — no tactical C2"},
	}
}

func sectorParamilitary() []map[string]any {
	return []map[string]any{
		{"force": "BSF", "system": "Enterprise IT", "status": "observed"},
		{"force": "CRPF", "system": "Enterprise IT", "status": "observed"},
		{"force": "CISF", "system": "Enterprise / airport desk IT", "status": "observed"},
		{"force": "ITBP", "system": "Enterprise IT", "status": "observed"},
		{"force": "SSB", "system": "Enterprise IT", "status": "observed"},
	}
}

func sectorDRDOLabs() []map[string]any {
	return []map[string]any{
		{"lab": "DRDO campus IT", "status": "observed", "note": "Campus enterprise only"},
		{"lab": "Research desk endpoints", "status": "observed"},
		{"lab": "Library / admin ERP", "status": "observed"},
		{"note": "No weapons design, telemetry, or classified C2 path"},
	}
}

func sectorCantonment() []map[string]any {
	return []map[string]any{
		{"system": "MES estate IT", "status": "observed"},
		{"system": "Cantonment board portals", "status": "observed"},
		{"system": "Station hospital HIMS", "status": "observed"},
		{"system": "Unit admin desktops", "status": "observed"},
	}
}

func sectorCriticalSites() []map[string]any {
	return []map[string]any{
		{"id": "site-rail-ndls", "name": "New Delhi station complex", "sector": "railways", "tier": "critical"},
		{"id": "site-grid-nldc", "name": "NLDC", "sector": "power", "tier": "critical"},
		{"id": "site-air-del", "name": "IGI Airport", "sector": "aviation", "tier": "critical"},
		{"id": "site-air-bom", "name": "CSMIA Mumbai", "sector": "aviation", "tier": "critical"},
		{"id": "site-air-blr", "name": "KIA Bengaluru", "sector": "aviation", "tier": "critical"},
		{"id": "site-port-jnpt", "name": "JNPT", "sector": "ports", "tier": "critical"},
		{"id": "site-gov-nic", "name": "NIC data centres", "sector": "government", "tier": "critical"},
		{"id": "site-tel-noc", "name": "National telecom NOC", "sector": "telecom", "tier": "high"},
		{"id": "site-mod-hq", "name": "MoD enterprise campus", "sector": "defence", "tier": "critical"},
		{"id": "site-icp-attari", "name": "ICP Attari", "sector": "border", "tier": "high"},
	}
}

func sectorCitizenServices() []map[string]any {
	return []map[string]any{
		{"system": "Common Service Centres", "status": "online"},
		{"system": "State Seva kendras", "status": "online"},
		{"system": "RTI portals", "status": "online"},
	}
}

func sectorSummary(store *Store, registry *CredentialRegistry) map[string]any {
	return map[string]any{
		"product":        "kavach-sectors",
		"mode":           "observe-only",
		"enforce":        false,
		"modules":        len(SectorModules()),
		"rail_systems":   len(sectorRailways()),
		"gov_portals":    len(sectorGovPortals()),
		"airports":       len(sectorAirports()),
		"flights":        len(sectorFlights()) - 1,
		"airlines":       len(sectorAirlines()) - 1,
		"defence_orgs":   len(sectorDefence()) - 1,
		"critical_sites": len(sectorCriticalSites()),
		"scada_hosts":    len(sectorSCADA(store, registry)) - 1,
		"events":         len(listSectorEvents("")),
		"sectors":        []string{"railways", "government", "energy", "telecom", "aviation", "defence", "ports", "health", "education", "civic"},
		"note":           "Critical infrastructure observe — never stops trains, cancels flights, trips power, or touches weapons/C2",
	}
}

func listSectorEvents(typ string) []map[string]any {
	sectorMu.Lock()
	defer sectorMu.Unlock()
	out := make([]map[string]any, 0, len(sectorEvents))
	for _, e := range sectorEvents {
		if typ != "" {
			t, _ := e["type"].(string)
			s, _ := e["sector"].(string)
			if !strings.EqualFold(t, typ) && !strings.EqualFold(s, typ) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func ingestSectorEvents(events []map[string]any) int {
	sectorMu.Lock()
	defer sectorMu.Unlock()
	n := 0
	for _, e := range events {
		if e == nil {
			continue
		}
		if e["id"] == nil {
			e["id"] = "sec-" + time.Now().UTC().Format("150405.000")
		}
		if e["time"] == nil {
			e["time"] = time.Now().UTC()
		}
		sectorEvents = append(sectorEvents, e)
		n++
	}
	if len(sectorEvents) > 2000 {
		sectorEvents = sectorEvents[len(sectorEvents)-2000:]
	}
	return n
}

// RegisterSectorsPlatform wires railways / government / critical-infra observe APIs.
func RegisterSectorsPlatform(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	get := func(path string, fn func() any) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			writeJSON(w, fn())
		})
	}

	get("/v1/sectors/modules", func() any { return SectorModules() })
	get("/v1/sectors/summary", func() any { return sectorSummary(store, registry) })
	get("/v1/sectors/railways", func() any { return sectorRailways() })
	get("/v1/sectors/rail-signaling", func() any { return sectorRailSignaling() })
	get("/v1/sectors/stations", func() any { return sectorStations() })
	get("/v1/sectors/passenger-apps", func() any { return sectorPassengerApps() })
	get("/v1/sectors/freight", func() any { return sectorFreight() })
	get("/v1/sectors/metro", func() any { return sectorMetro() })
	get("/v1/sectors/gov-portals", func() any { return sectorGovPortals() })
	get("/v1/sectors/ministries", func() any { return sectorMinistries() })
	get("/v1/sectors/e-office", func() any { return sectorEOffice() })
	get("/v1/sectors/digital-id", func() any { return sectorDigitalID() })
	get("/v1/sectors/tax", func() any { return sectorTax() })
	get("/v1/sectors/customs", func() any { return sectorCustoms() })
	get("/v1/sectors/elections", func() any { return sectorElections() })
	get("/v1/sectors/courts", func() any { return sectorCourts() })
	get("/v1/sectors/postal", func() any { return sectorPostal() })
	get("/v1/sectors/cert-in", func() any { return sectorCertIn() })
	get("/v1/sectors/power", func() any { return sectorPower() })
	get("/v1/sectors/scada", func() any { return sectorSCADA(store, registry) })
	get("/v1/sectors/oil-gas", func() any { return sectorOilGas() })
	get("/v1/sectors/telecom", func() any { return sectorTelecom() })
	get("/v1/sectors/spectrum", func() any { return sectorSpectrum() })
	get("/v1/sectors/aviation", func() any { return sectorAviation() })
	get("/v1/sectors/airports", func() any { return sectorAirports() })
	get("/v1/sectors/flights", func() any { return sectorFlights() })
	get("/v1/sectors/airlines", func() any { return sectorAirlines() })
	get("/v1/sectors/atc-it", func() any { return sectorATCIT() })
	get("/v1/sectors/baggage", func() any { return sectorBaggage() })
	get("/v1/sectors/air-cargo", func() any { return sectorAirCargo() })
	get("/v1/sectors/airport-security", func() any { return sectorAirportSecurity() })
	get("/v1/sectors/fids", func() any { return sectorFIDS() })
	get("/v1/sectors/ground-handling", func() any { return sectorGroundHandling() })
	get("/v1/sectors/dgca", func() any { return sectorDGCA() })
	get("/v1/sectors/ports", func() any { return sectorPorts() })
	get("/v1/sectors/highways", func() any { return sectorHighways() })
	get("/v1/sectors/transport-reg", func() any { return sectorTransportReg() })
	get("/v1/sectors/health", func() any { return sectorHealth() })
	get("/v1/sectors/pharma", func() any { return sectorPharma() })
	get("/v1/sectors/education", func() any { return sectorEducation() })
	get("/v1/sectors/smart-city", func() any { return sectorSmartCity() })
	get("/v1/sectors/water", func() any { return sectorWater() })
	get("/v1/sectors/space", func() any { return sectorSpace() })
	get("/v1/sectors/defence-civil", func() any { return sectorDefenceCivil() })
	get("/v1/sectors/defence", func() any { return sectorDefence() })
	get("/v1/sectors/defence-portals", func() any { return sectorDefencePortals() })
	get("/v1/sectors/border", func() any { return sectorBorder() })
	get("/v1/sectors/coast-guard", func() any { return sectorCoastGuard() })
	get("/v1/sectors/paramilitary", func() any { return sectorParamilitary() })
	get("/v1/sectors/drdo-labs", func() any { return sectorDRDOLabs() })
	get("/v1/sectors/cantonment", func() any { return sectorCantonment() })
	get("/v1/sectors/critical-sites", func() any { return sectorCriticalSites() })
	get("/v1/sectors/citizen-services", func() any { return sectorCitizenServices() })

	mux.HandleFunc("GET /v1/sectors/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query().Get("type")
		if q == "" {
			q = r.URL.Query().Get("sector")
		}
		writeJSON(w, listSectorEvents(q))
	})
	mux.HandleFunc("POST /v1/sectors/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var body struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		writeJSON(w, map[string]any{"ingested": ingestSectorEvents(body.Events), "enforce": false})
	})
}
