// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Command kavachctl is the Zyvor Kavach operator CLI — sister to netractl.
// Observation-only: it reads the controller HTTP API and never instructs
// contain/kill/isolate.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var base = strings.TrimRight(env("KAVACH_URL", "https://127.0.0.1:30899"), "/")

var configOnce sync.Once

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kavachctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		return nil
	}
	ensureConfig()
	if handled, err := omDispatch(args, os.Stdout); handled {
		return err
	}

	switch args[0] {
	case "status":
		return statusCmd(args[1:], os.Stdout)
	case "version", "--version":
		fmt.Println("kavachctl 0.1.1")
		return nil

	case "findings":
		return listCmd(os.Stdout, "/v1/findings", args[1:], "severity", "rule", "host")
	case "detections":
		return listCmd(os.Stdout, "/v1/detections", args[1:], "severity", "status", "host")
	case "incidents":
		return request("GET", "/v1/incidents", nil)
	case "timeline":
		return request("GET", "/v1/timeline", nil)
	case "recent-events":
		return request("GET", "/v1/recent-events", nil)
	case "hunt":
		return huntCmd(args[1:])

	case "fleet":
		return request("GET", "/v1/fleet", nil)
	case "hosts":
		return request("GET", "/v1/hosts", nil)
	case "host-groups":
		return request("GET", "/v1/host-groups", nil)
	case "agents":
		return request("GET", "/v1/agents", nil)
	case "tenants":
		return request("GET", "/v1/tenants", nil)
	case "sensor":
		return request("GET", "/v1/sensor", nil)
	case "sensor-health":
		return request("GET", "/v1/sensor-health", nil)
	case "ebpf":
		return ebpfCmd(args[1:])
	case "finance", "fin", "banking":
		return financeCmd(args[1:])
	case "sectors", "sector", "railways", "govt", "government":
		return sectorsCmd(args[1:])

	case "containment":
		return request("GET", "/v1/containment", nil)
	case "rtr":
		return rtrCmd(args[1:])
	case "cases":
		return request("GET", "/v1/cases", nil)
	case "threat-graph":
		return request("GET", "/v1/threat-graph", nil)
	case "storyline":
		return getQuery("/v1/storyline", pickFlags(args[1:], "id", "host"))
	case "air":
		return request("GET", "/v1/air/investigations", nil)

	case "intel":
		if len(args) > 1 && args[1] == "feeds" {
			return intelFeedsCmd(os.Stdout, args[2:])
		}
		return intelCmd(args[1:])
	case "lab":
		return labCmd(os.Stdout, args[1:])
	case "soc":
		return socCmd(os.Stdout, args[1:])
	case "posture":
		return postureCmd(os.Stdout, args[1:])
	case "identity":
		return identityCmd(args[1:])
	case "ueba":
		return request("GET", "/v1/ueba", nil)
	case "watchlists":
		return request("GET", "/v1/watchlists", nil)
	case "ioc":
		return request("GET", "/v1/ioc", nil)
	case "ioa":
		return request("GET", "/v1/ioa", nil)
	case "exclusions":
		return request("GET", "/v1/exclusions", nil)
	case "rules":
		return request("GET", "/v1/rules", nil)
	case "overwatch":
		return request("GET", "/v1/overwatch/alerts", nil)
	case "dns":
		return dnsCmd(args[1:])

	case "modules":
		return request("GET", "/v1/modules", nil)
	case "world":
		return worldCmd(args[1:])
	case "discover":
		return discoverCmd(args[1:])
	case "spotlight":
		return getQuery("/v1/spotlight/vulnerabilities", pickFlags(args[1:], "severity"))
	case "exposure":
		return request("GET", "/v1/exposure", nil)
	case "compliance":
		if len(args) > 1 && args[1] == "score" {
			return complianceScoreCmd(os.Stdout, args[2:])
		}
		if len(args) > 1 && (args[1] == "controls" || args[1] == "evidence" || args[1] == "cert-in-clock") {
			return complianceExtraCmd(os.Stdout, args[1:])
		}
		return request("GET", "/v1/compliance", nil)
	case "attack", "mitre":
		return attackCmd(os.Stdout, args[1:])
	case "watch", "tail":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return watchCmd(ctx, os.Stdout, args[1:])
	case "risk":
		return riskCmd(os.Stdout, args[1:])
	case "trends":
		return trendsCmd(os.Stdout, args[1:])
	case "export":
		return exportCmd(os.Stdout, args[1:])
	case "notes":
		return notesCmd(os.Stdout, args[1:])
	case "saved-searches", "searches":
		return savedSearchesCmd(os.Stdout, args[1:])
	case "alerts":
		return alertsCmd(os.Stdout, args[1:])
	case "journal":
		return journalCmd(os.Stdout, args[1:])
	case "doctor":
		return doctorCmd(os.Stdout)
	case "completion":
		return completionCmd(os.Stdout, args[1:])
	case "metrics":
		return request("GET", "/metrics", nil)
	case "zero-trust":
		return request("GET", "/v1/zero-trust", nil)
	case "sbom":
		return request("GET", "/v1/sbom", nil)
	case "fim":
		return request("GET", "/v1/fim", nil)
	case "persistence":
		return request("GET", "/v1/persistence", nil)
	case "firewall":
		return request("GET", "/v1/firewall/rules", nil)
	case "browser":
		return request("GET", "/v1/browser/extensions", nil)
	case "casb":
		return request("GET", "/v1/casb/apps", nil)
	case "cnapp":
		return cnappCmd(args[1:])
	case "ot":
		return request("GET", "/v1/ot/devices", nil)
	case "deception":
		return request("GET", "/v1/deception", nil)
	case "email":
		return request("GET", "/v1/email/threats", nil)
	case "dlp":
		return request("GET", "/v1/dlp/events", nil)
	case "forensics":
		return request("GET", "/v1/forensics", nil)
	case "sandbox":
		return request("GET", "/v1/sandbox", nil)
	case "device-control":
		return request("GET", "/v1/device-control", nil)
	case "yara":
		return request("GET", "/v1/yara", nil)
	case "sigma":
		return request("GET", "/v1/sigma", nil)
	case "prevention":
		return request("GET", "/v1/prevention/policies", nil)
	case "mdr":
		return request("GET", "/v1/mdr/queue", nil)
	case "bas":
		return request("GET", "/v1/bas", nil)
	case "itsm":
		return request("GET", "/v1/itsm/tickets", nil)
	case "notify":
		return request("GET", "/v1/notify/channels", nil)
	case "rbac":
		return request("GET", "/v1/rbac/roles", nil)
	case "retention":
		return request("GET", "/v1/retention", nil)
	case "network-discovery":
		return request("GET", "/v1/network-discovery", nil)
	case "itdr":
		return request("GET", "/v1/itdr/mfa", nil)
	case "tls":
		return request("GET", "/v1/tls/certs", nil)
	case "hyperautomation":
		return request("GET", "/v1/hyperautomation/workflows", nil)

	case "ai":
		return aiCmd(args[1:])
	case "audit":
		return request("GET", "/v1/audit", nil)
	case "report":
		return request("GET", "/v1/reports/summary", nil)
	case "siem":
		return siemCmd(args[1:])
	case "fusion":
		return fusionCmd(args[1:])
	case "connectors":
		return request("GET", "/v1/connectors", nil)
	case "cloud":
		return request("GET", "/v1/cloud/posture", nil)
	case "mobile":
		return request("GET", "/v1/mobile/devices", nil)

	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: kavachctl get <path>")
		}
		p := args[1]
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return request("GET", p, nil)

	default:
		return fmt.Errorf("unknown command %q (try: kavachctl --help)", args[0])
	}
}

func sectorsCmd(args []string) error {
	if len(args) < 1 {
		return request("GET", "/v1/sectors/summary", nil)
	}
	switch args[0] {
	case "summary", "status":
		return request("GET", "/v1/sectors/summary", nil)
	case "modules":
		return request("GET", "/v1/sectors/modules", nil)
	case "railways", "rail":
		return request("GET", "/v1/sectors/railways", nil)
	case "rail-signaling", "signaling":
		return request("GET", "/v1/sectors/rail-signaling", nil)
	case "stations":
		return request("GET", "/v1/sectors/stations", nil)
	case "passenger-apps", "apps":
		return request("GET", "/v1/sectors/passenger-apps", nil)
	case "freight":
		return request("GET", "/v1/sectors/freight", nil)
	case "metro":
		return request("GET", "/v1/sectors/metro", nil)
	case "gov-portals", "portals", "govt":
		return request("GET", "/v1/sectors/gov-portals", nil)
	case "ministries":
		return request("GET", "/v1/sectors/ministries", nil)
	case "e-office", "eoffice":
		return request("GET", "/v1/sectors/e-office", nil)
	case "digital-id", "digilocker":
		return request("GET", "/v1/sectors/digital-id", nil)
	case "tax", "gst":
		return request("GET", "/v1/sectors/tax", nil)
	case "customs":
		return request("GET", "/v1/sectors/customs", nil)
	case "elections":
		return request("GET", "/v1/sectors/elections", nil)
	case "courts":
		return request("GET", "/v1/sectors/courts", nil)
	case "postal":
		return request("GET", "/v1/sectors/postal", nil)
	case "cert-in", "certin":
		return request("GET", "/v1/sectors/cert-in", nil)
	case "power", "grid":
		return request("GET", "/v1/sectors/power", nil)
	case "scada":
		return request("GET", "/v1/sectors/scada", nil)
	case "oil-gas", "oil":
		return request("GET", "/v1/sectors/oil-gas", nil)
	case "telecom":
		return request("GET", "/v1/sectors/telecom", nil)
	case "spectrum":
		return request("GET", "/v1/sectors/spectrum", nil)
	case "aviation":
		return request("GET", "/v1/sectors/aviation", nil)
	case "airports":
		return request("GET", "/v1/sectors/airports", nil)
	case "flights", "flight":
		return request("GET", "/v1/sectors/flights", nil)
	case "airlines", "airline":
		return request("GET", "/v1/sectors/airlines", nil)
	case "atc-it", "atc":
		return request("GET", "/v1/sectors/atc-it", nil)
	case "baggage", "bhs":
		return request("GET", "/v1/sectors/baggage", nil)
	case "air-cargo", "cargo":
		return request("GET", "/v1/sectors/air-cargo", nil)
	case "airport-security":
		return request("GET", "/v1/sectors/airport-security", nil)
	case "fids":
		return request("GET", "/v1/sectors/fids", nil)
	case "ground-handling", "ground":
		return request("GET", "/v1/sectors/ground-handling", nil)
	case "dgca":
		return request("GET", "/v1/sectors/dgca", nil)
	case "ports":
		return request("GET", "/v1/sectors/ports", nil)
	case "highways", "fastag":
		return request("GET", "/v1/sectors/highways", nil)
	case "transport-reg", "vahan", "sarathi":
		return request("GET", "/v1/sectors/transport-reg", nil)
	case "gov-vehicles", "gov-fleet", "fleet-gov":
		return request("GET", "/v1/sectors/gov-vehicles", nil)
	case "public-vehicles", "public-fleet", "pub-vehicles":
		return request("GET", "/v1/sectors/public-vehicles", nil)
	case "city-buses", "buses", "stu":
		return request("GET", "/v1/sectors/city-buses", nil)
	case "brts", "brt":
		return request("GET", "/v1/sectors/brts", nil)
	case "taxis-cabs", "taxis", "cabs":
		return request("GET", "/v1/sectors/taxis-cabs", nil)
	case "autos-rickshaw", "autos", "rickshaw", "e-rickshaw":
		return request("GET", "/v1/sectors/autos-rickshaw", nil)
	case "school-buses", "schoolbus":
		return request("GET", "/v1/sectors/school-buses", nil)
	case "municipal-fleet", "municipal", "sanitation-fleet":
		return request("GET", "/v1/sectors/municipal-fleet", nil)
	case "intercity-coaches", "coaches", "roadways":
		return request("GET", "/v1/sectors/intercity-coaches", nil)
	case "ferries", "ferry":
		return request("GET", "/v1/sectors/ferries", nil)
	case "automotive", "cars", "auto":
		return request("GET", "/v1/sectors/automotive", nil)
	case "ev-charging", "ev":
		return request("GET", "/v1/sectors/ev-charging", nil)
	case "vehicle-oem", "oem":
		return request("GET", "/v1/sectors/vehicle-oem", nil)
	case "dealers":
		return request("GET", "/v1/sectors/dealers", nil)
	case "manufacturing", "industry", "plants":
		return request("GET", "/v1/sectors/manufacturing", nil)
	case "industrial-parks", "sez":
		return request("GET", "/v1/sectors/industrial-parks", nil)
	case "steel-cement", "steel", "cement":
		return request("GET", "/v1/sectors/steel-cement", nil)
	case "electronics-mfg", "electronics":
		return request("GET", "/v1/sectors/electronics-mfg", nil)
	case "textiles":
		return request("GET", "/v1/sectors/textiles", nil)
	case "health":
		return request("GET", "/v1/sectors/health", nil)
	case "pharma":
		return request("GET", "/v1/sectors/pharma", nil)
	case "education":
		return request("GET", "/v1/sectors/education", nil)
	case "smart-city", "civic":
		return request("GET", "/v1/sectors/smart-city", nil)
	case "water":
		return request("GET", "/v1/sectors/water", nil)
	case "space":
		return request("GET", "/v1/sectors/space", nil)
	case "isro-centers", "isro":
		return request("GET", "/v1/sectors/isro-centers", nil)
	case "launch-range", "launch":
		return request("GET", "/v1/sectors/launch-range", nil)
	case "ground-stations", "ttc":
		return request("GET", "/v1/sectors/ground-stations", nil)
	case "space-research":
		return request("GET", "/v1/sectors/space-research", nil)
	case "nsil-antrix", "nsil", "antrix":
		return request("GET", "/v1/sectors/nsil-antrix", nil)
	case "defence-civil", "disaster":
		return request("GET", "/v1/sectors/defence-civil", nil)
	case "defence", "defense", "mod":
		return request("GET", "/v1/sectors/defence", nil)
	case "defence-portals":
		return request("GET", "/v1/sectors/defence-portals", nil)
	case "border", "immigration":
		return request("GET", "/v1/sectors/border", nil)
	case "coast-guard", "icg":
		return request("GET", "/v1/sectors/coast-guard", nil)
	case "paramilitary", "bsf", "cisf":
		return request("GET", "/v1/sectors/paramilitary", nil)
	case "drdo-labs", "drdo":
		return request("GET", "/v1/sectors/drdo-labs", nil)
	case "cantonment", "mes":
		return request("GET", "/v1/sectors/cantonment", nil)
	case "critical-sites", "sites":
		return request("GET", "/v1/sectors/critical-sites", nil)
	case "citizen-services", "csc":
		return request("GET", "/v1/sectors/citizen-services", nil)
	case "events":
		return getQuery("/v1/sectors/events", pickFlags(args[1:], "type", "sector"))
	default:
		return fmt.Errorf("unknown sectors subcommand %q (try: kavachctl sectors summary)", args[0])
	}
}

func financeCmd(args []string) error {
	if len(args) < 1 {
		return request("GET", "/v1/finance/summary", nil)
	}
	switch args[0] {
	case "summary", "status":
		return request("GET", "/v1/finance/summary", nil)
	case "modules":
		return request("GET", "/v1/finance/modules", nil)
	case "institutions", "banks":
		return request("GET", "/v1/finance/institutions", nil)
	case "exchanges":
		return request("GET", "/v1/finance/exchanges", nil)
	case "markets":
		return request("GET", "/v1/finance/markets", nil)
	case "desks", "trading-desks":
		return request("GET", "/v1/finance/trading-desks", nil)
	case "workstations":
		return request("GET", "/v1/finance/workstations", nil)
	case "algo":
		return request("GET", "/v1/finance/algo", nil)
	case "market-data", "feeds":
		return request("GET", "/v1/finance/market-data", nil)
	case "payments", "payment-rails":
		return request("GET", "/v1/finance/payment-rails", nil)
	case "upi":
		return request("GET", "/v1/finance/upi", nil)
	case "cards":
		return request("GET", "/v1/finance/cards", nil)
	case "swift":
		return request("GET", "/v1/finance/swift", nil)
	case "treasury":
		return request("GET", "/v1/finance/treasury", nil)
	case "core", "core-banking":
		return request("GET", "/v1/finance/core-banking", nil)
	case "branches":
		return request("GET", "/v1/finance/branches", nil)
	case "atms":
		return request("GET", "/v1/finance/atms", nil)
	case "fraud":
		return request("GET", "/v1/finance/fraud", nil)
	case "insider":
		return request("GET", "/v1/finance/insider", nil)
	case "sanctions":
		return request("GET", "/v1/finance/sanctions", nil)
	case "kyc":
		return request("GET", "/v1/finance/kyc", nil)
	case "pci":
		return request("GET", "/v1/finance/pci", nil)
	case "rbi":
		return request("GET", "/v1/finance/rbi", nil)
	case "sebi":
		return request("GET", "/v1/finance/sebi", nil)
	case "nbfc":
		return request("GET", "/v1/finance/nbfc", nil)
	case "insurance":
		return request("GET", "/v1/finance/insurance", nil)
	case "insurance-lines", "ins-lines":
		return request("GET", "/v1/finance/insurance-lines", nil)
	case "insurance-tpa", "tpa":
		return request("GET", "/v1/finance/insurance-tpa", nil)
	case "reinsurance":
		return request("GET", "/v1/finance/reinsurance", nil)
	case "irdai":
		return request("GET", "/v1/finance/irdai", nil)
	case "motor-insurance", "motor":
		return request("GET", "/v1/finance/motor-insurance", nil)
	case "mutual-funds", "amfi":
		return request("GET", "/v1/finance/mutual-funds", nil)
	case "events":
		return getQuery("/v1/finance/events", pickFlags(args[1:], "type"))
	default:
		return fmt.Errorf("unknown finance subcommand %q (try: kavachctl finance summary)", args[0])
	}
}

func ebpfCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl ebpf status|health|coverage|capabilities|attachments|maps|census|summary|drops|events|processes|features|netra …")
	}
	switch args[0] {
	case "status":
		return request("GET", "/v1/ebpf/status", nil)
	case "health":
		return request("GET", "/v1/ebpf/health", nil)
	case "coverage":
		return request("GET", "/v1/ebpf/coverage", nil)
	case "capabilities":
		return request("GET", "/v1/ebpf/capabilities", nil)
	case "attachments":
		return request("GET", "/v1/ebpf/attachments", nil)
	case "maps":
		return request("GET", "/v1/ebpf/maps", nil)
	case "census":
		return request("GET", "/v1/ebpf/census", nil)
	case "summary":
		return request("GET", "/v1/ebpf/summary", nil)
	case "drops":
		return request("GET", "/v1/ebpf/drops", nil)
	case "events":
		return getQuery("/v1/ebpf/events", pickFlags(args[1:], "type"))
	case "processes":
		return request("GET", "/v1/ebpf/processes", nil)
	case "features":
		if len(args) >= 3 && args[1] != "" {
			// kavachctl ebpf features set <id> <mode>
			if args[1] == "set" && len(args) >= 4 {
				body, _ := json.Marshal(map[string]string{"mode": args[3]})
				return request("POST", "/v1/ebpf/features/"+args[2], body)
			}
		}
		return request("GET", "/v1/ebpf/features", nil)
	case "netra":
		if len(args) < 2 {
			return request("GET", "/v1/ebpf/netra/status", nil)
		}
		switch args[1] {
		case "status":
			return request("GET", "/v1/ebpf/netra/status", nil)
		case "drops":
			return request("GET", "/v1/ebpf/netra/drops", nil)
		case "flows":
			return request("GET", "/v1/ebpf/netra/flows", nil)
		case "attachments":
			return request("GET", "/v1/ebpf/netra/attachments", nil)
		default:
			return fmt.Errorf("usage: kavachctl ebpf netra status|drops|flows|attachments")
		}
	default:
		return fmt.Errorf("unknown ebpf subcommand %q", args[0])
	}
}

func huntCmd(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: kavachctl hunt query|kql <expression>")
	}
	expr := strings.Join(args[1:], " ")
	switch args[0] {
	case "query":
		body, _ := json.Marshal(map[string]string{"query": expr})
		return request("POST", "/v1/hunt/query", body)
	case "kql":
		body, _ := json.Marshal(map[string]string{"query": expr})
		return request("POST", "/v1/hunt/kql", body)
	default:
		return fmt.Errorf("usage: kavachctl hunt query|kql <expression>")
	}
}

func rtrCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl rtr commands|sessions")
	}
	switch args[0] {
	case "commands":
		return request("GET", "/v1/rtr/commands", nil)
	case "sessions":
		return request("GET", "/v1/rtr/sessions", nil)
	default:
		return fmt.Errorf("usage: kavachctl rtr commands|sessions")
	}
}

func intelCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl intel actors|indicators [--q text]")
	}
	switch args[0] {
	case "actors":
		return request("GET", "/v1/intel/actors", nil)
	case "indicators":
		return getQuery("/v1/intel/indicators", pickFlags(args[1:], "q"))
	default:
		return fmt.Errorf("usage: kavachctl intel actors|indicators")
	}
}

func identityCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl identity events|entities")
	}
	switch args[0] {
	case "events":
		return request("GET", "/v1/identity/events", nil)
	case "entities":
		return request("GET", "/v1/identity/entities", nil)
	default:
		return fmt.Errorf("usage: kavachctl identity events|entities")
	}
}

func dnsCmd(args []string) error {
	if len(args) >= 1 && args[0] == "threats" {
		return request("GET", "/v1/dns/threats", nil)
	}
	return request("GET", "/v1/dns/threats", nil)
}

func worldCmd(args []string) error {
	if len(args) >= 1 && (args[0] == "modules" || args[0] == "module") {
		return request("GET", "/v1/world/modules", nil)
	}
	return request("GET", "/v1/world/modules", nil)
}

func discoverCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl discover assets|apps")
	}
	switch args[0] {
	case "assets":
		return request("GET", "/v1/discover/assets", nil)
	case "apps":
		return request("GET", "/v1/discover/apps", nil)
	default:
		return fmt.Errorf("usage: kavachctl discover assets|apps")
	}
}

func cnappCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl cnapp workloads|misconfigs")
	}
	switch args[0] {
	case "workloads":
		return request("GET", "/v1/cnapp/workloads", nil)
	case "misconfigs":
		return request("GET", "/v1/cnapp/misconfigs", nil)
	default:
		return fmt.Errorf("usage: kavachctl cnapp workloads|misconfigs")
	}
}

func siemCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl siem status|export")
	}
	switch args[0] {
	case "status":
		return request("GET", "/v1/siem/status", nil)
	case "export":
		return request("GET", "/v1/siem/export", nil)
	default:
		return fmt.Errorf("usage: kavachctl siem status|export")
	}
}

func fusionCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl fusion playbooks|runs")
	}
	switch args[0] {
	case "playbooks":
		return request("GET", "/v1/fusion/playbooks", nil)
	case "runs":
		return request("GET", "/v1/fusion/runs", nil)
	default:
		return fmt.Errorf("usage: kavachctl fusion playbooks|runs")
	}
}

func aiCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl ai <subcommand>")
	}
	switch args[0] {
	case "capabilities":
		return request("GET", "/v1/ai/capabilities", nil)
	case "briefing", "brief":
		return request("GET", "/v1/ai/briefing", nil)
	case "scores":
		return request("GET", "/v1/ai/scores", nil)
	case "score":
		return getQuery("/v1/ai/score", pickFlags(args[1:], "id"))
	case "agents":
		return request("GET", "/v1/ai/agents", nil)
	case "cluster":
		return request("GET", "/v1/ai/cluster", nil)
	case "forecast":
		return request("GET", "/v1/ai/forecast", nil)
	case "anomaly":
		return request("GET", "/v1/ai/anomaly", nil)
	case "stream":
		return request("GET", "/v1/ai/stream", nil)
	case "guardian":
		return request("GET", "/v1/ai/guardian", nil)
	case "xdr-fusion":
		return request("GET", "/v1/ai/xdr-fusion", nil)
	case "memory":
		return request("GET", "/v1/ai/memory", nil)
	case "embeddings":
		return getQuery("/v1/ai/embeddings", pickFlags(args[1:], "id"))
	case "narrative":
		return getQuery("/v1/ai/narrative", pickFlags(args[1:], "id"))
	case "report":
		return getQuery("/v1/ai/report", pickFlags(args[1:], "id"))
	case "attack-path":
		return getQuery("/v1/ai/attack-path", pickFlags(args[1:], "id", "host"))
	case "similarity":
		return getQuery("/v1/ai/similarity", pickFlags(args[1:], "id"))
	case "classify":
		return getQuery("/v1/ai/classify", pickFlags(args[1:], "id"))
	case "fp-score":
		return getQuery("/v1/ai/fp-score", pickFlags(args[1:], "id"))
	case "remediation":
		return getQuery("/v1/ai/remediation", pickFlags(args[1:], "id"))
	case "playbook-suggest":
		return getQuery("/v1/ai/playbook-suggest", pickFlags(args[1:], "id"))
	case "history":
		return request("GET", "/v1/ai/chat", nil)
	case "chat":
		if len(args) < 2 {
			return fmt.Errorf("usage: kavachctl ai chat <message>")
		}
		body, _ := json.Marshal(map[string]string{"message": strings.Join(args[1:], " ")})
		return request("POST", "/v1/ai/chat", body)
	case "nl-hunt":
		if len(args) < 2 {
			return fmt.Errorf("usage: kavachctl ai nl-hunt <text>")
		}
		body, _ := json.Marshal(map[string]string{"query": strings.Join(args[1:], " ")})
		return request("POST", "/v1/ai/nl-hunt", body)
	case "assist":
		if len(args) < 2 {
			return fmt.Errorf("usage: kavachctl ai assist <text>")
		}
		body, _ := json.Marshal(map[string]string{"message": strings.Join(args[1:], " ")})
		return request("POST", "/v1/ai/assist", body)
	default:
		return fmt.Errorf("unknown ai subcommand %q", args[0])
	}
}

// --- HTTP / config (netractl sister) ---

func ensureConfig() {
	configOnce.Do(loadKavachDotenv)
	if v := strings.TrimSpace(os.Getenv("KAVACH_URL")); v != "" {
		base = strings.TrimRight(v, "/")
	}
	if os.Getenv("KAVACH_TLS_INSECURE") == "" && urlIsLoopback(base) {
		_ = os.Setenv("KAVACH_TLS_INSECURE", "true")
	}
}

func loadKavachDotenv() {
	if os.Getenv("KAVACH_SKIP_DOTENV") == "1" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	loadEnvFile(filepath.Join(home, ".kavach", "env"))
	if firstEnv("KAVACH_TOKEN", "ZYVOR_EDR_TOKEN") == "" {
		if b, err := os.ReadFile(filepath.Join(home, ".kavach", "api-key")); err == nil {
			if k := strings.TrimSpace(string(b)); k != "" {
				_ = os.Setenv("KAVACH_TOKEN", k)
			}
		}
	}
}

func loadEnvFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k == "" || os.Getenv(k) != "" {
			continue
		}
		_ = os.Setenv(k, v)
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func urlIsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func tlsInsecure() bool {
	v := strings.TrimSpace(os.Getenv("KAVACH_TLS_INSECURE"))
	if strings.EqualFold(v, "false") || v == "0" {
		return false
	}
	if strings.EqualFold(v, "true") || v == "1" {
		return true
	}
	return urlIsLoopback(base)
}

func httpClient(timeout time.Duration) *http.Client {
	ensureConfig()
	c := &http.Client{Timeout: timeout}
	if tlsInsecure() {
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} //nolint:gosec // lab self-signed
	}
	return c
}

func apiToken() string {
	return firstEnv("KAVACH_TOKEN", "ZYVOR_EDR_TOKEN")
}

func doRequest(method, path string, body []byte, headers map[string]string) ([]byte, int, error) {
	ensureConfig()
	token := apiToken()
	if token == "" && path != "/healthz" {
		return nil, 0, fmt.Errorf("set KAVACH_TOKEN (or ~/.kavach/api-key)")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Kavach-Actor", firstEnv("KAVACH_CLI_ACTOR", "kavachctl"))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient(45 * time.Second).Do(req)
	if err != nil {
		return nil, 0, annotateTLSErr(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

func annotateTLSErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate") {
		return fmt.Errorf("%w\nHint: chart TLS is self-signed by default. For NodePort:\n  export KAVACH_TLS_INSECURE=true\n  export KAVACH_URL=https://<node-ip>:30899\n  export KAVACH_TOKEN=$(cat ~/.kavach/api-key)", err)
	}
	return err
}

func request(method, path string, body []byte) error {
	b, code, err := doRequest(method, path, body, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(string(b), 400))
	}
	return printJSON(b)
}

func getQuery(path string, q map[string]string) error {
	if len(q) > 0 {
		vals := url.Values{}
		for k, v := range q {
			if v != "" {
				vals.Set(k, v)
			}
		}
		if enc := vals.Encode(); enc != "" {
			path += "?" + enc
		}
	}
	return request("GET", path, nil)
}

func printJSON(b []byte) error {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		fmt.Println(string(b))
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// pickFlags parses --key value and --key=value for the given keys.
func pickFlags(args []string, keys ...string) map[string]string {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--") {
			kv := strings.TrimPrefix(a, "--")
			if k, v, ok := strings.Cut(kv, "="); ok {
				if want[k] {
					out[k] = v
				}
				continue
			}
			if want[kv] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				out[kv] = args[i+1]
				i++
			}
		}
	}
	return out
}
