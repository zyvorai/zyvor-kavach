// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

// cliCommand is one kavachctl argv covered by unit tests / CI smoke.
type cliCommand struct {
	Name      string
	Args      []string
	Local     bool // help / no API
	Mutating  bool // POST/PUT — skipped on live unless KAVACH_CLI_ALLOW_MUTATE=1
	Streaming bool
	Optional  bool
}

func allCLICommands() []cliCommand {
	return []cliCommand{
		{Name: "help", Args: []string{"--help"}, Local: true},
		{Name: "version", Args: []string{"version"}, Local: true},
		{Name: "status-help", Args: []string{"status", "--help"}, Local: true},

		{Name: "status-json", Args: []string{"status", "--json"}},
		{Name: "fleet", Args: []string{"fleet"}},
		{Name: "hosts", Args: []string{"hosts"}},
		{Name: "agents", Args: []string{"agents"}},
		{Name: "sensor", Args: []string{"sensor"}},
		{Name: "modules", Args: []string{"modules"}},
		{Name: "world-modules", Args: []string{"world", "modules"}},
		{Name: "ebpf-status", Args: []string{"ebpf", "status"}},
		{Name: "ebpf-health", Args: []string{"ebpf", "health"}},
		{Name: "ebpf-events", Args: []string{"ebpf", "events", "--type", "exec"}},
		{Name: "ebpf-attachments", Args: []string{"ebpf", "attachments"}},
		{Name: "ebpf-features", Args: []string{"ebpf", "features"}},
		{Name: "ebpf-netra", Args: []string{"ebpf", "netra", "status"}},
		{Name: "finance-summary", Args: []string{"finance", "summary"}},
		{Name: "finance-exchanges", Args: []string{"finance", "exchanges"}},
		{Name: "finance-upi", Args: []string{"finance", "upi"}},
		{Name: "finance-sebi", Args: []string{"finance", "sebi"}},
		{Name: "sectors-summary", Args: []string{"sectors", "summary"}},
		{Name: "sectors-railways", Args: []string{"sectors", "railways"}},
		{Name: "sectors-gov-portals", Args: []string{"sectors", "gov-portals"}},
		{Name: "sectors-power", Args: []string{"sectors", "power"}},
		{Name: "sectors-airports", Args: []string{"sectors", "airports"}},
		{Name: "sectors-flights", Args: []string{"sectors", "flights"}},
		{Name: "sectors-defence", Args: []string{"sectors", "defence"}},
		{Name: "sectors-border", Args: []string{"sectors", "border"}},

		{Name: "findings", Args: []string{"findings"}},
		{Name: "detections", Args: []string{"detections"}},
		{Name: "incidents", Args: []string{"incidents"}},
		{Name: "timeline", Args: []string{"timeline"}},
		{Name: "hunt-query", Args: []string{"hunt", "query", "severity:high"}, Mutating: true},

		{Name: "containment", Args: []string{"containment"}},
		{Name: "rtr-commands", Args: []string{"rtr", "commands"}},
		{Name: "cases", Args: []string{"cases"}},
		{Name: "threat-graph", Args: []string{"threat-graph"}},
		{Name: "storyline", Args: []string{"storyline"}},
		{Name: "air", Args: []string{"air"}},

		{Name: "intel-actors", Args: []string{"intel", "actors"}},
		{Name: "intel-indicators", Args: []string{"intel", "indicators"}},
		{Name: "identity-events", Args: []string{"identity", "events"}},
		{Name: "ueba", Args: []string{"ueba"}},
		{Name: "watchlists", Args: []string{"watchlists"}},
		{Name: "ioc", Args: []string{"ioc"}},
		{Name: "overwatch", Args: []string{"overwatch"}},
		{Name: "dns-threats", Args: []string{"dns", "threats"}},

		{Name: "discover-assets", Args: []string{"discover", "assets"}},
		{Name: "spotlight", Args: []string{"spotlight"}},
		{Name: "exposure", Args: []string{"exposure"}},
		{Name: "compliance", Args: []string{"compliance"}},
		{Name: "zero-trust", Args: []string{"zero-trust"}},
		{Name: "sbom", Args: []string{"sbom"}},
		{Name: "fim", Args: []string{"fim"}},
		{Name: "persistence", Args: []string{"persistence"}},
		{Name: "casb", Args: []string{"casb"}},
		{Name: "cnapp-workloads", Args: []string{"cnapp", "workloads"}},

		{Name: "ai-capabilities", Args: []string{"ai", "capabilities"}},
		{Name: "ai-briefing", Args: []string{"ai", "briefing"}},
		{Name: "ai-scores", Args: []string{"ai", "scores"}},
		{Name: "ai-agents", Args: []string{"ai", "agents"}},
		{Name: "ai-chat", Args: []string{"ai", "chat", "summarize findings"}, Mutating: true},

		{Name: "audit", Args: []string{"audit"}},
		{Name: "report", Args: []string{"report"}},
		{Name: "siem-status", Args: []string{"siem", "status"}},
		{Name: "fusion-playbooks", Args: []string{"fusion", "playbooks"}},
		{Name: "connectors", Args: []string{"connectors"}},
	}
}
