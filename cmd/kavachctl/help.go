// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

func usage() {
	printHelp(os.Stdout)
}

func printHelp(w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	maybeBanner()
	fmt.Fprintln(w, "kavachctl — Zyvor Kavach CLI (sister to netractl)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Auth / config:")
	fmt.Fprintln(w, "  KAVACH_URL            Controller base (default https://127.0.0.1:30899)")
	fmt.Fprintln(w, "  KAVACH_TOKEN          Bearer token (or ~/.kavach/api-key / ZYVOR_EDR_TOKEN)")
	fmt.Fprintln(w, "  KAVACH_TLS_INSECURE   true to skip TLS verify (auto on loopback)")
	fmt.Fprintln(w, "  ~/.kavach/env         Optional dotenv (skipped if KAVACH_SKIP_DOTENV=1)")
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	section := func(title string) {
		fmt.Fprintln(tw)
		fmt.Fprintf(tw, "%s\t\n", colorize(os.Stdout, ansiBold, title))
	}
	row := func(cmd, desc string) {
		fmt.Fprintf(tw, "  %s\t%s\n", cmd, desc)
	}

	section("Cluster")
	row("status [--json] [--wait]", "Health + summary + fleet board")
	row("sensor", "Sensor / Netra poller / SIEM probe")
	row("modules", "Kavach module capability map")
	row("world modules", "Global XDR/EDR capability catalog")
	row("ebpf status|health|events|…", "Observe-only eBPF platform (never enforce)")
	row("finance summary|insurance|irdai|…", "Banks, markets, insurance (observe)")
	row("sectors summary|automotive|space|…", "Rail, aviation, industry, space, gov fleets (observe)")

	section("Detect")
	row("watch [--severity S] [--max-events N]", "Live tail of /v1/stream (colored, auto-reconnect)")
	row("findings [--severity --rule --host] [-o table|json|yaml]", "EDR findings")
	row("detections [--severity --status --host] [-o table|json|yaml]", "Insight detections (MITRE)")
	row("incidents", "Incident workflow state")
	row("timeline", "Insight timeline")
	row("recent-events", "Recent process/network events")
	row("hunt query <expr>", "POST /v1/hunt/query")
	row("hunt kql <expr>", "POST /v1/hunt/kql")

	section("Fleet")
	row("fleet", "Agent fleet status")
	row("hosts", "Host inventory")
	row("host-groups", "Host groups")
	row("agents", "Agent credential registry")
	row("tenants", "Multi-site tenants")
	row("sensor-health", "Sensor coverage gaps")

	section("Response (observation ledger)")
	row("containment", "Containment request ledger (never enforced)")
	row("rtr commands", "RTR read-only allowlist")
	row("rtr sessions", "Open RTR sessions")
	row("cases", "Case management")
	row("threat-graph", "Correlation graph")
	row("storyline [--id --host]", "Attack storyline")
	row("air", "Automated investigation suggestions")

	section("Intel / Identity")
	row("intel actors|indicators", "Threat intel")
	row("intel feeds list|status|add|rm|refresh", "Intel feeds (add: --name --url --format --interval --ttl-days --tlp)")
	row("lab rules list|add FILE|rm ID", "Detection lab sandbox rules (FILE or - for stdin)")
	row("lab validate FILE | test FILE --events FILE | backtest --rule FILE|--id ID", "Validate / test / backtest a rule (sandbox only)")
	row("soc metrics [--days N] | shift-report [--hours N] [--out F] | storyline HOST", "SOC metrics, shift handoff, host storyline")
	row("posture summary|vulns [--limit --explain]|assets list|add|rm|drift HOST|baseline [HOST]", "Posture priority, assets, drift")
	row("compliance controls|evidence --framework F [--format --out --force] | cert-in-clock", "Control results, evidence pack, CERT-In clock")
	row("identity events|entities", "Identity threats")
	row("ueba", "UEBA scores")
	row("watchlists", "Entity watchlists")
	row("ioc|ioa|exclusions|rules", "Detection content")
	row("search QUERY [--type T,...] [--limit N]", "Search findings, hosts, rules, CVEs, IOCs, cases")
	row("inspect file|script|cmdline|domain|reports|analyzers", "Static artifact inspector (file max 32 MiB; never executed)")
	row("inspect similar (--sha256 X | --digest D) [--limit N]", "Nearest earlier submissions by similarity digest (not maliciousness)")
	row("inspect config PATH|-", "Config hardening assessment per policy (not a malware verdict; parse-only)")
	row("detections scheduled list|show|create|update|delete|dryrun|run|history", "Scheduled hunts that record findings (writes admin-only; --yes)")
	row("hunts limits [--set key=value ...]", "Hunt quotas and refusals (--set admin-only)")
	row("exceptions list|create|update|expire|delete|suppressed|history", "Reporting-only suppressions with hash-chain integrity (nothing is blocked)")
	row("reports scheduled list|create|update|delete|run|runs", "Scheduled reports (pull-only; never emailed or pushed)")
	row("reports archive get RUN_ID [--out FILE]", "Fetch a stored report; writes only to the path you give")
	row("fleet slo [status]|history|definitions|set", "Agent heartbeat/telemetry SLOs; unreported items shown plainly")
	row("syslog status|samples|parse LINE|-", "Syslog listener status; parse is a dry run, never ingests")
	row("prov graph|stories|trace|status", "Provenance graph, scored stories, bounded trace")
	row("ransom hosts|host --host H|status", "Ransomware-indicator windows (report-only)")
	row("ttp similar|next|chains", "Resemblance to public adversary profiles (NOT attribution)")
	row("ml status|lineage|similar|baseline|beacons|synthesize|priority|reset|replay", "Local ML models (reset/replay need --yes)")
	row("overwatch", "OverWatch alerts")
	row("dns threats", "DNS security threats")

	section("World inventory")
	row("discover assets|apps", "Discover inventory")
	row("spotlight", "CVE inventory")
	row("exposure|compliance|zero-trust", "Posture scorecards")
	row("compliance score [--json]", "Posture grade table (CIS/NIST/SOC2/ISO)")
	row("attack [--json]", "MITRE ATT&CK coverage table (tactic, covered, hits)")
	row("metrics", "Prometheus metrics")
	row("sbom|fim|persistence|firewall|browser", "Host collectors")
	row("casb|cnapp workloads|cnapp misconfigs|ot", "Cloud / OT")
	row("deception|email|dlp|forensics|sandbox", "Adjacent domains")
	row("device-control|yara|sigma|prevention", "Control surfaces")
	row("mdr|bas|itsm|notify|rbac|retention", "Ops ledgers")

	section("Identity / vulns / cases / hunts")
	row("identity summary|indicators|risk|privileged|timeline USER", "ITDR")
	row("vulns software|advisories|findings|exposure|top; sbom HOST", "Vulnerability management")
	row("advisories list|status|refresh", "Worldwide CERT advisory feeds (opt-in, KAVACH_CERT_FEEDS)")
	row("incidents correlated; case list|show|create|update|comment|close|export", "Incidents and cases")
	row("hunt packs|run|run-all|schedules|schedule-add|schedule-rm|history|devices", "Hunt packs")
	row("ransomware risk|host H; containers risk; lateral", "Ransomware / lateral")

	section("Fleet health / governance / tuning")
	row("fleet health|gaps|stale|host HOST", "Sensor health and coverage gaps")
	row("prevalence executables|rare|first-seen", "Executable prevalence")
	row("blast-radius --host H", "Likely-affected graph")
	row("canary list|create|delete ID|trips", "Deception canaries")
	row("governance inventory|retention|redaction|redact-preview|subject", "Data governance (retention apply needs --yes)")
	row("tuning suggestions|history|apply|revert ID", "Detection tuning")
	row("digest list|set|delete ID|send-now ID|deliveries", "Scheduled digests")

	section("AI Hub")
	row("ai capabilities|briefing|scores|agents", "AI catalog / briefing")
	row("ai chat <text>", "SOC copilot")
	row("ai nl-hunt <text>", "Natural-language hunt")
	row("ai assist <text>", "Assistive analyst help")
	row("ai cluster|forecast|anomaly|stream|guardian|xdr-fusion", "AI reads")
	row("ai score|narrative|report [--id]", "Per-finding AI")

	section("Analyst workspace / risk / alerts")
	row("risk hosts|summary [--json]", "Per-host risk ranking / fleet risk index")
	row("trends [--days 7|14|30] [--bucket hour|day]", "Finding trend table + sparkline")
	row("export findings --format csv|json|ndjson [--severity --host --rule --since] [--out F] [--force]", "Stream findings")
	row("export report --format html|json [--out F] [--force]", "Executive posture report")
	row("notes list --finding ID | add --finding ID \"text\" | rm ID", "Finding notes")
	row("saved-searches list | add --name N --scope S --query Q | rm ID", "Saved searches")
	row("alerts rules list | add --url U [--type --min-severity ...] | rm ID", "Alert rules (URL path masked)")
	row("alerts deliveries", "Alert delivery log")
	row("journal [verify]", "Tamper-evident activity journal / chain check")

	section("Ops / export")
	row("audit", "Console audit log")
	row("report", "SOC summary report")
	row("siem status|export", "SIEM sink / NDJSON export")
	row("fusion playbooks|runs", "Fusion SOAR")
	row("connectors|cloud|mobile", "Integrations preview")
	row("get <path>", "Raw GET under /v1 or absolute path")
	row("doctor", "Check URL, token, /livez, /readyz, auth, TLS")
	row("completion bash|zsh|fish", "Shell completion script")

	_ = tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Sister to netractl. Observation-only — Kavach never contains, kills, or isolates.")
}
