#!/usr/bin/env ruby
# One-off generator used to add the previously undocumented routes to
# docs/openapi.yaml. Kept for provenance; the source of truth is now the YAML
# itself, guarded by internal/edr/openapi_routes_test.go.
#
# usage: ruby docs/tools/gen_openapi_stubs.rb <missing-routes-file> docs/openapi.yaml
require "json"

A = :adminsess   # admin token or console session (requireAdminOrSession)
T = :admintoken  # admin bearer token only
ROUTES = []
def r(m, p, s, auth: nil, q: [], body: nil, ok: "JSON response", errs: {}, ct: nil)
  ROUTES << { m: m, p: p, s: s, auth: auth, q: q, body: body, ok: ok, errs: errs, ct: ct }
end
def qp(n, t, d) = [n, t, d]

# --- case templates / workflow (case_templates_http.go)
r "GET", "/v1/case-templates", "List case templates (built-in and custom)", ok: "Template array; each has id, name, case_type, default_severity, checklist, sla_hours, default_tags, built_in"
r "POST", "/v1/case-templates", "Create a custom case template (admin token only)", auth: T, body: "Template: name, case_type, default_severity, checklist[], sla_hours{severity:hours}, default_tags[]", ok: "Created template", errs: { "400" => "Validation failed or too many templates", "403" => "Not the admin token" }
r "GET", "/v1/case-templates/{id}", "One case template", ok: "Template", errs: { "404" => "Not found" }
r "PUT", "/v1/case-templates/{id}", "Update a custom case template (admin token only; built-ins are read-only)", auth: T, body: "Template fields as for POST", ok: "Updated template", errs: { "400" => "Validation failed", "403" => "Built-in template or not the admin token", "404" => "Not found" }
r "DELETE", "/v1/case-templates/{id}", "Delete a custom case template (admin token only; built-ins are read-only)", auth: T, ok: "Deleted", errs: { "403" => "Built-in template or not the admin token", "404" => "Not found" }
r "GET", "/v1/cases/{id}/workflow", "Workflow view of a case: applied template, checklist progress and SLA", ok: "Workflow view", errs: { "404" => "Case not found" }
r "POST", "/v1/cases/{id}/assign", "Assign a case to an analyst (admin or session)", auth: A, body: '{"assignee": "<=80 chars"}', ok: "Updated workflow view", errs: { "400" => "Assignee too long", "404" => "Case not found" }
r "POST", "/v1/cases/{id}/apply-template", "Apply a template to a case, creating its checklist and SLA (admin or session)", auth: A, body: '{"template_id": "..."}', ok: "Updated workflow view", errs: { "404" => "Template or case not found" }
r "POST", "/v1/cases/{id}/checklist/{n}", "Tick or untick checklist step n (1-based; admin or session)", auth: A, body: '{"done": true|false} (required)', ok: "Updated workflow view", errs: { "400" => "Invalid step number or done missing", "404" => "No such checklist step (apply a template first)" }
r "GET", "/v1/case-workflow/journal", "Hash-chained journal of case workflow actions (newest 200) with chain verification", ok: "{intact, first_broken_seq, reason, entries[]}"

# --- chains (chains_http.go)
r "GET", "/v1/chains", "Correlated attack chains across findings, ranked by score", q: [qp("host", "string", "Restrict to one host"), qp("min_score", "number", "Minimum chain score"), qp("limit", "integer", "1-200, default 50")], ok: "{chains[], total, returned}"
r "GET", "/v1/chains/{id}", "One attack chain", ok: "Chain with linked case id if any", errs: { "404" => "Not found" }
r "POST", "/v1/chains/{id}/case", "Open (or return the existing) case for a chain (admin or session)", auth: A, ok: "{created, case}", errs: { "404" => "Chain not found" }

# --- content versions (content_versions_store.go)
r "GET", "/v1/content/versions", "Embedded content snapshot history (newest first)", q: [qp("items", "string", "1 = include per-item hashes")], ok: "{mode, count, history_cap, snapshots[]}"
r "GET", "/v1/content/changes", "Diff between two content snapshots (default: previous vs latest)", q: [qp("from", "string", "Snapshot seq or ref"), qp("to", "string", "Snapshot seq or ref, default latest")], ok: "{from, to, diff{added, removed, modified}}", errs: { "404" => "Unknown from/to snapshot" }
r "GET", "/v1/content/changelog", "Human-readable changelog entry per snapshot (newest first)", ok: "Changelog entries"

# --- coverage (blindspots_report.go)
r "GET", "/v1/coverage/telemetry", "Per-category telemetry inventory (live, nothing stored)", q: [qp("stale_days", "integer", "1-3650; a category silent for longer is stale")], ok: "{mode, caveat, stale_after_hours, categories[]}"
r "GET", "/v1/coverage/blindspots", "Detection blind-spot report: telemetry gaps against rules, with optional validation run", q: [qp("stale_days", "integer", "1-3650"), qp("validation", "string", "0 = skip the built-in validation run")], ok: "Blind-spot report"

# --- scheduled detections / hunt limits (detect_sched_http.go)
r "GET", "/v1/detections/scheduled", "List scheduled detections", ok: "{detections[], count, limits}"
r "POST", "/v1/detections/scheduled", "Create a scheduled detection (admin or session)", auth: A, body: "name, source (saved search or kavach-seq query), interval_sec (60-86400), severity, technique, state, max_matches, max_runtime_ms, dedup_window_sec", ok: "Created detection (201)", errs: { "400" => "Validation failed", "429" => "max_scheduled quota reached" }
r "GET", "/v1/detections/scheduled/{id}", "One scheduled detection with running flag", ok: "{detection, running, ...}", errs: { "404" => "Not found" }
r "PUT", "/v1/detections/scheduled/{id}", "Update a scheduled detection (admin or session)", auth: A, body: "Any subset of the POST fields", ok: "Updated detection", errs: { "400" => "Validation failed", "404" => "Not found" }
r "DELETE", "/v1/detections/scheduled/{id}", "Delete a scheduled detection (admin or session); findings already recorded are kept", auth: A, ok: "{deleted, findings_already_recorded_kept}", errs: { "404" => "Not found" }
r "POST", "/v1/detections/scheduled/{id}/dryrun", "Run now without recording anything (admin or session)", auth: A, ok: "Run result; 'recorded' is what WOULD be reported", errs: { "404" => "Not found" }
r "POST", "/v1/detections/scheduled/{id}/run", "Run now and record findings (admin or session)", auth: A, ok: "Run result", errs: { "404" => "Not found", "429" => "Hunt run quota reached" }
r "GET", "/v1/detections/scheduled/{id}/history", "Run history of a scheduled detection", ok: "{id, history[], retention}", errs: { "404" => "Not found" }
r "GET", "/v1/hunts/limits", "Hunt quotas, current usage and refusal log", ok: "{limits, usage, refused{counts, recent}, env[]}"
r "PUT", "/v1/hunts/limits", "Change hunt quotas (admin token only)", auth: T, body: "max_scheduled 1-500, max_runs_per_hour 1-3600, max_matches_per_run 1-1000, history_retention 1-500", ok: "Updated limits", errs: { "400" => "Value out of range", "403" => "Admin token required" }

# --- exceptions (exceptions_http.go)
r "GET", "/v1/exceptions", "List rule exceptions (all have an expiry)", q: [qp("status", "string", "Filter by status, e.g. active or expired")], ok: "{exceptions[], count, ...}"
r "GET", "/v1/exceptions/history", "Hash-chained exception change history", ok: "{history[], chain_ok, broken_at_seq}"
r "GET", "/v1/exceptions/suppressed", "Findings suppressed by exceptions (reporting only; nothing is blocked)", q: [qp("exception", "string", "Exception id")], ok: "{suppressed[], counts, total_suppressed}"
r "POST", "/v1/exceptions", "Create an exception (admin or session)", auth: A, body: "rule, host, path, reason, owner, expires (RFC3339, max 365 days)", ok: "Created exception", errs: { "400" => "Invalid body, expiry or scope", "429" => "Too many active exceptions" }
r "PUT", "/v1/exceptions/{id}", "Update an exception, or set expire_now (admin or session)", auth: A, body: "Any subset of the POST fields plus expire_now", ok: "Updated exception", errs: { "400" => "Invalid body", "404" => "Not found" }
r "DELETE", "/v1/exceptions/{id}", "Delete an exception (admin or session); suppressed findings are kept", auth: A, ok: "{deleted, suppressed_findings_kept}", errs: { "404" => "Not found" }

# --- scheduled reports (report_sched_http.go)
r "GET", "/v1/reports/scheduled", "List report schedules with limits and delivery note (pull-only)", ok: "{schedules[], templates_with_host_names, delivery, limits, redaction}"
r "POST", "/v1/reports/scheduled", "Create a report schedule (admin or session)", auth: A, body: "Schedule: template, params, frequency, retention, format", ok: "Created schedule (201)", errs: { "400" => "Validation failed" }
r "PUT", "/v1/reports/scheduled/{id}", "Update a report schedule (admin or session)", auth: A, body: "Schedule fields", ok: "Updated schedule", errs: { "400" => "Validation failed", "404" => "Not found" }
r "DELETE", "/v1/reports/scheduled/{id}", "Delete a schedule and its archived reports (admin or session)", auth: A, ok: "No content", errs: { "404" => "Not found" }
r "POST", "/v1/reports/scheduled/{id}/run", "Render a schedule now (admin or session)", auth: A, ok: "Run record", errs: { "404" => "Not found", "409" => "Run already in progress", "500" => "Render failed" }
r "GET", "/v1/reports/scheduled/{id}/runs", "Runs of a schedule", ok: "{schedule_id, runs[]}", errs: { "404" => "Schedule not found" }
r "GET", "/v1/reports/archive/{run_id}", "Download a rendered report (md, json or csv; X-Kavach-Report-SHA256 header)", ok: "Report bytes", errs: { "404" => "Report not found" }, ct: "application/octet-stream"

# --- fleet SLO (fleet_slo_http.go)
r "GET", "/v1/fleet/slo", "Fleet SLO report (heartbeat freshness, continuity, coverage)", ok: "SLO report"
r "PUT", "/v1/fleet/slo", "Set SLO targets (admin token only)", auth: T, body: "heartbeat_fresh_minutes, heartbeat_target_pct, continuity_gap_minutes, continuity_target_pct, coverage_target_pct, window_hours", ok: "Updated config", errs: { "400" => "Invalid JSON or value", "403" => "Admin token required" }
r "GET", "/v1/fleet/slo/definitions", "How each SLO is computed", ok: "SLO definitions"
r "GET", "/v1/fleet/slo/history", "SLO sample history", q: [qp("window", "string", "Duration 5m-72h, default 24h (e.g. 6h, 2d)"), qp("agent", "string", "Restrict to one agent")], ok: "SLO history series", errs: { "400" => "Bad window", "404" => "No SLO history for that agent" }

# --- hunt seq (hunt_eql_http.go)
r "POST", "/v1/hunt/seq", "Run a kavach-seq sequence/EQL-style hunt over retained events", body: '{"query": "...", "since": "24h|7d|RFC3339", "limit": n}', ok: "{query, kind, count, matches[], truncated, timed_out, scan_capped, scanned, elapsed_ms, semantics}", errs: { "400" => "Parse error (pos/line/col) or query uses unavailable fields" }
r "GET", "/v1/hunt/seq/fields", "Field catalogue, operators and limits for kavach-seq", ok: "{categories, join_keys, operators, notes, limits}"
r "GET", "/v1/hunt/seq/examples", "Example kavach-seq queries", ok: "{count, examples[]}"
r "POST", "/v1/hunt/seq/explain", "Parse and explain a query without running it", body: '{"query": "...", "since": "..."}', ok: "{ok, kind, tree, unavailable_fields, semantics} (parse errors are returned with ok=false and pos/line/col)", errs: { "400" => "Invalid JSON or since" }

# --- feedback (feedback_http.go)
r "POST", "/v1/feedback", "Record an analyst verdict on a finding (admin or session; hash-chained, nothing auto-applied)", auth: A, body: '{"finding_id", "verdict": true_positive|false_positive|benign_expected|needs_more_data, "note"}', ok: "Recorded entry", errs: { "400" => "Bad JSON, verdict or note too long", "404" => "Unknown finding_id" }
r "GET", "/v1/feedback", "List feedback entries, newest first", q: [qp("limit", "integer", "1-1000, default 100"), qp("finding_id", "string", ""), qp("rule", "string", ""), qp("host", "string", "")], ok: "{entries[]}"
r "GET", "/v1/feedback/verify", "Verify the feedback hash chain", ok: "Chain verification result"
r "GET", "/v1/feedback/rules", "Per-rule precision derived from feedback", ok: "Per-rule counts and precision"
r "GET", "/v1/feedback/summary", "Feedback summary", ok: "Summary counts"
r "POST", "/v1/feedback/export", "Export feedback as a research dataset (nothing leaves the host)", q: [qp("redact", "string", "1 = redact host and note fields")], ok: "Export payload"

# --- inspect (inspect_contract.go, inspect_sim_analyzer.go)
%w[file script cmdline domain config].each do |k|
  desc = { "file" => "raw bytes (application/octet-stream); ?name= optional", "script" => "raw text or {\"text\": ...}", "cmdline" => "raw text or {\"text\": ...}", "domain" => "raw text or {\"text\": ...} (one domain)", "config" => "raw text or {\"text\": ...} (configuration file, parse-only)" }[k]
  r "POST", "/v1/inspect/#{k}", "Inspect a #{k} (observe-only static analysis; nothing is executed)", q: (k == "file" ? [qp("name", "string", "Display file name")] : []), body: desc, ok: "Inspection report", errs: { "400" => "Empty input or invalid JSON", "413" => "Input larger than the inspect limit" }, ct: (k == "file" ? "application/octet-stream" : "text/plain")
end
r "GET", "/v1/inspect/reports", "Recent inspection reports (no input bytes)", q: [qp("limit", "integer", "Max reports")], ok: "{count, reports[], mode}"
r "GET", "/v1/inspect/analyzers", "Registered analyzers and the input size limit", ok: "{analyzers[], max_bytes, mode}"
r "GET", "/v1/inspect/similar", "Similar previously-inspected files by fuzzy digest", q: [qp("sha256", "string", "Query by a known report sha256"), qp("digest", "string", "Or a kavach-ctph1:... / kavach-lsh1:... digest"), qp("limit", "integer", "1-50, default 10")], ok: "Similarity matches", errs: { "400" => "Malformed or unsupported digest", "404" => "Unknown sha256" }

# --- ml (ml_*.go)
r "GET", "/v1/ml/status", "Local behaviour model status", ok: "Model status"
r "GET", "/v1/ml/lineage", "Process-lineage transition statistics", q: [qp("host", "string", ""), qp("limit", "integer", "")], ok: "Lineage edges"
r "GET", "/v1/ml/similar", "Commands similar to a given command line", q: [qp("q", "string", "Command line, 1-2048 bytes (required)"), qp("host", "string", "")], ok: "Similar commands", errs: { "400" => "q missing or too long" }
r "GET", "/v1/ml/baseline", "Per-host hour-of-week activity baseline", q: [qp("host", "string", "required")], ok: "Baseline", errs: { "400" => "host required" }
r "POST", "/v1/ml/reset", "Reset learned behaviour models (admin or session)", auth: A, ok: "{method, status: reset}"
r "POST", "/v1/ml/learn/replay", "Rebuild models from the retained store (admin or session)", auth: A, ok: "{method, status: replayed, events_replayed, source}"
r "GET", "/v1/ml/beacons", "Beaconing candidates from network events", q: [qp("host", "string", ""), qp("min_events", "integer", "4-100000"), qp("min_score", "number", ""), qp("limit", "integer", "1-200, default 20"), qp("exclude_private", "string", "1 or true")], ok: "Beacon candidates"
r "GET", "/v1/ml/priority", "Advisory finding priority score (does not change /v1/ai/score)", q: [qp("finding_id", "string", "Score one finding"), qp("host", "string", ""), qp("limit", "integer", "1-500, default 50")], ok: "{mode, model, weights, note, priority|items}", errs: { "404" => "Finding not found" }
r "POST", "/v1/ml/synthesize", "Synthesize detection ideas from a finding, command or event", body: "Exactly one of finding_id, command, event", ok: "Synthesis result", errs: { "400" => "Invalid body or not exactly one input", "404" => "Finding not found" }

# --- prov / ransom / syslog / ttp
r "GET", "/v1/prov/graph", "Provenance graph", q: [qp("host", "string", ""), qp("limit", "integer", "Node cap, default 500")], ok: "Graph nodes and edges"
r "GET", "/v1/prov/stories", "Provenance stories (attack narratives)", q: [qp("host", "string", "")], ok: "Stories"
r "GET", "/v1/prov/trace", "Trace back/forward from a finding", q: [qp("finding_id", "string", "Finding id"), qp("dir", "string", "back, fwd or both"), qp("hops", "integer", "Hop limit, default 3")], ok: "Trace subgraph", errs: { "400" => "Bad dir", "404" => "Finding not found" }
r "GET", "/v1/prov/status", "Provenance engine status", ok: "Status"
r "GET", "/v1/ransom/status", "Ransomware detector method, thresholds and blind spots (report-only)", ok: "{method, window, thresholds, alert_rule, primary, secondary, cannot_see, report_only}"
r "GET", "/v1/ransom/hosts", "Per-host ransomware indicator scores", ok: "{hosts[], report_only}"
r "GET", "/v1/ransom/host", "Ransomware windows for one host", q: [qp("host", "string", "required"), qp("limit", "integer", "")], ok: "{host, windows[], report_only}", errs: { "400" => "host required", "404" => "No file events for host" }
r "GET", "/v1/syslog/status", "Syslog listener status", ok: "Listener status (enabled false when not configured)"
r "GET", "/v1/syslog/samples", "Recent unparsed syslog lines (redacted, truncated to 512 chars)", ok: "{count, samples[], note}"
r "POST", "/v1/syslog/parse", "Parse one syslog line without ingesting it (admin or session)", auth: A, body: '{"line": "<=8KiB syslog line"}', ok: "{parsed, message, events, ingested: false}", errs: { "400" => "Missing or oversized line" }
r "GET", "/v1/ttp/similar", "Adversary profiles similar to observed techniques", q: [qp("techniques", "string", "Comma-separated ATT&CK ids"), qp("finding_ids", "string", "Comma-separated finding ids"), qp("host", "string", "Use that host's techniques")], ok: "{confidence, matches[], method}", errs: { "400" => "No usable technique input" }
r "GET", "/v1/ttp/next", "Hunt hints: techniques co-occurring in similar profiles (not a prediction)", q: [qp("techniques", "string", ""), qp("finding_ids", "string", ""), qp("host", "string", "")], ok: "{confidence, hints[], label}", errs: { "400" => "No usable technique input" }
r "GET", "/v1/ttp/chains", "Observed technique chains for a host against adversary profiles", q: [qp("host", "string", "required")], ok: "Chains", errs: { "400" => "host= required", "503" => "Adversary profiles unavailable" }

# --- validation lab, vuln priority, competitive
r "GET", "/v1/validate/scenarios", "Detection validation scenarios", q: [qp("kind", "string", ""), qp("platform", "string", ""), qp("technique", "string", "")], ok: "Scenario list"
r "GET", "/v1/validate/scenarios/{id}", "One validation scenario", ok: "Scenario", errs: { "404" => "Scenario not found" }
r "POST", "/v1/validate/run", "Replay scenarios through the detection engine in memory (no real events are produced)", body: '{"ids": [...], "all": bool, "include_custom": bool}', ok: "Per-scenario pass/fail and coverage", errs: { "400" => "Invalid body, neither ids nor all, or too many ids" }
r "GET", "/v1/validate/coverage", "Detection coverage by technique from scenarios", q: [qp("include_custom", "string", "true to include custom rules")], ok: "Coverage"
r "GET", "/v1/vulns/priority", "SSVC + EPSS + CVSS vulnerability prioritisation", q: [qp("host", "string", ""), qp("limit", "integer", "1-500, default 50")], ok: "{tree_version, total, count, ranking, epss, items[], limitations}", errs: { "400" => "limit must be 1-500" }
r "GET", "/v1/vulns/priority/status", "EPSS feed and prioritisation status", ok: "Status"
r "POST", "/v1/vulns/priority/refresh", "Refresh the EPSS cache now (only fetches when KAVACH_EPSS_FEED=on)", ok: "Refresh result"
r "GET", "/v1/vulns/priority/{cve}", "Prioritisation of one CVE across hosts", ok: "{cve, tree_version, hosts, ...}", errs: { "400" => "Invalid CVE id", "404" => "CVE not matched on any host" }
r "GET", "/v1/world/competitive", "Competitive feature matrix (embedded competitive_matrix.json)", ok: "Matrix", errs: { "500" => "Matrix unavailable" }

# --- misc POSTs
r "POST", "/v1/connectors", "Register a connector definition (admin or session)", auth: A, body: "Connector JSON", ok: "Registered connector", errs: { "400" => "Invalid" }
r "POST", "/v1/inventory", "Ingest a live inventory domain snapshot", body: "{domain, ...} (domain required)", ok: "Accepted", errs: { "400" => "Invalid inventory payload" }
r "POST", "/v1/rbac/roles", "Add or update a role (admin or session)", auth: A, body: "Role JSON", ok: "Role saved", errs: { "400" => "Invalid" }

# --- ebpf
{ "status" => "eBPF sensor status", "health" => "eBPF sensor health", "coverage" => "eBPF coverage", "attachments" => "eBPF attachments", "maps" => "eBPF maps",
  "census" => "eBPF census", "summary" => "eBPF summary", "drops" => "eBPF dropped-event counters", "processes" => "eBPF-observed processes", "features" => "eBPF feature gates" }.each do |k, s|
  r "GET", "/v1/ebpf/#{k}", "#{s} (observe-only)"
end
r "GET", "/v1/ebpf/capabilities", "eBPF capabilities (observe-only; enforce=false)", ok: "{capabilities[], enforce}"
r "GET", "/v1/ebpf/events", "Ingested eBPF events", q: [qp("type", "string", "Event type filter")]
r "POST", "/v1/ebpf/events", "Ingest eBPF events", body: '{"events": [...], "lost": n}', ok: "{ingested, lost}", errs: { "400" => "Bad JSON" }
r "POST", "/v1/ebpf/features/{id}", "Set an observation sensor gate", body: '{"mode": "auto|on|off"}', ok: "{id, mode, enforce: false}", errs: { "400" => "Bad JSON or mode", "404" => "Unknown feature" }
%w[status drops flows attachments].each do |k|
  r "GET", "/v1/ebpf/netra/#{k}", "Proxy of the Netra eBPF #{k} view (read-only)"
end

# --- sectors / finance events
r "POST", "/v1/sectors/events", "Ingest sector observation events", body: '{"events": [{...}]}', ok: "{ingested, enforce: false}", errs: { "400" => "Bad JSON" }
r "POST", "/v1/finance/events", "Ingest finance observation events", body: '{"events": [{...}]}', ok: "{ingested, enforce: false}", errs: { "400" => "Bad JSON" }

# sector / finance catalogue GETs come straight from the missing list
missing = File.read(ARGV[0]).lines.map(&:strip)
missing.each do |l|
  next unless l =~ %r{^GET (/v1/(sectors|finance)/([a-z-]+))\s}
  path, grp, name = $1, $2, $3
  next if ROUTES.any? { |x| x[:p] == path && x[:m] == "GET" }
  r "GET", path, "Observe-only #{grp} view: #{name.tr('-', ' ')}", ok: "JSON view (enforce=false)"
end

def q(s) = s.to_json

def render(x)
  out = +"    #{x[:m].downcase}:\n"
  out << "      summary: #{q(x[:s])}\n"
  out << "      security: []\n" if false
  out << "      x-auth: #{x[:auth] == T ? 'admin-token' : 'admin-or-session'}\n" if x[:auth]
  params = x[:p].scan(/\{(\w+)\}/).flatten.map { |n| [n, "path", (n == "n" ? "integer" : "string"), "", true] }
  params += x[:q].map { |n, t, d| [n, "query", t, d, false] }
  unless params.empty?
    out << "      parameters:\n"
    params.each do |n, i, t, d, req|
      out << "        - { name: #{n}, in: #{i}, #{req ? 'required: true, ' : ''}schema: { type: #{t} }#{d.empty? ? '' : ", description: #{q(d)}"} }\n"
    end
  end
  if x[:body]
    out << "      requestBody:\n        content:\n          #{x[:ct] || 'application/json'}:\n            schema: { type: #{x[:ct] ? 'string' : 'object'} }\n        description: #{q(x[:body])}\n"
  end
  out << "      responses:\n"
  created = %w[/v1/exceptions /v1/case-templates /v1/detections/scheduled /v1/reports/scheduled]
  okcode = x[:m] == "DELETE" && x[:ok] == "No content" ? "204" : (x[:m] == "POST" && created.include?(x[:p]) ? "201" : "200")
  out << "        \"#{okcode}\": { description: #{q(x[:ok])} }\n"
  x[:errs].each { |c, d| out << "        \"#{c}\": { description: #{q(d)} }\n" }
  out
end

text = File.read(ARGV[1])
lines = text.lines
ci = lines.index { |l| l.start_with?("components:") }
head = lines[0...ci].join
tail = lines[ci..].join
by_path = ROUTES.group_by { |x| x[:p] }
append = +""
by_path.each do |p, ops|
  block = ops.map { |x| render(x) }.join
  key = "  #{p}:\n"
  if head.include?(key)
    head.sub!(key) { key + block }
  else
    append << key << block
  end
end
head << "\n" unless head.end_with?("\n")
File.write(ARGV[1], head + append + tail)
puts "added #{ROUTES.size} operations on #{by_path.size} paths"
