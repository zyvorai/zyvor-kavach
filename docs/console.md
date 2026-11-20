# Console

The Kavach web console is an Apple.com / Netra-sister SPA served from the controller. It is a single embedded file, `internal/edr/dashboard.html`, served by `internal/edr/dashboard.go`: no build step and no external assets. It is observation-only like the rest of Kavach.

---

## Login

| Field | Demo value |
|-------|------------|
| Username | `admin` |
| Password | `Admin@321` |

Password **is** the server bearer (`KAVACH_TOKEN`). The form posts candidates to `POST /v1/session` and receives an HttpOnly `zyvor_session` cookie (1h, SameSite=Strict).

Wrong username or password gives "Wrong username or password."

Legacy lab tokens that used `Admin@321Admin@321` are still tried when the password is `Admin@321`, for smooth upgrades.

Sign out calls `POST /v1/logout` and reloads.

---

## Layout

- Shell max width **1800px** (`--shell-max`, Netra sister), so wide displays are used fully.
- Sticky translucent nav with the primary tabs and a **Browse** overflow menu.
- Observation-only banner on every page.
- Theme: system, light or dark. The default follows the operating-system colour scheme (`prefers-color-scheme`) and tracks live changes; the toggle (and the palette action "Cycle theme") cycles system, light, dark. The choice is stored in `localStorage` (`kavach-theme`: `auto`, `light` or `dark`) inside try/catch, so a blocked store just falls back to the OS setting.
- Hash routing: opening a page sets `#/<id>` (for example `#/models`). A link with a valid `#/<id>` opens that page, and the last page is remembered in `localStorage` (`kavach-page`). The URL is replaced, not pushed, so the browser Back button leaves the console rather than stepping through pages you visited. An id that is not a page is ignored.
- Netra-matching button system: blue primary CTA, quiet secondary, danger only for destructive-looking ledgers.
- Phone width: CSS breakpoints at 860px (sequence-hunt grid), 820px and 640px. See "Dark mode and phone width" for what has and has not been checked.

---

## Page conventions

These apply to every page unless its entry says otherwise.

- **Auth and errors.** Pages use the session cookie. A `401` from the main data load returns you to the login form. Other load failures show the HTTP error text, either in the page error line or as a "Could not load ..." row in the affected table.
- **Empty states.** An empty list shows a title and one sentence about why it is empty (no data yet, feature off by default, feed not configured) instead of a blank table.
- **Admin-only actions.** Some writes need the admin bearer or an active signed-in session (for example Models reset and rebuild). Without it the server answers 401 or 403 and the page shows the message; nothing is changed.
- **Mutating controls.** Where a page has buttons that change state (enroll, revoke, transition, save, schedule, purge) they change only Kavach's own records. No page contains, kills, blocks or isolates anything.
- **Refresh.** Alerts polls every 10 s, Intel feeds every 30 s, Regulatory clocks and the Evidence CERT-In countdown tick every second. Polling pauses while the browser tab is hidden or the sign-in form is showing. Every other page loads when opened and again on its own Reload, Refresh or Load button.

---

## Pages (primary)

| Page | Hash | g-key | Purpose | Data |
|------|------|-------|---------|------|
| Overview | `#/overview` | `g o` | Story hero, live metrics, chapter links | `/v1/summary`, `/v1/fleet`, `/v1/findings`, `/v1/incidents`, `/v1/reports/summary` |
| Detect | `#/detect` | `g d` | Findings from rules matched against process activity; a row opens the finding drawer, where analyst verdicts are recorded | `/v1/findings` |
| Detections | `#/detections` | `g t` | Insight detections with ATT&CK mapping and triage; Save search stores the current filter | `/v1/detections`, `/v1/saved-searches` |
| Hunt | `#/hunt` | `g h` | FQL-lite queries across findings, processes and network events, for example `host: demo rule: ransomware` | `POST /v1/hunt/query` |
| Incidents | `#/incidents` | `g i` | Analyst workflow state per finding; Transition records a state change with an optional note | `/v1/incidents`, `POST /v1/incidents/transition` |
| Hosts | `#/hosts` | `g s` | Host inventory; Record request writes to a containment ledger that is never enforced | `/v1/hosts`, `/v1/containment` |
| Fleet | `#/fleet` | `g f` | Agents; online means a heartbeat within the last 90 seconds; Enroll issues an enrollment, revoke removes an agent | `/v1/fleet`, `/v1/agents/enroll`, `/v1/agents/revoke` |
| AI Hub | `#/ai` | `g a` | Chat, daily briefing, triage autopilot, multi-agent run, what-if, XDR fusion, guardian, NL hunt. Assistive only | `/v1/ai/*` |
| World | `#/world` | `g w` | Global vendor capability catalog, KQL runner, storyline loader and a "Domain API" selector (CASB, email, DLP, CNAPP, exposure, compliance, FIM, persistence, YARA, Sigma, network discovery and more) | `/v1/world/modules`, `/v1/hunt/kql`, `/v1/storyline`, the selected domain endpoint |

## Browse menu

Timeline, Prevent, Intel, Identity, Spotlight, OverWatch, Response, Ops, Observe, eBPF, Alerts, Risk, SOC, Posture, Finance, Sectors, Modules, Integrations, Detection lab, Intel feeds, Evidence, Fleet health, Prevalence, Canaries, Governance, Tuning, Identity threats, Vulnerabilities, Cases, Hunt packs, Ransomware, Content library, Adversaries, Rule health, Export, Search, CERT advisories, Regulatory clocks, Models, Inspector, Provenance, Ransomware behaviour, TTP similarity, Competitive, Syslog, Content versions, Reports and SLO, Automation, Attack chains, Feedback, Vulnerability priority, Sequence hunt, Coverage, Posture trend, Executive digest, Auditor bundle.

The menu is read from `internal/edr/dashboard.html`; `TestDocsConsoleListsMenuPages` fails when a page is missing here.

### Browse pages: purpose, route, data source

Every page has the hash `#/<id>` using the id column. Endpoints are what the page loader calls (read from `dashboard.html`); a trailing `*` means several sub-routes. "g then X" means press `g`, then the key within 1.2 seconds.

#### Triage and operations

| Page | id | g-key | Purpose and controls | Data |
|------|----|-------|----------------------|------|
| Timeline | `timeline` | `g l` | Latest process and network signals | `/v1/recent-events` |
| Prevent | `prevent` | none | Detect-only IOA rules and prevention policies; never quarantines | `/v1/ioa`, `/v1/prevention/policies`, `/v1/exclusions` |
| Intel | `intel` | none | Actor profiles, IOC intel, custom IOCs | `/v1/intel/actors`, `/v1/ioc`, `/v1/intel/indicators` |
| Identity | `identity` | none | Identity anomalies, entity risk, UEBA scores | `/v1/identity/events`, `/v1/identity/entities`, `/v1/ueba` |
| Spotlight | `spotlight` | none | CVE posture with prioritisation seeds | `/v1/spotlight/vulnerabilities`, `/v1/discover/*` |
| OverWatch | `overwatch` | none | Managed-hunting style alert feed | `/v1/overwatch/alerts` |
| Response | `response` | none | Read-only RTR diagnostics and SOAR playbook ledger; "Open and execute" records a session, it does not act on the host | `/v1/rtr/*`, `/v1/fusion/playbooks`, `/v1/fusion/runs` |
| Ops | `ops` | none | Cases, audit trail, device and firewall inventory, cloud and mobile preview, connectors, threat graph | `/v1/cases`, `/v1/audit`, `/v1/device-control`, `/v1/firewall/rules`, `/v1/cloud/posture`, `/v1/mobile/devices`, `/v1/connectors`, `/v1/threat-graph` |
| Observe | `observe` | `g v` | ATT&CK coverage matrix, compliance grade, live detection feed over SSE (shows a placeholder when empty) | `/v1/attack/matrix`, `/v1/compliance/score`, `/v1/stream` |
| eBPF | `ebpf` | `g e` | Health score, backend, event and lost counters, feature table, recent events | `/v1/ebpf/status`, `/health`, `/features`, `/events` |
| Alerts | `alerts` | `g n` | Webhook and Slack notification rules and the delivery log; Add rule. Rules only notify (polls every 10 s) | `/v1/alerts/rules`, `/v1/alerts/deliveries` |
| Risk | `risk` | `g k` | Fleet risk index, ranked hosts, trends (7, 14 or 30 days; by day or hour), findings export as CSV, JSON or NDJSON | `/v1/risk/*`, `/v1/trends`, `/v1/export/findings`, `/v1/export/report` |
| SOC | `soc` | `g x` | Response metrics (7, 30 or 90 days), backlog, noisy rules, host storylines, shift handoff; Print report | `/v1/soc/metrics`, `/v1/storyline/host`, `/v1/soc/shift-report` |
| Posture | `posture` | `g p` | Exposure-style view: vulnerability priority, asset criticality (Save asset), drift against a baseline (Take baseline) | `/v1/posture/*`, `/v1/search` |
| Modules | `modules` | `g m` | Capability map; observation-only where response would enforce | `/v1/modules`, `/v1/world/modules` |
| Integrations | `integrations` | none | SIEM sinks and the active process sensor backend | `/v1/siem/status`, `/v1/sensor` |
| Finance | `finance` | none | See the Finance page section | `/v1/finance/*` |
| Sectors | `sectors` | none | See the Sectors page section | `/v1/sectors/*` |

#### Assurance, content and reporting

| Page | id | g-key | Purpose and controls | Data |
|------|----|-------|----------------------|------|
| Detection lab | `lab` | `g b` | Sandbox: write, validate, test and backtest rules; Starter template; Save to lab. Lab rules never go live | `/v1/lab/rules*` |
| Intel feeds | `feeds` | `g u` | Add feed and refresh; feeds only add indicators for matching (polls every 30 s) | `/v1/intel/feeds`, `/v1/intel/feeds/status` |
| Evidence | `evidence` | `g c` | Signals mapped to framework controls, evidence pack, CERT-In clock (ticks each second) | `/v1/compliance/*` |
| Fleet health | `fleethealth` | `g r` | Heartbeats, sensor coverage, stale agents, shadow hosts; Show host | `/v1/fleet/health`, `/v1/fleet/stale`, `/v1/fleet/coverage-gaps` |
| Prevalence | `prevalence` | `g y` | How common each executable is; First seen and Blast radius for a host | `/v1/prevalence/*`, `/v1/graph/blast-radius` |
| Canaries | `canaries` | `g j` | Create and delete tripwires and review trips. Canary values are non-functional | `/v1/deception/canaries`, `/v1/deception/trips` |
| Governance | `governance` | `g z` | Inventory, retention (Preview purge; applying needs confirmation), redaction, subject lookup | `/v1/governance/*` |
| Tuning | `tuning` | `g q` | Advisory noise reduction (apply and revert are human actions) and scheduled digests. Critical findings are never suppressed | `/v1/tuning/*`, `/v1/digests*` |
| Identity threats | `itdr` | `g g` | Credential theft, Kerberoasting, pass-the-hash, impossible travel and privileged use; indicators and timeline | `/v1/identity/itdr/*` |
| Vulnerabilities | `vulns` | `g 1` | Installed software matched against advisories; SBOM download; advisory feed status and Refresh feeds. Advice only | `/v1/vulns/*`, `/v1/sbom/` |
| Cases | `cases` | `g 2` | Correlated incidents, create and update cases, SLA clocks, comments, markdown export | `/v1/cases`, `/v1/incidents/correlated`, `/v1/case-templates` |
| Hunt packs | `huntpacks` | `g 3` | Run prepared hunts, Run all packs, schedule, history, removable devices | `/v1/hunts/*`, `/v1/devices/removable` |
| Ransomware | `ransomware` | `g 4` | Ransomware precursors, container posture, lateral movement. Report only | `/v1/ransomware/*`, `/v1/containers/risk`, `/v1/lateral/edges` |
| Content library | `content` | `g 5` | Tabs Rules, Coverage, Hunt packs, Queries, Guidance, Report templates. Read only | `/v1/content/*`, `/v1/hunts/packs`, `/v1/queries/library`, `/v1/guidance`, `/v1/reports/templates` |
| Adversaries | `adversaries` | `g 6` | Public actor profiles mapped to ATT&CK and to Kavach content; Profiles and Coverage ranking | `/v1/adversaries*` |
| Rule health | `rulehealth` | `g 7` | Which rules fire, which are noisy, which are silent; Change state records a lifecycle state with an optional note | `/v1/rules/health`, `/v1/rules/lifecycle/*`, `/v1/rules/history/*` |
| Export | `export` | `g 8` | Preview first 5 records, Download, resume with the next cursor; filters host, rule id, since (RFC 3339) | `/v1/export/findings`, `/iocs`, `/attack-layer` |
| Search | `search` | `g /` | See the Search page section | `/v1/search` |
| CERT advisories | `advisories` | `g =` | National CERT advisories, highlighted when a CVE appears in your inventory; Refresh feeds; filters CVE, since, text | `/v1/advisories*` |
| Regulatory clocks | `regulatory` | `g -` | Breach-notification regimes, Save selection, time left for each open high or critical finding | `/v1/regulatory/profile`, `/regimes`, `/clocks` |
| Posture trend | `trend` | `g ^` | Counts-only snapshots of compliance score, ATT&CK coverage, findings by severity, SLO budget and rule health; Compare two snapshots | `/v1/posture/trend`, `/v1/posture/trend/diff` |
| Executive digest | `digest` | `g &` | Weekly summary where each sentence lists the measured factors behind it; unmeasured items are listed as not assessed; download Markdown, printable HTML or JSON | `/v1/reports/digest` |
| Auditor bundle | `auditor` | `g *` | Manifest, then a zip of evidence with a hash per file | `/v1/compliance/auditor-bundle` |

#### Research, models and analysis

| Page | id | g-key | Purpose and controls | Data |
|------|----|-------|----------------------|------|
| Models | `models` | `g 0` | See the Models page section | `/v1/ml/*` |
| Inspector | `inspector` | `g 9` | See the Inspector page section | `/v1/inspect/*` |
| Provenance | `provenance` | `g [` | Findings grouped into ranked stories over a process graph; open a story for its sub-graph; status lists limitations | `/v1/prov/status`, `/v1/prov/stories`, `/v1/prov/trace` |
| Ransomware behaviour | `ransomware-behaviour` | `g ]` | Per-host score over sliding windows of file events; ranked hosts and a timeline. Never blocks or quarantines | `/v1/ransom/status`, `/v1/ransom/hosts`, `/v1/ransom/host` |
| TTP similarity | `ttp` | `g ;` | Compare a host's techniques, or a typed list such as `T1059, T1003`, with summaries of public adversary reporting; next-technique hints and chains | `/v1/ttp/similar`, `/v1/ttp/next`, `/v1/ttp/chains` |
| Competitive | `competitive` | `g %` | Feature matrix built from public vendor documentation, and the backlog. Not a benchmark. See [competitive-analysis](competitive-analysis.md) | `/v1/world/competitive` |
| Syslog | `syslog` | `g $` | Listener status and samples (listener is off by default); Parse (dry run) tests a line without storing it. See [syslog-listener](syslog-listener.md) | `/v1/syslog/status`, `/samples`, `/parse` |
| Content versions | `versions` | `g #` | Snapshots of embedded content recorded at startup when it differs; Compare two builds; change log | `/v1/content/versions`, `/changes`, `/changelog` |
| Reports and SLO | `reports` | `g @` | Scheduled pull-only reports (Create schedule, run now, run history, archive download) and fleet SLO status | `/v1/reports/scheduled*`, `/v1/reports/archive/`, `/v1/fleet/slo` |
| Automation | `automation` | `g !` | Scheduled detections, hunt quotas, expiring rule exceptions, suppressed findings and history | `/v1/detections/scheduled*`, `/v1/hunts/limits`, `/v1/exceptions*` |
| Attack chains | `chains` | `g \` | Heuristic grouping of findings with the reason for each grouping; open a chain and create a case from it | `/v1/chains*`, `/v1/case-templates` |
| Feedback | `feedback` | ``g ` `` (backtick) | Analyst verdicts per rule with a precision interval, hash-chain verification, recent verdicts | `/v1/feedback*` |
| Vulnerability priority | `vulnprio` | `g '` | CVEs ranked by an SSVC decision tree; defaults used for unknown inputs are shown; Refresh EPSS now (opt-in feed) | `/v1/vulns/priority*` |
| Sequence hunt | `huntseq` | `g .` | kavach-seq: write a sequence or single-event query, Run or Explain; fields that are not collected are reported | `/v1/hunt/seq*` |
| Coverage | `coverage` | `g ,` | Claimed techniques scored by replaying synthetic scenarios in memory (Run scenarios), plus telemetry blind spots | `/v1/validate/coverage`, `/v1/validate/run`, `/v1/coverage/blindspots`, `/v1/coverage/telemetry` |

Pages with no g-key (Prevent, Intel, Identity, Spotlight, OverWatch, Response, Ops, Integrations, Finance, Sectors) are reached from the menu, the palette or the hash. Press `?` in the console for the live list.

#### Not in the console

These features have no page and are used through the API, `kavachctl` or MCP: the software exposure report and SBOM or advisory import (`/v1/exposure/*`, see [exposure](exposure.md)), cloud and SaaS audit-log ingestion (`/v1/cloud/audit/*`, see [cloud-audit](cloud-audit.md)), the Sigma importer and exporter (`/v1/sigma`, see [sigma-import](sigma-import.md)), and the Inspector's SARIF export and report clustering. A raw `GET` of some of these is reachable from the World page "Domain API" selector.

---

## Usability features

- **Command palette**: Ctrl/Cmd+K or `/` opens it (`/` is ignored while an input is focused; pressed right after `g` it goes to Search instead). Type a page name to jump (the hint shows the page's g-key), or a lookup: `host web01`, `cve CVE-2024-1234`, `ioc <ip|domain|hash>`, `rule`, `case`, `finding`, `technique`, `huntpack` (a bare CVE id, IPv4 address, 32 to 64 character hex hash or dotted domain is recognised too). Every query of two or more characters also offers "Search everything for ...". Lookups open the Search page with the type preset. The palette also offers theme toggle, shortcuts help and CSV/JSON export of the first table on the page. Arrow keys move, Enter runs, Esc closes. Empty result text: "Nothing matches. Try a page name, "host web01", "cve CVE-2024-1234" or an IP."
- **Keyboard help**: `?` lists every shortcut, including all `g` page keys. Shortcuts are ignored while typing in an input, textarea or select, while an overlay or the finding drawer is open, and while signed out. Modifier combinations other than Ctrl/Cmd+K are ignored.
- **Tables**: each table has a tool row with a row count (or "Loading..." / "No rows to show"), a **Columns** toggle, and **CSV** / **JSON** export of the rows already loaded in the browser (visible columns only; nothing is refetched). Click or press Enter on a header to sort ascending, again for descending, a third time to clear. Numbers, percentages and ISO dates sort naturally, and sort and hidden columns survive reloads of the table data. CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'` to stop spreadsheet formula injection.
- **Saved views**: a bar at the top of each page saves the current filter inputs, selects, sort and hidden columns under a name (up to 40 characters). Views live only in this browser's `localStorage` (`kavach-views-<page>`, up to 20 per page); they are never sent to the server and secret-like fields (token, password, key) are never captured. Applying a view fills the fields and says so; press the page's own action to run it. Saving with no name asks for one. If storage is blocked the bar says "Could not save: browser storage is unavailable." and the page still works.

Known limits: pages that render lists as cards rather than tables get no sort or export; tables with expandable detail rows are not sortable; saved views do not follow you to another browser or profile; table tools attach after the page renders (a short delay) and are rebuilt when a table's contents change.

### Dark mode and phone width

All of the above use the same CSS tokens as the rest of the console (dark values under `[data-theme="dark"]`), and the tool rows and view bars wrap at phone width. The initial usability pass (palette, tables, saved views) and the later Models and Inspector tabs were each checked only in headless Chrome at desktop width in the light theme. **These were later checked in headless Chrome in light and dark at 1280px and 390px against synthetic data (palette, table tools, saved views, all 11 Models tabs, Inspector modes and results, Competitive); see [console-qa](console-qa.md) for exactly what was and was not exercised.** At phone width the section tabs wrap to their own row under the brand, and the Browse menu scrolls if the screen is short.

---

## Search page

`GET /v1/search?q=&types=&limit=`; see [global-search](global-search.md). Controls: a text box (2 to 128 characters), a result type select (All types, Findings, Hosts, Rules, Hunt packs, Queries, Guidance, Techniques, CVEs, IOCs, Cases, Saved searches), arrow keys to move through results and Enter to open one. Palette lookups preset the type and run the search on arrival. Empty state: "Type at least 2 characters. Use the arrow keys to move through results, Enter to open."

---

## Models page

Local statistical models learned from this fleet's own events. They give hints and rankings, never verdicts, and where there is too little data the page says so rather than showing a score ("not enough data"). Data from `/v1/ml/*`. Eleven tabs:

| Tab | Endpoint | Controls |
|-----|----------|----------|
| Status | `/v1/ml/status` | Model summary with per-type learned events. Administration panel: Reset models, Rebuild from retained events (replay); both ask for confirmation and need an administrator or signed-in session |
| Lineage | `/v1/ml/lineage` | Host filter (empty for the whole fleet), Load |
| Similar | `/v1/ml/similar` | Command line to compare, Load |
| Baseline | `/v1/ml/baseline` | Host, Load (hour-of-week baseline) |
| Beacons | `/v1/ml/beacons` | Host (optional), Load |
| Draft rule | `/v1/ml/synthesize`, `/v1/content/custom`, `/v1/rules/lifecycle/` | Draft a rule from observed behaviour; saving it goes through custom content, in testing state |
| Priority | `/v1/ml/priority` | Ranked findings with a factor reference |
| DNS tunneling | `/v1/ml/dns` | Host filter (empty for all hosts), Load |
| Users | `/v1/ml/users` | User filter (empty for all users), Load |
| Peers | `/v1/ml/peers` | Host filter (empty for all hosts), Load |
| Alert fatigue | `/v1/ml/fatigue` | Rule id filter, "Retune candidates only" checkbox, Load |

Details: [local-models](local-models.md), [local-models-net](local-models-net.md). Known limits: a host or user with fewer events than a model's minimum shows not-enough-data; the DNS tunneling "ok with flagged windows" state was not reached in QA because the synthetic burst stayed under the 50-lookup minimum; the learned-events cell is rendered per type (an earlier build printed `[object Object]`).

---

## Inspector page

Static analysis of an artifact. Nothing is executed and no network connection is made for you. Data from `/v1/inspect/*`; see [artifact-analyzers](artifact-analyzers.md).

- Two tabs: **Analyze** and **Recent reports** (`/v1/inspect/reports`). Analyzer limits come from `/v1/inspect/analyzers`.
- Eight input modes: **File** (drop or choose a file; read in the browser and sent as raw bytes to `/v1/inspect/file`), **Script**, **Command line**, **Domain**, **Config**, **Lockfile**, **URL**, **Email** (the text modes post to `/v1/inspect/<kind>`; pasted text is capped at 4 MiB in the browser).
- Uploaded bytes and pasted text are not stored. Only the resulting report and its sha256 are kept, in a capped in-memory list cleared when the server restarts.
- The report view has a "Similar submissions" section (`/v1/inspect/similar`); a 404 there means the content is not indexed, which is expected.
- Config reports are shown as a pass, fail or unknown table and are `not_scored`, never "clean".
- Not in the page: SARIF export and report clustering exist in the API only.

See [domain-inspector](domain-inspector.md), [config-assessment](config-assessment.md), [lockfile-inspection](lockfile-inspection.md) and [url-email-inspection](url-email-inspection.md) for the per-mode analyzers.

---

## eBPF page

Health score, backend, event/lost counters, feature table, recent events. Data from `/v1/ebpf/status|health|features|events`. See [ebpf](ebpf.md).

---

## Finance page

Dalal Street band: modules, institutions, exchanges, insurance, events. Tables for venues, payment rails, institutions, insurers, IRDAI posture, and recent finance events. Data from `/v1/finance/summary|exchanges|payment-rails|institutions|insurance|irdai|events`, loaded with the main console load (not on opening the page). See [finance](finance.md).

---

## Sectors page

Critical infrastructure band: modules, public fleets, city buses, ISRO, events. Tables for government vehicles, city buses, taxis, OEMs, manufacturing, ISRO centers, airports, flights, defence, railways, portals, and recent sector events. Data from `/v1/sectors/summary|gov-vehicles|city-buses|taxis-cabs|vehicle-oem|manufacturing|isro-centers|airports|flights|defence|railways|gov-portals|events`, loaded with the main console load. The many other `/v1/sectors/*` routes are API and `kavachctl` only. See [sectors](sectors.md).

---

## Auth for APIs from the browser

Session cookie is enough for same-origin `fetch`. Automations should use:

```bash
Authorization: Bearer $KAVACH_TOKEN
```

---

## Related

- [Tutorial](tutorial.md)
- [Architecture](architecture.md)
- [kavachctl](kavachctl.md) for the CLI twin
- [Console QA](console-qa.md) for what was and was not checked
- Design notes: [APPLE-UX-CONTRACT](design/APPLE-UX-CONTRACT.md)
