# Detection validation lab: research, design and honest findings

The validation lab measures which ATT&CK techniques Kavach actually detects, instead of trusting
the rule-to-technique mappings in the ATT&CK matrix. It is the open, in-process analogue of
breach-and-attack-simulation and ATT&CK-Evaluations-style scoring.

Safety model: the lab only replays SYNTHETIC EVENTS (data) through the detection engines in memory.
It never executes anything, never touches the host, never writes findings to the real store, ledger or
SIEM exporter, and never changes any process-wide detection list. A test (`TestValReplayIsolation`)
snapshots the store, its ledger bytes, the IOC and IOA lists and the content registry pointer before
and after a full replay and fails on any difference.

Every API response carries the note: "Synthetic data replayed in memory; measured on Kavach's own
scenarios; not a guarantee against real attacks."

## 1. Research

Sources are listed in two groups. "Opened" means the page content was actually fetched and read in this
session. "Snippet only" means only a search-result summary was read.

### 1.1 Opened

1. **MITRE Caldera, GitHub README** (https://github.com/mitre/caldera). Caldera is a platform for
   automated adversary emulation, assisted manual red teaming and automated incident response, built on
   ATT&CK. It has a core (an asynchronous command-and-control server with a REST API and web UI) plus
   plugins that add agents, reporting and TTP collections. The README names plugins such as Stockpile
   (technique and profile storehouse) and Atomic and Emu (sources of TTPs and emulation plans). It does
   not explain the data model itself.
2. **Caldera documentation, "Learning the terminology"**
   (https://caldera.readthedocs.io/en/latest/Learning-the-terminology.html). Agents are programs that
   check in periodically and are grouped (red or blue). Abilities are single implementations of an
   ATT&CK tactic or technique, carrying commands, supported platforms and executors, payloads and an
   output parser. An adversary profile is a collection of abilities representing a threat actor, and an
   operation joins an adversary profile to an agent group with a planner deciding order. This split
   (what runs / where it runs / in which order) shaped the lab's separation of scenario (what), platform
   (where) and step order (when).
3. **MITRE Center for Threat-Informed Defense, Attack Flow**
   (https://center-for-threat-informed-defense.github.io/attack-flow/). Attack Flow is a language for
   describing how adversaries chain and sequence techniques toward a goal, maintained by the Center.
   The landing page does not describe the data model, so only its purpose is used here: chains of
   techniques are a first-class thing to represent, which is why the lab has ~20 multi-step campaign
   scenarios in addition to single-technique emulations.
4. **DeTT&CT wiki, home page** (https://github.com/rabobank-cdc/DeTTECT/wiki). DeTT&CT lets a team
   administer and score data source quality, visibility and detection coverage per technique, and
   links to scoring pages and a scoring table spreadsheet. The home page only names the three areas.
5. **DeTT&CT wiki, "Detection scoring"** (https://github.com/rabobank-cdc/DeTTECT/wiki/Detection-scoring).
   Detection is scored on a scale from -1 (none) through 0 (logged for forensics or context only) to 5
   (excellent), where the middle levels rise with analytic sophistication, real-time operation, how
   many known variants are covered and how easy false positives are to filter. The key idea used here:
   coverage is a graded property of evidence, not a yes/no tick, and a score is only meaningful against
   the variants actually tested. The lab uses a coarser four-state outcome (Detected, Partial, Missed,
   Not-testable) plus an explicit "untested" bucket, because it measures only one or a few variants per
   technique.
6. **Atomic Red Team, GitHub README** (https://github.com/redcanaryco/atomic-red-team). A library of
   tests mapped to ATT&CK, kept in an `atomics` folder, documented through the wiki. The README does not
   describe the test file structure.
7. **Atomic Red Team wiki, "Atomic Test Structure"**
   (https://github.com/redcanaryco/atomic-red-team/wiki/Atomic-Test-Structure). The page says tests are
   defined in a structured format usable by automation, are focused and have few dependencies, and
   points to a separate YAML schema page. The field list (technique id, platforms, inputs, commands) was
   NOT confirmed from the fetched pages; it comes from the task brief. Nothing from Atomic Red Team's
   test commands or text was copied: Atomic is a catalogue of commands to run, whereas the lab's
   scenarios are original synthetic event sequences that are never run.

### 1.2 Snippet only (search-result summaries, not opened pages)

8. **ATT&CK Evaluations detection categories** (web search; summaries of vendor blogs and a MITRE
   Medium post, the primary MITRE pages could not be fetched). Reported categories: General Behavior,
   Specific Behavior, Indicators of Compromise, Telemetry and None in early rounds, later Enrichment,
   Delayed, Configuration Change and Tainted modifiers; later rounds describe levels as General, Tactic
   and Technique. The Delayed modifier is reported as applying when detection needed human augmentation
   or was not timely; Configuration Change as a change to the product during the evaluation. One
   summary says the Telemetry category was dropped in 2024. These are secondary descriptions and may
   be inexact. The lab borrows the technique/tactic/general distinction (see Partial below) but does
   not model Delayed or Configuration Change.
9. **Top ATT&CK Techniques methodology** (web search; CTID GitHub repository listing, Microsoft,
   CrowdStrike and MITRE Engenuity Medium coverage, none opened). Summaries describe a score combining
   prevalence, choke point and actionability. The lab does not rank techniques by this methodology; it
   only reports per-technique results so a team can combine them with such a ranking.
10. **Academic and industry coverage studies** (web search). A University of Illinois paper on endpoint
    detection rulesets (Carbon Black, Splunk, Elastic, Sigma) is summarized as finding that many ATT&CK
    techniques are hard to realise as rules and that technique labels do not consistently imply
    coverage of the same real-world threats. Vendor reports (CardinalOps and others) measure rule
    configuration, not whether rules fire on adversary behavior. The takeaway used: "covered on paper"
    and "detected in practice" differ, which is the gap this lab quantifies.

### 1.3 Could not be fetched

`attackevals.mitre-engenuity.org` and `top-attack-techniques.mitre-engenuity.org` did not resolve from
this environment, and the MITRE Medium post returned HTTP 403. Their content is therefore not cited
beyond the snippets above.

## 2. Design

* **Scenario** (`internal/edr/scenarios/*.json`, embedded): `id`, `name`, `description`, `kind`
  (`single|chain|benign`), `platform` (`linux|macos|windows`), `tactics`, `techniques`, `benign`,
  ordered `steps`, and `expect` (technique ids or rule ids). A step has a `type`
  (process, network, file, registry, dns, auth, module), an optional `at` offset, its type's event
  fields (the same fields the engines read) and an optional step-level `expect`. Loading is strict:
  unknown fields, fields belonging to another event type, bad enums (validated through the telemetry
  validator) and duplicate ids are rejected.
* **Replay** (`validate_replay.go`): process events run through `Detect` (built-in rules, IOC, IOA),
  network events through the content matcher plus the denied-flow correlation, file events through a
  fresh `FileDetections` plus the content matcher, telemetry events through the same telemetry view and
  content matcher the live POST handlers use. Content rules are evaluated against a private registry
  built from the embedded packs (`contentEvaluateWith`, a small refactor of `contentEvaluate` that
  takes the registry as a parameter), and customer rules are excluded unless the request passes
  `include_custom`. The lab never calls `Store.Ingest*`.
* **Scoring**, per technique: Detected (a rule mapped to the technique, or to a sub-technique of an
  expected parent, fired), Partial (rules fired, but only for the parent technique, a different technique
  in the same tactic, or other tactics or unmapped rules), Missed (nothing fired), Not-testable
  (needs telemetry Kavach does not collect; reason recorded in `scenarios/not_testable.json`) and
  Untested (claimed but no scenario: the claimed-but-not-measured gap). Benign controls pass only if
  nothing at medium severity or above fires.
* **Endpoints** (all `requireAuth`; the POST is read-only compute): `GET /v1/validate/scenarios`,
  `GET /v1/validate/scenarios/{id}`, `POST /v1/validate/run {ids|all, include_custom?}`,
  `GET /v1/validate/coverage`.
* **Regression gate** (`TestValDetectedRateFloor`): the share of non-benign scenarios whose
  expectations are all Detected must stay at or above `valDetectedFloor` (0.60; measured 0.649 when
  written), and benign false positives must stay at 0. Raise the floor as detection improves; lowering
  it needs a recorded reason here.

## 3. Results (measured on the shipped packs)

| Measure | Value |
|---|---|
| Scenarios | 152 single-technique, 19 campaign chains, 33 benign controls (204 total) |
| Claimed techniques (built-in + live content rules) | 245 |
| Claimed tactic coverage (ATT&CK matrix, 14 tactics) | 42% (matrix field `coverage_pct`) |
| Detected | 95 techniques = 38.7% of claimed |
| Detected or Partial | 112 = 45.7% of claimed |
| Partial | 17 |
| Missed | 26 |
| Not-testable | 11 |
| Untested (claimed, no scenario) | 96 |
| Detected rate over tested techniques | 68.8% (95 of 138) |
| Scenario pass rate (non-benign, strict) | 64.9% (111 of 171) |
| Benign controls firing at medium or above | 0 of 33 |

So the claim "245 techniques covered" is, at this moment, verified for 95 of them. 107 of the 245 have
no scenario or cannot be tested, and 43 were tested and not cleanly detected.

Per tactic (Detected / claimed): Initial Access 2/7, Execution 12/27, Persistence 21/52, Privilege
Escalation 6/13, Defense Evasion 24/66, Credential Access 16/34, Discovery 8/18, Lateral Movement 8/18,
Collection 6/11, Command and Control 5/19, Exfiltration 3/10, Impact 6/12. Command and Control (26%)
and Exfiltration (30%) are the weakest measured tactics; Defense Evasion is the largest claim and the
largest unmeasured block.

### 3.1 Missed techniques (every one)

Scenario fired nothing at all:

`T1021.003` DCOM lateral movement, `T1021.006` WinRM (Invoke-Command), `T1048.003` DNS exfiltration
(hex-labelled TXT queries), `T1059.007` JavaScript via node, `T1074.001` local data staging, `T1082`
systeminfo, `T1083` file and directory discovery (find over the whole disk), `T1095` socat relay,
`T1102.001` dead-drop TXT lookup, `T1110` failed-login burst (auth events), `T1115` pbpaste clipboard
read, `T1135` smbclient share listing, `T1491.001` wallpaper defacement (file modify), `T1497.001`
sysctl VM check, `T1498` hping3 flood, `T1518.001` WMIC securitycenter2 query, `T1529` shutdown -h now,
`T1546.003` WMI subscription via PowerShell, `T1548.002` ms-settings UAC bypass registry write,
`T1552.003` reading `.bash_history`, `T1555.003` copying the Chrome Login Data file, `T1564.001` hidden
dot-directory, `T1568.002` DGA-like lookups, `T1580` aws ec2 describe-instances, `T1613` kubectl get
pods, `T1651` aws ssm send-command.

Caveats on reading this list: each scenario is one variant written by this project, not a sample of
real attacker tooling. A miss means "this variant was not detected", not "the technique is
undetected". Several of these (T1082, T1083, T1135, T1580, T1613, T1115) are discovery or collection
behaviors that are common on healthy systems, so a miss may be a deliberate precision trade-off; the
lab reports it without judging. T1110 is expected: the content framework is per-event and states that
failure-burst rules are out of scope.

### 3.2 Partial techniques (17)

`T1021.004`, `T1048`, `T1190`, `T1195.002`, `T1485`, `T1537`, `T1543.001`, `T1550.002`, `T1566.001`,
`T1609`, `T1610`, `T1620` had rules fire for other tactics or only unmapped rules; `T1055.008`,
`T1071.004`, `T1090`, `T1204.004`, `T1546.004` had a different technique in the same tactic fire
(usually a more specific or differently mapped rule: ptrace injection mapped to `T1055.001`, DNS tunnel
tools mapped to `T1572`, SSH SOCKS mapped to `T1572`, a PowerShell cradle mapped to `T1059.001`).
Some Partial results are mapping disagreements rather than missing detections: the behavior was seen but
filed under a neighbouring technique.

### 3.3 Not-testable (11)

`T1014`, `T1027.002`, `T1030`, `T1055`, `T1055.001`, `T1055.009`, `T1055.012`, `T1205.002`,
`T1550.003`, `T1565.001`, `T1573.002`. Reasons are in `scenarios/not_testable.json` (memory/API,
flow-volume, TLS or file-content telemetry that Kavach does not collect). The matrix still claims some
of them through command-line string rules; the lab cannot show those rules detect the behavior.

### 3.4 Claimed but not measured (96)

No scenario was written for these claimed techniques (full list via `GET /v1/validate/coverage` under
`claimed_not_measured`). They include parent-level ids (`T1003`, `T1059`, `T1071`, `T1546`, `T1548`,
`T1552`, `T1555`, `T1562`, `T1564`, `T1567`) whose sub-techniques are measured, plus many Windows and
telemetry-only items (for example `T1218.001`, `T1218.003`, `T1218.008`, `T1220`, `T1221`, `T1546.007`,
`T1546.008`, `T1546.009`, `T1547.005`, `T1553.005`, `T1558.001`, `T1562.002`, `T1574.001`,
`T1574.002`) and cloud or container items (`T1078.004`, `T1098.001`, `T1098.006`, `T1136.003`,
`T1528`, `T1555.006`, `T1562.007`, `T1648`). Closing this gap is the next coverage-validation task.

## 4. Other findings about the product

These came out of reading the code while building the lab. Nothing was changed.

* `MapDetection` silently maps a finding whose rule has no ATT&CK entry to `T1082` (Discovery). Built-in
  rules `unsafe-permissions`, `persistence-attempt`, `script-inline-execution` and `root-history-clear`
  have no `ruleMITRE` entry, so they would be reported as System Information Discovery. The lab reports
  such findings as "unmapped" instead.
* By code reading (not exercised by a scenario): `Detect` emits IOC findings with rule ids of the form
  `ioc-<type>` (for example `ioc-domain`), while `ruleMITRE` keys are `ioc-domain-match`,
  `ioc-ip-match` and `ioc-hash-match`, so IOC findings would also fall to the `T1082` default.
* IOA findings carry the technique only as a tag (`ioa-ioa-1` and so on), not in `ruleMITRE`, so they
  are absent from the ATT&CK matrix coverage even though they fire.
* The matrix reports 42% tactic coverage, a count of tactics with at least one rule, which says
  little about technique-level detection. Technique-level measured coverage is 38.7% of claimed.

## 5. Honest limits

* Synthetic data authored by this project. Scenarios were written from public ATT&CK knowledge
  without consulting rule patterns, but a single variant per technique is a weak sample, and the same
  author wrote scenarios and read the rules' descriptions.
* One scenario per technique mostly; no evasion variants (obfuscation, renaming, living off other
  binaries). "Detected" says nothing about robustness.
* Per-event content rules are evaluated; stateful and process-global detectors are not driven:
  `RansomwareFindings` (per-host global windows) is deliberately not invoked to avoid touching live state, and
  `mass-file-activity` uses a private fresh detector.
* IOC, IOA and exclusion lists are the process's live lists (read only); customer custom-content rules
  and legacy custom rules are excluded by default.
* No model of Delayed or Configuration Change modifiers, of timeliness, of alert triage, or of
  telemetry loss. Telemetry types (registry, dns, auth, module) are evaluated at the engine level; a
  collector that supplies them must exist in the deployment.
* Detected means a rule mapped to the technique fired, not that the mapping is right, and not that the
  alert was actionable. Benign controls are 33 everyday sequences, not a measure of production noise.

## 6. Follow-up: ATT&CK mapping fixes (before / after)

Section 4 recorded defects in how findings are mapped to ATT&CK. They are fixed as follows. Sections 1
to 5 above are the original measurement and are kept unchanged as the "before" record.

**Fixes**

1. `MapDetection` no longer defaults an unmapped rule to T1082. It returns `unmapped: true` with empty
   `tactic`, `technique` and `technique_id`. The ATT&CK matrix response has a new `unmapped_rules` list
   (built-in rules that can fire but have no technique, plus rule ids seen in findings) and
   `unmapped_hits`; unmapped findings count toward neither coverage nor `observed_hits`. The generic AI
   behaviour class (`suspicious_generic`) no longer claims T1082 either; narratives and incident reports
   say "no ATT&CK technique is mapped" instead.
2. Four built-in rules that silently relied on the default now carry a justified mapping:

   | Rule | Trigger | Technique | Why |
   |---|---|---|---|
   | `unsafe-permissions` | `chmod 777 /etc/...` | T1222.002 (Defense Evasion) | Loosening permissions on sensitive config is Linux and Mac File and Directory Permissions Modification. |
   | `persistence-attempt` | `crontab`, `at`, `systemctl enable` | T1053 (Persistence) | Scheduled Task/Job covers cron and at. `systemctl enable` is strictly T1543.002, which the rule does not distinguish, so the parent is used and no sub-technique is over-claimed. |
   | `script-inline-execution` | `python/perl/ruby/node/php` with `-c`, base64 or `/dev/tcp` | T1059 (Execution) | Interpreter-driven execution; same technique as `lolbin-netcat-shell`. |
   | `root-history-clear` | root shell running `history -c` | T1070.003 (Defense Evasion) | Clear Command History. |

   Every other built-in rule id was run through the mapper (test `TestNoRuleDefaultsToT1082`). Two
   remain intentionally unmapped and are reported in `unmapped_rules`: `ransomware-churn` (a weak
   canary-path churn signal, not a specific technique) and `identity-from-finding` (an identity event
   derived from findings, not a finding rule). A test fails if any rule maps to T1082 without T1082
   being its technique.
3. IOC findings are emitted as `ioc-<type>` (`ioc-domain`, `ioc-ipv4`, `ioc-sha256`, ...) while
   `ruleMITRE` is keyed `ioc-*-match`. The lookup now aliases `ioc-domain` to the domain match,
   `ioc-ipv4`/`ioc-ipv6` to the IP match and `ioc-sha256`/`ioc-md5`/`ioc-sha1` to the hash match
   (T1071, T1071, T1204). Operator-added IOC types without an alias stay unmapped. Verified by driving
   real IOC matches through `Detect`.
4. IOA findings (`ioa-<id>`) are resolved through the IOA rule's `TechniqueID`, and enabled IOAs with a
   known technique count toward matrix coverage. Findings from an IOA that was later edited or deleted
   still map through the technique tag on the finding. An IOA with an unknown technique id contributes
   no coverage.
5. The lab's technique resolver also applies the IOC aliasing, and two scenarios were added so the
   newly mapped techniques are measured rather than merely claimed: `emu-t1053-crontab-persist` and
   `emu-t1059-python-inline-b64`.

**Measured before / after** (same harness, shipped packs, no live content registry loaded for the matrix
figures; the lab figures use the embedded packs)

| Measure | Before | After |
|---|---|---|
| ATT&CK matrix tactics covered (of 14) | 6 (42%) | 7 (50%) |
| ATT&CK matrix techniques listed (built-in + IOA) | 13 | 17 |
| Lab claimed techniques | 245 | 246 |
| Lab Detected | 95 (38.7%) | 97 (39.4%) |
| Lab Partial / Missed / Not-testable | 17 / 26 / 11 | 17 / 26 / 11 |
| Lab Untested (claimed, no scenario) | 96 | 95 |
| Scenarios | 204 | 206 |
| Non-benign scenarios passing | 111 of 171 (64.9%) | 113 of 173 (65.3%) |
| Benign controls firing at medium or above | 0 of 33 | 0 of 33 |
| Findings fired in replay with no ATT&CK mapping | 10 of 427 (`persistence-attempt` 4, `script-inline-execution` 3, `root-history-clear` 2, `unsafe-permissions` 1) | 0 of 431 |

Reading the numbers: the 4 remapped rules did not change any pre-existing technique's Detected count,
because the lab already reported their findings as unmapped (it never used the T1082 default), so the
gain there is the removal of 10 unmapped fires. The matrix gain (42% to 50% tactic coverage) is real:
Persistence is now covered by a built-in rule, and IOA techniques (T1003, T1059, T1490) appear in the
matrix. The two added scenarios account for the +2 Detected. The detected-rate floor
(`valDetectedFloor`, 0.60) is unchanged; measured rate is 0.653.

Limits that remain: the 50% figure counts tactics with at least one mapped rule, not detection quality;
the IOC alias for `ioc-sha256` maps all hash matches to T1204 (User Execution), which is a coarse label
for "a known-bad hash was seen in a command line"; and the IOA mapping trusts the technique id an
operator typed.
