# Artifact analyzers: shortcuts, disk images, macros, scripts, CI/config

Five analyzers registered with `RegisterAnalyzer` in the artifact inspector. They add no new kinds or routes: they run on the existing `file`, `script` and `config` kinds (`POST /v1/inspect/file|script|config`, `kavachctl inspect file|script|config`). All are parse-only: nothing is executed, mounted, extracted, fetched or stored, each analyzer honours the builder caps (200 findings, 500 IOCs, 16 layers, 512-char strings) and the 5 s per-analyzer budget, and each has a `recover()` so a hostile input becomes an analyzer error, never a crash. Scoring caps are unchanged; weights are in the table below and feed the existing top-10 sum.

| Analyzer | Kind | Code | Finding ids |
|---|---|---|---|
| `file-lnk` | file | `inspect_file_lnk.go` | `lnk-arguments`, `lnk-lolbin-target`, `lnk-args-*`, `lnk-unc-target`, `lnk-long-args`, `lnk-minimised`, `lnk-icon-mismatch`, `lnk-appended-data`, `lnk-malformed` |
| `file-diskimage` | file | `inspect_file_iso.go` | `iso-autorun`, `iso-executable`, `iso-shortcut`, `iso-script`, `iso-lnk-plus-payload`, `iso-empty`, `disk-image-unlisted` |
| `file-vba` | file | `inspect_file_vba.go` | `vba-autoexec`, `vba-shell-object`, `vba-winapi`, `vba-obfuscated-strings`, `vba-download-exec`, `vba-no-source` |
| `script-static` | script | `inspect_script_static.go` | `scr-download-exec`, `scr-reverse-shell`, `scr-eval-decoded`, `scr-persist-{cron,systemd,shellrc,sshkey,preload,launchd,wintask}` |
| `config-extra` | config | `inspect_config_extra.go` | `cfgx-gha-*`, `cfgx-gl-*`, `cfgx-k8s-*`, `cfgx-df-*` |

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

## Tests

`internal/edr/inspect_artifacts_test.go` holds hand-built fixtures (no binary blobs are checked in): golden findings per analyzer, benign cases that must stay clean, limit tests (string caps, entry/module/blob/depth caps, directory loops, decompression cap, oversize input), a seeded mutation test and `FuzzArtifactAnalyzers` (`go test ./internal/edr -run XXX -fuzz FuzzArtifactAnalyzers -fuzztime 20s`). `inspect_integration_artifacts_test.go` drives each analyzer through the HTTP endpoints.
