# Offline evidence import

Backlog item 16 in `docs/competitive-analysis.md` asks for an offline evidence collector. Kavach is observation-only and cannot reach a host that has no agent, so it does not ship a collector. It ships the import side: an analyst runs standard read-only commands on the host (by hand or with their own tooling), uploads the text, and Kavach parses it into events and replays them through the same detection engines in an isolated import case. Nothing is executed, and the live store is never touched unless an admin explicitly promotes the case.

## Endpoints

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/evidence/import` | admin token or session | Create a case from artefacts (JSON or multipart) |
| `GET /v1/evidence/cases` | any authenticated | List cases (newest first) |
| `GET /v1/evidence/cases/{id}` | any authenticated | Full case; `?download=1` adds a `Content-Disposition` for export as JSON |
| `DELETE /v1/evidence/cases/{id}` | admin token or session | Delete a case |
| `POST /v1/evidence/cases/{id}/promote` | admin token only | Ingest the would-fire findings into the live store, tagged `evidence-import`; `409` if already promoted |

JSON body: `{"case":"ir-2026-11","host":"web01","collected_at":"2026-11-13T09:00:00Z","artefacts":[{"name":"ps -ef","format":"","content":"..."}]}`. Multipart: text fields `case`, `host`, `collected_at`, and one file part per artefact; the form field name is the format hint (for example `ps -ef`) and the file name is the display name. `format` can be a format id (below) or a command name; when omitted Kavach infers it from the name and then from the content.

Limits: 4 MiB per artefact (an oversized artefact is listed as failed, the rest of the case still imports), 32 MiB per request (`413`), 64 artefacts, 20,000 events and 2,000 findings per case, 300,000 lines per artefact, 8 KiB per line (longer lines are truncated and counted), at most 2 imports at once (`429`), 60 seconds of replay.

## Host label and impersonation guard

The analyst supplies `host` (1-64 characters of `A-Za-z0-9._-`, no `:`). Every event and finding carries the host `import:<case>:<host>`. A label cannot contain `:` or start with `import`, and no field inside an artefact is read as a host, so an import can never produce an event attributed to an enrolled agent's host name. Promotion refuses any finding whose host is outside the `import:` namespace.

## Formats parsed

| Format id | Typical command | Becomes |
|---|---|---|
| `ps` | `ps aux`, `ps -ef` (macOS too) | process event: executable, command, pid, ppid, uid; parent executable resolved from the same listing |
| `ss` | `ss -tunap` | network event per established or connected peer, with pid and name from the process column |
| `netstat` | `netstat -an`, `netstat -antp`, `netstat -ano` (Windows) | network event per non-listening row |
| `lsof` | `lsof -i` | network event for rows with `->` |
| `crontab`, `crontab_system` | `crontab -l`, `/etc/crontab`, `/etc/cron.d/*` | process event per scheduled command (system form has a user column) |
| `ls`, `filelist` | `ls -l /etc/cron*`, recent-file listings, plain path lists | file event (operation `listed`) with path |
| `systemd_unit_files`, `systemd_units` | `systemctl list-unit-files`, `list-units` | file event with path `systemd:<unit>` |
| `launchctl` | `launchctl list` | file event with path `launchd:<label>` |
| `history` | `.bash_history` (with `#epoch` lines), zsh extended history, PowerShell `ConsoleHost_history.txt` | process event per command; real timestamps when present |
| `tasklist` | `tasklist /v /fo csv`, plain `tasklist` | process event (no command line in tasklist) |
| `process_csv` | `wmic process get ... /format:csv`, `Get-Process \| ConvertTo-Csv` | process event with command line when the CSV has one |
| `schtasks` | `schtasks /query /fo csv /v` | process event from "Task To Run" |
| `reg` | `reg export` `.reg` text, `reg query` of Run keys | registry telemetry (operation `set`) |
| `authlog` | `/var/log/auth.log`, `secure` (sshd Failed/Accepted lines) | auth telemetry |
| `passwd`, `dpkg`, `rpm` | `/etc/passwd`, `dpkg -l`, `rpm -qa` | inventory only (no events); passwd notes extra uid 0 accounts |

UTF-16 text (PowerShell redirection) is decoded; control and bidirectional-override characters are replaced with spaces. A line that does not parse is counted as failed or skipped and never aborts the artefact.

## What a case contains

An id (`ev-<10 hex>`), the artefact inventory (format, bytes, lines, parsed, skipped, failed, truncated lines, notes, status `parsed`/`partial`/`failed`), event totals, findings that would fire (rule, severity, engine, ATT&CK technique and tactic, artefact and line, evidence), a timeline (up to 500 entries, firing events first), extracted IOCs (public IPs, URLs, domains, hashes, up to 500 with first source and count), and the promote status. Findings are de-duplicated by rule and evidence.

## Isolation

Replay follows `validate_replay.go`: the private immutable embedded-content registry (`valRegistry`), a fresh file-rate window, and the pure `Detect` and content-evaluation functions. Customer-authored rules are not applied, so a result depends only on shipped content. The store is not passed to the replay, and a test compares the store contents and the findings file before and after an import with findings. `POST .../promote` is the only path to the store, is admin-token only, writes each finding with tags `evidence-import`, `case:<id>`, `artefact:<name>` and the technique, stamped with the promotion time, and a second call returns `409`.

## Storage

Cases live in memory in a ring of 20 (the oldest is evicted). Setting `KAVACH_EVIDENCE_PERSIST=1` also keeps metadata only in `<store>.evidence.json` (see `docs/persistence-files.md`): no artefact text, commands, paths, IOC values or timeline. Cases restored after a restart show `metadata_only: true` and cannot be promoted.

## Honest limits

- A listing is a snapshot. `ps` and `tasklist` carry no start times, so replayed events get synthetic timestamps 10 seconds apart from `collected_at` (flagged `time_synthetic`). Only history and auth logs carry real times. Rate-based rules such as mass file activity cannot fire on listings.
- Parent/child is known only where the listing has a PPID (`ps -ef`, `ps aux` has none); `ss`, `netstat` and `lsof` rows do not link to process events, so the netra correlation is not available.
- `ps` may truncate or reorder the command column depending on terminal width; paths with spaces on Unix cannot be split reliably, so the executable can be wrong. Kernel threads and zombies are skipped.
- WMIC CSV is unquoted, so commas inside a command line are re-joined heuristically. Registry hex and DWORD values are not decoded. Windows `tasklist` has no command line. Service and launchd listings carry no unit file path or command, so only a name-based file event is produced.
- Cron, scheduled-task and history lines are treated as process events, which is useful for catching `curl | sh` but means a command that was scheduled, not necessarily run, is reported.
- Content that relies on hashes, signatures, module loads, DNS or per-event parent paths cannot be exercised from text listings.
- Absence of findings is not evidence of a clean host. This is triage of what the analyst supplied.

## Sources opened

Read on 2026-11-13 while building this feature.

- https://docs.velociraptor.app/docs/deployment/offline_collections/ : offline collectors are binaries with embedded artifacts that run without a server and write a zip container (a `data.zip` plus `metadata.json`), optionally encrypted, optionally uploaded. The page does not specify per-artifact result formats, so no Velociraptor container import is attempted.
- https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts : Defender's "Collect investigation package" zip includes autoruns (one file per auto-start registry location, with an error message when a key is missing), installed programs as CSV, and network connection files (`ActiveNetConnections.txt`, `Arp.txt`, `DnsCache.txt`, `IpConfig.txt`, firewall logs). This guided the artefact set (autoruns, connections, programs). Only the part of the page about the package was read.
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query : `/fo` takes TABLE, LIST or CSV, and `/v` (verbose) is valid with LIST or CSV. The column list is not on the page; the `TaskName` and `Task To Run` headers used by the parser are from general knowledge (UNVERIFIED here).
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist : `/v` gives verbose task information, `/fo` takes table, list or csv, `/nh` suppresses headers. Column names are not on the page (UNVERIFIED; the sample uses the commonly seen header).
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat : `-a`, `-n`, `-o` (adds the PID) and the Proto, Local Address, Foreign Address, State columns with the listed TCP states.
- https://man7.org/linux/man-pages/man1/ps.1.html : `ps aux` columns USER, PID, %CPU, %MEM, VSZ, RSS, TT, STAT, START, TIME, COMMAND; `ps -ef` columns UID, PID, PPID, C, STIME, TTY, TIME, CMD; the command column width is undefined when piped or redirected unless `COLUMNS`, `-w` or `w` is used; brackets mean the arguments are unavailable.
- https://man7.org/linux/man-pages/man8/ss.8.html : `-p` shows processes using sockets. The page does not describe the default columns or the process field format, so the parser is based on commonly seen output (UNVERIFIED).
- https://man7.org/linux/man-pages/man1/systemctl.1.html : `list-units` shows UNIT, LOAD, ACTIVE, SUB (and a description); `list-unit-files` lists installed unit files with their enablement state. Only the first 100,000 of about 145,000 characters were read; the PRESET column is not documented there.
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export : `reg export <key> <file.reg>`; the output layout is not described on the page. The `.reg` text layout parsed here (header line, `[KEY]` sections, `"name"="data"` with `\\` and `\"` escapes, `hex:` continuation lines) is from general knowledge (UNVERIFIED).

## UNVERIFIED parts

Formats not covered by any page above and written from general knowledge, so they may not match every OS version: `lsof -i` columns and `->` form, macOS `netstat` dot-separated ports, WMIC CSV layout, `Get-Process | ConvertTo-Csv` headers, crontab and `/etc/cron.d` syntax, `ls -l` output, bash `#epoch` and zsh `: epoch:dur;cmd` history forms, `launchctl list` columns, `dpkg -l` and `rpm -qa` layouts, the sshd `Failed`/`Accepted` log line wording, and `reg query` layout. The golden test samples were written by the implementer, not captured from real hosts.
