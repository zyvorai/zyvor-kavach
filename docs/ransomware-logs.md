# Ransomware indicators from file-activity and backup-job logs

Offline analytics over file-activity logs (file-server audit, EDR file events, Sysmon-style exports) and backup-job logs (Veeam-style events, other backup products) that you send. Kavach is observation only: it never stops a process, restores a file, locks a share or changes a backup job, and it reads no file content, so an entropy value or flag is whatever your tool wrote. Research and sources: [RESEARCH-vendors-identity-intel.md](RESEARCH-vendors-identity-intel.md). The agent-fed process-event detector is described in [research-ransomware.md](research-ransomware.md); this is the log-upload counterpart.

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `POST /v1/ransom/logs?host=` | admin token | analyse a log; stores findings, returns a report |
| `GET /v1/ransom/logs/sources` | any authenticated | rule ids, severities and thresholds |

CLI: `kavachctl ransomlog analyze FILE [--host NAME] [--json]`, `kavachctl ransomlog sources`.

Body: JSON array, wrapper object, one object or JSON lines. Limits: 8 MiB, 50,000 records (413 above), 64 KiB per line, 25 findings per rule. Findings are attributed to the host named in the record (so they group with other findings for that host); records without a host use `ransom:<host param>` or `ransom:logs`.

## Fields read

Time (`time`, `timestamp`, `@timestamp`, ...), host (`host`, `hostname`, `computer`, ...), `user`, `process`, an operation (`operation`, `op`, `action`, `event`, `activity`, ...), a path (`path`, `file`, `target_filename`, ...), a new path (`new_path`, `destination`, or an `old_path` field with `path` as the new name), `command` (`command_line`, `cmdline`, ...), `job`, event text (`message`, `status`, `detail`, ...), `entropy` (0 to 8 bits per byte) or a flag (`high_entropy`, `encrypted`, `entropy_flag`), `data_size` or similar size fields, and retention fields (`retention_old`/`retention_new`). Nothing else is read.

## Rules

Thresholds are Kavach's own choices; none of the vendors surveyed publishes numbers.

| Rule | Technique | Severity | Fires when |
|---|---|---|---|
| `rwlog-an-mass-rename` | T1486 | high | 50 or more renames on one host within 60 seconds |
| `rwlog-an-extension-churn` | T1486 | high | 30 or more files renamed to the same new extension within 5 minutes, and that extension is at least 80% of the extension-changing renames in the window |
| `rwlog-an-high-entropy-writes` | T1486 | high | 30 or more writes with entropy at least 7.5 or an encrypted flag within 5 minutes on a host |
| `rwlog-an-ransom-note-spread` | T1486 | high | a file whose name contains a ransom-note keyword (decrypt, restore_files, how_to_recover, ransom, ...) created in 5 or more directories within 10 minutes |
| `rwlog-an-mass-delete` | T1485 | high | 100 or more deletions on one host within 60 seconds |
| `rwlog-an-recovery-inhibit-command` | T1490 | high | a command line that deletes shadow copies or recovery data (vssadmin, wmic shadowcopy, diskshadow, wbadmin delete, bcdedit recovery settings, Win32_ShadowCopy delete, tmutil local snapshot deletion, zfs snapshot destroy) |
| `rwlog-an-backup-deletion` | T1490 | high | 3 or more backup, snapshot or restore-point deletions within 10 minutes on a host |
| `rwlog-an-backup-config-weakened` | T1490 | medium | retention reduced (fields or text), a backup job disabled or deleted, immutability disabled, a repository removed |
| `rwlog-an-backup-malware-flag` | T1486 | high | the backup product's own text says malware activity, EncryptedData or ransomware detected |
| `rwlog-an-backup-change-spike` | T1486 | medium | a job's size or change-rate value is 3 or more times its median over 3 or more earlier runs in the file |
| `rwlog-an-backup-tamper-near-encryption` | T1490 | critical | backup tampering (command, deletion burst or weakened configuration) and an encryption indicator occur within an hour of each other, on any hosts |

Shadow-copy and recovery commands are matched with bounded Go regular expressions (linear time) over at most 2,048 bytes of the command.

## Honest limits

- No file content is read. A producer that does not compute entropy gives no entropy signal; a producer that flags too liberally causes false positives.
- Bulk renames by installers, archivers, sync clients, build systems and migrations look like ransomware to a count. Review the process and path.
- Backup "size" fields differ between products (bytes, change rate); the spike rule only compares a job with its own earlier runs in the same file.
- Host attribution trusts the host field of the log.
- Extension matching takes the text after the last dot (up to 16 characters); double extensions are judged by the last one.
- A ransomware family that overwrites in place without renaming only appears through entropy flags, deletions, notes or recovery-inhibiting commands.
