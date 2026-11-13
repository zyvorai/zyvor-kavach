# Content rule tuning: benign false-positive guard

This documents the benign-event corpus that every embedded content rule (716 rules in
`internal/edr/content/*.json`) is checked against, the tuning applied when rules fired on it, and
what this guard does and does not prove.

## The corpus

`internal/edr/testdata/benign_corpus.json` holds 1,611 hand-written, realistic, non-malicious
events. Each carries `kind`, `os`, the event fields, and (for file and network events) a `note`
naming the process that would have caused it.

| Kind     | Linux | macOS | Windows |
|----------|------:|------:|--------:|
| process  | 279   | 131   | 201     |
| file     | 127   | 84    | 97      |
| network  | 96    | 38    | 61      |
| registry | -     | -     | 165     |
| dns      | 62    | 27    | 39      |
| auth     | 21    | 13    | 26      |
| module   | 30    | 22    | 92      |

Coverage themes: package managers (apt, dpkg, dnf, snap, brew, pip, npm, cargo, go, choco),
compilers and build tools (gcc, clang, make, MSBuild, Xcode, dotnet), browsers and their updaters,
IDEs (VS Code, JetBrains, Visual Studio), backup agents (restic, borg, Veeam, Time Machine,
Backblaze, wbadmin, robocopy), systemd/launchd/Windows service plumbing, cron and scheduled tasks,
ssh/scp/rsync administration, Docker/containerd/kubectl/helm/terraform, git, Office
(Word/Excel/Outlook/ClickToRun), AV/EDR agents and updaters (Defender, ClamAV, CrowdStrike,
SentinelOne), Windows Update/WSUS/SCCM, AD/Kerberos/LDAP traffic, monitoring agents, VPNs, DNS
lookups for common update and SaaS hosts, interactive/network/service logons, and signed driver and
library loads.

Only the event fields the live ingestion path actually supplies are populated: live file events
carry only `path` and `operation`, live network events only `destination` (see
`contentFileFindings` and `contentNetworkFindings`). The writer or client process is recorded only in
the free-text `note`, so no rule can be "tuned" with a field it will not have in production.

## The test

`TestContentBenignCorpus` (`internal/edr/content_benign_corpus_test.go`) evaluates every embedded
rule against every corpus event of the rule's `event_type`. The event's OS is deliberately not used
to filter, because the live path (`contentEvaluate`) selects rules by event kind only. It also
enforces a corpus floor (500+ events, 20+ per kind, 50+ per OS).

- A hit by any rule of severity medium, high or critical fails the test with a per-rule report
  (rule id, hit count, first three offending events).
- Rules at severity `low` may fire. They are informational audit signals; their hits are logged by the
  test, not failed. This is the one policy decision in the guard: lowering severity to `low` is an
  accepted resolution for activity that is routine for administrators but still worth recording.
- `TestContentHarness` and each rule's own positive and negative samples are unchanged and still pass.

## What was changed

Initial run: 58 rules fired (114 hits). After tuning: 0 rules at medium or above fire. No rule was
dropped. 51 rules were touched: 23 had severity lowered (some also tightened), the rest were
tightened with `not` clauses. All `not` regexes respect the 256-character regex limit, so long
allow-lists are split across an `any`.

Exclusion lists below are name-based and therefore evadable (see limits).

### Severity lowered, no way to tell benign from malicious with the fields available

| Rule | Change | Why |
|------|--------|-----|
| lx-cron-dir-file-written, ioa-file-cron-dir-write | medium to low, plus exclusion of package-shipped `/etc/cron.*` file names | `crontab -e` and package installs write these paths constantly; the live file event has no writer |
| lx-systemd-unit-file-written, ioa-file-systemd-unit-created | medium to low, plus exclusion of `/lib` and `/usr/lib/systemd/system` | package-managed unit directories; admin-authored units in `/etc` remain as a low signal |
| lx-sudoers-file-written | medium to low | its own positive sample is the cloud-init sudoers file, so no exclusion is possible |
| lx-port-scanner-active-flags, ioa-network-sweep-cmdline | medium to low | `nmap -sV` on a subnet is routine admin and vulnerability-management work |
| ioa-gtfobins-python-pty-spawn | medium to low | `pty.spawn` is a common TTY upgrade by admins |
| linux-authorized-keys-modified, ioa-file-rc-local-or-profile-write, ioa-file-macos-zsh-startup-write | medium to low | key and shell-profile edits are routine and indistinguishable by path |
| ioa-file-pam-or-sshd-config-write, macos-sshd-config-modified | high/medium to low | admins edit `sshd_config`; PAM edits are lost in the same rule |
| macos-tcc-database-modified | high to low | `tccd` rewrites TCC.db on every consent |
| macos-cloud-metadata-endpoint | medium to low | cloud-init and agents read 169.254.169.254 on every boot; the rule is macOS-labelled but fires on any host |
| win-nltest-domain-trusts | medium to low | `nltest /dclist` is common in logon scripts |
| win-cipher-wipe-free-space | high to low | `cipher /w` is also normal media sanitisation; it is also an anti-forensics/ransomware step, so this is a real loss of signal |
| win-file-spooler-dll-drop | high to low | every printer driver install drops DLLs here |
| win-file-task-xml-drop, ioa-file-windows-tasks-dir-write | medium/high to low, plus vendor task-name exclusions | admin `schtasks /create` is the same artifact as attacker persistence |

### Tightened with `not` context, severity kept (or only reduced one step)

| Rule | Change | Why |
|------|--------|-----|
| lx-motd-script-written | exclude stock Ubuntu motd script names | dpkg ships these |
| ioa-file-sudoers-write, macos-sudoers-modified | exclude `90-cloud-init-users`, `README`, vagrant entries | cloud image provisioning |
| macos-launchdaemon-plist-written, ioa-file-macos-launchdaemon-created | high to medium, exclude well-known vendor bundle-id prefixes | Microsoft, Docker, Jamf, CrowdStrike installers (the Apple prefix stays alertable in the ioa rule because its own sample uses it) |
| macos-launchagent-system-wide-written, macos-launchagent-plist-created | exclude vendor bundle-id prefixes | Google Keystone, Adobe, Dropbox etc. |
| macos-kext-bundle-installed, macos-system-extension-staged | exclude known vendor kext and system-extension names | CrowdStrike, Backblaze, VMware, etc. |
| macos-xattr-remove-quarantine | exclude targets that are an app bundle directly under `/Applications` | brew/MDM/CI app installs |
| macos-security-unlock-keychain-password | high to medium, exclude CI-style keychain names (`build`, `ci`, `runner`, `temp`, `signing`, `release`) | CI signing pipelines pass `-p` by design |
| macos-installer-pkg-silent-temp | exclude well-known vendor pkg names | MDM and scripted installs from `/tmp` |
| win-forfiles-command-exec, ioa-lolbin-forfiles-pcalua-indirect | exclude file-operation payloads (`del`, `echo`, `copy`, ...) | the standard log-cleanup idiom `forfiles ... /c "cmd /c del @path"` |
| win-curl-exe-download-write | exclude downloads from a list of well-known vendor hosts (host-anchored) | installer fetches from python.org, github.com, microsoft.com, etc. |
| ioa-exec-from-appdata-with-network-args | exclude Defender, Package Cache and similar `ProgramData` executables; bound IPv4 octets to 1 to 3 digits | the old `\d+.\d+.\d+.\d+` matched the Defender platform version `4.18.23110.3-0` as an IP |
| win-file-startup-folder-exe, ioa-file-windows-startup-folder-exec | exclude shortcuts of common apps (OneNote, Teams, Slack, Zoom, ...) | installer-created startup `.lnk` files |
| ioa-file-windows-public-programdata-executable | exclude Package Cache, Chocolatey, Defender, Docker, Veeam subtrees | installer caches |
| win-file-office-startup-macro | exclude `Normal.dotm` and `PERSONAL.XLSB` | Word and Excel rewrite them routinely |
| ioa-net-container-control-ports | exclude loopback | local Docker/kubelet client traffic |
| ioa-net-database-port-raw-ip, ioa-net-legacy-cleartext-ports-raw-ip, ioa-net-resolver-bypass-ports | exclude RFC1918, loopback, link-local and multicast | internal database, syslog and mDNS traffic |
| ioa-net-implant-default-ports | port 8089 exempt when the destination is private | Splunk management port |
| win-net-smb-rdp-winrm-external, win-net-ldap-kerberos-external | exclude single-label hosts and `.local/.internal/.lan/.corp/.intranet` names | domain-joined clients talking to internal DCs by name |
| windows-run-key-value-added (seed), reg-run-value-points-to-user-writable-dir | exclude values under Program Files, `%windir%` and similar, and per-user dirs of known apps (OneDrive, Teams, Slack, Discord, Spotify, Zoom) | most Run values are vendor autostarts |
| reg-defender-exclusion-added | exclude backup, SCCM cache, SQL Server and SoftwareDistribution paths | vendor-documented exclusions |
| reg-ifeo-debugger-set | exclude `procexp`, `vsjitdebugger`, `windbg`, `cdb`, `ntsd` debuggers | Process Explorer replacing Task Manager, debugger setups |

### Rules that still fire at low severity on the corpus (allowed)

26 low-severity rules fire 36 times, including six that were already low and are untouched:
ioa-net-cloud-metadata-reach, macos-aws-credentials-touched, macos-kube-docker-config-touched,
win-file-hosts-modified, win-whoami-priv-all, ioa-net-lateral-ports-raw-ip. The latter fires on
internal SMB to a raw IP because its own positive samples are private addresses.

### Corpus events removed or reshaped

Two events originally drafted for the corpus were taken out because they are not benign noise:
enabling RDP (`fDenyTSConnections=0`) and creating a `NOPASSWD` sudoers drop-in. The IFEO event was
rewritten to the realistic Process Explorer replacement of `taskmgr.exe`. Writer and client
executables were removed from file and network events to match the live event shape.

## Honest limits

- The corpus is 1,611 hand-written events, not production telemetry. Passing it is evidence against
  gross false positives, not proof of low noise on a real fleet. Rules never exercised by a corpus
  event (most of the 716, which target attacker tradecraft) are untested by this guard, and a clean run does
  not measure detection quality (false negatives).
- Allow-lists are name-based. An attacker who names a LaunchDaemon `com.microsoft.x.plist`, a Run
  value under `Program Files`, a task `GoogleUpdateTaskMachineUA`, or downloads from github.com
  evades the tightened rule. Vendor-name exclusion trades recall for noise; it is not a trust decision.
- File and network events carry no actor, so persistence-path rules cannot separate an admin
  edit from an attacker edit. Severity `low` there is an honest statement of the signal, but it also
  lowers priority for true persistence; findings from these rules should be correlated, not triaged alone.
- OS is not enforced when rules are evaluated, so OS-labelled rules fire on other OSes' paths
  (a macOS rule matched a Linux `~/.aws` path). That is existing behaviour and was not changed here.
- Several lowered rules (`win-cipher-wipe-free-space`, `macos-tcc-database-modified`,
  `win-file-spooler-dll-drop`, `ioa-file-pam-or-sshd-config-write`) lost high-severity coverage of
  real attacker techniques because the benign and malicious forms are identical in the fields available.
  Restoring them needs richer telemetry (writer process, signer) rather than more regex.
- The low-severity allowance is a test policy. If you want zero firing at every severity,
  tighten the guard and drop or exclude the 26 rules above, accepting the lost coverage.
