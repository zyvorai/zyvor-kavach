// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// GuidanceEntry is an advisory explainer. Kavach is observation-only: every
// remediation step is a suggestion for a human; nothing is applied by Kavach.
type GuidanceEntry struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"` // rule|technique
	Title            string   `json:"title"`
	WhatItMeans      string   `json:"what_it_means"`
	WhyItMatters     string   `json:"why_it_matters"`
	HowToInvestigate []string `json:"how_to_investigate"`
	HowToRemediate   []string `json:"how_to_remediate"`
	FalsePositives   string   `json:"false_positive_notes"`
	References       []string `json:"references"`
}

// EmittedRuleNames lists every rule name the code can emit (Detect, ransomware,
// file_events, ingest, deception_tokens, ruleMITRE keys, default IOA ids).
// Maintained by hand; the test asserts each has an entry. Not covered
// individually: "custom-<name>" (operator-defined; prefix fallback to the
// "custom-rule" entry) and operator-added "ioc-<type>"/"ioa-<id>" values
// (prefix fallback to ioc-generic/ioa-generic).
var EmittedRuleNames = []string{
	"shell-network-redirection", "download-execute", "unsafe-permissions", "lolbin-netcat-shell",
	"persistence-attempt", "script-inline-execution", "download-chmod-execute", "root-history-clear",
	"ioc-domain", "ioc-ipv4", "ioc-sha256", "ioc-hash-match", "ioc-domain-match", "ioc-ip-match",
	"ioa-ioa-1", "ioa-ioa-2", "ioa-ioa-3", "ioa-credential-dump", "ioa-lateral-smb",
	"custom-rule", "ransomware-burst", "ransomware-extension-burst", "ransomware-churn",
	"mass-file-activity", "netra-denied-process", "deception-canary-tripped",
	"identity-password-spray", "identity-impossible-travel", "identity-from-finding",
	"ioc-generic", "ioa-generic",
}

var techniqueIDRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func techniqueURL(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return "https://attack.mitre.org/techniques/" + id[:i] + "/" + id[i+1:] + "/"
	}
	return "https://attack.mitre.org/techniques/" + id + "/"
}

func ruleEntry(id, title, means, why, fp, tid string, inv, rem []string) GuidanceEntry {
	e := GuidanceEntry{ID: id, Kind: "rule", Title: title, WhatItMeans: means, WhyItMatters: why,
		HowToInvestigate: inv, HowToRemediate: rem, FalsePositives: fp, References: []string{}}
	if tid != "" {
		e.References = []string{techniqueURL(tid)}
	}
	return e
}

type tacticTpl struct {
	why string
	inv []string
	rem []string
	fp  string
}

var tacticTemplates = map[string]tacticTpl{
	"Initial Access": {"Initial access marks where an intruder may first have entered; early scoping limits spread.",
		[]string{"Identify the earliest related event on the host or account.", "Review authentication, email and web-exposure logs around that time.", "Check whether the same indicator appears on other hosts."},
		[]string{"Consider closing or restricting the exposed entry point (advisory).", "Consider rotating credentials involved.", "Consider patching the exposed service after change review."},
		"Legitimate administrators, vendors and scanners can produce similar activity; confirm with the owner."},
	"Execution": {"Execution shows code actually ran, so impact may already be possible.",
		[]string{"Review the process tree, parent, user and full command line.", "Check the binary's path, hash and signer against known-good.", "Look for follow-on network or file activity from the same PID."},
		[]string{"Consider having the owner confirm or stop the activity through your normal process.", "Consider tightening application allow-listing (advisory).", "Consider reviewing whether the user needs this interpreter or tool."},
		"Admin scripts, build systems and package managers commonly look similar; check change tickets."},
	"Persistence": {"Persistence lets an intruder survive reboots and clean-up attempts.",
		[]string{"List scheduled jobs, services, startup items and keys for recent changes.", "Compare against a known-good baseline or configuration management.", "Identify which account created the item and when."},
		[]string{"Consider removing unapproved persistence mechanisms after capturing evidence.", "Consider restricting who can create jobs or services.", "Consider re-checking the host after changes for re-creation."},
		"Software installers and config management legitimately add services and jobs."},
	"Privilege Escalation": {"Higher privileges widen what an intruder can read, change or disable.",
		[]string{"Check which account gained elevated rights and how.", "Review sudo/admin logs and recent group changes.", "Look for new SUID files, tokens or service configuration changes."},
		[]string{"Consider revoking unneeded privileges (advisory).", "Consider patching the exploited component.", "Consider enforcing least privilege and just-in-time admin."},
		"Planned admin work and maintenance windows also elevate privileges."},
	"Defense Evasion": {"Evasion reduces the visibility defenders rely on and can hide other activity.",
		[]string{"Check logging and security tooling health on the host.", "Compare file names, paths and signers with legitimate versions.", "Review actions by the same user in the preceding hour."},
		[]string{"Consider restoring logging and security tooling configuration.", "Consider forwarding logs off-host to preserve evidence.", "Consider reviewing the account used."},
		"Some legitimate software repackages, obfuscates or clears state; verify the vendor."},
	"Credential Access": {"Stolen credentials let intruders move without malware and are hard to spot.",
		[]string{"Identify the accounts and secrets that could have been exposed.", "Review sign-ins for those accounts from new locations or hosts.", "Check for access to credential stores, memory dumps or key files."},
		[]string{"Consider rotating exposed credentials and keys (advisory).", "Consider enforcing multi-factor authentication.", "Consider reviewing where secrets are stored."},
		"Password managers, backup tools and security scanners may touch the same stores."},
	"Discovery": {"Discovery is typically reconnaissance that precedes lateral movement or data theft.",
		[]string{"Identify the user and process running the enumeration.", "Check whether the pattern repeats across hosts.", "Look for what the actor did next."},
		[]string{"Consider limiting who can enumerate sensitive inventory.", "Consider reviewing the account's role.", "Consider monitoring for follow-on activity."},
		"Inventory agents, monitoring tools and admins routinely run these commands."},
	"Lateral Movement": {"Lateral movement shows an intruder spreading from one system to another.",
		[]string{"Map source and destination hosts and the account used.", "Review remote-login and share-access logs on both ends.", "Check for tooling dropped on the destination."},
		[]string{"Consider restricting remote-admin paths between segments.", "Consider rotating the account used.", "Consider segmenting the network (advisory)."},
		"IT operations, patching and backup tools use remote services legitimately."},
	"Collection": {"Collection indicates data being gathered, possibly ahead of theft.",
		[]string{"Identify what data was touched and its sensitivity.", "Check for archives or staging directories.", "Review who owns the account and whether the access is expected."},
		[]string{"Consider tightening access to the sensitive data.", "Consider reviewing data-loss controls.", "Consider notifying the data owner."},
		"Backups, sync clients and search indexers read broad file sets."},
	"Command and Control": {"C2 channels let an intruder steer compromised hosts remotely.",
		[]string{"Identify the destination, process and timing (beacon regularity).", "Check threat intelligence and passive DNS for the destination.", "Look for other hosts contacting the same destination."},
		[]string{"Consider blocking the destination at network controls after review.", "Consider having the owner examine the host.", "Consider reviewing proxy and DNS egress policy."},
		"CDNs, SaaS and update services can resemble beacons; check the application."},
	"Exfiltration": {"Exfiltration is the point at which data leaves your control.",
		[]string{"Quantify volume, destination and timing of outbound data.", "Identify the process and account responsible.", "Determine what data classes may be involved."},
		[]string{"Consider egress restrictions for the destination (advisory).", "Consider engaging incident response and legal as policy requires.", "Consider rotating exposed secrets."},
		"Cloud backups and sanctioned uploads can look similar."},
	"Impact": {"Impact techniques damage availability or integrity and can be business-critical.",
		[]string{"Determine scope: which hosts and file sets are affected.", "Check for ransom notes, mass renames or deleted backups.", "Preserve evidence before any recovery."},
		[]string{"Consider involving incident response immediately.", "Consider verifying offline backups are intact.", "Consider restoring from known-good backups after root cause is understood."},
		"Large batch jobs, migrations and bulk clean-ups can look similar."},
}

type techDef struct{ id, title, tactic, means string }

var techniqueDefs = []techDef{
	{"T1190", "Exploit Public-Facing Application", "Initial Access", "A weakness in an internet-facing application may have been used to gain entry."},
	{"T1133", "External Remote Services", "Initial Access", "Remote access services such as VPN or RDP may have been used to enter the network."},
	{"T1566", "Phishing", "Initial Access", "A deceptive message may have delivered a link or attachment to a user."},
	{"T1566.001", "Spearphishing Attachment", "Initial Access", "A targeted email attachment may have been opened to start an intrusion."},
	{"T1078", "Valid Accounts", "Initial Access", "A legitimate credential may be in use by someone other than its owner."},
	{"T1078.004", "Cloud Accounts", "Initial Access", "A cloud identity may be misused to access cloud resources."},
	{"T1195", "Supply Chain Compromise", "Initial Access", "A trusted dependency or vendor update may have carried malicious code."},
	{"T1189", "Drive-by Compromise", "Initial Access", "Visiting a web page may have led to code execution on the browser host."},
	{"T1091", "Replication Through Removable Media", "Initial Access", "Removable media may have been used to introduce or spread code."},
	{"T1059", "Command and Scripting Interpreter", "Execution", "A shell or scripting runtime was used to run commands."},
	{"T1059.001", "PowerShell", "Execution", "PowerShell was used to run commands, often with encoded or hidden content."},
	{"T1059.003", "Windows Command Shell", "Execution", "cmd.exe was used to run commands or batch files."},
	{"T1059.004", "Unix Shell", "Execution", "A Unix shell ran commands that may include network or download actions."},
	{"T1059.006", "Python", "Execution", "A Python interpreter ran inline or downloaded code."},
	{"T1204", "User Execution", "Execution", "A user may have been induced to run a file or command."},
	{"T1204.002", "User Execution: Malicious File", "Execution", "A user may have opened a file that executed unwanted code."},
	{"T1047", "Windows Management Instrumentation", "Execution", "WMI may have been used to run commands locally or remotely."},
	{"T1053", "Scheduled Task/Job", "Execution", "A scheduled job may run code at set times."},
	{"T1053.003", "Cron", "Persistence", "A cron entry may run code repeatedly or at boot."},
	{"T1053.005", "Scheduled Task", "Persistence", "A Windows scheduled task may run code persistently."},
	{"T1569", "System Services", "Execution", "A service was used to launch code."},
	{"T1203", "Exploitation for Client Execution", "Execution", "A client application bug may have been exploited to run code."},
	{"T1106", "Native API", "Execution", "Code called operating-system APIs directly, bypassing common tooling."},
	{"T1129", "Shared Modules", "Execution", "A library may have been loaded to run attacker code."},
	{"T1543", "Create or Modify System Process", "Persistence", "A system service or daemon was created or changed."},
	{"T1543.002", "Systemd Service", "Persistence", "A systemd unit was created or changed and may run code at boot."},
	{"T1543.003", "Windows Service", "Persistence", "A Windows service was created or modified."},
	{"T1547", "Boot or Logon Autostart Execution", "Persistence", "Code was configured to run at boot or logon."},
	{"T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "A run key or startup item may launch code at logon."},
	{"T1546", "Event Triggered Execution", "Persistence", "Code was tied to a system event such as a login or file open."},
	{"T1136", "Create Account", "Persistence", "A new account may give an intruder durable access."},
	{"T1098", "Account Manipulation", "Persistence", "An account's permissions or credentials were changed."},
	{"T1505", "Server Software Component", "Persistence", "A web shell or server plug-in may provide hidden access."},
	{"T1505.003", "Web Shell", "Persistence", "A script on a web server may provide remote command access."},
	{"T1574", "Hijack Execution Flow", "Persistence", "A loader path or library was manipulated to run other code."},
	{"T1574.006", "Dynamic Linker Hijacking", "Persistence", "LD_PRELOAD or similar settings may load attacker libraries."},
	{"T1197", "BITS Jobs", "Persistence", "BITS may be abused to download or run payloads."},
	{"T1037", "Boot or Logon Initialization Scripts", "Persistence", "Init scripts may run attacker code at startup."},
	{"T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "A software flaw may have been used to gain higher rights."},
	{"T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "Mechanisms such as sudo or UAC may have been abused."},
	{"T1548.001", "Setuid and Setgid", "Privilege Escalation", "SUID/SGID bits may allow code to run with elevated rights."},
	{"T1548.003", "Sudo and Sudo Caching", "Privilege Escalation", "sudo configuration or cached tokens may allow privilege gain."},
	{"T1134", "Access Token Manipulation", "Privilege Escalation", "Tokens may have been duplicated or altered to act as another user."},
	{"T1611", "Escape to Host", "Privilege Escalation", "A container may have broken out to the underlying host."},
	{"T1055", "Process Injection", "Defense Evasion", "Code was injected into another process to hide or gain rights."},
	{"T1036", "Masquerading", "Defense Evasion", "A file or process may be disguised as something legitimate."},
	{"T1036.005", "Match Legitimate Name or Location", "Defense Evasion", "A binary may reuse a trusted name or path."},
	{"T1027", "Obfuscated Files or Information", "Defense Evasion", "Content may be encoded or packed to evade inspection."},
	{"T1070", "Indicator Removal", "Defense Evasion", "Logs or artifacts may have been deleted to hide activity."},
	{"T1070.003", "Clear Command History", "Defense Evasion", "Shell history may have been cleared to hide commands."},
	{"T1070.004", "File Deletion", "Defense Evasion", "Files may have been deleted to remove evidence."},
	{"T1562", "Impair Defenses", "Defense Evasion", "Security tooling or logging may have been weakened."},
	{"T1562.001", "Disable or Modify Tools", "Defense Evasion", "A security tool may have been stopped or changed."},
	{"T1222", "File and Directory Permissions Modification", "Defense Evasion", "Permissions may have been loosened to allow access or tampering."},
	{"T1222.002", "Linux and Mac File Permissions Modification", "Defense Evasion", "chmod or chown may have made sensitive files writable or executable."},
	{"T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "Content was decoded at run time, often before execution."},
	{"T1218", "System Binary Proxy Execution", "Defense Evasion", "A trusted system binary may have been used to run other code."},
	{"T1112", "Modify Registry", "Defense Evasion", "Registry values may have been altered to hide or persist."},
	{"T1550", "Use Alternate Authentication Material", "Defense Evasion", "Tokens, tickets or hashes may be used instead of passwords."},
	{"T1550.002", "Pass the Hash", "Lateral Movement", "A password hash may have been used to authenticate without the password."},
	{"T1550.003", "Pass the Ticket", "Lateral Movement", "A Kerberos ticket may have been reused to impersonate an account."},
	{"T1003", "OS Credential Dumping", "Credential Access", "Credentials may have been extracted from system memory or stores."},
	{"T1003.001", "LSASS Memory", "Credential Access", "Credentials may have been read from LSASS process memory."},
	{"T1003.008", "/etc/passwd and /etc/shadow", "Credential Access", "Account files may have been read to obtain password hashes."},
	{"T1110", "Brute Force", "Credential Access", "Repeated guessing of credentials was attempted."},
	{"T1110.001", "Password Guessing", "Credential Access", "Multiple passwords were tried against an account."},
	{"T1110.003", "Password Spraying", "Credential Access", "A few common passwords were tried across many accounts."},
	{"T1110.004", "Credential Stuffing", "Credential Access", "Leaked credential pairs may have been replayed against a service."},
	{"T1552", "Unsecured Credentials", "Credential Access", "Credentials stored in files, history or metadata may have been accessed."},
	{"T1552.001", "Credentials In Files", "Credential Access", "Secrets in configuration or plain files may have been read."},
	{"T1552.004", "Private Keys", "Credential Access", "Private key material may have been accessed."},
	{"T1555", "Credentials from Password Stores", "Credential Access", "Password managers or keychains may have been read."},
	{"T1558", "Steal or Forge Kerberos Tickets", "Credential Access", "Kerberos tickets may have been stolen or forged."},
	{"T1558.003", "Kerberoasting", "Credential Access", "Service tickets may have been requested to crack service-account passwords offline."},
	{"T1056", "Input Capture", "Credential Access", "Keystrokes or prompts may have been captured."},
	{"T1539", "Steal Web Session Cookie", "Credential Access", "Session cookies may have been taken to bypass login."},
	{"T1528", "Steal Application Access Token", "Credential Access", "Application or cloud tokens may have been taken."},
	{"T1082", "System Information Discovery", "Discovery", "System details such as OS and hardware were gathered."},
	{"T1083", "File and Directory Discovery", "Discovery", "File listings were enumerated to find interesting data."},
	{"T1057", "Process Discovery", "Discovery", "Running processes were listed."},
	{"T1018", "Remote System Discovery", "Discovery", "Other hosts on the network were enumerated."},
	{"T1016", "System Network Configuration Discovery", "Discovery", "Network settings and interfaces were enumerated."},
	{"T1049", "System Network Connections Discovery", "Discovery", "Active connections were listed."},
	{"T1033", "System Owner/User Discovery", "Discovery", "The current user or logged-in users were identified."},
	{"T1087", "Account Discovery", "Discovery", "Accounts and groups were enumerated."},
	{"T1069", "Permission Groups Discovery", "Discovery", "Group memberships were enumerated."},
	{"T1046", "Network Service Discovery", "Discovery", "Open ports and services were scanned."},
	{"T1613", "Container and Resource Discovery", "Discovery", "Containers and orchestration resources were listed."},
	{"T1021", "Remote Services", "Lateral Movement", "Remote login or management services were used to reach another host."},
	{"T1021.001", "Remote Desktop Protocol", "Lateral Movement", "RDP was used to reach another system."},
	{"T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "SMB admin shares were used to reach or copy files to another system."},
	{"T1021.004", "SSH", "Lateral Movement", "SSH was used to reach another system."},
	{"T1570", "Lateral Tool Transfer", "Lateral Movement", "Tools were copied between internal systems."},
	{"T1210", "Exploitation of Remote Services", "Lateral Movement", "A remote service flaw may have been exploited to move between hosts."},
	{"T1005", "Data from Local System", "Collection", "Local files were gathered."},
	{"T1039", "Data from Network Shared Drive", "Collection", "Files were gathered from network shares."},
	{"T1560", "Archive Collected Data", "Collection", "Data was compressed or encrypted, often before exfiltration."},
	{"T1074", "Data Staged", "Collection", "Data was consolidated in a staging location."},
	{"T1113", "Screen Capture", "Collection", "Screenshots may have been taken."},
	{"T1071", "Application Layer Protocol", "Command and Control", "Common protocols such as HTTP or DNS may carry control traffic."},
	{"T1071.001", "Web Protocols", "Command and Control", "HTTP(S) may carry control traffic."},
	{"T1071.004", "DNS", "Command and Control", "DNS queries may carry control traffic."},
	{"T1105", "Ingress Tool Transfer", "Command and Control", "Tools or payloads were downloaded onto a host."},
	{"T1095", "Non-Application Layer Protocol", "Command and Control", "A raw transport protocol may carry control traffic."},
	{"T1572", "Protocol Tunneling", "Command and Control", "Traffic may be wrapped inside another protocol."},
	{"T1090", "Proxy", "Command and Control", "Traffic may be relayed to hide its endpoint."},
	{"T1219", "Remote Access Software", "Command and Control", "Remote access tools may provide interactive control."},
	{"T1571", "Non-Standard Port", "Command and Control", "A protocol may be used on an unusual port."},
	{"T1573", "Encrypted Channel", "Command and Control", "Encryption may hide control traffic contents."},
	{"T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Data may leave over the existing control channel."},
	{"T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "Data may leave over a protocol different from the main C2 channel."},
	{"T1567", "Exfiltration Over Web Service", "Exfiltration", "Data may be uploaded to an external web service."},
	{"T1486", "Data Encrypted for Impact", "Impact", "Files may have been encrypted to deny access, typical of ransomware."},
	{"T1485", "Data Destruction", "Impact", "Files or data may have been deleted or overwritten."},
	{"T1490", "Inhibit System Recovery", "Impact", "Backups, shadow copies or recovery settings may have been removed."},
	{"T1489", "Service Stop", "Impact", "Services may have been stopped to disrupt operations or unlock files."},
	{"T1496", "Resource Hijacking", "Impact", "Compute may be used for unauthorized work such as mining."},
	{"T1498", "Network Denial of Service", "Impact", "Network resources may be flooded to degrade availability."},
	{"T1531", "Account Access Removal", "Impact", "Accounts may have been locked or removed to block responders."},
	{"T1565", "Data Manipulation", "Impact", "Data may have been altered to affect integrity."},
}

func rulesCatalog() []GuidanceEntry {
	return []GuidanceEntry{
		ruleEntry("shell-network-redirection", "Shell with network redirection (possible reverse shell)",
			"A shell command line uses /dev/tcp or interactive redirection, a pattern common in reverse shells.",
			"A reverse shell gives a remote party interactive control of the host.",
			"Rare legitimate uses exist in health-check scripts or developer test snippets.", "T1105",
			[]string{"Read the full command, user, parent process and working directory.", "Identify the remote address and whether the host should reach it.", "Check for other activity by the same user shortly before and after."},
			[]string{"Consider confirming with the owner whether the command was intended.", "Consider blocking the destination at egress controls after review.", "Consider rotating credentials of the account used if unexplained."}),
		ruleEntry("download-execute", "Download piped into a shell",
			"curl or wget output appears to be piped directly into a shell.",
			"The code is executed without being inspected or stored, so a hostile or tampered source runs with the user's rights.",
			"Common in vendor install instructions and bootstrap scripts.", "T1204.002",
			[]string{"Identify the URL and verify the domain's reputation.", "Check whether the user was following a documented install procedure.", "Look for files, services or cron entries created afterwards."},
			[]string{"Consider downloading, reviewing and verifying checksums before running installers.", "Consider limiting direct internet access from servers.", "Consider removing anything installed if the source is untrusted."}),
		ruleEntry("unsafe-permissions", "Sensitive configuration made broadly writable",
			"A command appears to set world-writable permissions under /etc.",
			"Writable system configuration lets any local user alter authentication or service behavior.",
			"Occasionally done by mistake during troubleshooting; still worth correcting.", "T1222.002",
			[]string{"Check the current permissions of the affected paths.", "Identify who ran the command and why.", "Review changes to the files since the command ran."},
			[]string{"Consider restoring expected permissions from your package manager or baseline.", "Consider reviewing the files for unexpected edits.", "Consider auditing who may run chmod as root."}),
		ruleEntry("lolbin-netcat-shell", "Netcat-style tool with shell execution",
			"A netcat-like binary was run with options that can attach a shell.",
			"This is a classic way to open a remote command channel using a common tool.",
			"Network engineers sometimes use these flags for debugging.", "T1059",
			[]string{"Check the listening port or remote address involved.", "Review the parent process and user.", "Look for established connections from the process."},
			[]string{"Consider confirming intent with the owner.", "Consider removing netcat from hosts that do not need it.", "Consider egress filtering for the remote address."}),
		ruleEntry("persistence-attempt", "Possible persistence via cron or systemd",
			"A command touches cron or enables a service in a way that can make code run repeatedly.",
			"Persistence keeps an intruder on the host after a reboot.",
			"Routine administration and software installs do this often.", "T1053.003",
			[]string{"Inspect the created or changed cron entry or unit.", "Check the command it runs and the file's owner and hash.", "Compare with configuration management records."},
			[]string{"Consider removing unapproved jobs or units after saving evidence.", "Consider restricting who can write cron and unit files.", "Consider re-checking the host later for re-creation."}),
		ruleEntry("script-inline-execution", "Interpreter with inline or encoded payload",
			"A scripting interpreter ran inline code, base64 content or a network-backed pattern.",
			"Inline payloads avoid leaving script files and are common in intrusions.",
			"Developers and ops tooling often use python -c or similar one-liners.", "T1059",
			[]string{"Decode any base64 content in a safe environment.", "Check the parent process and whether it is an automation tool.", "Look for network connections or file writes from the process."},
			[]string{"Consider confirming the one-liner with its owner.", "Consider restricting interpreters on hosts that do not need them.", "Consider tracing the origin if the parent is unexpected."}),
		ruleEntry("download-chmod-execute", "Download followed by chmod +x",
			"A command fetches a file and marks it executable.",
			"This is a common step for staging a payload on a host.",
			"Common in legitimate manual installs of single-binary tools.", "T1036",
			[]string{"Identify the downloaded file and its hash.", "Check the URL's reputation.", "Look for the file being run afterwards."},
			[]string{"Consider quarantining the file for analysis through your process.", "Consider limiting outbound downloads from servers.", "Consider verifying software sources."}),
		ruleEntry("root-history-clear", "Root shell cleared history",
			"A root shell ran a history-clearing command.",
			"Clearing history can hide prior commands from investigators.",
			"Administrators sometimes clear history out of habit or to remove typed secrets.", "T1070.003",
			[]string{"Review other logs (auth, auditd, sudo) for activity before the clear.", "Identify who held the root session.", "Check for other log or file tampering."},
			[]string{"Consider forwarding shell and audit logs off-host.", "Consider limiting direct root logins.", "Consider following up with the administrator."}),
		ruleEntry("ioc-domain", "Known-bad domain observed",
			"Host activity references a domain in your IOC list.",
			"IOC lists encode infrastructure linked to prior malicious activity.",
			"IOC entries can be stale or overly broad; verify the source and age.", "T1071",
			[]string{"Check the process and user that referenced the domain.", "Review DNS history for other hosts.", "Confirm the IOC's source and confidence."},
			[]string{"Consider blocking the domain at DNS or proxy after review.", "Consider examining the host if contact succeeded.", "Consider retiring the IOC if it is stale."}),
		ruleEntry("ioc-ipv4", "Known-bad IP address observed",
			"Host activity references an IPv4 address in your IOC list.",
			"The address may belong to attacker infrastructure.",
			"Shared hosting and recycled addresses can cause false matches.", "T1071",
			[]string{"Check the connection direction, port and process.", "Review other hosts contacting the address.", "Check the IOC age and source."},
			[]string{"Consider blocking the address at the firewall after review.", "Consider examining the host if traffic succeeded.", "Consider expiring old IOCs."}),
		ruleEntry("ioc-sha256", "Known-bad file hash observed",
			"A file hash matches an entry in your IOC list.",
			"Hash matches are high-precision identifiers for specific known files.",
			"Placeholder or empty-file hashes in sample data can match benign items.", "T1204",
			[]string{"Locate the file and its path, owner and creation time.", "Check how it arrived.", "Check whether other hosts hold the same hash."},
			[]string{"Consider isolating the file for analysis per your process.", "Consider reviewing the source of the file.", "Consider scanning other hosts for the hash."}),
		ruleEntry("ioc-hash-match", "File hash IOC match", "A file hash matched a threat-intelligence entry.", "Indicates a known file may be present.", "Verify the IOC source; test hashes can match empty files.", "T1204",
			[]string{"Locate and identify the file.", "Check its provenance.", "Search other hosts for the hash."}, []string{"Consider quarantining the file through your process.", "Consider reviewing how it arrived.", "Consider updating the IOC if it is a false match."}),
		ruleEntry("ioc-domain-match", "Domain IOC match", "A domain matched a threat-intelligence entry.", "Indicates possible contact with known malicious infrastructure.", "Stale or broad IOC entries cause noise.", "T1071",
			[]string{"Check the process and user.", "Review DNS logs across hosts.", "Verify IOC confidence."}, []string{"Consider blocking at DNS or proxy after review.", "Consider examining affected hosts.", "Consider pruning old IOCs."}),
		ruleEntry("ioc-ip-match", "IP IOC match", "An IP address matched a threat-intelligence entry.", "Indicates possible contact with known malicious infrastructure.", "Shared or recycled addresses can cause false matches.", "T1071",
			[]string{"Check direction, port and process.", "Review other hosts' flows to the address.", "Verify IOC confidence."}, []string{"Consider blocking at the firewall after review.", "Consider examining affected hosts.", "Consider pruning old IOCs."}),
		ruleEntry("ioc-generic", "IOC match (other type)", "Host activity matched an operator-defined IOC of a type without its own entry.", "The matched indicator was deemed worth watching by your team or feed.", "Depends on the feed quality; check the IOC source.", "T1071",
			[]string{"Read the finding's description for the indicator and source.", "Check the process and user involved.", "Review where else the indicator appears."}, []string{"Consider acting according to the IOC's documented response.", "Consider tuning the IOC if noisy.", "Consider escalating if contact is confirmed."}),
		ruleEntry("ioa-ioa-1", "Credential dumping tool pattern", "Command-line text matches names associated with credential dumping tools such as mimikatz, procdump on lsass, or secretsdump.", "Dumped credentials enable lateral movement and privilege gain.", "Security testing and incident-response tools use these names; check for an approved exercise.", "T1003",
			[]string{"Identify the process, user and host.", "Check whether LSASS or credential files were accessed.", "Review sign-ins by credentials that may have been exposed."}, []string{"Consider rotating credentials that were in memory on the host.", "Consider enabling credential-protection features (advisory).", "Consider involving incident response."}),
		ruleEntry("ioa-ioa-2", "Living-off-the-land shell pattern", "Command-line text matches interactive-shell or encoded-command patterns such as bash -i, /dev/tcp, nc -e or powershell -enc.", "These patterns often establish remote control or hide commands.", "Admin and CI scripts may contain similar text.", "T1059",
			[]string{"Read the full command and decode any encoded content safely.", "Check the parent process and destination.", "Look for follow-on activity."}, []string{"Consider confirming intent with the owner.", "Consider constraining shell interpreters via policy.", "Consider egress filtering."}),
		ruleEntry("ioa-ioa-3", "Ransomware preparation pattern", "Command-line text matches deletion of backups or recovery settings (vssadmin delete, wbadmin delete, bcdedit /set).", "Removing recovery options is a frequent step just before encryption.", "Rare in normal operations; verify with the system owner.", "T1490",
			[]string{"Identify the user and process that ran the command.", "Check for mass file changes or ransom notes.", "Verify the state of backups and shadow copies."}, []string{"Consider involving incident response immediately.", "Consider protecting offline backups.", "Consider reviewing the account used."}),
		ruleEntry("ioa-credential-dump", "Credential dump behavior", "Behavior consistent with credential dumping was observed.", "Exposed credentials can be reused across the environment.", "Approved security testing may match.", "T1003",
			[]string{"Review process access to credential stores.", "Check account sign-ins afterwards.", "Identify the actor account."}, []string{"Consider rotating affected credentials.", "Consider enabling credential protection.", "Consider an incident-response review."}),
		ruleEntry("ioa-lateral-smb", "Lateral movement over SMB", "Activity consistent with SMB admin-share use to reach other hosts was observed.", "Attackers use admin shares to copy tools and run code remotely.", "Software deployment and backup tools use SMB admin shares.", "T1021.002",
			[]string{"Identify the source, destination and account.", "Check files written to the destination.", "Verify whether a deployment was scheduled."}, []string{"Consider restricting admin-share access between segments.", "Consider rotating the account used.", "Consider reviewing remote-admin privileges."}),
		ruleEntry("ioa-generic", "IOA match (other pattern)", "Command-line text matched an operator-defined behavior pattern without its own entry.", "Your team flagged this behavior as worth reviewing.", "Depends on how specific the pattern is.", "",
			[]string{"Read the pattern's description in the finding.", "Check the process, parent and user.", "Look for related activity."}, []string{"Consider following the pattern's documented response.", "Consider tuning the pattern if noisy.", "Consider escalating if unexplained."}),
		ruleEntry("custom-rule", "Custom detection rule matched", "An operator-authored rule matched host activity.", "Custom rules usually encode local knowledge of what is abnormal for your estate.", "Quality depends on rule design; check hit history for noise.", "",
			[]string{"Read the rule's query and the matched evidence.", "Review the rule's past hits and dispositions.", "Check the host's role."}, []string{"Consider following the rule's runbook.", "Consider tuning or narrowing the rule if noisy.", "Consider documenting expected exceptions."}),
		ruleEntry("ransomware-burst", "Create/delete churn resembling ransomware", "A high volume of file creates and deletes occurred in a short window.", "Ransomware often rewrites many files quickly.", "Build tools, package managers and backup jobs can produce similar bursts.", "T1486",
			[]string{"Identify the process and path responsible.", "Look for ransom notes or renamed extensions.", "Check whether a batch job was scheduled."}, []string{"Consider involving incident response if unexplained.", "Consider verifying backups are intact and offline.", "Consider limiting write access on affected shares."}),
		ruleEntry("ransomware-extension-burst", "Many files with ransomware-style extensions", "Multiple files with extensions associated with ransomware appeared quickly.", "Mass renaming to known extensions is a strong, though not conclusive, signal.", "Some extensions are reused by benign tools; this is not proof of encryption.", "T1486",
			[]string{"List the affected files and extensions.", "Identify the process creating them.", "Check for ransom notes."}, []string{"Consider involving incident response.", "Consider preserving evidence before recovery.", "Consider restoring from verified backups later."}),
		ruleEntry("ransomware-churn", "Elevated file modification on canary path", "Unusual modification churn was seen on a watched canary path.", "Canary paths should be quiet; activity there suggests mass file handling.", "Indexers, antivirus and sync tools can touch canary paths.", "T1486",
			[]string{"Identify the process touching the canary path.", "Check whether other paths show churn.", "Review recent software changes."}, []string{"Consider confirming with the owner of the process.", "Consider widening monitoring temporarily.", "Consider reviewing backup status."}),
		ruleEntry("mass-file-activity", "Mass file activity", "A large number of file changes occurred in a short window on a host.", "May indicate ransomware, destruction or a large batch job.", "Migrations, builds and backups commonly trigger this.", "T1485",
			[]string{"Identify the process and directories involved.", "Check for deletions versus renames.", "Look for change tickets or scheduled jobs."}, []string{"Consider confirming the workload with its owner.", "Consider incident response if unexplained.", "Consider checking backups."}),
		ruleEntry("netra-denied-process", "Network-denied process observed", "A process that network policy marks as denied was seen.", "Policy-violating network behavior can indicate unauthorized software or evasion.", "Policy may be out of date for new legitimate software.", "T1071",
			[]string{"Identify the process, destination and user.", "Check the policy entry and its age.", "Review whether the software is approved."}, []string{"Consider updating the policy if the software is legitimate.", "Consider removing unapproved software.", "Consider reviewing egress controls."}),
		ruleEntry("deception-canary-tripped", "Canary token used", "A planted decoy credential or file was touched or used.", "Canaries have no legitimate users, so any access suggests someone is searching for secrets.", "Backup, search or indexing software may read decoys.", "T1552",
			[]string{"Identify which token was triggered and by what host or account.", "Check what else that actor accessed.", "Determine the access path (share, repo, host)."}, []string{"Consider treating the actor as suspicious until explained.", "Consider rotating real secrets stored nearby.", "Consider tightening access to the location."}),
		ruleEntry("identity-password-spray", "Password spraying pattern", "Failed sign-ins spread across many accounts with few attempts each.", "Spraying avoids lockouts and can compromise weak passwords.", "Misconfigured services or password changes can look similar.", "T1110.003",
			[]string{"List targeted accounts and source addresses.", "Check for any successful sign-ins following failures.", "Review lockout and MFA logs."}, []string{"Consider enforcing MFA and strong password policy.", "Consider blocking abusive sources after review.", "Consider resetting any account with a suspicious success."}),
		ruleEntry("identity-impossible-travel", "Impossible travel", "The same account signed in from distant places in too short a time.", "May indicate stolen credentials or session theft.", "VPNs, mobile networks and proxies produce false positives.", "T1550",
			[]string{"Compare the source locations, devices and times.", "Check whether a VPN or proxy explains it.", "Review actions taken in the session."}, []string{"Consider resetting credentials and revoking sessions if unexplained.", "Consider requiring MFA.", "Consider contacting the user."}),
		ruleEntry("identity-from-finding", "Identity signal derived from a finding", "An identity indicator was inferred from host findings (for example privileged command use).", "It links host activity to a user account for investigation.", "Derived signals are low-confidence on their own.", "",
			[]string{"Review the source finding.", "Check the user's recent activity.", "Correlate with sign-in data."}, []string{"Consider reviewing the user's privileges.", "Consider confirming activity with the user.", "Consider adding MFA if absent."}),
	}
}

func techniqueEntries() []GuidanceEntry {
	out := make([]GuidanceEntry, 0, len(techniqueDefs))
	for _, d := range techniqueDefs {
		t := tacticTemplates[d.tactic]
		out = append(out, GuidanceEntry{
			ID: d.id, Kind: "technique", Title: d.title + " (" + d.id + ")",
			WhatItMeans:      d.means + " Tactic: " + d.tactic + ".",
			WhyItMatters:     t.why,
			HowToInvestigate: t.inv,
			HowToRemediate:   t.rem,
			FalsePositives:   t.fp,
			References:       []string{techniqueURL(d.id)},
		})
	}
	return out
}

var guidanceCatalog = func() []GuidanceEntry {
	all := append(rulesCatalog(), techniqueEntries()...)
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind > all[j].Kind // rule before technique
		}
		return all[i].ID < all[j].ID
	})
	return all
}()

func guidanceByID(id string) (GuidanceEntry, bool) {
	for _, e := range guidanceCatalog {
		if strings.EqualFold(e.ID, id) {
			return e, true
		}
	}
	return GuidanceEntry{}, false
}

// ResolveGuidance picks guidance for a rule: exact rule entry, custom prefix,
// then the rule's ATT&CK technique (and its parent), then ioc-/ioa- generics.
func ResolveGuidance(rule string) (GuidanceEntry, bool) {
	if e, ok := guidanceByID(rule); ok && e.Kind == "rule" {
		return e, true
	}
	if strings.HasPrefix(rule, "custom-") {
		return guidanceByID("custom-rule")
	}
	if m, ok := ruleMITRE[rule]; ok {
		if e, ok := guidanceByID(m.ID); ok {
			return e, true
		}
		if i := strings.IndexByte(m.ID, '.'); i > 0 {
			if e, ok := guidanceByID(m.ID[:i]); ok {
				return e, true
			}
		}
	}
	switch {
	case strings.HasPrefix(rule, "ioc-"):
		return guidanceByID("ioc-generic")
	case strings.HasPrefix(rule, "ioa-"):
		return guidanceByID("ioa-generic")
	}
	return GuidanceEntry{}, false
}

// RegisterGuidance wires the advisory guidance catalogue endpoints.
func RegisterGuidance(mux *http.ServeMux, token string, store *Store) {
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/guidance", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		kind := strings.ToLower(r.URL.Query().Get("kind"))
		q := strings.ToLower(r.URL.Query().Get("q"))
		out := make([]GuidanceEntry, 0)
		for _, e := range guidanceCatalog {
			if kind != "" && e.Kind != kind {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(e.ID+" "+e.Title+" "+e.WhatItMeans), q) {
				continue
			}
			out = append(out, e)
		}
		write(w, map[string]any{"count": len(out), "advisory_only": true, "entries": out})
	})
	mux.HandleFunc("GET /v1/guidance/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		e, ok := guidanceByID(r.PathValue("id"))
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		write(w, e)
	})
	mux.HandleFunc("GET /v1/findings/{id}/guidance", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		for _, f := range store.List() {
			if f.ID != id {
				continue
			}
			e, ok := ResolveGuidance(f.Rule)
			if !ok {
				http.Error(w, "no guidance for rule", 404)
				return
			}
			write(w, map[string]any{"finding_id": id, "rule": f.Rule, "advisory_only": true, "guidance": e})
			return
		}
		http.Error(w, "finding not found", 404)
	})
}
