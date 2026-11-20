// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

// Query library: curated, read-only starter queries. Every entry is written
// for a syntax the platform really parses:
//
//	fql-lite       POST /v1/hunt/query  (host:, rule:, severity:, exe:, cmdline:)
//	kql-lite       POST /v1/hunt/kql    (keyword subset over findings or events)
//	console-filter the detections filter box (case-insensitive substring over
//	               rule, host, technique id, status and severity)
//
// fql-lite matches rule/host/exe as substrings, and cmdline: only constrains
// process events (findings ignore it). Age and stale-host views cannot be
// expressed by any existing parser, so none are offered. Observation only.

const (
	LangFQL     = "fql-lite"
	LangKQL     = "kql-lite"
	LangConsole = "console-filter"
)

type LibraryQuery struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactic      string   `json:"tactic"`
	Technique   string   `json:"technique,omitempty"`
	Language    string   `json:"language"`
	Query       string   `json:"query"`
	Tags        []string `json:"tags"`
}

func lq(id, name, desc, tactic, tech, lang, query string, tags ...string) LibraryQuery {
	return LibraryQuery{ID: id, Name: name, Description: desc, Tactic: tactic, Technique: tech, Language: lang, Query: query, Tags: tags}
}

func fq(id, name, desc, tactic, tech, query string, tags ...string) LibraryQuery {
	return lq(id, name, desc, tactic, tech, LangFQL, query, tags...)
}

// QueryLibrary returns a copy of the curated library.
func QueryLibrary() []LibraryQuery { return append([]LibraryQuery{}, queryLibrary...) }

var queryLibrary = []LibraryQuery{
	// ---- Findings triage ----
	fq("triage-critical", "Critical findings", "Every critical-severity finding, the first queue to clear.", "triage", "", "severity:critical", "severity", "queue"),
	fq("triage-high", "High findings", "All high-severity findings awaiting review.", "triage", "", "severity:high", "severity", "queue"),
	fq("triage-medium", "Medium findings", "Medium-severity findings for the daily sweep.", "triage", "", "severity:medium", "severity"),
	fq("triage-low", "Low findings", "Low-severity findings, useful for tuning review.", "triage", "", "severity:low", "severity", "tuning"),
	fq("triage-info", "Informational findings", "Informational findings that rarely need action.", "triage", "", "severity:info", "severity", "tuning"),
	fq("triage-critical-shell", "Critical findings from shells", "Critical findings whose executable is a shell.", "triage", "", "severity:critical exe:sh", "severity", "shell"),
	fq("triage-high-bash", "High findings running bash", "High-severity findings whose evidence executable is bash.", "triage", "", "severity:high exe:bash", "severity", "shell"),
	fq("triage-high-python", "High findings running python", "High-severity findings driven by a Python interpreter.", "triage", "", "severity:high exe:python", "severity", "interpreter"),
	fq("triage-critical-tmp", "Critical findings from /tmp", "Critical findings whose executable lives under /tmp.", "triage", "", "severity:critical exe:/tmp/", "severity", "staging"),
	fq("triage-high-tmp", "High findings from /tmp", "High-severity findings whose executable lives under /tmp.", "triage", "", "severity:high exe:/tmp/", "severity", "staging"),
	lq("triage-console-critical", "Console: critical", "Detections table filter: critical severity.", "triage", "", LangConsole, "critical", "severity", "console"),
	lq("triage-console-high", "Console: high", "Detections table filter: high severity.", "triage", "", LangConsole, "high", "severity", "console"),
	lq("triage-console-new", "Console: new status", "Detections still in the new status.", "triage", "", LangConsole, "new", "status", "console"),
	lq("triage-console-open", "Console: open status", "Detections currently open.", "triage", "", LangConsole, "open", "status", "console"),
	lq("triage-console-acked", "Console: acknowledged", "Detections already acknowledged by an analyst.", "triage", "", LangConsole, "ack", "status", "console"),
	lq("triage-kql-high", "KQL: high and critical findings", "Findings at high or critical severity through the KQL-lite endpoint.", "triage", "", LangKQL, "Findings | where severity == high", "severity", "kql"),
	lq("triage-kql-all", "KQL: every finding", "Unfiltered findings listing; a sanity check of the store.", "triage", "", LangKQL, "Findings", "kql", "inventory"),
	lq("triage-kql-alerts", "KQL: alerts view", "Alert-flavoured findings listing.", "triage", "", LangKQL, "alerts | where severity == high", "kql", "severity"),

	// ---- Findings by rule ----
	fq("rule-ransomware", "Ransomware indicators", "Any rule with ransomware in its name (burst, churn, extension).", "impact", "T1486", "rule:ransomware", "ransomware", "rule"),
	fq("rule-ransomware-burst", "Ransomware burst", "Rapid file modification bursts.", "impact", "T1486", "rule:ransomware-burst", "ransomware", "rule"),
	fq("rule-ransomware-churn", "Ransomware churn", "Sustained file churn consistent with encryption.", "impact", "T1486", "rule:ransomware-churn", "ransomware", "rule"),
	fq("rule-ransomware-ext", "Ransomware extension burst", "Mass renames to a new extension.", "impact", "T1486", "rule:ransomware-extension", "ransomware", "rule"),
	fq("rule-mass-file", "Mass file activity", "Large numbers of file changes; may be a batch job or ransomware.", "impact", "T1486", "rule:mass-file-activity", "files", "rule"),
	fq("rule-ransomware-critical", "Critical ransomware", "Ransomware rules at critical severity.", "impact", "T1486", "rule:ransomware severity:critical", "ransomware", "severity"),
	fq("rule-download-execute", "Download then execute", "A fetched payload run soon after download.", "execution", "T1105", "rule:download-execute", "download", "rule"),
	fq("rule-download-chmod", "Download, chmod, execute", "Fetch, mark executable and run chain.", "execution", "T1105", "rule:download-chmod-execute", "download", "rule"),
	fq("rule-script-inline", "Inline script execution", "Interpreters given code on the command line.", "execution", "T1059", "rule:script-inline-execution", "script", "rule"),
	fq("rule-script-inline-high", "Inline script, high severity", "Inline script execution at high severity.", "execution", "T1059", "rule:script-inline-execution severity:high", "script", "severity"),
	fq("rule-netcat-shell", "Netcat shell", "Netcat used to bind or reverse a shell.", "execution", "T1059.004", "rule:lolbin-netcat-shell", "lolbin", "rule"),
	fq("rule-shell-redirect", "Shell network redirection", "Shells redirecting to /dev/tcp style sockets.", "execution", "T1059.004", "rule:shell-network-redirection", "shell", "network"),
	fq("rule-unsafe-perms", "Unsafe permissions", "World-writable or otherwise unsafe permissions.", "defense-evasion", "T1222", "rule:unsafe-permissions", "permissions", "rule"),
	fq("rule-history-clear", "Root history cleared", "Shell history wiped by root.", "defense-evasion", "T1070.003", "rule:root-history-clear", "anti-forensics", "rule"),
	fq("rule-netra-denied", "Netra denied process", "Processes denied by network XDR policy.", "command-and-control", "", "rule:netra-denied-process", "xdr", "network"),
	fq("rule-custom", "Custom detection hits", "Findings from analyst-authored custom rules.", "triage", "", "rule:custom-", "custom", "rule"),
	fq("rule-ioc", "IOC matches", "Findings produced by threat-intel indicator matches.", "triage", "", "rule:ioc-", "intel", "ioc"),
	fq("rule-ioa", "IOA matches", "Findings produced by behavioural indicators of attack.", "triage", "", "rule:ioa-", "intel", "ioa"),
	fq("rule-identity", "Identity-derived findings", "Identity detections derived from host findings.", "credential-access", "", "rule:identity-from-finding", "identity", "rule"),

	// ---- Persistence ----
	fq("pers-attempt", "Persistence attempts", "Any persistence-attempt finding.", "persistence", "T1053", "rule:persistence-attempt", "persistence", "rule"),
	fq("pers-cron", "Cron persistence", "Findings mentioning cron.", "persistence", "T1053.003", "rule:cron", "cron", "persistence"),
	fq("pers-attempt-high", "High persistence attempts", "Persistence attempts at high severity.", "persistence", "T1053", "rule:persistence severity:high", "persistence", "severity"),
	fq("pers-crontab-cmd", "crontab invocations", "Process events invoking crontab.", "persistence", "T1053.003", "exe:crontab", "cron", "events"),
	fq("pers-crontab-edit", "crontab edit commands", "Command lines containing crontab.", "persistence", "T1053.003", "cmdline:crontab", "cron", "events"),
	fq("pers-systemctl-enable", "systemctl enable", "Command lines enabling a unit.", "persistence", "T1543.002", "cmdline:systemctl", "systemd", "events"),
	fq("pers-systemd-exe", "systemctl executions", "Process events for systemctl.", "persistence", "T1543.002", "exe:systemctl", "systemd", "events"),
	fq("pers-rc-local", "rc.local edits", "Command lines referencing rc.local.", "persistence", "T1037.004", "cmdline:rc.local", "boot", "events"),
	fq("pers-authorized-keys", "authorized_keys writes", "Command lines touching authorized_keys.", "persistence", "T1098.004", "cmdline:authorized_keys", "ssh", "events"),
	fq("pers-ld-preload", "ld.so.preload", "Command lines referencing ld.so.preload.", "persistence", "T1574.006", "cmdline:ld.so.preload", "preload", "events"),
	fq("pers-bashrc", "Shell profile edits", "Command lines touching .bashrc.", "persistence", "T1546.004", "cmdline:.bashrc", "shell", "events"),
	fq("pers-at-job", "at job scheduling", "Process events for the at scheduler.", "persistence", "T1053.002", "exe:/at", "scheduler", "events"),
	fq("pers-useradd", "Account creation", "useradd invocations.", "persistence", "T1136.001", "cmdline:useradd", "account", "events"),
	fq("pers-adduser", "adduser invocations", "adduser command lines.", "persistence", "T1136.001", "cmdline:adduser", "account", "events"),
	fq("pers-usermod", "usermod changes", "Group or shell changes through usermod.", "persistence", "T1098", "cmdline:usermod", "account", "events"),

	// ---- Credential access ----
	fq("cred-shadow", "Shadow file access", "Command lines reading /etc/shadow.", "credential-access", "T1003.008", "cmdline:/etc/shadow", "shadow", "events"),
	fq("cred-passwd", "passwd file access", "Command lines reading /etc/passwd.", "credential-access", "T1087.001", "cmdline:/etc/passwd", "passwd", "events"),
	fq("cred-ssh-keys", "SSH private key access", "Command lines touching id_rsa.", "credential-access", "T1552.004", "cmdline:id_rsa", "ssh", "events"),
	fq("cred-aws-creds", "AWS credentials file", "Command lines referencing .aws/credentials.", "credential-access", "T1552.001", "cmdline:.aws/credentials", "cloud", "events"),
	fq("cred-kube-config", "Kubeconfig access", "Command lines referencing .kube/config.", "credential-access", "T1552.001", "cmdline:.kube/config", "kubernetes", "events"),
	fq("cred-history", "Shell history reads", "Command lines reading bash_history.", "credential-access", "T1552.003", "cmdline:bash_history", "history", "events"),
	fq("cred-mimikatz", "Mimikatz strings", "Command lines mentioning mimikatz.", "credential-access", "T1003", "cmdline:mimikatz", "tool", "events"),
	fq("cred-lazagne", "LaZagne strings", "Command lines mentioning lazagne.", "credential-access", "T1555", "cmdline:lazagne", "tool", "events"),
	fq("cred-hashcat", "Hash cracking tools", "Process events for hashcat.", "credential-access", "T1110.002", "exe:hashcat", "cracking", "events"),
	fq("cred-john", "John the Ripper", "Process events for john.", "credential-access", "T1110.002", "exe:john", "cracking", "events"),
	fq("cred-hydra", "Online brute force", "Process events for hydra.", "credential-access", "T1110.001", "exe:hydra", "bruteforce", "events"),
	fq("cred-sudo", "Privilege switch via sudo", "sudo invocations.", "privilege-escalation", "T1548.003", "exe:sudo", "privesc", "events"),
	fq("cred-su", "su invocations", "Process events for su.", "privilege-escalation", "T1548", "exe:/su", "privesc", "events"),
	fq("cred-identity-high", "High identity findings", "Identity-derived findings at high severity.", "credential-access", "", "rule:identity severity:high", "identity", "severity"),

	// ---- Lateral movement ----
	fq("lat-ssh", "SSH client use", "Process events for ssh.", "lateral-movement", "T1021.004", "exe:ssh", "ssh", "events"),
	fq("lat-ssh-agent-fwd", "SSH agent forwarding", "Command lines using ssh -A.", "lateral-movement", "T1563.001", "cmdline:ssh", "ssh", "events"),
	fq("lat-scp", "scp transfers", "Process events for scp.", "lateral-movement", "T1021.004", "exe:scp", "transfer", "events"),
	fq("lat-rsync", "rsync transfers", "Process events for rsync.", "lateral-movement", "T1570", "exe:rsync", "transfer", "events"),
	fq("lat-sshpass", "sshpass usage", "Password-on-the-command-line SSH.", "lateral-movement", "T1021.004", "cmdline:sshpass", "ssh", "events"),
	fq("lat-psexec", "psexec-style tooling", "Command lines naming psexec.", "lateral-movement", "T1021.002", "cmdline:psexec", "tool", "events"),
	fq("lat-impacket", "Impacket tooling", "Command lines referencing impacket.", "lateral-movement", "T1021", "cmdline:impacket", "tool", "events"),
	fq("lat-nc", "netcat executions", "Process events for nc.", "lateral-movement", "T1570", "exe:/nc", "netcat", "events"),
	fq("lat-socat", "socat relays", "Process events for socat.", "lateral-movement", "T1090", "exe:socat", "relay", "events"),
	fq("lat-proxychains", "proxychains pivoting", "Command lines using proxychains.", "lateral-movement", "T1090", "cmdline:proxychains", "pivot", "events"),
	fq("lat-ssh-tunnel", "SSH tunnels", "Command lines for ssh port forwards.", "lateral-movement", "T1572", "cmdline:ssh exe:ssh", "tunnel", "events"),
	fq("lat-netcat-high", "Netcat findings, high", "Netcat shell findings at high severity.", "lateral-movement", "T1059.004", "rule:netcat severity:high", "netcat", "severity"),

	// ---- Exfiltration, collection and command-and-control ----
	fq("exf-curl", "curl executions", "Process events for curl.", "exfiltration", "T1048", "exe:curl", "http", "events"),
	fq("exf-curl-upload", "curl uploads", "curl command lines carrying an upload flag.", "exfiltration", "T1048.003", "cmdline:curl exe:curl", "http", "events"),
	fq("exf-wget", "wget executions", "Process events for wget.", "command-and-control", "T1105", "exe:wget", "http", "events"),
	fq("exf-wget-post", "wget POST data", "wget command lines with --post.", "exfiltration", "T1048.003", "cmdline:--post", "http", "events"),
	fq("exf-scp-out", "scp outbound", "scp command lines.", "exfiltration", "T1048", "cmdline:scp", "transfer", "events"),
	fq("exf-tar", "Archive creation", "tar invocations that often precede staging.", "collection", "T1560.001", "exe:/tar", "archive", "events"),
	fq("exf-zip", "zip archives", "zip invocations used for staging.", "collection", "T1560.001", "exe:/zip", "archive", "events"),
	fq("exf-gpg", "gpg encryption", "gpg used to encrypt before transfer.", "collection", "T1560.003", "exe:gpg", "archive", "events"),
	fq("exf-base64", "base64 encoding", "base64 invocations that may hide payloads.", "defense-evasion", "T1027", "exe:base64", "encoding", "events"),
	fq("exf-dnscat", "DNS tunnelling tools", "Command lines naming dnscat.", "exfiltration", "T1048.003", "cmdline:dnscat", "dns", "events"),
	fq("exf-iodine", "iodine tunnel", "Process events for iodine.", "exfiltration", "T1572", "exe:iodine", "dns", "events"),
	fq("exf-rclone", "rclone cloud sync", "rclone commonly copies data to cloud storage.", "exfiltration", "T1567.002", "exe:rclone", "cloud", "events"),
	fq("exf-megacmd", "MEGA client", "Command lines referencing mega.", "exfiltration", "T1567.002", "cmdline:mega-", "cloud", "events"),
	fq("exf-pastebin", "Paste site access", "Command lines referencing pastebin.", "exfiltration", "T1567", "cmdline:pastebin", "web", "events"),
	fq("exf-transfersh", "transfer.sh uploads", "Command lines referencing transfer.sh.", "exfiltration", "T1567", "cmdline:transfer.sh", "web", "events"),
	fq("exf-dev-tcp", "Reverse shell redirects", "Command lines using /dev/tcp.", "command-and-control", "T1059.004", "cmdline:/dev/tcp", "shell", "events"),
	lq("exf-kql-curl", "KQL: curl events", "Process events matching curl through KQL-lite.", "exfiltration", "T1048", LangKQL, "DeviceProcessEvents | where cmd contains curl", "kql", "events"),
	lq("exf-kql-wget", "KQL: wget events", "Process events matching wget through KQL-lite.", "command-and-control", "T1105", LangKQL, "DeviceProcessEvents | where cmd contains wget", "kql", "events"),

	// ---- Container and cloud ----
	fq("cont-exec", "Container exec", "Exec sessions into running containers.", "execution", "T1609", "rule:container_exec", "container", "rule"),
	fq("cont-privileged", "Privileged containers", "Containers started with privileged mode.", "privilege-escalation", "T1611", "rule:privileged_container", "container", "rule"),
	fq("cont-root", "Root containers", "Containers running as uid 0.", "privilege-escalation", "T1610", "rule:root_container", "container", "rule"),
	fq("cont-host-mount", "Host filesystem mounts", "Containers with host paths mounted.", "privilege-escalation", "T1611", "rule:host_mount", "container", "rule"),
	fq("cont-host-ns", "Host namespaces", "Containers sharing host namespaces.", "privilege-escalation", "T1611", "rule:host_namespace", "container", "rule"),
	fq("cont-any", "Any container rule", "Every finding from container-related rules.", "execution", "T1610", "rule:container", "container", "rule"),
	fq("cont-any-critical", "Critical container findings", "Container rules at critical severity.", "privilege-escalation", "T1611", "rule:container severity:critical", "container", "severity"),
	fq("cont-docker-run", "docker run", "Command lines launching containers.", "execution", "T1610", "cmdline:docker", "container", "events"),
	fq("cont-docker-priv", "docker --privileged", "Command lines requesting privileged mode.", "privilege-escalation", "T1611", "cmdline:--privileged", "container", "events"),
	fq("cont-docker-sock", "docker.sock exposure", "Command lines mounting docker.sock.", "privilege-escalation", "T1611", "cmdline:docker.sock", "container", "events"),
	fq("cont-kubectl-exec", "kubectl exec", "Command lines opening a shell in a pod.", "execution", "T1609", "cmdline:kubectl", "kubernetes", "events"),
	fq("cont-kubectl", "kubectl invocations", "Process events for kubectl.", "discovery", "T1613", "exe:kubectl", "kubernetes", "events"),
	fq("cont-nsenter", "nsenter escapes", "nsenter can step into host namespaces.", "privilege-escalation", "T1611", "exe:nsenter", "container", "events"),
	fq("cont-crictl", "crictl runtime access", "Process events for crictl.", "discovery", "T1613", "exe:crictl", "container", "events"),
	fq("cloud-aws-cli", "AWS CLI", "Process events for the aws cli.", "discovery", "T1580", "exe:/aws", "cloud", "events"),
	fq("cloud-gcloud", "gcloud CLI", "Process events for gcloud.", "discovery", "T1580", "exe:gcloud", "cloud", "events"),
	fq("cloud-az", "Azure CLI", "Process events for az.", "discovery", "T1580", "exe:/az", "cloud", "events"),
	fq("cloud-metadata", "Cloud metadata service", "Command lines calling 169.254.169.254.", "credential-access", "T1552.005", "cmdline:169.254.169.254", "cloud", "events"),
	fq("cloud-s3-cp", "S3 copy", "Command lines running aws s3 cp or sync.", "exfiltration", "T1537", "cmdline:s3", "cloud", "events"),
	fq("cloud-terraform", "Terraform runs", "Process events for terraform.", "discovery", "", "exe:terraform", "cloud", "iac"),

	// ---- Noisy-rule review and tuning ----
	fq("noise-low-all", "Low severity sweep", "Low findings; sort by rule to spot noisy rules.", "tuning", "", "severity:low", "noise", "tuning"),
	fq("noise-unsafe-perms", "Unsafe permissions volume", "Often the loudest rule; review for baseline exceptions.", "tuning", "", "rule:unsafe-permissions", "noise", "rule"),
	fq("noise-mass-file", "Mass file volume", "Batch jobs trip this rule; check owners.", "tuning", "", "rule:mass-file-activity", "noise", "rule"),
	fq("noise-script-inline", "Inline script volume", "Automation commonly triggers this rule.", "tuning", "", "rule:script-inline-execution", "noise", "rule"),
	fq("noise-cron", "Cron volume", "Legitimate scheduled jobs resemble persistence.", "tuning", "", "rule:cron", "noise", "rule"),
	fq("noise-container-exec", "Container exec volume", "Debug sessions inflate this rule.", "tuning", "", "rule:container_exec", "noise", "rule"),
	fq("noise-root-container", "Root container volume", "Base images running as root.", "tuning", "", "rule:root_container", "noise", "rule"),
	fq("noise-info", "Informational sweep", "Informational findings that may be candidates for suppression.", "tuning", "", "severity:info", "noise", "tuning"),
	fq("noise-custom-low", "Custom rules at low severity", "Check custom rules that rarely matter.", "tuning", "", "rule:custom- severity:low", "noise", "custom"),
	fq("noise-ioc-low", "Low severity IOC hits", "Weak intel matches worth reviewing for retirement.", "tuning", "", "rule:ioc- severity:low", "noise", "intel"),

	// ---- Host views ----
	fq("host-web", "Web tier findings", "Findings on hosts with web in their name.", "triage", "", "host:web", "host", "tier"),
	fq("host-db", "Database tier findings", "Findings on hosts with db in their name.", "triage", "", "host:db", "host", "tier"),
	fq("host-prod", "Production findings", "Findings on hosts with prod in their name.", "triage", "", "host:prod", "host", "environment"),
	fq("host-prod-critical", "Production critical", "Critical findings on production hosts.", "triage", "", "host:prod severity:critical", "host", "severity"),
	fq("host-prod-high", "Production high", "High findings on production hosts.", "triage", "", "host:prod severity:high", "host", "severity"),
	fq("host-staging", "Staging findings", "Findings on staging hosts.", "triage", "", "host:staging", "host", "environment"),
	fq("host-k8s-node", "Kubernetes node findings", "Findings on hosts with node in their name.", "triage", "", "host:node", "host", "kubernetes"),
	fq("host-bastion", "Bastion findings", "Findings on bastion or jump hosts.", "lateral-movement", "", "host:bastion", "host", "ssh"),
	fq("host-ci", "CI runner findings", "Findings on hosts with ci in their name.", "triage", "", "host:ci", "host", "build"),
	lq("host-new-console", "Console: new detections by host", "Detections still new; sort by host for newly seen machines.", "triage", "", LangConsole, "new", "host", "console"),
}

func libraryTactics() []string {
	set := map[string]bool{}
	for _, q := range queryLibrary {
		set[q.Tactic] = true
	}
	out := []string{}
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func filterLibrary(tactic, tag, q string) []LibraryQuery {
	tactic, tag, q = strings.ToLower(strings.TrimSpace(tactic)), strings.ToLower(strings.TrimSpace(tag)), strings.ToLower(strings.TrimSpace(q))
	out := []LibraryQuery{}
	for _, e := range queryLibrary {
		if tactic != "" && e.Tactic != tactic {
			continue
		}
		if tag != "" {
			found := false
			for _, t := range e.Tags {
				if t == tag {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(e.ID+" "+e.Name+" "+e.Description+" "+e.Query+" "+strings.Join(e.Tags, " ")), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// librarySaveForm maps a library entry to what the saved-search path stores.
// The console applies a saved detections search as a plain substring filter,
// so a single-value fql query is saved as that value; anything richer is
// stored under scope "findings" verbatim.
func librarySaveForm(e LibraryQuery) (scope, query string) {
	if e.Language == LangConsole {
		return "detections", e.Query
	}
	if e.Language == LangFQL {
		f := parseHuntQuery(e.Query)
		if len(f) == 1 {
			for _, k := range []string{"rule", "severity", "host"} {
				if v, ok := f[k]; ok {
					return "detections", v
				}
			}
		}
	}
	return "findings", e.Query
}

func findLibraryQuery(id string) (LibraryQuery, bool) {
	for _, e := range queryLibrary {
		if e.ID == id {
			return e, true
		}
	}
	return LibraryQuery{}, false
}

// RegisterQueryLibrary wires the read-only query library and its save action.
func RegisterQueryLibrary(mux *http.ServeMux, token string, ws *Workspace) {
	mux.HandleFunc("GET /v1/queries/library", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		v := r.URL.Query()
		out := filterLibrary(v.Get("tactic"), v.Get("tag"), v.Get("q"))
		wsJSON(w, 200, map[string]any{"queries": out, "count": len(out), "tactics": libraryTactics()})
	})
	mux.HandleFunc("GET /v1/queries/library/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		e, ok := findLibraryQuery(r.PathValue("id"))
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		wsJSON(w, 200, e)
	})
	mux.HandleFunc("POST /v1/queries/library/{id}/save", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		e, found := findLibraryQuery(r.PathValue("id"))
		if !found {
			http.Error(w, "not found", 404)
			return
		}
		scope, query := librarySaveForm(e)
		in := SavedSearch{ID: newWSID("ss-"), Name: cleanText(e.Name, false), Scope: scope, Query: cleanText(query, false), Author: wsActor(admin), Created: time.Now().UTC()}
		ws.mu.Lock()
		defer ws.mu.Unlock()
		if len(ws.data.Searches) >= maxSavedSearches {
			http.Error(w, "too many saved searches", 400)
			return
		}
		ws.data.Searches = append(ws.data.Searches, in)
		ws.appendJournalLocked(in.Author, "saved_search.create", in.ID+" "+in.Name)
		if err := ws.saveLocked(); err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		wsJSON(w, 201, in)
	})
}
