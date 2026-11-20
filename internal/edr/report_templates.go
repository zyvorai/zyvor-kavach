package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Report templates render markdown from existing in-process data. They are
// read-only: no template triggers any action on a host.

type reportSection struct {
	Heading string `json:"heading"`
	Source  string `json:"source"` // findings, severities, rules, hosts, fleet, vulns, overwatch, modules, manual
	Prompt  string `json:"prompt"`
}

type ReportTemplate struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Audience string          `json:"audience"`
	Summary  string          `json:"summary"`
	Sections []reportSection `json:"sections,omitempty"`
}

func sec(h, src, prompt string) reportSection { return reportSection{h, src, prompt} }

func rt(id, title, aud, sum string, s ...reportSection) ReportTemplate {
	return ReportTemplate{ID: id, Title: title, Audience: aud, Summary: sum, Sections: s}
}

func complianceTpl(id, fw string) ReportTemplate {
	return rt("compliance-"+id, fw+" compliance evidence", "auditor", "Observation evidence relevant to "+fw+" monitoring and incident controls.",
		sec("Monitoring coverage", "fleet", "Hosts reporting telemetry demonstrate continuous monitoring."),
		sec("Detection activity", "severities", "Detections by severity in the reporting window."),
		sec("Vulnerability posture", "vulns", "Open exposure relevant to vulnerability management controls."),
		sec("Control mapping notes", "manual", "Map each item above to the "+fw+" control identifiers your assessor uses."))
}

func ReportTemplates() []ReportTemplate {
	return []ReportTemplate{
		rt("executive-weekly", "Executive weekly summary", "executive", "One page view of risk, detections and fleet coverage.",
			sec("Headline numbers", "findings", ""), sec("Severity mix", "severities", ""), sec("Fleet coverage", "fleet", ""), sec("Decisions needed", "manual", "List decisions or budget asks for leadership.")),
		rt("soc-handover", "SOC shift handover", "soc", "State of the queue for the next shift.",
			sec("Open detections", "findings", ""), sec("Noisiest rules", "rules", ""), sec("Open OverWatch alerts", "overwatch", ""), sec("Carry-over actions", "manual", "Work in progress and who holds it.")),
		rt("vuln-exposure", "Vulnerability exposure", "vuln-mgmt", "Known CVEs on the fleet.",
			sec("Exposure", "vulns", ""), sec("Affected hosts", "hosts", ""), sec("Remediation owners", "manual", "Assign owners and dates.")),
		complianceTpl("iso27001", "ISO 27001"),
		complianceTpl("soc2", "SOC 2"),
		complianceTpl("pci-dss", "PCI DSS"),
		complianceTpl("hipaa", "HIPAA"),
		complianceTpl("nist-csf", "NIST CSF"),
		complianceTpl("dpdp", "India DPDP Act"),
		complianceTpl("rbi", "RBI cyber resilience"),
		complianceTpl("gdpr", "GDPR"),
		complianceTpl("cis", "CIS Controls"),
		rt("certin-incident", "CERT-In incident report skeleton", "regulator", "Skeleton for a CERT-In incident notification; fill manual fields before sending.",
			sec("Detections in window", "findings", ""), sec("Affected hosts", "hosts", ""), sec("Indicators and rules", "rules", ""),
			sec("Incident details", "manual", "Date and time of detection, type of incident, affected systems, impact."),
			sec("Actions taken by owners", "manual", "Record actions the system owners performed; Kavach itself takes none.")),
		rt("ransomware-readiness", "Ransomware readiness", "ciso", "Preparedness view for ransomware scenarios.",
			sec("Recent high severity detections", "severities", ""), sec("Monitored hosts", "fleet", ""), sec("Exposure", "vulns", ""),
			sec("Backup and recovery evidence", "manual", "Attach last restore test results.")),
		rt("fleet-health", "Fleet health", "ops", "Agent status across hosts.", sec("Agent status", "fleet", ""), sec("Platform modules", "modules", "")),
		rt("board-summary", "Board summary", "board", "Plain-language risk statement.",
			sec("Risk snapshot", "severities", ""), sec("Coverage", "fleet", ""), sec("Narrative", "manual", "Two paragraphs on trend and material risks.")),
		rt("monthly-ciso", "Monthly CISO report", "ciso", "Month view for the security leader.",
			sec("Totals", "findings", ""), sec("Top rules", "rules", ""), sec("Exposure", "vulns", ""), sec("Program notes", "manual", "")),
		rt("daily-brief", "Daily detection brief", "soc", "What fired today.", sec("Detections", "findings", ""), sec("Top rules", "rules", "")),
		rt("top-hosts", "Noisiest hosts", "soc", "Hosts ranked by finding count.", sec("Hosts", "hosts", "")),
		rt("top-rules", "Detection rule review", "detection-eng", "Rule frequency for tuning.", sec("Rules", "rules", ""), sec("Tuning decisions", "manual", "")),
		rt("overwatch-digest", "OverWatch digest", "soc", "Managed hunt alert state.", sec("Alerts", "overwatch", "")),
		rt("kev-exposure", "Known exploited exposure", "vuln-mgmt", "CVEs flagged as exploited in the wild.", sec("Exploited CVEs", "vulns", ""), sec("Hosts", "hosts", "")),
		rt("incident-postmortem", "Incident post-mortem", "ir", "Structure for a closed incident.",
			sec("Related detections", "findings", ""), sec("Timeline", "manual", ""), sec("Root cause", "manual", ""), sec("Follow-ups", "manual", "")),
		rt("audit-readiness", "Audit readiness checklist", "auditor", "Evidence index before an audit.", sec("Coverage", "fleet", ""), sec("Modules", "modules", ""), sec("Gaps", "manual", "")),
		rt("insider-risk", "Insider risk review", "hr-legal", "Behavioural detections for review.", sec("Detections", "findings", ""), sec("Context", "manual", "Add HR-approved context only.")),
		rt("identity-review", "Identity activity review", "iam", "Authentication related detections.", sec("Detections", "findings", ""), sec("Rules", "rules", ""), sec("Access owner notes", "manual", "")),
		rt("cloud-container", "Cloud and container review", "platform", "Workload related detections.", sec("Detections", "findings", ""), sec("Hosts", "hosts", ""), sec("Platform notes", "manual", "")),
		rt("ot-review", "OT and plant review", "ot", "Operational technology view.", sec("Detections", "findings", ""), sec("Fleet", "fleet", ""), sec("Plant operations notes", "manual", "")),
		rt("finance-review", "Financial services review", "risk", "Payments and banking view.", sec("Detections", "findings", ""), sec("Exposure", "vulns", ""), sec("Regulatory notes", "manual", "")),
		rt("quarterly-trend", "Quarterly trend", "executive", "Quarter on quarter framing.", sec("Totals", "findings", ""), sec("Severity mix", "severities", ""), sec("Comparison to last quarter", "manual", "")),
		rt("third-party", "Third-party assurance pack", "customer", "Evidence for customer security reviews.", sec("Coverage", "fleet", ""), sec("Modules", "modules", ""), sec("Statements", "manual", "")),
		rt("tuning-digest", "Detection tuning digest", "detection-eng", "Candidates for rule tuning.", sec("Rules", "rules", ""), sec("Severity mix", "severities", ""), sec("Decisions", "manual", "")),
		rt("customer-notice", "Customer notification draft", "legal", "Draft inputs for notice; legal must review.", sec("Facts from detections", "findings", ""), sec("Notice text", "manual", "")),
	}
}

type reportData struct {
	ok       bool
	findings []Finding
	agents   []AgentStatus
	haveFlt  bool
	vulns    []Vulnerability
	owOpen   int
}

func gatherReportData(store *Store, registry *CredentialRegistry) reportData {
	var d reportData
	if store != nil {
		d.ok = true
		d.findings = store.List()
	}
	if registry != nil {
		d.haveFlt = true
		d.agents = registry.Status(time.Now(), 90*time.Second)
	}
	vulnMu.Lock()
	d.vulns = append([]Vulnerability{}, vulns...)
	vulnMu.Unlock()
	owMu.Lock()
	for _, a := range owAlerts {
		if a.Status == "open" {
			d.owOpen++
		}
	}
	owMu.Unlock()
	return d
}

func counted(m map[string]int, limit int) []string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var out []string
	for i, e := range l {
		if i >= limit {
			break
		}
		out = append(out, fmt.Sprintf("- %s: %d", e.k, e.v))
	}
	return out
}

func renderSection(s reportSection, d reportData) string {
	noData := "_No data available for this section._"
	var lines []string
	switch s.Source {
	case "findings":
		if !d.ok {
			return noData
		}
		lines = []string{fmt.Sprintf("- Total detections: %d", len(d.findings))}
	case "severities", "rules", "hosts":
		if !d.ok || len(d.findings) == 0 {
			return noData
		}
		m := map[string]int{}
		for _, f := range d.findings {
			switch s.Source {
			case "severities":
				m[f.Severity]++
			case "rules":
				m[f.Rule]++
			default:
				m[f.Host]++
			}
		}
		lines = counted(m, 10)
	case "fleet":
		if !d.haveFlt || len(d.agents) == 0 {
			return noData
		}
		m := map[string]int{}
		for _, a := range d.agents {
			m[a.State]++
		}
		lines = append([]string{fmt.Sprintf("- Agents: %d", len(d.agents))}, counted(m, 10)...)
	case "vulns":
		if len(d.vulns) == 0 {
			return noData
		}
		m := map[string]int{}
		kev := 0
		for _, v := range d.vulns {
			m[v.Severity]++
			if v.Exploited {
				kev++
			}
		}
		lines = append([]string{fmt.Sprintf("- CVEs: %d (exploited in the wild: %d)", len(d.vulns), kev)}, counted(m, 10)...)
	case "overwatch":
		lines = []string{fmt.Sprintf("- Open alerts: %d", d.owOpen)}
	case "modules":
		lines = []string{fmt.Sprintf("- Platform modules: %d", len(KavachModules()))}
	default:
		p := s.Prompt
		if p == "" {
			p = "Analyst to complete."
		}
		return "_Manual section._ " + p
	}
	return strings.Join(lines, "\n")
}

// RenderReportTemplate renders a template to markdown.
func RenderReportTemplate(t ReportTemplate, store *Store, registry *CredentialRegistry) string {
	d := gatherReportData(store, registry)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", t.Title)
	fmt.Fprintf(&b, "Audience: %s  \nGenerated: %s\n\n%s\n\n", t.Audience, time.Now().UTC().Format(time.RFC3339), t.Summary)
	for _, s := range t.Sections {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", s.Heading, renderSection(s, d))
	}
	b.WriteString("_Kavach is observation-only; this report records what was seen and requests nothing automatically._\n")
	return b.String()
}

func RegisterReportTemplates(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/reports/templates", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out := ReportTemplates()
		for i := range out {
			out[i].Sections = nil
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/reports/templates/{id}/render", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		for _, t := range ReportTemplates() {
			if t.ID == id {
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				_, _ = w.Write([]byte(RenderReportTemplate(t, store, registry)))
				return
			}
		}
		http.Error(w, "template not found", 404)
	})
}
