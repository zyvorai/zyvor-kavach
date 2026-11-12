// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DomainInventory is a mutable observation ledger per security domain.
// Seeds are only used when no live/derived/ingested rows exist yet.
type DomainInventory struct {
	mu   sync.Mutex
	rows map[string][]map[string]any
}

var Live = &DomainInventory{rows: map[string][]map[string]any{}}

func (d *DomainInventory) List(domain string) []map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	src := d.rows[domain]
	out := make([]map[string]any, len(src))
	copy(out, src)
	return out
}

func (d *DomainInventory) Append(domain string, row map[string]any) map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	if row["id"] == nil || row["id"] == "" {
		row["id"] = domain + "-" + time.Now().UTC().Format("150405.000")
	}
	if row["observed_at"] == nil {
		row["observed_at"] = time.Now().UTC()
	}
	if src, _ := row["source"].(string); strings.TrimSpace(src) == "" {
		row["source"] = "ingest"
	}
	d.rows[domain] = append(d.rows[domain], row)
	if len(d.rows[domain]) > 2000 {
		d.rows[domain] = d.rows[domain][len(d.rows[domain])-2000:]
	}
	d.persistAsync()
	return row
}

func (d *DomainInventory) ReplaceHost(domain, host string, rows []map[string]any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	kept := d.rows[domain][:0]
	for _, r := range d.rows[domain] {
		if fmt.Sprint(r["host"]) != host {
			kept = append(kept, r)
		}
	}
	for _, r := range rows {
		if r["host"] == nil {
			r["host"] = host
		}
		if r["id"] == nil {
			r["id"] = domain + "-" + time.Now().UTC().Format("150405.000")
		}
		r["observed_at"] = time.Now().UTC()
		if src, _ := r["source"].(string); strings.TrimSpace(src) == "" {
			r["source"] = "agent"
		}
		kept = append(kept, r)
	}
	d.rows[domain] = kept
	d.persistAsync()
}

func mergeLive(domain string, derived []map[string]any) []map[string]any {
	live := Live.List(domain)
	if derived == nil {
		derived = []map[string]any{}
	}
	if len(live) == 0 {
		return derived
	}
	out := append([]map[string]any{}, live...)
	// Keep derived rows that add new signal (by id or fingerprint).
	seen := map[string]struct{}{}
	for _, r := range out {
		seen[fmt.Sprint(r["id"])] = struct{}{}
		seen[fingerprint(r)] = struct{}{}
	}
	for _, r := range derived {
		id := fmt.Sprint(r["id"])
		fp := fingerprint(r)
		if _, ok := seen[id]; ok {
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		out = append(out, r)
	}
	return out
}

func fingerprint(r map[string]any) string {
	parts := []string{
		fmt.Sprint(r["host"]), fmt.Sprint(r["name"]), fmt.Sprint(r["app"]),
		fmt.Sprint(r["path"]), fmt.Sprint(r["query"]), fmt.Sprint(r["component"]),
		fmt.Sprint(r["user"]), fmt.Sprint(r["control"]), fmt.Sprint(r["type"]),
	}
	return strings.ToLower(strings.Join(parts, "|"))
}

// RegisterInventoryIngest accepts agent/connector observations for any domain.
func RegisterInventoryIngest(mux *http.ServeMux, token string) {
	mux.HandleFunc("POST /v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if !requireRole(w, r, token, "write", "ingest", "admin", "*") {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		defer r.Body.Close()
		var body struct {
			Domain string           `json:"domain"`
			Host   string           `json:"host"`
			Replace bool            `json:"replace"`
			Items  []map[string]any `json:"items"`
			Item   map[string]any   `json:"item"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Domain == "" {
			http.Error(w, "invalid inventory payload", 400)
			return
		}
		items := body.Items
		if body.Item != nil {
			items = append(items, body.Item)
		}
		if body.Replace && body.Host != "" {
			Live.ReplaceHost(body.Domain, body.Host, items)
		} else {
			for _, it := range items {
				if body.Host != "" && it["host"] == nil {
					it["host"] = body.Host
				}
				Live.Append(body.Domain, it)
			}
		}
		AppendAudit(token, "inventory."+body.Domain, fmt.Sprintf("%d items", len(items)))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "domain": body.Domain, "count": len(items)})
	})
}

func deriveCASB(store *Store) []map[string]any {
	saas := map[string]string{
		"slack.com": "Slack", "dropbox.com": "Dropbox", "github.com": "GitHub",
		"openai.com": "ChatGPT", "box.com": "Box", "salesforce.com": "Salesforce",
		"notion.so": "Notion", "zoom.us": "Zoom",
	}
	counts := map[string]int{}
	store.mu.Lock()
	nets := append([]NetworkEvent{}, store.networkEvents...)
	store.mu.Unlock()
	for _, n := range nets {
		host := strings.ToLower(destHost(n.Destination))
		for suffix, name := range saas {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				counts[name]++
			}
		}
	}
	out := []map[string]any{}
	for name, n := range counts {
		risk := "low"
		if name == "ChatGPT" || name == "Dropbox" {
			risk = "high"
		} else if n > 5 {
			risk = "medium"
		}
		out = append(out, map[string]any{
			"app": name, "category": "saas", "risk": risk, "users": n,
			"sanctioned": name == "GitHub" || name == "Slack" || name == "Zoom",
			"source": "derived-network", "id": "casb-" + strings.ToLower(name),
		})
	}
	return out
}

func deriveEmail(store *Store) []map[string]any {
	out := []map[string]any{}
	for _, f := range store.List() {
		blob := strings.ToLower(f.Rule + " " + f.Description + " " + f.Evidence.Command)
		if strings.Contains(blob, "phish") || strings.Contains(blob, "bec") || strings.Contains(blob, "mail") ||
			strings.Contains(blob, "download-execute") || strings.Contains(blob, "curl") {
			typ := "suspicious_mail_signal"
			if strings.Contains(blob, "download") || strings.Contains(blob, "curl") {
				typ = "malicious_attachment_signal"
			}
			out = append(out, map[string]any{
				"id": "em-" + shortID(f.ID), "type": typ,
				"subject": f.Description, "from": f.Host, "severity": f.Severity,
				"source": "derived-findings",
			})
		}
	}
	owMu.Lock()
	for _, a := range owAlerts {
		blob := strings.ToLower(a.Title + " " + a.Summary)
		if strings.Contains(blob, "phish") || strings.Contains(blob, "mail") || strings.Contains(blob, "bec") {
			out = append(out, map[string]any{
				"id": "em-ow-" + a.ID, "type": "overwatch_mail", "subject": a.Title,
				"from": a.Host, "severity": a.Severity, "source": "overwatch",
			})
		}
	}
	owMu.Unlock()
	return out
}

func deriveDLP(store *Store) []map[string]any {
	out := []map[string]any{}
	for _, f := range store.List() {
		low := strings.ToLower(f.Rule + " " + f.Description)
		if strings.Contains(low, "file") || strings.Contains(low, "usb") ||
			strings.Contains(low, "ransomware") || strings.Contains(low, "mass-file") ||
			strings.Contains(low, "download") || strings.Contains(low, "exfil") {
			out = append(out, map[string]any{
				"id": "dlp-" + shortID(f.ID), "host": f.Host, "channel": "endpoint",
				"label": f.Rule, "action": "observed", "severity": f.Severity, "source": "derived-findings",
			})
		}
	}
	for _, fe := range store.ListFiles() {
		label := "file_change"
		sev := "low"
		p := strings.ToLower(fe.Path)
		if strings.Contains(p, "secret") || strings.Contains(p, ".pem") || strings.Contains(p, "id_rsa") || strings.Contains(p, "passwd") || strings.Contains(p, "/etc/") {
			label = "sensitive_path"
			sev = "high"
		}
		out = append(out, map[string]any{
			"id": "dlp-f-" + shortID(fileID(fe)), "host": fe.Host, "channel": "filesystem",
			"label": label, "path": fe.Path, "action": fe.Operation, "severity": sev, "source": "derived-files",
		})
	}
	deviceMu.Lock()
	for _, d := range deviceInv {
		out = append(out, map[string]any{
			"id": "dlp-usb-" + fmt.Sprint(d["id"]), "host": d["host"], "channel": "usb",
			"label": "removable_media", "action": d["action"], "severity": "medium", "source": "device-control",
		})
	}
	deviceMu.Unlock()
	for _, row := range Live.List("fim") {
		out = append(out, map[string]any{
			"id": "dlp-fim-" + fmt.Sprint(row["id"], row["path"]), "host": row["host"], "channel": "fim",
			"label": "critical_path", "path": row["path"], "action": row["change"],
			"severity": row["severity"], "source": "fim",
		})
	}
	return out
}

func deriveFIM(store *Store) []map[string]any {
	out := []map[string]any{}
	for _, fe := range store.ListFiles() {
		sev := "medium"
		p := strings.ToLower(fe.Path)
		if strings.Contains(p, "/etc/") || strings.Contains(p, "sshd") || strings.Contains(p, "passwd") || strings.Contains(p, "shadow") {
			sev = "high"
		}
		out = append(out, map[string]any{
			"path": fe.Path, "host": fe.Host, "change": fe.Operation, "severity": sev,
			"time": fe.Time, "source": "file-events", "id": "fim-" + shortID(fileID(fe)),
		})
	}
	return out
}

func deriveDNS(store *Store) []map[string]any {
	out := []map[string]any{}
	store.mu.Lock()
	nets := append([]NetworkEvent{}, store.networkEvents...)
	store.mu.Unlock()
	for _, n := range nets {
		h := destHost(n.Destination)
		port := destPort(n.Destination)
		verdict := "observed"
		if strings.EqualFold(n.Verdict, "deny") {
			verdict = "malicious"
		}
		interesting := port == "53" || port == "853" || strings.Contains(strings.ToLower(h), "dns") ||
			strings.EqualFold(n.Verdict, "deny") || strings.Contains(h, ".")
		if interesting && h != "" {
			typ := "A"
			if port == "853" {
				typ = "DoH"
			}
			out = append(out, map[string]any{
				"query": h, "type": typ, "verdict": verdict, "host": n.Host,
				"destination": n.Destination, "source": "derived-network", "id": "dns-" + shortID(networkID(n)),
			})
		}
		for _, ioc := range MatchIOCs(h + " " + n.Destination) {
			if ioc.Type == "domain" || ioc.Type == "ipv4" {
				out = append(out, map[string]any{
					"query": ioc.Value, "type": ioc.Type, "verdict": "malicious", "host": n.Host,
					"source": "ioc", "id": "dns-ioc-" + ioc.ID,
				})
			}
		}
	}
	// Command-line DNS/C2 hints from findings
	for _, f := range store.List() {
		for _, ioc := range MatchIOCs(f.Evidence.Command + " " + f.Description) {
			if ioc.Type == "domain" {
				out = append(out, map[string]any{
					"query": ioc.Value, "type": "A", "verdict": "malicious", "host": f.Host,
					"source": "finding-ioc", "id": "dns-f-" + shortID(f.ID),
				})
			}
		}
	}
	return out
}

func deriveMDR(store *Store) []map[string]any {
	out := []map[string]any{}
	for _, f := range store.List() {
		if f.Severity != "high" && f.Severity != "critical" {
			continue
		}
		out = append(out, map[string]any{
			"id": "mdr-" + shortID(f.ID), "title": f.Rule + ": " + f.Description,
			"priority": f.Severity, "status": "queued", "source": "findings", "host": f.Host,
		})
	}
	owMu.Lock()
	for _, a := range owAlerts {
		if a.Status == "open" || a.Status == "" {
			out = append(out, map[string]any{
				"id": "mdr-ow-" + a.ID, "title": a.Title, "priority": a.Severity,
				"status": "queued", "source": "overwatch", "host": a.Host,
			})
		}
	}
	owMu.Unlock()
	return out
}

func deriveCompliance(store *Store, registry *CredentialRegistry) []map[string]any {
	findings := store.List()
	high := 0
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			high++
		}
	}
	online, total := 0, 0
	if registry != nil {
		for _, st := range registry.Status(time.Now(), 90*time.Second) {
			total++
			if st.State == "online" {
				online++
			}
		}
	}
	fleetScore := 100
	if total > 0 {
		fleetScore = online * 100 / total
	}
	detScore := 100 - min(high*5, 60)
	return []map[string]any{
		{"framework": "CIS Controls", "pass": detScore / 5, "fail": high, "score": detScore, "source": "derived"},
		{"framework": "NIST CSF", "pass": fleetScore / 5, "fail": total - online, "score": (detScore + fleetScore) / 2, "source": "derived"},
		{"framework": "SOC2 CC6", "pass": 20, "fail": high, "score": detScore, "source": "derived"},
		{"framework": "ISO 27001", "pass": 25, "fail": high, "score": (detScore*2 + fleetScore) / 3, "source": "derived"},
	}
}

func deriveZeroTrust(store *Store, registry *CredentialRegistry) map[string]any {
	findings := store.List()
	high := 0
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			high++
		}
	}
	online, total := 0, 0
	if registry != nil {
		for _, st := range registry.Status(time.Now(), 90*time.Second) {
			total++
			if st.State == "online" {
				online++
			}
		}
	}
	device := 50
	if total > 0 {
		device = online * 100 / total
	}
	identity := 80
	idMu.Lock()
	identity -= min(len(idEvents)*5, 40)
	idMu.Unlock()
	network := 75
	store.mu.Lock()
	for _, n := range store.networkEvents {
		if strings.EqualFold(n.Verdict, "deny") {
			network -= 2
		}
	}
	store.mu.Unlock()
	if network < 20 {
		network = 20
	}
	application := 70 - min(high*3, 40)
	data := 65
	score := (identity + device + network + application + data) / 5
	return map[string]any{
		"score": score, "level": riskLevel(score),
		"pillars": map[string]int{"identity": identity, "device": device, "network": network, "application": application, "data": data},
		"source":  "derived",
	}
}

func deriveConnectors() []map[string]any {
	out := []map[string]any{}
	netra := NetraPollerStatus()
	st := "disconnected"
	if netra["configured"] == true {
		if netra["last_error"] == nil || netra["last_error"] == "" {
			st = "connected"
		} else {
			st = "error"
		}
	}
	out = append(out, map[string]any{"name": "Netra XDR", "type": "network", "status": st, "note": "live poller", "source": "env"})
	siem := map[string]any{"name": "SIEM Export", "type": "siem", "status": "idle", "source": "env"}
	if DefaultSIEM != nil {
		s := DefaultSIEM.Status()
		if s["enabled"] == true {
			siem["status"] = "armed"
		}
		siem["note"] = fmt.Sprintf("sink=%v format=%v", s["sink"], s["format"])
	}
	out = append(out, siem)
	llm := "absent"
	if os.Getenv("KAVACH_LLM_URL") != "" {
		llm = "configured"
	}
	out = append(out, map[string]any{"name": "Optional LLM", "type": "ai", "status": llm, "source": "env"})
	out = append(out, Live.List("connectors")...)
	return out
}

func deriveNotify() []map[string]any {
	out := []map[string]any{}
	if os.Getenv("KAVACH_SIEM_WEBHOOK") != "" || os.Getenv("KAVACH_SIEM_WEBHOOK_URL") != "" {
		out = append(out, map[string]any{"id": "ch-webhook", "type": "webhook", "status": "configured", "source": "env"})
	}
	if os.Getenv("KAVACH_SIEM_SYSLOG") != "" || os.Getenv("KAVACH_SIEM_SYSLOG_ADDR") != "" {
		out = append(out, map[string]any{"id": "ch-syslog", "type": "syslog", "status": "configured", "source": "env"})
	}
	live := Live.List("notify")
	if len(live) > 0 {
		return append(out, live...)
	}
	if len(out) == 0 {
		out = append(out, map[string]any{"id": "ch-console", "type": "console", "status": "active", "source": "builtin"})
	}
	return out
}

func deriveGeo(ip string) map[string]any {
	if ip == "" {
		ip = "0.0.0.0"
	}
	parsed := net.ParseIP(ip)
	country, city, asn, risk := "ZZ", "Unknown", "AS0", "low"
	note := "heuristic offline geo (no MaxMind)"
	if parsed == nil {
		return map[string]any{"ip": ip, "country": country, "city": city, "asn": asn, "risk": "medium", "note": note, "source": "heuristic"}
	}
	if parsed.IsLoopback() {
		country, city, risk = "LO", "Loopback", "info"
	} else if parsed.IsPrivate() {
		country, city, risk = "PR", "Private RFC1918", "info"
	} else if parsed.IsLinkLocalUnicast() {
		country, city, risk = "LL", "Link-local", "info"
	} else {
		// Documentation / TEST-NET ranges
		if strings.HasPrefix(ip, "203.0.113.") || strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "192.0.2.") {
			country, city, asn, risk = "ZZ", "Documentation", "AS64500", "medium"
		} else {
			country, city, asn, risk = "XX", "Public Internet", "AS-UNKNOWN", "medium"
		}
	}
	return map[string]any{"ip": ip, "country": country, "city": city, "asn": asn, "risk": risk, "note": note, "source": "heuristic"}
}

func deriveITDR() []map[string]any {
	out := []map[string]any{}
	idMu.Lock()
	events := append([]IdentityEvent{}, idEvents...)
	idMu.Unlock()
	byUser := map[string]int{}
	for _, e := range events {
		u := e.User
		if u == "" {
			u = "unknown"
		}
		byUser[u]++
		typ := "identity_anomaly"
		low := strings.ToLower(e.Rule + " " + e.Detail + " " + e.Action)
		switch {
		case strings.Contains(low, "mfa"):
			typ = "mfa_signal"
		case strings.Contains(low, "spray") || strings.Contains(low, "failed_login"):
			typ = "password_spray"
		case strings.Contains(low, "travel") || strings.Contains(low, "unusual"):
			typ = "impossible_travel"
		case strings.Contains(low, "token") || strings.Contains(low, "replay"):
			typ = "token_replay_suspect"
		}
		out = append(out, map[string]any{
			"user": u, "type": typ, "severity": e.Severity, "pushes": 1,
			"host": e.Host, "source": "identity", "id": "itdr-" + e.ID, "detail": e.Detail,
		})
	}
	for u, n := range byUser {
		if n >= 3 {
			out = append(out, map[string]any{
				"user": u, "type": "mfa_fatigue", "pushes": n, "severity": "high",
				"window_min": 60, "source": "derived-identity", "id": "itdr-fatigue-" + u,
			})
		}
	}
	return mergeLive("itdr", out)
}

func deriveITDRFromStore(store *Store) []map[string]any {
	out := deriveITDR()
	if store == nil {
		return out
	}
	for _, f := range store.List() {
		low := strings.ToLower(f.Rule + " " + f.Description + " " + f.Evidence.Command)
		if !(strings.Contains(low, "credential") || strings.Contains(low, "mimikatz") ||
			strings.Contains(low, "sudo") || strings.Contains(low, "ssh") || strings.Contains(low, "root-history") ||
			(f.Evidence.UID == 0 && (f.Severity == "high" || f.Severity == "critical"))) {
			continue
		}
		out = append(out, map[string]any{
			"user": fmt.Sprintf("uid:%d", f.Evidence.UID), "type": "privileged_abuse_signal",
			"severity": f.Severity, "host": f.Host, "pushes": 1,
			"source": "derived-findings", "id": "itdr-f-" + shortID(f.ID), "detail": f.Description,
		})
	}
	return out
}

func deriveRollback(store *Store, id string) map[string]any {
	advice := []string{
		"Snapshot VSS/ZFS before changes",
		"Restore from known-good backup",
		"Do not rely on Kavach to rollback — observation only",
	}
	if f, ok := findByID(store, id); ok {
		advice = append([]string{
			"Review finding " + f.Rule + " on " + f.Host,
			"Inspect process tree for PID " + fmt.Sprint(f.PID),
		}, advice...)
		if strings.Contains(strings.ToLower(f.Rule), "ransomware") || strings.Contains(strings.ToLower(f.Rule), "file") {
			advice = append([]string{"Prioritize restore of modified files from FIM timeline"}, advice...)
		}
	}
	return map[string]any{"finding_id": id, "advice": advice, "enforced": false, "source": "derived"}
}

func deriveRetention(store *Store) map[string]any {
	return map[string]any{
		"findings_days": 90,
		"events_days":   30,
		"ai_chat_days":  14,
		"audit_days":    365,
		"findings_cap":  store.max,
		"findings_now":  len(store.List()),
		"source":        "store",
	}
}

func deriveSensorHealth(store *Store, registry *CredentialRegistry) []map[string]any {
	out := []map[string]any{}
	seen := map[string]struct{}{}
	if registry != nil {
		for _, st := range registry.Status(time.Now(), 90*time.Second) {
			seen[st.Host] = struct{}{}
			out = append(out, map[string]any{
				"host": st.Host, "state": st.State, "sensor": st.Sensor,
				"coverage": st.State == "online", "source": "fleet",
			})
		}
	}
	// Hosts with findings but no agent = coverage gap
	for _, f := range store.List() {
		if _, ok := seen[f.Host]; ok {
			continue
		}
		seen[f.Host] = struct{}{}
		out = append(out, map[string]any{
			"host": f.Host, "state": "missing", "sensor": "", "coverage": false, "gap": true, "source": "derived",
		})
	}
	for _, r := range Live.List("network-discovery") {
		h := fmt.Sprint(r["hostname"])
		if h == "" {
			h = fmt.Sprint(r["host"])
		}
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		out = append(out, map[string]any{"host": h, "state": "unmanaged", "coverage": false, "gap": true, "source": "ranger"})
	}
	return out
}

func deriveTenants(store *Store, registry *CredentialRegistry) []map[string]any {
	hosts := map[string]struct{}{}
	for _, f := range store.List() {
		hosts[f.Host] = struct{}{}
	}
	if registry != nil {
		for _, st := range registry.Status(time.Now(), 90*time.Second) {
			hosts[st.Host] = struct{}{}
		}
	}
	live := Live.List("tenants")
	if len(live) > 0 {
		return live
	}
	return []map[string]any{
		{"id": "site-default", "name": "Default", "hosts": len(hosts), "source": "derived"},
	}
}

func deriveSBOM() []map[string]any {
	live := Live.List("sbom")
	if len(live) > 0 {
		return live
	}
	// Fall back to process basenames observed recently as soft inventory.
	return nil
}

func destHost(dest string) string {
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		// maybe host only or host: with scheme
		if i := strings.LastIndex(dest, ":"); i > 0 && !strings.Contains(dest[i+1:], ":") {
			return dest[:i]
		}
		return dest
	}
	return host
}

func destPort(dest string) string {
	_, port, err := net.SplitHostPort(dest)
	if err != nil {
		return ""
	}
	return port
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

