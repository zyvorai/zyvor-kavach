// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const exportMaxRows = 50000

// csvSafe neutralises spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func filterFindings(r *http.Request, all []Finding) ([]Finding, error) {
	q := r.URL.Query()
	sev, host, rule := strings.ToLower(q.Get("severity")), q.Get("host"), q.Get("rule")
	var since time.Time
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("since must be RFC3339")
		}
		since = t
	}
	out := make([]Finding, 0, len(all))
	for _, f := range all {
		if sev != "" && strings.ToLower(f.Severity) != sev {
			continue
		}
		if host != "" && f.Host != host {
			continue
		}
		if rule != "" && f.Rule != rule {
			continue
		}
		if !since.IsZero() && f.Time.Before(since) {
			continue
		}
		out = append(out, f)
		if len(out) >= exportMaxRows {
			break
		}
	}
	return out, nil
}

func exportFindings(w http.ResponseWriter, r *http.Request, store *Store) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "csv" && format != "json" && format != "ndjson" {
		http.Error(w, "format must be csv, json or ndjson", 400)
		return
	}
	fs, err := filterFindings(r, store.List())
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	ct := map[string]string{"csv": "text/csv; charset=utf-8", "json": "application/json", "ndjson": "application/x-ndjson"}[format]
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="kavach-findings.`+format+`"`)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	switch format {
	case "csv":
		cw := csv.NewWriter(bw)
		_ = cw.Write([]string{"id", "time", "host", "pid", "rule", "severity", "description", "executable", "command", "destination", "tags"})
		for _, f := range fs {
			_ = cw.Write([]string{csvSafe(f.ID), f.Time.UTC().Format(time.RFC3339), csvSafe(f.Host), strconv.Itoa(f.PID),
				csvSafe(f.Rule), csvSafe(f.Severity), csvSafe(f.Description), csvSafe(f.Evidence.Executable),
				csvSafe(f.Evidence.Command), csvSafe(f.Destination), csvSafe(strings.Join(f.Tags, ";"))})
		}
		cw.Flush()
	case "ndjson":
		enc := json.NewEncoder(bw)
		for _, f := range fs {
			_ = enc.Encode(f)
		}
	default:
		_, _ = bw.WriteString("[")
		for i, f := range fs {
			if i > 0 {
				_, _ = bw.WriteString(",")
			}
			b, _ := json.Marshal(f)
			_, _ = bw.Write(b)
		}
		_, _ = bw.WriteString("]")
	}
}

type hostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

func buildReport(store *Store, registry *CredentialRegistry) map[string]any {
	fs := store.List()
	sev := map[string]int{}
	hosts := map[string]int{}
	for _, f := range fs {
		sev[strings.ToLower(f.Severity)]++
		hosts[f.Host]++
	}
	top := make([]hostCount, 0, len(hosts))
	for h, c := range hosts {
		top = append(top, hostCount{h, c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Host < top[j].Host
	})
	if len(top) > 10 {
		top = top[:10]
	}
	return map[string]any{
		"generated":  time.Now().UTC().Format(time.RFC3339),
		"mode":       "observe-only",
		"total":      len(fs),
		"severity":   sev,
		"top_hosts":  top,
		"attack":     BuildATTACKMatrix(fs),
		"compliance": BuildComplianceScore(store, registry),
	}
}

func renderReportHTML(rep map[string]any) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kavach Executive Posture Report</title><style>
body{font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#111;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{margin-bottom:0}h2{border-bottom:1px solid #ccc;padding-bottom:.2rem;margin-top:2rem}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #ddd}
.grade{font-size:3rem;font-weight:700}.muted{color:#666}
@media print{body{max-width:none;margin:0}h2{page-break-after:avoid}table{page-break-inside:avoid}}
</style></head><body>`)
	b.WriteString("<h1>Executive Posture Report</h1><p class=\"muted\">Generated " + e(fmt.Sprint(rep["generated"])) + " &middot; observe-only</p>")
	b.WriteString("<h2>Findings</h2><p>Total: <strong>" + strconv.Itoa(rep["total"].(int)) + "</strong></p><table><tr><th>Severity</th><th>Count</th></tr>")
	sev := rep["severity"].(map[string]int)
	keys := make([]string, 0, len(sev))
	for k := range sev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("<tr><td>" + e(k) + "</td><td>" + strconv.Itoa(sev[k]) + "</td></tr>")
	}
	b.WriteString("</table><h2>Top hosts</h2><table><tr><th>Host</th><th>Findings</th></tr>")
	for _, h := range rep["top_hosts"].([]hostCount) {
		b.WriteString("<tr><td>" + e(h.Host) + "</td><td>" + strconv.Itoa(h.Count) + "</td></tr>")
	}
	comp := rep["compliance"].(map[string]any)
	b.WriteString("</table><h2>Compliance</h2><p><span class=\"grade\">" + e(fmt.Sprint(comp["grade"])) + "</span> overall " + e(fmt.Sprint(comp["overall"])) + "/100</p><table><tr><th>Framework</th><th>Score</th><th>Grade</th><th>Failing</th></tr>")
	craw, _ := json.Marshal(comp)
	var cm struct {
		Frameworks []map[string]any `json:"frameworks"`
	}
	_ = json.Unmarshal(craw, &cm)
	for _, f := range cm.Frameworks {
		b.WriteString("<tr><td>" + e(fmt.Sprint(f["framework"])) + "</td><td>" + e(fmt.Sprint(f["score"])) + "</td><td>" + e(fmt.Sprint(f["grade"])) + "</td><td>" + e(fmt.Sprint(f["failing"])) + "</td></tr>")
	}
	b.WriteString("</table><h2>MITRE ATT&amp;CK</h2><table><tr><th>Tactic</th><th>Covered</th><th>Hits</th><th>Techniques</th></tr>")
	// Round-trip through JSON so we don't depend on the map's concrete types.
	raw, _ := json.Marshal(rep["attack"])
	var am struct {
		Tactics []ATTACKTactic `json:"tactics"`
	}
	_ = json.Unmarshal(raw, &am)
	for _, t := range am.Tactics {
		names := make([]string, 0, len(t.Techniques))
		for _, x := range t.Techniques {
			names = append(names, x.ID+" "+x.Name)
		}
		cov := "no"
		if t.Covered {
			cov = "yes"
		}
		b.WriteString("<tr><td>" + e(t.Tactic) + "</td><td>" + cov + "</td><td>" + strconv.Itoa(t.Hits) + "</td><td>" + e(strings.Join(names, ", ")) + "</td></tr>")
	}
	b.WriteString("</table></body></html>")
	return b.String()
}

// RegisterExport wires /v1/export/findings and /v1/export/report. Read-only.
func RegisterExport(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/export/findings", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		exportFindings(w, r, store)
	})
	mux.HandleFunc("GET /v1/export/report", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rep := buildReport(store, registry)
		switch r.URL.Query().Get("format") {
		case "", "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
			_, _ = w.Write([]byte(renderReportHTML(rep)))
		case "json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rep)
		default:
			http.Error(w, "format must be html or json", 400)
		}
	})
}
