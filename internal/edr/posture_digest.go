// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- executive weekly digest (pull-only: JSON, Markdown, printable HTML; never emailed) ----

// ExecDigestFactor is the measured value that backs a statement.
type ExecDigestFactor struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// ExecDigestStatement is one claim. It is only produced when its factors exist.
type ExecDigestStatement struct {
	Text    string             `json:"text"`
	Factors []ExecDigestFactor `json:"factors"`
}

// ExecDigest is the weekly executive summary.
type ExecDigest struct {
	GeneratedAt time.Time             `json:"generated_at"`
	PeriodDays  int                   `json:"period_days"`
	Baseline    *time.Time            `json:"baseline_snapshot_time,omitempty"`
	Statements  []ExecDigestStatement `json:"statements"`
	NotAssessed []string              `json:"not_assessed"`
	Caveats     []string              `json:"caveats"`
	Mode        string                `json:"mode"`
}

var digestCaveats = []string{
	"Observation-only: Kavach reports what it measured and takes no action.",
	"Compliance scores are indicative evidence over observable controls, not an audit opinion or certification.",
	"Every statement lists the measured factors it rests on; where a number could not be measured it is listed under not assessed rather than estimated.",
	"Comparisons use the stored posture snapshots; gaps in history mean Kavach was not running.",
	"Findings counts come from a bounded store and may omit aged-out records.",
}

func fPct(p *float64) string { return strconv.FormatFloat(*p, 'f', 2, 64) + "%" }
func sgn(n int) string {
	if n > 0 {
		return "+" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// buildDigest is a pure function of the two snapshots, the period and the clock.
func buildDigest(cur PostureSnapshot, base *PostureSnapshot, days int, now time.Time) ExecDigest {
	d := ExecDigest{GeneratedAt: now.UTC(), PeriodDays: days, Mode: "observe-only", Statements: []ExecDigestStatement{}, NotAssessed: []string{}, Caveats: digestCaveats}
	if base != nil {
		t := base.Time
		d.Baseline = &t
	} else {
		d.NotAssessed = append(d.NotAssessed, fmt.Sprintf("Change over the last %d days: no stored snapshot that old yet.", days))
	}
	has := func(name string) bool {
		for _, u := range cur.Unavailable {
			if u == name {
				return false
			}
		}
		return true
	}

	if has("compliance_score") && len(cur.FrameworkScores) > 0 {
		txt := fmt.Sprintf("The compliance evidence score is %d (grade %s) across %d frameworks.", cur.ComplianceScore, cur.ComplianceGrade, len(cur.FrameworkScores))
		fac := []ExecDigestFactor{{"overall_score", strconv.Itoa(cur.ComplianceScore), "/v1/compliance/score"}, {"grade", cur.ComplianceGrade, "/v1/compliance/score"}}
		if base != nil {
			txt += fmt.Sprintf(" That is %s points versus the baseline.", sgn(cur.ComplianceScore-base.ComplianceScore))
			fac = append(fac, ExecDigestFactor{"baseline_score", strconv.Itoa(base.ComplianceScore), "posture snapshot " + base.Time.Format(time.RFC3339)})
		}
		d.Statements = append(d.Statements, ExecDigestStatement{txt, fac})
	} else {
		d.NotAssessed = append(d.NotAssessed, "Compliance score: not available.")
	}
	if cur.TacticsTotal > 0 {
		txt := fmt.Sprintf("Detection content covers %d of %d ATT&CK tactics.", cur.TacticsCovered, cur.TacticsTotal)
		fac := []ExecDigestFactor{{"tactics_covered", strconv.Itoa(cur.TacticsCovered), "/v1/compliance/score evidence"}, {"tactics_total", strconv.Itoa(cur.TacticsTotal), "/v1/compliance/score evidence"}}
		if base != nil && base.TacticsTotal > 0 && base.TacticsCovered != cur.TacticsCovered {
			txt += fmt.Sprintf(" Tactics covered changed by %s.", sgn(cur.TacticsCovered-base.TacticsCovered))
			fac = append(fac, ExecDigestFactor{"baseline_tactics_covered", strconv.Itoa(base.TacticsCovered), "posture snapshot"})
		}
		d.Statements = append(d.Statements, ExecDigestStatement{txt, fac})
	}
	{
		txt := fmt.Sprintf("Kavach holds %d findings: %d critical, %d high.", cur.FindingsTotal, cur.FindingsBySev["critical"], cur.FindingsBySev["high"])
		fac := []ExecDigestFactor{{"findings_total", strconv.Itoa(cur.FindingsTotal), "findings store"}, {"critical", strconv.Itoa(cur.FindingsBySev["critical"]), "findings store"}, {"high", strconv.Itoa(cur.FindingsBySev["high"]), "findings store"}}
		if base != nil {
			txt += fmt.Sprintf(" Versus the baseline: total %s, critical %s, high %s.", sgn(cur.FindingsTotal-base.FindingsTotal),
				sgn(cur.FindingsBySev["critical"]-base.FindingsBySev["critical"]), sgn(cur.FindingsBySev["high"]-base.FindingsBySev["high"]))
			fac = append(fac, ExecDigestFactor{"baseline_findings_total", strconv.Itoa(base.FindingsTotal), "posture snapshot"})
		}
		d.Statements = append(d.Statements, ExecDigestStatement{txt, fac})
	}
	if cur.HeartbeatBudgetPct != nil {
		txt := fmt.Sprintf("Agent heartbeat error budget remaining is %s across %d active agents.", fPct(cur.HeartbeatBudgetPct), cur.AgentsActive)
		fac := []ExecDigestFactor{{"heartbeat_budget_remaining_pct", fPct(cur.HeartbeatBudgetPct), "/v1/fleet/slo"}, {"active_agents", strconv.Itoa(cur.AgentsActive), "/v1/fleet/slo"}}
		if base != nil && base.HeartbeatBudgetPct != nil {
			txt += fmt.Sprintf(" It was %s at the baseline.", fPct(base.HeartbeatBudgetPct))
			fac = append(fac, ExecDigestFactor{"baseline_heartbeat_budget_remaining_pct", fPct(base.HeartbeatBudgetPct), "posture snapshot"})
		}
		d.Statements = append(d.Statements, ExecDigestStatement{txt, fac})
	} else {
		d.NotAssessed = append(d.NotAssessed, "Fleet SLO budget: no judged samples (no enrolled agents or too little history); not estimated.")
	}
	if cur.ContinuityBudgetPct != nil {
		d.Statements = append(d.Statements, ExecDigestStatement{fmt.Sprintf("Telemetry continuity error budget remaining is %s.", fPct(cur.ContinuityBudgetPct)),
			[]ExecDigestFactor{{"continuity_budget_remaining_pct", fPct(cur.ContinuityBudgetPct), "/v1/fleet/slo"}}})
	}
	if has("rule_health") && cur.RulesTotal > 0 {
		txt := fmt.Sprintf("Of %d detection rules, %d have never fired in the retention window (silent) and %d are flagged noisy.", cur.RulesTotal, cur.RulesSilent, cur.RulesNoisy)
		fac := []ExecDigestFactor{{"rules_total", strconv.Itoa(cur.RulesTotal), "/v1/rules/health"}, {"rules_silent", strconv.Itoa(cur.RulesSilent), "/v1/rules/health"}, {"rules_noisy", strconv.Itoa(cur.RulesNoisy), "/v1/rules/health"}}
		if base != nil && base.RulesTotal > 0 && base.RulesNoisy != cur.RulesNoisy {
			txt += fmt.Sprintf(" Noisy rules changed by %s.", sgn(cur.RulesNoisy-base.RulesNoisy))
			fac = append(fac, ExecDigestFactor{"baseline_rules_noisy", strconv.Itoa(base.RulesNoisy), "posture snapshot"})
		}
		d.Statements = append(d.Statements, ExecDigestStatement{txt, fac})
	} else {
		d.NotAssessed = append(d.NotAssessed, "Rule health: not available.")
	}
	return d
}

// Markdown renders the digest.
func (d ExecDigest) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Kavach weekly security digest\n\nGenerated %s (UTC), period %d days. Observation-only.\n\n", d.GeneratedAt.Format(time.RFC3339), d.PeriodDays)
	if d.Baseline != nil {
		fmt.Fprintf(&b, "Comparison baseline: snapshot of %s.\n\n", d.Baseline.Format(time.RFC3339))
	}
	b.WriteString("## Summary\n\n")
	for _, s := range d.Statements {
		fmt.Fprintf(&b, "- %s\n", s.Text)
		for _, f := range s.Factors {
			fmt.Fprintf(&b, "  - factor `%s` = %s (%s)\n", f.Name, f.Value, f.Source)
		}
	}
	if len(d.NotAssessed) > 0 {
		b.WriteString("\n## Not assessed\n\n")
		for _, n := range d.NotAssessed {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	b.WriteString("\n## Caveats\n\n")
	for _, c := range d.Caveats {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	return b.String()
}

var digestTmpl = template.Must(template.New("digest").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kavach weekly security digest</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#555;--line:#ddd}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8e8e8;--mut:#a0a0a0;--line:#333}}
@media print{:root{--bg:#fff;--fg:#000;--mut:#333;--line:#999}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:46rem;margin:0 auto;padding:1rem 16px}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.5rem}small,.f{color:var(--mut)}li{margin:.4rem 0}.f{display:block;font-size:.85rem}
</style></head><body>
<h1>Kavach weekly security digest</h1>
<p>Generated {{.GeneratedAt}} (UTC), period {{.PeriodDays}} days. Observation-only.{{if .Baseline}} Baseline snapshot: {{.Baseline}}.{{end}}</p>
<h2>Summary</h2><ul>{{range .Statements}}<li>{{.Text}}{{range .Factors}}<span class="f">factor {{.Name}} = {{.Value}} ({{.Source}})</span>{{end}}</li>{{end}}</ul>
{{if .NotAssessed}}<h2>Not assessed</h2><ul>{{range .NotAssessed}}<li>{{.}}</li>{{end}}</ul>{{end}}
<h2>Caveats</h2><ul>{{range .Caveats}}<li>{{.}}</li>{{end}}</ul></body></html>`))

func (d ExecDigest) HTML() []byte {
	var b bytes.Buffer
	_ = digestTmpl.Execute(&b, map[string]any{"GeneratedAt": d.GeneratedAt.Format(time.RFC3339), "PeriodDays": d.PeriodDays,
		"Baseline": func() string {
			if d.Baseline == nil {
				return ""
			}
			return d.Baseline.Format(time.RFC3339)
		}(), "Statements": d.Statements, "NotAssessed": d.NotAssessed, "Caveats": d.Caveats})
	return b.Bytes()
}

// ---- auditor evidence bundle ----

const (
	bundlePartCap  = 4 << 20
	bundleTotalCap = 24 << 20
)

type bundlePart struct {
	Name string
	Data []byte
}

// BundleManifestEntry lists one file with its SHA-256.
type BundleManifestEntry struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Note   string `json:"note,omitempty"`
}

// BundleManifest is the machine-readable index of the bundle.
type BundleManifest struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Mode        string                `json:"mode"`
	Files       []BundleManifestEntry `json:"files"`
	Caveats     []string              `json:"caveats"`
	Redactions  int                   `json:"redacted_fields"`
	Note        string                `json:"note"`
}

var bundleCaveats = []string{
	"Observation-only evidence: nothing in this bundle certifies compliance or constitutes an audit opinion.",
	"Compliance statuses are derived from signals Kavach could observe; manual and not-applicable controls are listed as such.",
	"Lab measurement is synthetic replay of embedded scenarios, not a recording of your environment.",
	"Config assessment is a policy catalogue summary; Kavach only assesses configuration text an analyst submits and stores none of it.",
	"Fields that look like secrets or tokens, and the API token itself, are removed from every JSON file.",
	"MANIFEST.sha256 covers every file except itself and MANIFEST.json; verify with sha256sum -c MANIFEST.sha256.",
}

var secretKeyParts = []string{"token", "secret", "password", "passwd", "authorization", "api_key", "apikey", "private_key", "credential", "bearer"}

func secretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, p := range secretKeyParts {
		if strings.Contains(lk, p) {
			return true
		}
	}
	return false
}

func scrubValue(v any, token string, n *int) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			if secretKey(k) {
				delete(x, k)
				*n++
				continue
			}
			x[k] = scrubValue(vv, token, n)
		}
		return x
	case []any:
		for i := range x {
			x[i] = scrubValue(x[i], token, n)
		}
		return x
	case string:
		if len(token) >= 8 && strings.Contains(x, token) {
			*n++
			return strings.ReplaceAll(x, token, "[redacted]")
		}
	}
	return v
}

// scrubJSON removes secret-looking keys and the API token; output has sorted keys and is stable.
func scrubJSON(raw []byte, token string, n *int) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte(`{"unavailable":true,"reason":"not valid JSON"}`)
	}
	v = scrubValue(v, token, n)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return b.Bytes()
}

func bundleStub(note string, extra map[string]any) []byte {
	m := map[string]any{"unavailable": true, "reason": note}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return append(b, '\n')
}

// buildAuditorBundle is deterministic for a given set of parts and clock: sorted entries, fixed
// timestamps, no randomness.
func buildAuditorBundle(parts []bundlePart, now time.Time, redactions int) ([]byte, BundleManifest, error) {
	now = now.UTC().Truncate(time.Second)
	sort.Slice(parts, func(i, j int) bool { return parts[i].Name < parts[j].Name })
	man := BundleManifest{GeneratedAt: now, Mode: "observe-only", Caveats: bundleCaveats, Files: []BundleManifestEntry{}, Redactions: redactions,
		Note: "Pull-only bundle built in memory; no secrets or tokens are included."}
	total := 0
	var sums strings.Builder
	files := []bundlePart{}
	for _, p := range parts {
		entry := BundleManifestEntry{Path: p.Name}
		data := p.Data
		if len(data) > bundlePartCap {
			entry.Note = fmt.Sprintf("truncated: original %d bytes exceeded the %d byte per-file cap", len(data), bundlePartCap)
			data = bundleStub("file exceeded per-file size cap", map[string]any{"original_bytes": len(data)})
		}
		if total+len(data) > bundleTotalCap {
			return nil, man, fmt.Errorf("bundle exceeds %d bytes", bundleTotalCap)
		}
		total += len(data)
		h := sha256.Sum256(data)
		entry.Bytes, entry.SHA256 = len(data), hex.EncodeToString(h[:])
		man.Files = append(man.Files, entry)
		fmt.Fprintf(&sums, "%s  %s\n", entry.SHA256, p.Name)
		files = append(files, bundlePart{p.Name, data})
	}
	mb, _ := json.MarshalIndent(man, "", "  ")
	files = append(files, bundlePart{"MANIFEST.json", append(mb, '\n')}, bundlePart{"MANIFEST.sha256", []byte(sums.String())})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return nil, man, err
		}
		if _, err := w.Write(f.Data); err != nil {
			return nil, man, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, man, err
	}
	return buf.Bytes(), man, nil
}

func bundleCaveatsMD() []byte {
	var b strings.Builder
	b.WriteString("# Caveats\n\nThis bundle was produced by Kavach, an observation-only security platform.\n\n")
	for _, c := range bundleCaveats {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	return []byte(b.String())
}

// gatherBundleParts collects the evidence files; failures become explicit stubs, never silent gaps.
func gatherBundleParts(h http.Handler, token string, eng *postureEngine) ([]bundlePart, int) {
	n := 0
	var parts []bundlePart
	add := func(name, route string) {
		_, code, body := internalGet(h, token, route)
		if code != 200 {
			parts = append(parts, bundlePart{name, bundleStub("source returned an error", map[string]any{"source": route, "status": code})})
			return
		}
		parts = append(parts, bundlePart{name, scrubJSON(body, token, &n)})
	}
	add("compliance/evidence.json", "/v1/compliance/evidence")
	add("compliance/score.json", "/v1/compliance/score")
	add("content/versions.json", "/v1/content/versions")
	add("lab/validation-coverage.json", "/v1/validate/coverage")

	type polRow struct {
		ID       string   `json:"id"`
		Title    string   `json:"title"`
		Severity string   `json:"severity"`
		Area     string   `json:"area,omitempty"`
		Formats  []string `json:"formats"`
	}
	pols, err := ConfigPolicies()
	if err != nil {
		parts = append(parts, bundlePart{"config-assessment/policy-catalog.json", bundleStub("policy catalog failed to load", nil)})
	} else {
		rows := make([]polRow, 0, len(pols))
		byArea, bySev := map[string]int{}, map[string]int{}
		for _, p := range pols {
			rows = append(rows, polRow{p.ID, p.Title, p.Severity, p.Area, p.AppliesTo.Formats})
			byArea[p.Area]++
			bySev[p.Severity]++
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		b, _ := json.MarshalIndent(map[string]any{"policies_total": len(rows), "by_area": byArea, "by_severity": bySev, "policies": rows,
			"note": "Catalogue only. Kavach assesses configuration text an analyst submits via POST /v1/inspect/config; none is stored."}, "", "  ")
		parts = append(parts, bundlePart{"config-assessment/policy-catalog.json", append(b, '\n')})
	}
	snaps := eng.Snapshots()
	tb, _ := json.MarshalIndent(map[string]any{"count": len(snaps), "snapshots": snaps}, "", "  ")
	parts = append(parts, bundlePart{"posture/trend.json", append(tb, '\n')})
	parts = append(parts, bundlePart{"CAVEATS.md", bundleCaveatsMD()})
	return parts, n
}

func registerDigestAndBundle(mux *http.ServeMux, token string, store *Store, eng *postureEngine) {
	mux.HandleFunc("GET /v1/reports/digest", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		days := 7
		if v := r.URL.Query().Get("days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 90 {
				http.Error(w, "days must be 1..90", 400)
				return
			}
			days = n
		}
		format := strings.ToLower(r.URL.Query().Get("format"))
		if format == "" {
			format = "json"
		}
		if format != "json" && format != "md" && format != "html" {
			http.Error(w, "format must be json, md or html", 400)
			return
		}
		now := time.Now().UTC()
		cur := collectPosture(mux, token, store, now)
		var base *PostureSnapshot
		if b, ok := snapshotAtOrBefore(eng.Snapshots(), now.AddDate(0, 0, -days)); ok {
			base = &b
		}
		d := buildDigest(cur, base, days, now)
		switch format {
		case "md":
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write([]byte(d.Markdown()))
		case "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(d.HTML())
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(d)
		}
	})
	mux.HandleFunc("GET /v1/compliance/auditor-bundle", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		parts, red := gatherBundleParts(mux, token, eng)
		now := time.Now().UTC()
		zb, man, err := buildAuditorBundle(parts, now, red)
		if err != nil {
			http.Error(w, "bundle too large", http.StatusInsufficientStorage)
			return
		}
		if r.URL.Query().Get("manifest") == "1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(man)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="kavach-auditor-bundle-`+now.Format("20060102")+`.zip"`)
		w.Header().Set("X-Kavach-Bundle-Files", strconv.Itoa(len(man.Files)+2))
		_, _ = w.Write(zb)
	})
}
