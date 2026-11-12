// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// splitArgs separates positional arguments from --flags. Flags named in
// valueKeys consume the following token as a value (or use --k=v).
func splitArgs(args []string, valueKeys ...string) (pos []string, flags map[string]string) {
	want := map[string]bool{}
	for _, k := range valueKeys {
		want[k] = true
	}
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") || a == "--" {
			pos = append(pos, a)
			continue
		}
		kv := strings.TrimPrefix(a, "--")
		if k, v, ok := strings.Cut(kv, "="); ok {
			flags[k] = v
			continue
		}
		if want[kv] && i+1 < len(args) {
			flags[kv] = args[i+1]
			i++
			continue
		}
		flags[kv] = "true"
	}
	return pos, flags
}

// apiDo performs an authenticated call and turns non-2xx into an error that
// carries the server's message.
func apiDo(method, path string, body any) ([]byte, error) {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	b, code, err := doRequest(method, path, raw, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, truncate(string(b), 400))
	}
	return b, nil
}

func apiGetMap(path string) (map[string]any, []byte, error) {
	b, err := apiDo("GET", path, nil)
	if err != nil {
		return nil, nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, b, fmt.Errorf("decode %s: %w", path, err)
	}
	return m, b, nil
}

func emitJSON(out io.Writer, b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newTab(out io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(out, 0, 2, 2, ' ', 0) }

func listOf(m map[string]any, key string) []map[string]any {
	l, _ := m[key].([]any)
	out := make([]map[string]any, 0, len(l))
	for _, e := range l {
		if em, ok := e.(map[string]any); ok {
			out = append(out, em)
		}
	}
	return out
}

func fmtTime(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format("2006-01-02 15:04")
	}
	return s
}

func floatFrom(m map[string]any, k string) float64 {
	f, _ := m[k].(float64)
	return f
}

func bandPaint(color bool, band string) string { return paint(color, sevColor(band), band) }

func stdoutColor(out io.Writer) bool {
	f, ok := out.(*os.File)
	return ok && useColor(f)
}

// ---- risk ----

func riskCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl risk hosts|summary [--json]")
	}
	asJSON := hasFlag(args[1:], "--json")
	color := stdoutColor(out)
	switch args[0] {
	case "hosts":
		m, raw, err := apiGetMap("/v1/risk/hosts")
		if err != nil {
			return err
		}
		if asJSON {
			return emitJSON(out, raw)
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "RANK\tHOST\tRISK\tBAND\tFINDINGS\tLAST SEEN\tTOP RULES")
		for _, h := range listOf(m, "hosts") {
			var rules []string
			for _, r := range listOf(h, "top_rules") {
				rules = append(rules, fmt.Sprintf("%s(%d)", strFrom(r, "rule"), intFrom(r, "count")))
			}
			fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%d\t%s\t%s\n", intFrom(h, "rank"), truncate(strFrom(h, "host"), 32),
				intFrom(h, "risk"), bandPaint(color, strFrom(h, "band")), intFrom(h, "findings"),
				fmtTime(strFrom(h, "last_seen")), truncate(strings.Join(rules, ", "), 60))
		}
		return tw.Flush()
	case "summary":
		m, raw, err := apiGetMap("/v1/risk/summary")
		if err != nil {
			return err
		}
		if asJSON {
			return emitJSON(out, raw)
		}
		fmt.Fprintf(out, "Fleet risk index: %d (%s)  hosts: %d\n\n", intFrom(m, "fleet_risk_index"), bandPaint(color, strFrom(m, "band")), intFrom(m, "hosts"))
		bands, _ := m["bands"].(map[string]any)
		tw := newTab(out)
		fmt.Fprintln(tw, "BAND\tHOSTS")
		for _, b := range []string{"critical", "high", "medium", "low"} {
			fmt.Fprintf(tw, "%s\t%d\n", bandPaint(color, b), intFrom(bands, b))
		}
		return tw.Flush()
	}
	return fmt.Errorf("usage: kavachctl risk hosts|summary [--json]")
}

// ---- trends ----

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

func sparkline(vals []int) string {
	max := 0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range vals {
		i := 0
		if max > 0 && v > 0 {
			i = (v*(len(sparkRunes)-1) + max - 1) / max
		}
		b.WriteRune(sparkRunes[i])
	}
	return b.String()
}

func trendsCmd(out io.Writer, args []string) error {
	_, f := splitArgs(args, "days", "bucket")
	q := url.Values{}
	if v := f["days"]; v != "" {
		q.Set("days", v)
	}
	if v := f["bucket"]; v != "" {
		q.Set("bucket", v)
	}
	path := "/v1/trends"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	m, raw, err := apiGetMap(path)
	if err != nil {
		return err
	}
	if hasFlag(args, "--json") {
		return emitJSON(out, raw)
	}
	buckets := listOf(m, "buckets")
	totals := make([]int, len(buckets))
	for i, b := range buckets {
		totals[i] = intFrom(b, "total")
	}
	fmt.Fprintf(out, "%d day(s), %s buckets  total %d  previous %d  delta %+d (%.1f%%)\n",
		intFrom(m, "days"), strFrom(m, "bucket"), intFrom(m, "total"), intFrom(m, "previous_total"),
		intFrom(m, "delta"), floatFrom(m, "delta_pct"))
	fmt.Fprintf(out, "%s\n\n", sparkline(totals))

	// Roll hourly buckets up to days so the table stays compact.
	type row struct {
		label                   string
		total, low, med, hi, cr int
	}
	var rows []row
	idx := map[string]int{}
	for _, b := range buckets {
		label := strFrom(b, "start")
		if len(label) >= 10 {
			label = label[:10]
		}
		i, ok := idx[label]
		if !ok {
			i = len(rows)
			idx[label] = i
			rows = append(rows, row{label: label})
		}
		sv, _ := b["severity"].(map[string]any)
		rows[i].total += intFrom(b, "total")
		rows[i].low += intFrom(sv, "low")
		rows[i].med += intFrom(sv, "medium")
		rows[i].hi += intFrom(sv, "high")
		rows[i].cr += intFrom(sv, "critical")
	}
	tw := newTab(out)
	fmt.Fprintln(tw, "DAY\tTOTAL\tLOW\tMEDIUM\tHIGH\tCRITICAL")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\n", r.label, r.total, r.low, r.med, r.hi, r.cr)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if rules := listOf(m, "top_rules"); len(rules) > 0 {
		var parts []string
		for _, r := range rules {
			parts = append(parts, fmt.Sprintf("%s(%d)", strFrom(r, "rule"), intFrom(r, "count")))
		}
		fmt.Fprintf(out, "\ntop rules: %s\n", strings.Join(parts, ", "))
	}
	return nil
}

// ---- export ----

const exportUsage = "usage: kavachctl export findings|report [--format F] [--out FILE] [--force]"

func exportCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", exportUsage)
	}
	_, f := splitArgs(args[1:], "format", "severity", "host", "rule", "since", "out")
	var path string
	format := strings.ToLower(f["format"])
	switch args[0] {
	case "findings":
		if format == "" {
			format = "json"
		}
		if format != "csv" && format != "json" && format != "ndjson" {
			return fmt.Errorf("invalid --format %q (csv|json|ndjson)", format)
		}
		q := url.Values{"format": {format}}
		for _, k := range []string{"severity", "host", "rule", "since"} {
			if f[k] != "" {
				q.Set(k, f[k])
			}
		}
		path = "/v1/export/findings?" + q.Encode()
	case "report":
		if format == "" {
			format = "html"
		}
		if format != "html" && format != "json" {
			return fmt.Errorf("invalid --format %q (html|json)", format)
		}
		path = "/v1/export/report?format=" + format
	default:
		return fmt.Errorf("%s", exportUsage)
	}
	return streamTo(out, path, f["out"], hasFlag(args, "--force"))
}

// streamTo copies a GET response body to a file (never overwriting unless
// force) or to out when no file is given. The file is only created after the
// server has answered 2xx, and removed again if the copy fails.
func streamTo(out io.Writer, path, file string, force bool) error {
	ensureConfig()
	if apiToken() == "" {
		return fmt.Errorf("set KAVACH_TOKEN (or ~/.kavach/api-key)")
	}
	if file != "" && !force {
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", file)
		}
	}
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken())
	req.Header.Set("X-Kavach-Actor", firstEnv("KAVACH_CLI_ACTOR", "kavachctl"))
	resp, err := httpClient(0).Do(req)
	if err != nil {
		return annotateTLSErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(b), 400))
	}
	if file == "" {
		_, err = io.Copy(out, resp.Body)
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	fh, err := os.OpenFile(file, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists (use --force to overwrite)", file)
		}
		return err
	}
	n, err := io.Copy(fh, resp.Body)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(file)
		return err
	}
	fmt.Fprintf(out, "wrote %d bytes to %s\n", n, file)
	return nil
}

// ---- notes ----

func notesCmd(out io.Writer, args []string) error {
	usage := fmt.Errorf("usage: kavachctl notes list --finding ID | add --finding ID \"text\" | rm ID")
	if len(args) < 1 {
		return usage
	}
	pos, f := splitArgs(args[1:], "finding")
	asJSON := hasFlag(args, "--json")
	switch args[0] {
	case "list", "ls":
		if f["finding"] == "" {
			return fmt.Errorf("--finding ID is required")
		}
		m, raw, err := apiGetMap("/v1/notes?finding_id=" + url.QueryEscape(f["finding"]))
		if err != nil {
			return err
		}
		if asJSON {
			return emitJSON(out, raw)
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tAUTHOR\tCREATED\tTEXT")
		for _, n := range listOf(m, "notes") {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strFrom(n, "id"), strFrom(n, "author"), fmtTime(strFrom(n, "created")),
				truncate(strings.ReplaceAll(strFrom(n, "text"), "\n", " "), 80))
		}
		return tw.Flush()
	case "add":
		text := strings.TrimSpace(strings.Join(pos, " "))
		if f["finding"] == "" || text == "" {
			return fmt.Errorf("usage: kavachctl notes add --finding ID \"text\"")
		}
		b, err := apiDo("POST", "/v1/notes", map[string]string{"finding_id": f["finding"], "text": text})
		if err != nil {
			return err
		}
		return printCreated(out, b, "note", asJSON)
	case "rm", "delete":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kavachctl notes rm ID")
		}
		if _, err := apiDo("DELETE", "/v1/notes?id="+url.QueryEscape(pos[0]), nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed note %s\n", pos[0])
		return nil
	}
	return usage
}

func printCreated(out io.Writer, b []byte, what string, asJSON bool) error {
	if asJSON {
		return emitJSON(out, b)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	fmt.Fprintf(out, "created %s %s\n", what, strFrom(m, "id"))
	return nil
}

// ---- saved searches ----

func savedSearchesCmd(out io.Writer, args []string) error {
	usage := fmt.Errorf("usage: kavachctl saved-searches list | add --name N [--scope detections|findings|hosts] --query Q | rm ID")
	if len(args) < 1 {
		return usage
	}
	pos, f := splitArgs(args[1:], "name", "scope", "query")
	asJSON := hasFlag(args, "--json")
	switch args[0] {
	case "list", "ls":
		m, raw, err := apiGetMap("/v1/saved-searches")
		if err != nil {
			return err
		}
		if asJSON {
			return emitJSON(out, raw)
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tNAME\tSCOPE\tQUERY\tAUTHOR")
		for _, s := range listOf(m, "saved_searches") {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", strFrom(s, "id"), truncate(strFrom(s, "name"), 30), strFrom(s, "scope"),
				truncate(strFrom(s, "query"), 50), strFrom(s, "author"))
		}
		return tw.Flush()
	case "add":
		scope := f["scope"]
		if scope == "" {
			scope = "findings"
		}
		if f["name"] == "" {
			return fmt.Errorf("--name is required")
		}
		q := f["query"]
		if q == "" {
			q = strings.Join(pos, " ")
		}
		b, err := apiDo("POST", "/v1/saved-searches", map[string]string{"name": f["name"], "scope": scope, "query": q})
		if err != nil {
			return err
		}
		return printCreated(out, b, "saved search", asJSON)
	case "rm", "delete":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kavachctl saved-searches rm ID")
		}
		if _, err := apiDo("DELETE", "/v1/saved-searches?id="+url.QueryEscape(pos[0]), nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed saved search %s\n", pos[0])
		return nil
	}
	return usage
}

// ---- alerts ----

// maskURL hides the path and query of a webhook URL (they usually hold secrets).
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "***"
	}
	s := u.Scheme + "://" + u.Host
	if p := strings.Trim(u.Path, "/"); p != "" {
		s += "/***"
	}
	if u.RawQuery != "" {
		s += "?***"
	}
	return s
}

func alertsCmd(out io.Writer, args []string) error {
	usage := fmt.Errorf("usage: kavachctl alerts rules list|add|rm | alerts deliveries")
	if len(args) < 1 {
		return usage
	}
	asJSON := hasFlag(args, "--json")
	switch args[0] {
	case "deliveries":
		m, raw, err := apiGetMap("/v1/alerts/deliveries")
		if err != nil {
			return err
		}
		if asJSON {
			return emitJSON(out, raw)
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "TIME\tRULE\tFINDING\tTYPE\tDESTINATION\tSTATUS\tTRIES\tHTTP\tERROR")
		for _, d := range listOf(m, "deliveries") {
			code := ""
			if c := intFrom(d, "http_status"); c != 0 {
				code = fmt.Sprint(c)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", fmtTime(strFrom(d, "time")), strFrom(d, "rule_id"),
				truncate(strFrom(d, "finding_id"), 20), strFrom(d, "type"), strFrom(d, "destination_host"),
				strFrom(d, "status"), intFrom(d, "attempts"), code, truncate(strFrom(d, "error"), 40))
		}
		return tw.Flush()
	case "rules", "rule":
		return alertRulesCmd(out, args[1:], asJSON)
	}
	return usage
}

func alertRulesCmd(out io.Writer, args []string, asJSON bool) error {
	usage := fmt.Errorf("usage: kavachctl alerts rules list | add --url URL [--type webhook|slack] [--min-severity S] [--rule-contains X] [--host-contains Y] | rm ID")
	if len(args) < 1 {
		return usage
	}
	pos, f := splitArgs(args[1:], "min-severity", "type", "url", "rule-contains", "host-contains")
	switch args[0] {
	case "list", "ls":
		m, raw, err := apiGetMap("/v1/alerts/rules")
		if err != nil {
			return err
		}
		if asJSON {
			return emitJSON(out, raw)
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tMIN SEV\tTYPE\tRULE~\tHOST~\tURL\tCREATED")
		for _, r := range listOf(m, "rules") {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", strFrom(r, "id"), strFrom(r, "min_severity"), strFrom(r, "type"),
				strFrom(r, "rule_contains"), strFrom(r, "host_contains"), maskURL(strFrom(r, "url")), fmtTime(strFrom(r, "created")))
		}
		return tw.Flush()
	case "add":
		if f["url"] == "" {
			return fmt.Errorf("--url is required")
		}
		body := map[string]string{"min_severity": f["min-severity"], "type": f["type"], "url": f["url"],
			"rule_contains": f["rule-contains"], "host_contains": f["host-contains"]}
		b, err := apiDo("POST", "/v1/alerts/rules", body)
		if err != nil {
			return err
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		journalNote("alert_rule.create", strFrom(m, "id"))
		if asJSON {
			m["url"] = maskURL(strFrom(m, "url"))
			nb, _ := json.Marshal(m)
			return emitJSON(out, nb)
		}
		fmt.Fprintf(out, "created alert rule %s -> %s %s\n", strFrom(m, "id"), strFrom(m, "type"), maskURL(strFrom(m, "url")))
		return nil
	case "rm", "delete":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kavachctl alerts rules rm ID")
		}
		if _, err := apiDo("DELETE", "/v1/alerts/rules?id="+url.QueryEscape(pos[0]), nil); err != nil {
			return err
		}
		journalNote("alert_rule.delete", pos[0])
		fmt.Fprintf(out, "removed alert rule %s\n", pos[0])
		return nil
	}
	return usage
}

// journalNote records an alert-rule change in the tamper-evident journal.
// Best effort: the rule change itself already succeeded.
func journalNote(action, target string) {
	if _, err := apiDo("POST", "/v1/journal", map[string]string{"action": action, "target": target}); err != nil {
		fmt.Fprintf(os.Stderr, "kavachctl: warning: journal entry not recorded: %v\n", err)
	}
}

// ---- journal ----

func journalCmd(out io.Writer, args []string) error {
	asJSON := hasFlag(args, "--json")
	if len(args) > 0 && args[0] == "verify" {
		m, raw, err := apiGetMap("/v1/journal/verify")
		if err != nil {
			return err
		}
		valid, _ := m["valid"].(bool)
		if asJSON {
			if err := emitJSON(out, raw); err != nil {
				return err
			}
		} else if valid {
			fmt.Fprintf(out, "journal chain valid (%d entries)\n", intFrom(m, "entries"))
		} else {
			fmt.Fprintf(out, "journal chain BROKEN at seq %d: %s\n", intFrom(m, "first_broken_seq"), strFrom(m, "reason"))
		}
		if !valid {
			return fmt.Errorf("journal verification failed")
		}
		return nil
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") && args[0] != "list" {
		return fmt.Errorf("usage: kavachctl journal [verify] [--json]")
	}
	m, raw, err := apiGetMap("/v1/journal")
	if err != nil {
		return err
	}
	if asJSON {
		return emitJSON(out, raw)
	}
	entries := listOf(m, "entries")
	sort.SliceStable(entries, func(i, j int) bool { return intFrom(entries[i], "seq") < intFrom(entries[j], "seq") })
	tw := newTab(out)
	fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tACTION\tTARGET")
	for _, e := range entries {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", intFrom(e, "seq"), fmtTime(strFrom(e, "time")), strFrom(e, "actor"),
			strFrom(e, "action"), truncate(strFrom(e, "target"), 60))
	}
	return tw.Flush()
}
