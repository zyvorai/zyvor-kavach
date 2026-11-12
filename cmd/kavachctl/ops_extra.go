// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// opsStdin is where "-" file arguments read from (overridable in tests).
var opsStdin io.Reader = os.Stdin

const labNotice = "SANDBOX: detection lab rules never fire alerts and never touch production detections."

// readInputFile reads a file, or stdin when name is "-".
func readInputFile(name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("a FILE argument is required (or - for stdin)")
	}
	if name == "-" {
		return io.ReadAll(io.LimitReader(opsStdin, 4<<20))
	}
	return os.ReadFile(name)
}

// writeNoClobber writes data to file, refusing to overwrite unless force.
func writeNoClobber(out io.Writer, file string, data []byte, force bool) error {
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
	_, err = fh.Write(data)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(file)
		return err
	}
	fmt.Fprintf(out, "wrote %d bytes to %s\n", len(data), file)
	return nil
}

// precheckNoClobber fails early if file exists and force is not set.
func precheckNoClobber(file string, force bool) error {
	if file != "" && !force {
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", file)
		}
	}
	return nil
}

// serverMsg extracts a readable message from an error response body.
func serverMsg(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		if s := strFrom(m, "error"); s != "" {
			return s
		}
	}
	return truncate(string(b), 400)
}

// opsCall performs a call and turns non-2xx into an error carrying the server message.
func opsCall(method, path string, body []byte) ([]byte, error) {
	b, code, err := doRequest(method, path, body, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, serverMsg(b))
	}
	return b, nil
}

func decodeMap(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return m, nil
}

// opsGetMap GETs path and renders per --json/-o json/yaml. When rendered is
// true the caller has nothing more to do; otherwise it renders the table.
func opsGetMap(out io.Writer, path string, args []string) (m map[string]any, rendered bool, err error) {
	format, err := outputFormat(args, "table")
	if err != nil {
		return nil, false, err
	}
	b, err := opsCall("GET", path, nil)
	if err != nil {
		return nil, false, err
	}
	m, err = decodeMap(b)
	if err != nil {
		return nil, false, err
	}
	switch format {
	case "json":
		return m, true, emitJSON(out, b)
	case "yaml":
		writeYAMLish(out, m, 0)
		return m, true, nil
	}
	return m, false, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---- intel feeds ----

const intelFeedsUsage = "usage: kavachctl intel feeds list|status | add --name N --url U --format csv|plain|stix-lite-json [--interval MIN] [--ttl-days N] [--tlp T] | rm ID|NAME | refresh ID|NAME"

func intelFeedsCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", intelFeedsUsage)
	}
	pos, f := splitArgs(args[1:], "name", "url", "format", "interval", "ttl-days", "tlp", "output", "o")
	rest := args[1:]
	switch args[0] {
	case "list":
		m, done, err := opsGetMap(out, "/v1/intel/feeds", rest)
		if err != nil || done {
			return err
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tNAME\tFORMAT\tINTERVAL\tTTL\tTLP\tENABLED\tURL")
		feeds := listOf(m, "feeds")
		for _, fd := range feeds {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%dm\t%dd\t%s\t%s\t%s\n", strFrom(fd, "id"), truncate(strFrom(fd, "name"), 28),
				strFrom(fd, "format"), intFrom(fd, "interval"), intFrom(fd, "ttl_days"), strFrom(fd, "tlp"),
				yesNo(fd["enabled"] == true), maskURL(strFrom(fd, "url")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d feed(s)\n", len(feeds))
		return nil
	case "status":
		m, done, err := opsGetMap(out, "/v1/intel/feeds/status", rest)
		if err != nil || done {
			return err
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tLAST FETCH\tADDED\tEXPIRED\tACTIVE\tERROR")
		for _, s := range listOf(m, "status") {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", strFrom(s, "id"), truncate(strFrom(s, "name"), 28), strFrom(s, "status"),
				fmtTime(strFrom(s, "last_fetch")), intFrom(s, "added"), intFrom(s, "expired"), intFrom(s, "active"), truncate(strFrom(s, "error"), 40))
		}
		return tw.Flush()
	case "add":
		if f["name"] == "" || f["url"] == "" || f["format"] == "" {
			return fmt.Errorf("add requires --name, --url and --format\n%s", intelFeedsUsage)
		}
		body := map[string]any{"name": f["name"], "url": f["url"], "format": f["format"]}
		for _, k := range []struct{ flag, key string }{{"interval", "interval"}, {"ttl-days", "ttl_days"}} {
			if f[k.flag] != "" {
				n, err := strconv.Atoi(f[k.flag])
				if err != nil {
					return fmt.Errorf("invalid --%s %q", k.flag, f[k.flag])
				}
				body[k.key] = n
			}
		}
		if f["tlp"] != "" {
			body["tlp"] = f["tlp"]
		}
		raw, _ := json.Marshal(body)
		b, err := opsCall("POST", "/v1/intel/feeds", raw)
		if err != nil {
			return err
		}
		if hasFlag(args, "--json") {
			return emitJSON(out, b)
		}
		m, _ := decodeMap(b)
		fmt.Fprintf(out, "added feed %s (%s) %s\n", strFrom(m, "id"), strFrom(m, "name"), maskURL(strFrom(m, "url")))
		return nil
	case "rm", "refresh":
		if len(pos) != 1 {
			return fmt.Errorf("%s", intelFeedsUsage)
		}
		id, err := resolveFeedID(pos[0])
		if err != nil {
			return err
		}
		if args[0] == "rm" {
			if _, err := opsCall("DELETE", "/v1/intel/feeds?id="+url.QueryEscape(id), nil); err != nil {
				return err
			}
			fmt.Fprintf(out, "removed feed %s\n", id)
			return nil
		}
		b, err := opsCall("POST", "/v1/intel/feeds/refresh?id="+url.QueryEscape(id), nil)
		if err != nil {
			return err
		}
		if hasFlag(args, "--json") {
			return emitJSON(out, b)
		}
		m, _ := decodeMap(b)
		fmt.Fprintf(out, "refreshed %s: %s added=%d expired=%d active=%d %s\n", strFrom(m, "name"), strFrom(m, "status"),
			intFrom(m, "added"), intFrom(m, "expired"), intFrom(m, "active"), truncate(strFrom(m, "error"), 80))
		return nil
	}
	return fmt.Errorf("%s", intelFeedsUsage)
}

// resolveFeedID accepts a feed id (fd-...) or a case-insensitive name.
func resolveFeedID(ref string) (string, error) {
	if strings.HasPrefix(ref, "fd-") {
		return ref, nil
	}
	b, err := opsCall("GET", "/v1/intel/feeds", nil)
	if err != nil {
		return "", err
	}
	m, err := decodeMap(b)
	if err != nil {
		return "", err
	}
	for _, fd := range listOf(m, "feeds") {
		if strings.EqualFold(strFrom(fd, "name"), ref) || strFrom(fd, "id") == ref {
			return strFrom(fd, "id"), nil
		}
	}
	return "", fmt.Errorf("feed %q not found", ref)
}

// ---- detection lab ----

const labUsage = "usage: kavachctl lab rules list|add FILE|rm ID | validate FILE | test FILE --events FILE | backtest (--rule FILE | --id ID)   (FILE may be - for stdin)"

func labCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", labUsage)
	}
	switch args[0] {
	case "rules":
		return labRulesCmd(out, args[1:])
	case "validate":
		pos, _ := splitArgs(args[1:])
		if len(pos) != 1 {
			return fmt.Errorf("%s", labUsage)
		}
		rule, err := readInputFile(pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(out, labNotice)
		b, code, err := doRequest("POST", "/v1/lab/rules/validate", rule, nil)
		if err != nil {
			return err
		}
		if code >= 300 {
			return fmt.Errorf("invalid rule: %s", serverMsg(b))
		}
		if hasFlag(args, "--json") {
			return emitJSON(out, b)
		}
		fmt.Fprintln(out, "rule is valid")
		return nil
	case "test":
		pos, f := splitArgs(args[1:], "events")
		if len(pos) != 1 || f["events"] == "" {
			return fmt.Errorf("%s", labUsage)
		}
		return labTest(out, pos[0], f["events"], hasFlag(args, "--json"))
	case "backtest":
		_, f := splitArgs(args[1:], "rule", "id")
		return labBacktestCmd(out, f["rule"], f["id"], hasFlag(args, "--json"))
	}
	return fmt.Errorf("%s", labUsage)
}

func labTest(out io.Writer, ruleFile, eventsFile string, asJSON bool) error {
	if ruleFile == "-" && eventsFile == "-" {
		return fmt.Errorf("rule and events cannot both come from stdin")
	}
	rule, err := readInputFile(ruleFile)
	if err != nil {
		return err
	}
	evRaw, err := readInputFile(eventsFile)
	if err != nil {
		return err
	}
	events := json.RawMessage(evRaw)
	var wrapped struct {
		Events json.RawMessage `json:"events"`
	}
	if json.Unmarshal(evRaw, &wrapped) == nil && len(wrapped.Events) > 0 {
		events = wrapped.Events
	}
	body, _ := json.Marshal(map[string]json.RawMessage{"rule": rule, "events": events})
	fmt.Fprintln(out, labNotice)
	b, err := opsCall("POST", "/v1/lab/rules/test", body)
	if err != nil {
		return err
	}
	if asJSON {
		return emitJSON(out, b)
	}
	m, err := decodeMap(b)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "events: %d  condition matched: %d  hits: %d\n", intFrom(m, "events"), intFrom(m, "condition_matched"), len(asList(m["hits"])))
	tw := newTab(out)
	fmt.Fprintln(tw, "EVENT\tMATCHED")
	for _, r := range listOf(m, "results") {
		fmt.Fprintf(tw, "%d\t%s\n", intFrom(r, "index"), yesNo(r["matched"] == true))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	printLabHits(out, listOf(m, "hits"))
	return nil
}

func printLabHits(out io.Writer, hits []map[string]any) {
	if len(hits) == 0 {
		return
	}
	fmt.Fprintln(out, "\nSample hits:")
	tw := newTab(out)
	fmt.Fprintln(tw, "TIME\tHOST\tWHY")
	for _, h := range hits {
		ev, _ := h["event"].(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\n", fmtTime(strFrom(ev, "time")), truncate(strFrom(ev, "host"), 28), truncate(strFrom(h, "why"), 70))
	}
	_ = tw.Flush()
}

func labBacktestCmd(out io.Writer, ruleFile, id string, asJSON bool) error {
	if (ruleFile == "") == (id == "") {
		return fmt.Errorf("backtest needs exactly one of --rule FILE or --id ID")
	}
	var body []byte
	if id != "" {
		body, _ = json.Marshal(map[string]string{"rule_id": id})
	} else {
		rule, err := readInputFile(ruleFile)
		if err != nil {
			return err
		}
		body, _ = json.Marshal(map[string]json.RawMessage{"rule": rule})
	}
	fmt.Fprintln(out, labNotice)
	b, err := opsCall("POST", "/v1/lab/rules/backtest", body)
	if err != nil {
		return err
	}
	if asJSON {
		return emitJSON(out, b)
	}
	m, err := decodeMap(b)
	if err != nil {
		return err
	}
	trunc := ""
	if m["truncated"] == true {
		trunc = "  TRUNCATED at event cap"
	}
	fmt.Fprintf(out, "events scanned: %d (hosts %d, span %.1f d)%s\n", intFrom(m, "events_scanned"), intFrom(m, "hosts_observed"), floatFrom(m, "span_days"), trunc)
	fmt.Fprintf(out, "hits: %d   noise: %.2f hits/host/day\n", intFrom(m, "hit_count"), floatFrom(m, "noise_per_host_per_day"))
	days := listOf(m, "hits_per_day")
	if len(days) > 0 {
		vals := make([]int, len(days))
		for i, d := range days {
			vals[i] = intFrom(d, "hits")
		}
		fmt.Fprintf(out, "hits/day: %s  (%s .. %s)\n", sparkline(vals), strFrom(days[0], "day"), strFrom(days[len(days)-1], "day"))
	}
	if top := listOf(m, "top_hosts"); len(top) > 0 {
		fmt.Fprintln(out, "\nTop hosts:")
		tw := newTab(out)
		for _, h := range top {
			fmt.Fprintf(tw, "%s\t%d\n", strFrom(h, "host"), intFrom(h, "hits"))
		}
		_ = tw.Flush()
	}
	printLabHits(out, listOf(m, "hit_sample"))
	return nil
}

func labRulesCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", labUsage)
	}
	switch args[0] {
	case "list":
		m, done, err := opsGetMap(out, "/v1/lab/rules", args[1:])
		if err != nil || done {
			return err
		}
		fmt.Fprintln(out, labNotice)
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tNAME\tTECHNIQUE\tENABLED\tMODE\tUPDATED")
		rules := listOf(m, "rules")
		for _, r := range rules {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", strFrom(r, "id"), truncate(strFrom(r, "name"), 32), strFrom(r, "technique"),
				yesNo(r["enabled"] == true), strFrom(r, "mode"), fmtTime(strFrom(r, "updated")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d rule(s)\n", len(rules))
		return nil
	case "add":
		pos, _ := splitArgs(args[1:])
		if len(pos) != 1 {
			return fmt.Errorf("%s", labUsage)
		}
		rule, err := readInputFile(pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(out, labNotice)
		b, err := opsCall("POST", "/v1/lab/rules", rule)
		if err != nil {
			return err
		}
		if hasFlag(args, "--json") {
			return emitJSON(out, b)
		}
		m, _ := decodeMap(b)
		r, _ := m["rule"].(map[string]any)
		fmt.Fprintf(out, "saved lab rule %s (%s)\n", strFrom(r, "id"), strFrom(r, "name"))
		return nil
	case "rm":
		pos, _ := splitArgs(args[1:])
		if len(pos) != 1 {
			return fmt.Errorf("%s", labUsage)
		}
		if _, err := opsCall("DELETE", "/v1/lab/rules?id="+url.QueryEscape(pos[0]), nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed lab rule %s\n", pos[0])
		return nil
	}
	return fmt.Errorf("%s", labUsage)
}

// ---- soc ----

const socUsage = "usage: kavachctl soc metrics [--days N] | shift-report [--hours N] [--out FILE] [--force] | storyline HOST [--hours N]"

func socCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", socUsage)
	}
	pos, f := splitArgs(args[1:], "days", "hours", "out", "output", "o")
	switch args[0] {
	case "metrics":
		q := ""
		if f["days"] != "" {
			q = "?days=" + url.QueryEscape(f["days"])
		}
		m, done, err := opsGetMap(out, "/v1/soc/metrics"+q, args[1:])
		if err != nil || done {
			return err
		}
		renderSOCMetrics(out, m)
		return nil
	case "shift-report":
		if err := precheckNoClobber(f["out"], hasFlag(args, "--force")); err != nil {
			return err
		}
		q := ""
		if f["hours"] != "" {
			q = "?hours=" + url.QueryEscape(f["hours"])
		}
		b, err := opsCall("GET", "/v1/soc/shift-report"+q, nil)
		if err != nil {
			return err
		}
		m, err := decodeMap(b)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		if hasFlag(args, "--json") {
			_ = emitJSON(&buf, b)
		} else {
			renderShiftReport(&buf, m)
		}
		if f["out"] != "" {
			return writeNoClobber(out, f["out"], buf.Bytes(), hasFlag(args, "--force"))
		}
		_, err = out.Write(buf.Bytes())
		return err
	case "storyline":
		if len(pos) != 1 {
			return fmt.Errorf("%s", socUsage)
		}
		q := "?host=" + url.QueryEscape(pos[0])
		if f["hours"] != "" {
			q += "&hours=" + url.QueryEscape(f["hours"])
		}
		m, done, err := opsGetMap(out, "/v1/storyline/host"+q, args[1:])
		if err != nil || done {
			return err
		}
		renderHostStoryline(out, m)
		return nil
	}
	return fmt.Errorf("%s", socUsage)
}

func fmtMinutes(v float64) string {
	if v <= 0 {
		return "-"
	}
	if v >= 120 {
		return fmt.Sprintf("%.1fh", v/60)
	}
	return fmt.Sprintf("%.0fm", v)
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func renderSOCMetrics(out io.Writer, m map[string]any) {
	fmt.Fprintf(out, "SOC metrics, last %d day(s)\n", intFrom(m, "days"))
	fmt.Fprintf(out, "tickets %d  acknowledged %d  resolved %d  open backlog %d\n", intFrom(m, "tickets"), intFrom(m, "acknowledged"), intFrom(m, "resolved"), intFrom(m, "open_backlog"))
	fmt.Fprintf(out, "MTTA %s  MTTR %s\n", fmtMinutes(floatFrom(m, "mtta_minutes")), fmtMinutes(floatFrom(m, "mttr_minutes")))
	if bk, ok := m["backlog_by_severity"].(map[string]any); ok {
		fmt.Fprintln(out, "\nBacklog by severity and age:")
		tw := newTab(out)
		fmt.Fprintln(tw, "SEVERITY\t<1h\t1h-24h\t1d-7d\t>7d")
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			b, ok := bk[s].(map[string]any)
			if !ok {
				continue
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", s, intFrom(b, "lt_1h"), intFrom(b, "1h_24h"), intFrom(b, "1d_7d"), intFrom(b, "gt_7d"))
		}
		_ = tw.Flush()
	}
	if br, ok := m["sla_breaches"].(map[string]any); ok && len(br) > 0 {
		fmt.Fprintln(out, "\nSLA breaches:")
		tw := newTab(out)
		fmt.Fprintln(tw, "SEVERITY\tACK\tRESOLVE")
		for _, s := range sortedKeys(br) {
			b, _ := br[s].(map[string]any)
			fmt.Fprintf(tw, "%s\t%d\t%d\n", s, intFrom(b, "ack", "Ack"), intFrom(b, "resolve", "Resolve"))
		}
		_ = tw.Flush()
	}
	if rules := listOf(m, "top_noisy_rules"); len(rules) > 0 {
		fmt.Fprintln(out, "\nTop noisy rules:")
		tw := newTab(out)
		fmt.Fprintln(tw, "RULE\tTOTAL\tFALSE POSITIVE\tFP RATE")
		for _, r := range rules {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%.1f%%\n", truncate(strFrom(r, "rule"), 40), intFrom(r, "total"), intFrom(r, "false_positive", "fp"), floatFrom(r, "false_positive_rate"))
		}
		_ = tw.Flush()
	}
}

func renderShiftReport(out io.Writer, m map[string]any) {
	fmt.Fprintf(out, "Shift report, last %d hour(s) (generated %s)\n", intFrom(m, "hours"), fmtTime(strFrom(m, "generated_at")))
	c, _ := m["counts"].(map[string]any)
	fmt.Fprintf(out, "new %d  open %d  closed %d\n", intFrom(c, "new"), intFrom(c, "open"), intFrom(c, "closed"))
	if hosts := listOf(m, "highest_risk_hosts"); len(hosts) > 0 {
		fmt.Fprintln(out, "\nHighest-risk hosts:")
		tw := newTab(out)
		fmt.Fprintln(tw, "HOST\tRISK\tBAND\tFINDINGS")
		for _, h := range hosts {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%d\n", strFrom(h, "host"), intFrom(h, "risk"), strFrom(h, "band"), intFrom(h, "findings"))
		}
		_ = tw.Flush()
	}
	if cr := listOf(m, "unresolved_criticals"); len(cr) > 0 {
		fmt.Fprintln(out, "\nUnresolved criticals:")
		tw := newTab(out)
		fmt.Fprintln(tw, "FINDING\tHOST\tRULE\tTIME\tSTATE")
		for _, x := range cr {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", strFrom(x, "finding_id"), strFrom(x, "host"), truncate(strFrom(x, "rule"), 36), fmtTime(strFrom(x, "time")), strFrom(x, "state"))
		}
		_ = tw.Flush()
	}
	if qs, _ := m["recommended_questions"].([]any); len(qs) > 0 {
		fmt.Fprintln(out, "\nQuestions for the next shift:")
		for _, q := range qs {
			fmt.Fprintf(out, "  - %v\n", q)
		}
	}
}

func renderHostStoryline(out io.Writer, m map[string]any) {
	steps := listOf(m, "steps")
	fmt.Fprintf(out, "Storyline for %s since %s: %d step(s), %d burst(s)\n", strFrom(m, "host"), fmtTime(strFrom(m, "since")), len(steps), len(asList(m["bursts"])))
	if t, _ := m["tactics"].([]any); len(t) > 0 {
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = fmt.Sprint(x)
		}
		fmt.Fprintf(out, "tactics: %s\n", strings.Join(parts, " > "))
	}
	tw := newTab(out)
	fmt.Fprintln(tw, "TIME\tBURST\tTACTIC\tTECHNIQUE\tKIND\tSEVERITY\tSUMMARY")
	for _, s := range steps {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n", fmtTime(strFrom(s, "time")), intFrom(s, "burst"), strFrom(s, "tactic"),
			strFrom(s, "technique_id"), strFrom(s, "kind"), strFrom(s, "severity"), truncate(strFrom(s, "summary"), 60))
	}
	_ = tw.Flush()
}

// ---- posture ----

const postureUsage = "usage: kavachctl posture summary | vulns [--limit N] [--explain] | assets list|add --host H --criticality 1-5 [--owner O] [--tags a,b]|rm HOST | drift HOST | baseline [HOST]"

func postureCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", postureUsage)
	}
	pos, f := splitArgs(args[1:], "limit", "output", "o")
	rest := args[1:]
	switch args[0] {
	case "summary":
		m, done, err := opsGetMap(out, "/v1/posture/summary", rest)
		if err != nil || done {
			return err
		}
		as, _ := m["assets"].(map[string]any)
		vu, _ := m["vulnerabilities"].(map[string]any)
		dr, _ := m["drift"].(map[string]any)
		fmt.Fprintf(out, "assets registered: %d   observed hosts: %d\n", intFrom(as, "registered"), intFrom(m, "observed_hosts"))
		if d, ok := as["by_criticality"].(map[string]any); ok {
			fmt.Fprintf(out, "criticality 1..5: %d %d %d %d %d\n", intFrom(d, "1"), intFrom(d, "2"), intFrom(d, "3"), intFrom(d, "4"), intFrom(d, "5"))
		}
		fmt.Fprintf(out, "vulnerabilities: %d (score >= 70: %d)\n", intFrom(vu, "total"), intFrom(vu, "score_70_plus"))
		printVulnTable(out, listOf(vu, "top"), false)
		fmt.Fprintf(out, "\nbaselined hosts: %d\n", intFrom(dr, "baselined_hosts"))
		if hs := listOf(dr, "hosts_with_drift"); len(hs) > 0 {
			tw := newTab(out)
			fmt.Fprintln(tw, "HOST\tDRIFT\tHIGHEST")
			for _, h := range hs {
				fmt.Fprintf(tw, "%s\t%d\t%s\n", strFrom(h, "host"), intFrom(h, "total"), strFrom(h, "highest_severity"))
			}
			_ = tw.Flush()
		}
		return nil
	case "vulns":
		q := ""
		if f["limit"] != "" {
			if n, err := strconv.Atoi(f["limit"]); err != nil || n < 0 {
				return fmt.Errorf("invalid --limit %q", f["limit"])
			}
			q = "?limit=" + url.QueryEscape(f["limit"])
		}
		m, done, err := opsGetMap(out, "/v1/posture/vuln-priority"+q, rest)
		if err != nil || done {
			return err
		}
		items := listOf(m, "items")
		printVulnTable(out, items, hasFlag(args, "--explain"))
		fmt.Fprintf(out, "%d vulnerabilit(ies)\nmodel: %s\n", len(items), strFrom(m, "model"))
		return nil
	case "assets":
		return postureAssetsCmd(out, args[1:])
	case "drift":
		if len(pos) != 1 {
			return fmt.Errorf("%s", postureUsage)
		}
		m, done, err := opsGetMap(out, "/v1/posture/drift?host="+url.QueryEscape(pos[0]), rest)
		if err != nil || done {
			return err
		}
		if m["has_baseline"] != true {
			fmt.Fprintf(out, "%s has no baseline; run: kavachctl posture baseline %s\n", strFrom(m, "host"), strFrom(m, "host"))
			return nil
		}
		fmt.Fprintf(out, "%s drift since %s: %d change(s), highest %s\n", strFrom(m, "host"), fmtTime(strFrom(m, "baseline_at")), intFrom(m, "total"), strFrom(m, "highest_severity"))
		tw := newTab(out)
		fmt.Fprintln(tw, "CHANGE\tDOMAIN\tKEY\tBEFORE\tAFTER\tSEVERITY\tREASON")
		for _, kind := range []string{"added", "removed", "changed"} {
			for _, d := range listOf(m, kind) {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", kind, strFrom(d, "domain"), truncate(strFrom(d, "key"), 36),
					truncate(strFrom(d, "before"), 20), truncate(strFrom(d, "after"), 20), strFrom(d, "severity_hint"), truncate(strFrom(d, "reason"), 40))
			}
		}
		return tw.Flush()
	case "baseline":
		if len(pos) > 1 {
			return fmt.Errorf("%s", postureUsage)
		}
		path := "/v1/posture/baseline"
		if len(pos) == 1 {
			path += "?host=" + url.QueryEscape(pos[0])
		}
		b, err := opsCall("POST", path, nil)
		if err != nil {
			return err
		}
		m, _ := decodeMap(b)
		fmt.Fprintf(out, "baselined %d host(s)\n", intFrom(m, "baselined"))
		return nil
	}
	return fmt.Errorf("%s", postureUsage)
}

func printVulnTable(out io.Writer, items []map[string]any, explain bool) {
	if len(items) == 0 {
		return
	}
	tw := newTab(out)
	fmt.Fprintln(tw, "RANK\tSCORE\tSEVERITY\tCVE\tHOST\tPRODUCT")
	for _, v := range items {
		fmt.Fprintf(tw, "%d\t%.1f\t%s\t%s\t%s\t%s\n", intFrom(v, "rank"), floatFrom(v, "score"), strFrom(v, "severity"), strFrom(v, "cve"),
			truncate(strFrom(v, "host"), 28), truncate(strFrom(v, "product"), 28))
	}
	_ = tw.Flush()
	if !explain {
		return
	}
	for _, v := range items {
		fmt.Fprintf(out, "\n#%d %s on %s = %.1f\n", intFrom(v, "rank"), strFrom(v, "cve"), strFrom(v, "host"), floatFrom(v, "score"))
		tw := newTab(out)
		for _, c := range listOf(v, "breakdown") {
			fmt.Fprintf(tw, "  %s\t%.1f/%.0f\t%s\n", strFrom(c, "factor"), floatFrom(c, "points"), floatFrom(c, "max"), strFrom(c, "detail"))
		}
		_ = tw.Flush()
	}
}

func postureAssetsCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", postureUsage)
	}
	pos, f := splitArgs(args[1:], "host", "criticality", "owner", "tags", "output", "o")
	switch args[0] {
	case "list":
		format, err := outputFormat(args[1:], "table")
		if err != nil {
			return err
		}
		b, err := opsCall("GET", "/v1/posture/assets", nil)
		if err != nil {
			return err
		}
		var rows []map[string]any
		if err := json.Unmarshal(b, &rows); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if format == "json" {
			return emitJSON(out, b)
		}
		if format == "yaml" {
			var v any
			_ = json.Unmarshal(b, &v)
			writeYAMLish(out, v, 0)
			return nil
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "HOST\tCRITICALITY\tOWNER\tTAGS\tUPDATED")
		for _, a := range rows {
			tags := []string{}
			if t, ok := a["tags"].([]any); ok {
				for _, x := range t {
					tags = append(tags, fmt.Sprint(x))
				}
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", strFrom(a, "host"), intFrom(a, "criticality"), strFrom(a, "owner"), strings.Join(tags, ","), fmtTime(strFrom(a, "updated")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d asset(s)\n", len(rows))
		return nil
	case "add":
		host := f["host"]
		if host == "" && len(pos) == 1 {
			host = pos[0]
		}
		crit, err := strconv.Atoi(f["criticality"])
		if host == "" || err != nil || crit < 1 || crit > 5 {
			return fmt.Errorf("add requires --host H and --criticality 1-5")
		}
		body := map[string]any{"host": host, "criticality": crit, "owner": f["owner"]}
		if f["tags"] != "" {
			body["tags"] = strings.Split(f["tags"], ",")
		}
		raw, _ := json.Marshal(body)
		if _, err := opsCall("POST", "/v1/posture/assets", raw); err != nil {
			return err
		}
		fmt.Fprintf(out, "registered asset %s (criticality %d)\n", host, crit)
		return nil
	case "rm":
		if len(pos) != 1 {
			return fmt.Errorf("%s", postureUsage)
		}
		if _, err := opsCall("DELETE", "/v1/posture/assets?host="+url.QueryEscape(pos[0]), nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed asset %s\n", pos[0])
		return nil
	}
	return fmt.Errorf("%s", postureUsage)
}

// ---- compliance (extended) ----

const complianceUsage = "usage: kavachctl compliance [score] | controls --framework F | evidence --framework F [--format html|json] [--out FILE] [--force] | cert-in-clock"

func complianceExtraCmd(out io.Writer, args []string) error {
	_, f := splitArgs(args[1:], "framework", "format", "out", "output", "o")
	fwQ := func() (string, error) {
		if f["framework"] == "" {
			return "", fmt.Errorf("--framework is required\n%s", complianceUsage)
		}
		return "framework=" + url.QueryEscape(f["framework"]), nil
	}
	switch args[0] {
	case "controls":
		q, err := fwQ()
		if err != nil {
			return err
		}
		m, done, err := opsGetMap(out, "/v1/compliance/controls?"+q, args[1:])
		if err != nil || done {
			return err
		}
		controls := listOf(m, "controls")
		fmt.Fprintf(out, "%s controls (observe-only, not a certification)\n", strFrom(m, "framework"))
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tSTATUS\tTITLE\tNOTE")
		for _, c := range controls {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strFrom(c, "id"), strFrom(c, "status"), truncate(strFrom(c, "title"), 48), truncate(strFrom(c, "note"), 50))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d control(s)\n", len(controls))
		return nil
	case "evidence":
		q, err := fwQ()
		if err != nil {
			return err
		}
		format := strings.ToLower(f["format"])
		if format == "" {
			format = "json"
		}
		if format != "html" && format != "json" {
			return fmt.Errorf("invalid --format %q (html|json)", format)
		}
		return streamTo(out, "/v1/compliance/evidence?"+q+"&format="+format, f["out"], hasFlag(args, "--force"))
	case "cert-in-clock":
		m, done, err := opsGetMap(out, "/v1/compliance/cert-in-clock", args[1:])
		if err != nil || done {
			return err
		}
		fmt.Fprintf(out, "CERT-In %dh reporting clock (informational; Kavach does not file reports)\n", intFrom(m, "window_hours"))
		tw := newTab(out)
		fmt.Fprintln(tw, "FINDING\tSEVERITY\tHOST\tRULE\tSTATUS\tDEADLINE\tREMAINING")
		rows := listOf(m, "incidents")
		for _, r := range rows {
			rem := time.Duration(int64(floatFrom(r, "remaining_seconds"))) * time.Second
			left := fmtRemaining(rem)
			if r["overdue"] == true {
				left = "OVERDUE " + fmtRemaining(-rem)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", strFrom(r, "finding_id"), strFrom(r, "severity"), truncate(strFrom(r, "host"), 24),
				truncate(strFrom(r, "rule"), 32), strFrom(r, "status"), fmtTime(strFrom(r, "deadline")), left)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d open high/critical incident(s)\n", len(rows))
		return nil
	}
	return fmt.Errorf("%s", complianceUsage)
}

func fmtRemaining(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Minute)
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}
