// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// ---- shared output helpers ----

// hasFlag reports whether a bare boolean flag (e.g. --json) is present.
func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		for _, n := range names {
			if a == n || a == n+"=true" {
				return true
			}
		}
	}
	return false
}

// outputFormat resolves --json / --output|-o into table|json|yaml.
func outputFormat(args []string, def string) (string, error) {
	f := def
	if hasFlag(args, "--json") {
		f = "json"
	}
	for i, a := range args {
		v := ""
		switch {
		case a == "--output" || a == "-o":
			if i+1 < len(args) {
				v = args[i+1]
			}
		case strings.HasPrefix(a, "--output="):
			v = strings.TrimPrefix(a, "--output=")
		}
		if v != "" {
			f = strings.ToLower(v)
		}
	}
	switch f {
	case "table", "json", "yaml":
		return f, nil
	case "yml":
		return "yaml", nil
	}
	return "", fmt.Errorf("unknown --output %q (table|json|yaml)", f)
}

// writeYAMLish renders a decoded JSON value as simple indented YAML-like text.
func writeYAMLish(w io.Writer, v any, indent int) {
	pad := strings.Repeat("  ", indent)
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch x[k].(type) {
			case map[string]any, []any:
				fmt.Fprintf(w, "%s%s:\n", pad, k)
				writeYAMLish(w, x[k], indent+1)
			default:
				fmt.Fprintf(w, "%s%s: %s\n", pad, k, scalar(x[k]))
			}
		}
	case []any:
		for _, e := range x {
			switch e.(type) {
			case map[string]any, []any:
				fmt.Fprintf(w, "%s-\n", pad)
				writeYAMLish(w, e, indent+1)
			default:
				fmt.Fprintf(w, "%s- %s\n", pad, scalar(e))
			}
		}
	default:
		fmt.Fprintf(w, "%s%s\n", pad, scalar(v))
	}
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func sevColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "\033[1;31m"
	case "high":
		return "\033[31m"
	case "medium":
		return "\033[33m"
	case "low":
		return "\033[36m"
	}
	return ansiDim
}

func paint(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + resetColor
}

func sevRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// fetchJSON performs an authenticated GET and decodes the JSON body.
func fetchJSON(path string) (any, []byte, error) {
	b, code, err := doRequest("GET", path, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if code >= 300 {
		return nil, b, fmt.Errorf("HTTP %d: %s", code, truncate(string(b), 400))
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, b, fmt.Errorf("decode %s: %w", path, err)
	}
	return v, b, nil
}

func asList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case map[string]any:
		for _, k := range []string{"items", "findings", "detections", "data"} {
			if l, ok := x[k].([]any); ok {
				return l
			}
		}
	}
	return nil
}

// ---- findings / detections with --output ----

func listCmd(out io.Writer, path string, args []string, filters ...string) error {
	format, err := outputFormat(args, "json")
	if err != nil {
		return err
	}
	q := pickFlags(args, filters...)
	if format == "json" {
		return getQuery(path, q)
	}
	vals := url.Values{}
	for k, v := range q {
		if v != "" {
			vals.Set(k, v)
		}
	}
	p := path
	if enc := vals.Encode(); enc != "" {
		p += "?" + enc
	}
	v, _, err := fetchJSON(p)
	if err != nil {
		return err
	}
	if format == "yaml" {
		writeYAMLish(out, v, 0)
		return nil
	}
	rows := asList(v)
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tHOST\tRULE\tSTATUS")
	for _, r := range rows {
		m, _ := r.(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			truncate(strFrom(m, "id"), 24), strFrom(m, "severity"), truncate(strFrom(m, "host"), 28),
			truncate(strFrom(m, "rule"), 36), strFrom(m, "status"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d row(s)\n", len(rows))
	return nil
}

// ---- attack matrix ----

func attackCmd(out io.Writer, args []string) error {
	format, err := outputFormat(args, "table")
	if err != nil {
		return err
	}
	v, raw, err := fetchJSON("/v1/attack/matrix")
	if err != nil {
		return err
	}
	switch format {
	case "json":
		return printJSON(raw)
	case "yaml":
		writeYAMLish(out, v, 0)
		return nil
	}
	m, _ := v.(map[string]any)
	color := useColor(os.Stdout)
	fmt.Fprintf(out, "%s  coverage %d/%d (%d%%)  observed hits %d\n\n",
		strFrom(m, "framework"), intFrom(m, "covered"), intFrom(m, "total"), intFrom(m, "coverage_pct"), intFrom(m, "observed_hits"))
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TACTIC\tCOVERED\tHITS\tTECHNIQUES")
	tactics, _ := m["tactics"].([]any)
	for _, t := range tactics {
		tm, _ := t.(map[string]any)
		cov := "no"
		if b, _ := tm["covered"].(bool); b {
			cov = "yes"
		}
		hits := intFrom(tm, "hits")
		hs := strconv.Itoa(hits)
		if hits > 0 {
			hs = paint(color, "\033[1;31m", hs)
		}
		covStr := paint(color, ansiDim, cov)
		if cov == "yes" {
			covStr = paint(color, ansiGreen, cov)
		}
		techs, _ := tm["techniques"].([]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", strFrom(tm, "tactic"), covStr, hs, len(techs))
	}
	return tw.Flush()
}

// ---- compliance score ----

func complianceScoreCmd(out io.Writer, args []string) error {
	format, err := outputFormat(args, "table")
	if err != nil {
		return err
	}
	v, raw, err := fetchJSON("/v1/compliance/score")
	if err != nil {
		return err
	}
	switch format {
	case "json":
		return printJSON(raw)
	case "yaml":
		writeYAMLish(out, v, 0)
		return nil
	}
	m, _ := v.(map[string]any)
	fmt.Fprintf(out, "Overall posture: %d (grade %s)  [%s]\n\n", intFrom(m, "overall"), strFrom(m, "grade"), strFrom(m, "mode"))
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "FRAMEWORK\tSCORE\tGRADE\tFAILING")
	fws, _ := m["frameworks"].([]any)
	for _, f := range fws {
		fm, _ := f.(map[string]any)
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d\n", strFrom(fm, "framework"), intFrom(fm, "score"), strFrom(fm, "grade"), intFrom(fm, "failing"))
	}
	return tw.Flush()
}

// ---- watch (SSE) ----

type watchOpts struct {
	MinSeverity string
	MaxEvents   int // 0 = unlimited
	Backoff     time.Duration
	MaxBackoff  time.Duration
	Color       bool
}

func watchCmd(ctx context.Context, out io.Writer, args []string) error {
	pf := pickFlags(args, "severity", "max-events")
	o := watchOpts{MinSeverity: pf["severity"], Backoff: time.Second, MaxBackoff: 30 * time.Second, Color: useColor(os.Stdout)}
	if o.MinSeverity != "" && sevRank(o.MinSeverity) == 0 {
		return fmt.Errorf("invalid --severity %q (low|medium|high|critical)", o.MinSeverity)
	}
	if s := pf["max-events"]; s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid --max-events %q", s)
		}
		o.MaxEvents = n
	}
	return watchStream(ctx, out, o)
}

type fatalErr struct{ error }

func watchStream(ctx context.Context, out io.Writer, o watchOpts) error {
	ensureConfig()
	if apiToken() == "" {
		return fmt.Errorf("set KAVACH_TOKEN (or ~/.kavach/api-key)")
	}
	count := 0
	delay := o.Backoff
	for {
		n, err := streamOnce(ctx, out, o, o.MaxEvents-count)
		count += n
		if n > 0 {
			delay = o.Backoff
		}
		if ctx.Err() != nil || (o.MaxEvents > 0 && count >= o.MaxEvents) {
			return nil
		}
		if fe, ok := err.(fatalErr); ok {
			return fe.error
		}
		msg := "stream closed"
		if err != nil {
			msg = err.Error()
		}
		fmt.Fprintf(os.Stderr, "kavachctl: %s; reconnecting in %s\n", msg, delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if delay *= 2; delay > o.MaxBackoff {
			delay = o.MaxBackoff
		}
	}
}

// streamOnce runs a single SSE connection and returns the events printed.
func streamOnce(ctx context.Context, out io.Writer, o watchOpts, remaining int) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/stream", nil)
	if err != nil {
		return 0, fatalErr{err}
	}
	req.Header.Set("Authorization", "Bearer "+apiToken())
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-Kavach-Actor", firstEnv("KAVACH_CLI_ACTOR", "kavachctl"))
	resp, err := httpClient(0).Do(req)
	if err != nil {
		return 0, annotateTLSErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return 0, fatalErr{fmt.Errorf("HTTP %d: token rejected by /v1/stream", resp.StatusCode)}
	}
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP %d from /v1/stream", resp.StatusCode)
	}
	min := sevRank(o.MinSeverity)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	event := ""
	printed := 0
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			ev := event
			event = ""
			if ev != "" && ev != "finding" {
				continue
			}
			var d map[string]any
			if json.Unmarshal([]byte(data), &d) != nil {
				continue
			}
			if sevRank(strFrom(d, "severity")) < min {
				continue
			}
			printEvent(out, d, o.Color)
			printed++
			if o.MaxEvents > 0 && printed >= remaining {
				return printed, nil
			}
		case line == "":
			event = ""
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return printed, err
	}
	return printed, nil
}

func printEvent(out io.Writer, d map[string]any, color bool) {
	sev := strings.ToUpper(strFrom(d, "severity"))
	ts := strFrom(d, "time")
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		ts = t.Local().Format("15:04:05")
	}
	tech := strFrom(d, "technique_id")
	if tech != "" {
		tech = " " + tech
	}
	fmt.Fprintf(out, "%s  %s  %-24s %s%s  %s\n", ts, paint(color, sevColor(sev), fmt.Sprintf("%-8s", sev)),
		truncate(strFrom(d, "host"), 24), strFrom(d, "rule"), tech, truncate(strFrom(d, "description"), 80))
}

// ---- doctor ----

func probe(path string) (int, error) {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := httpClient(10 * time.Second).Do(req)
	if err != nil {
		return 0, annotateTLSErr(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

func doctorCmd(out io.Writer) error {
	ensureConfig()
	fails := 0
	color := useColor(os.Stdout)
	line := func(ok, warn bool, name, detail string) {
		mark := paint(color, ansiGreen, "ok  ")
		if warn {
			mark = paint(color, "\033[33m", "warn")
		}
		if !ok {
			mark = paint(color, "\033[31m", "FAIL")
			fails++
		}
		fmt.Fprintf(out, "[%s] %-14s %s\n", mark, name, detail)
	}
	if strings.TrimSpace(os.Getenv("KAVACH_URL")) != "" {
		line(true, false, "KAVACH_URL", base)
	} else {
		line(true, true, "KAVACH_URL", "unset; using default "+base)
	}
	tok := apiToken()
	if tok == "" {
		line(false, false, "KAVACH_TOKEN", "not set (env, ~/.kavach/api-key, ZYVOR_EDR_TOKEN)")
	} else {
		line(true, false, "KAVACH_TOKEN", fmt.Sprintf("set (%d chars)", len(tok)))
	}
	for _, p := range []string{"/livez", "/readyz"} {
		code, err := probe(p)
		switch {
		case err != nil:
			line(false, false, p, err.Error())
		case code == 200:
			line(true, false, p, "HTTP 200")
		default:
			line(false, false, p, fmt.Sprintf("HTTP %d", code))
		}
	}
	if tok != "" {
		_, code, err := doRequest("GET", "/v1/summary", nil, nil)
		switch {
		case err != nil:
			line(false, false, "auth", err.Error())
		case code == 401 || code == 403:
			line(false, false, "auth", fmt.Sprintf("HTTP %d: token rejected", code))
		case code >= 300:
			line(false, false, "auth", fmt.Sprintf("HTTP %d from /v1/summary", code))
		default:
			line(true, false, "auth", "token accepted (/v1/summary)")
		}
	} else {
		line(false, false, "auth", "skipped (no token)")
	}
	switch {
	case !strings.HasPrefix(base, "https://"):
		line(true, true, "tls", "plain HTTP; token is sent unencrypted")
	case tlsInsecure() && urlIsLoopback(base):
		line(true, false, "tls", "https, verification skipped on loopback")
	case tlsInsecure():
		line(true, true, "tls", "verification disabled (KAVACH_TLS_INSECURE) on a non-loopback host")
	default:
		line(true, false, "tls", "https, certificate verified (self-signed? set KAVACH_TLS_INSECURE=true)")
	}
	if fails > 0 {
		return fmt.Errorf("doctor: %d check(s) failed", fails)
	}
	fmt.Fprintln(out, "all checks passed")
	return nil
}

// ---- completion ----

func topLevelCommands() []string {
	return []string{
		"status", "version", "findings", "detections", "incidents", "timeline", "recent-events", "hunt",
		"fleet", "hosts", "host-groups", "agents", "tenants", "sensor", "sensor-health", "ebpf", "finance",
		"sectors", "containment", "rtr", "cases", "threat-graph", "storyline", "air", "intel", "identity",
		"ueba", "watchlists", "ioc", "ioa", "exclusions", "rules", "overwatch", "dns", "modules", "world",
		"discover", "spotlight", "exposure", "compliance", "attack", "metrics", "zero-trust", "sbom", "fim",
		"persistence", "firewall", "browser", "casb", "cnapp", "ot", "ai", "audit", "report", "siem", "fusion",
		"connectors", "cloud", "mobile", "risk", "trends", "export", "notes", "saved-searches", "alerts", "journal", "get", "watch", "doctor", "completion", "lab", "soc", "posture", "help",
	}
}

func completionCmd(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kavachctl completion bash|zsh|fish")
	}
	cmds := strings.Join(topLevelCommands(), " ")
	switch args[0] {
	case "bash":
		fmt.Fprintf(out, `_kavachctl() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "%s" -- "$cur") )
  else
    COMPREPLY=( $(compgen -W "--json --output --severity --host --rule --status --help --days --bucket --format --out --force --since --finding --min-severity --type --url --rule-contains --host-contains --framework --hours --explain --limit --events --id --name --interval --ttl-days --tlp --criticality --owner --tags" -- "$cur") )
  fi
}
complete -F _kavachctl kavachctl
`, cmds)
	case "zsh":
		fmt.Fprintf(out, `#compdef kavachctl
_kavachctl() {
  local -a cmds
  cmds=(%s)
  if (( CURRENT == 2 )); then
    _describe 'command' cmds
  else
    _arguments '--json[raw JSON]' '--output[table|json|yaml]:format:(table json yaml)' '--severity[severity filter]:sev:(low medium high critical)' '--host[host]' '--rule[rule]' '--status[status]' '--days[trend window]:days:(7 14 30)' '--bucket[bucket]:bucket:(hour day)' '--format[export format]:fmt:(csv json ndjson html)' '--out[output file]:file:_files' '--force[overwrite]' '--since[RFC3339]' '--finding[finding id]' '--min-severity[alert min severity]:sev:(low medium high critical)' '--type[alert type]:type:(webhook slack)' '--url[destination]' '--rule-contains[substring]' '--host-contains[substring]' '--framework[framework]:fw:(cis nist soc2 iso27001)' '--hours[window hours]' '--explain[score breakdown]' '--limit[row limit]' '--events[events file]:file:_files' '--id[id]' '--name[name]' '--interval[minutes]' '--ttl-days[days]' '--tlp[tlp]:tlp:(clear green amber red)' '--criticality[1-5]:n:(1 2 3 4 5)' '--owner[owner]' '--tags[tags]'
  fi
}
compdef _kavachctl kavachctl
`, cmds)
	case "fish":
		fmt.Fprintln(out, "complete -c kavachctl -f")
		fmt.Fprintf(out, "complete -c kavachctl -n '__fish_use_subcommand' -a '%s'\n", cmds)
		fmt.Fprintln(out, "complete -c kavachctl -l json -d 'raw JSON'")
		fmt.Fprintln(out, "complete -c kavachctl -l output -x -a 'table json yaml'")
		fmt.Fprintln(out, "complete -c kavachctl -l severity -x -a 'low medium high critical'")
		fmt.Fprintln(out, "complete -c kavachctl -l days -x -a '7 14 30'")
		fmt.Fprintln(out, "complete -c kavachctl -l bucket -x -a 'hour day'")
		fmt.Fprintln(out, "complete -c kavachctl -l format -x -a 'csv json ndjson html'")
		fmt.Fprintln(out, "complete -c kavachctl -l out -r")
		fmt.Fprintln(out, "complete -c kavachctl -l force")
		fmt.Fprintln(out, "complete -c kavachctl -l min-severity -x -a 'low medium high critical'")
		fmt.Fprintln(out, "complete -c kavachctl -l type -x -a 'webhook slack'")
		fmt.Fprintln(out, "complete -c kavachctl -l framework -x")
		fmt.Fprintln(out, "complete -c kavachctl -l hours -x")
		fmt.Fprintln(out, "complete -c kavachctl -l explain -d 'score breakdown'")
		fmt.Fprintln(out, "complete -c kavachctl -l events -r")
		fmt.Fprintln(out, "complete -c kavachctl -l tlp -x -a 'clear green amber red'")
		fmt.Fprintln(out, "complete -c kavachctl -l criticality -x -a '1 2 3 4 5'")
	default:
		return fmt.Errorf("unknown shell %q (bash|zsh|fish)", args[0])
	}
	return nil
}
