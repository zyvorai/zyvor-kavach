// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

const mlUsage = `usage: kavachctl ml <command>
  status [--json]                               model readiness
  lineage [--host H] [--limit N]                rare parent->child process transitions
  similar COMMAND... [--host H]                 nearest known-bad exemplars and host history
  baseline --host H                             per-host hourly activity baseline
  beacons [--min-events N] [--exclude-private] [--host H] [--limit N] [--min-score S]
  synthesize (--finding ID | --command TEXT) [--out FILE]   draft a rule (nothing is saved)
  priority (--finding ID | --host H) [--limit N]            fused triage priority
  reset [--yes]                                 clear learned ML state (mutating)
  replay [--yes]                                relearn from the retained store (mutating)`

// mlInteractive reports whether a confirmation prompt can be answered; tests override it.
var mlInteractive = func() bool { return isTTY(os.Stdin) }

// mlCall performs a request and returns the body; HTTP >= 300 becomes an error carrying the body.
func mlCall(method, path string, body []byte, headers map[string]string) ([]byte, error) {
	b, code, err := doRequest(method, path, body, headers)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(b)), 400))
	}
	return b, nil
}

// mlDispatch handles `kavachctl ml ...`.
func mlDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "ml" {
		return false, nil
	}
	return true, mlRun(out, args[1:])
}

func mlRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", mlUsage)
	}
	pos, f, b := omParse(args[1:], "host", "limit", "min-events", "min-score", "finding", "command", "out")
	j := b["json"]
	switch args[0] {
	case "status":
		return mlGeneric(out, "/v1/ml/status", j)
	case "lineage":
		return mlGeneric(out, omQuery("/v1/ml/lineage", f, "host", "limit"), j)
	case "similar":
		q := strings.TrimSpace(strings.Join(pos, " "))
		if q == "" {
			return fmt.Errorf("usage: kavachctl ml similar COMMAND... [--host H]")
		}
		v := url.Values{"q": {q}}
		if f["host"] != "" {
			v.Set("host", f["host"])
		}
		return mlGeneric(out, "/v1/ml/similar?"+v.Encode(), j)
	case "baseline":
		if f["host"] == "" {
			return fmt.Errorf("usage: kavachctl ml baseline --host H")
		}
		return mlGeneric(out, omQuery("/v1/ml/baseline", f, "host"), j)
	case "beacons":
		v := url.Values{}
		if f["min-events"] != "" {
			v.Set("min_events", f["min-events"])
		}
		if b["exclude-private"] {
			v.Set("exclude_private", "1")
		}
		for _, k := range []string{"host", "limit"} {
			if f[k] != "" {
				v.Set(k, f[k])
			}
		}
		if f["min-score"] != "" {
			v.Set("min_score", f["min-score"])
		}
		p := "/v1/ml/beacons"
		if e := v.Encode(); e != "" {
			p += "?" + e
		}
		return mlBeacons(out, p, j)
	case "synthesize":
		return mlSynthesize(out, f, j)
	case "priority":
		if (f["finding"] == "") == (f["host"] == "") {
			return fmt.Errorf("usage: kavachctl ml priority (--finding ID | --host H) [--limit N]")
		}
		v := url.Values{}
		if f["finding"] != "" {
			v.Set("finding_id", f["finding"])
		} else {
			v.Set("host", f["host"])
		}
		if f["limit"] != "" {
			v.Set("limit", f["limit"])
		}
		return mlPriority(out, "/v1/ml/priority?"+v.Encode(), j)
	case "reset":
		return mlMutate(out, b["yes"], "reset", "/v1/ml/reset", "This clears all learned ML state (lineage, similarity history, baselines).", j)
	case "replay":
		return mlMutate(out, b["yes"], "replay", "/v1/ml/learn/replay", "This relearns the ML models from the retained event store.", j)
	}
	return fmt.Errorf("unknown ml command %q\n%s", args[0], mlUsage)
}

func mlMutate(out io.Writer, yes bool, name, path, warn string, asJSON bool) error {
	if !yes {
		if !mlInteractive() {
			return fmt.Errorf("ml %s is mutating; re-run with --yes to confirm", name)
		}
		fmt.Fprintf(os.Stderr, "%s Continue? [y/N] ", warn)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return fmt.Errorf("aborted")
		}
	}
	raw, err := mlCall("POST", path, []byte("{}"), nil)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	return mlShow(out, raw)
}

func mlGeneric(out io.Writer, path string, asJSON bool) error {
	raw, err := mlCall("GET", path, nil, nil)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	return mlShow(out, raw)
}

// mlShow prints method/status and every nested not_enough_data location up front, then the
// full response as indented JSON.
func mlShow(out io.Writer, raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["method"]; ok {
			fmt.Fprintf(out, "method: %v\n", s)
		}
		if s, ok := m["status"]; ok {
			fmt.Fprintf(out, "status: %v\n", s)
		}
		var nd []string
		mlFindNED("", v, &nd)
		sort.Strings(nd)
		for _, p := range nd {
			fmt.Fprintf(out, "not_enough_data: %s\n", p)
		}
	}
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") != nil {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	fmt.Fprintln(out, buf.String())
	return nil
}

func mlFindNED(path string, v any, acc *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if s, _ := t["status"].(string); s == "not_enough_data" && path != "" {
			*acc = append(*acc, path)
		}
		for k, c := range t {
			mlFindNED(strings.TrimPrefix(path+"."+k, "."), c, acc)
		}
	case []any:
		for i, c := range t {
			mlFindNED(fmt.Sprintf("%s[%d]", path, i), c, acc)
		}
	}
}

func mlBeacons(out io.Writer, path string, asJSON bool) error {
	raw, err := mlCall("GET", path, nil, nil)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var r struct {
		Model        string `json:"model"`
		MinEvents    int    `json:"min_events"`
		SeriesScored int    `json:"series_scored"`
		NotEnough    int    `json:"not_enough_data"`
		Excluded     int    `json:"excluded_benign_periodic"`
		ExclPrivate  bool   `json:"exclude_private"`
		Suspects     []struct {
			Host        string  `json:"host"`
			Destination string  `json:"destination"`
			Status      string  `json:"status"`
			Events      int     `json:"events"`
			PeriodSec   float64 `json:"period_sec"`
			CV          float64 `json:"cv"`
			Score       float64 `json:"score"`
			Level       string  `json:"level"`
		} `json:"suspects"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	fmt.Fprintf(out, "method: %s   min events: %d   scored: %d   exclude private: %v\n", r.Model, r.MinEvents, r.SeriesScored, r.ExclPrivate)
	fmt.Fprintf(out, "not_enough_data: %d series below the minimum event count\n", r.NotEnough)
	fmt.Fprintf(out, "excluded benign periodic: %d\n", r.Excluded)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tDESTINATION\tLEVEL\tSCORE\tEVENTS\tPERIOD_S\tCV\tSTATUS")
	for _, s := range r.Suspects {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.1f\t%d\t%.1f\t%.3f\t%s\n", s.Host, s.Destination, s.Level, s.Score, s.Events, s.PeriodSec, s.CV, s.Status)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(r.Suspects) == 0 {
		fmt.Fprintln(out, "no beacon suspects")
	}
	return nil
}

type mlPriorityRow struct {
	FindingID string  `json:"finding_id"`
	Host      string  `json:"host"`
	Rule      string  `json:"rule"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	Level     string  `json:"level"`
	Coverage  float64 `json:"coverage"`
	Factors   []struct {
		Name  string  `json:"name"`
		Value float64 `json:"value"`
		Note  string  `json:"note"`
	} `json:"factors"`
	Omitted []string `json:"omitted"`
}

func mlPriority(out io.Writer, path string, asJSON bool) error {
	raw, err := mlCall("GET", path, nil, nil)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var r struct {
		Model      string          `json:"model"`
		Note       string          `json:"note"`
		Total      int             `json:"total"`
		Priority   *mlPriorityRow  `json:"priority"`
		Priorities []mlPriorityRow `json:"priorities"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	fmt.Fprintf(out, "method: %s\n", r.Model)
	if r.Priority != nil {
		p := r.Priority
		fmt.Fprintf(out, "finding %s on %s (%s, %s)\nPriority: %.1f (%s)   coverage %.2f\n", p.FindingID, p.Host, p.Rule, p.Severity, p.Score, p.Level, p.Coverage)
		for _, f := range p.Factors {
			fmt.Fprintf(out, "  %-14s %.2f  %s\n", f.Name, f.Value, f.Note)
		}
		for _, o := range p.Omitted {
			fmt.Fprintf(out, "  omitted: %s\n", o)
		}
	} else {
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "FINDING\tHOST\tRULE\tSEVERITY\tPRIORITY\tLEVEL\tCOVERAGE")
		for _, p := range r.Priorities {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%.1f\t%s\t%.2f\n", p.FindingID, p.Host, p.Rule, p.Severity, p.Score, p.Level, p.Coverage)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d findings\n", r.Total)
	}
	if r.Note != "" {
		fmt.Fprintln(out, r.Note)
	}
	return nil
}

func mlSynthesize(out io.Writer, f map[string]string, asJSON bool) error {
	if (f["finding"] == "") == (f["command"] == "") {
		return fmt.Errorf("usage: kavachctl ml synthesize (--finding ID | --command TEXT) [--out FILE]")
	}
	req := map[string]string{}
	if f["finding"] != "" {
		req["finding_id"] = f["finding"]
	} else {
		req["command"] = f["command"]
	}
	body, _ := json.Marshal(req)
	// A 422 still carries the draft rule and the failed validation verdict, so read the body
	// regardless of status and decide afterwards.
	raw, code, err := doRequest("POST", "/v1/ml/synthesize", body, nil)
	if err != nil {
		return err
	}
	var r struct {
		Model      string          `json:"model"`
		Error      string          `json:"error"`
		Rule       json.RawMessage `json:"rule"`
		Validation struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		} `json:"validation"`
		SrcMatches bool     `json:"source_event_matches"`
		Lifecycle  string   `json:"recommended_initial_lifecycle"`
		NextSteps  []string `json:"next_steps"`
	}
	if jerr := json.Unmarshal(raw, &r); jerr != nil || (code >= 300 && len(r.Rule) == 0) {
		if code >= 300 {
			msg := r.Error
			if msg == "" {
				msg = truncate(strings.TrimSpace(string(raw)), 400)
			}
			return fmt.Errorf("HTTP %d: %s", code, msg)
		}
		return jerr
	}
	if f["out"] != "" && len(r.Rule) > 0 {
		var buf bytes.Buffer
		_ = json.Indent(&buf, r.Rule, "", "  ")
		buf.WriteByte('\n')
		if err := os.WriteFile(f["out"], buf.Bytes(), 0o600); err != nil {
			return err
		}
	}
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
	} else {
		fmt.Fprintf(out, "method: %s\n", r.Model)
		if r.Error != "" {
			fmt.Fprintf(out, "no rule proposed: %s\n", r.Error)
		} else {
			var buf bytes.Buffer
			_ = json.Indent(&buf, r.Rule, "", "  ")
			fmt.Fprintf(out, "Proposed rule:\n%s\n", buf.String())
			v := "VALID"
			if !r.Validation.Valid {
				v = "INVALID: " + r.Validation.Error
			}
			fmt.Fprintf(out, "\nValidation: %s\n", v)
			fmt.Fprintf(out, "Source event matches the rule: %v\n", r.SrcMatches)
			fmt.Fprintf(out, "Recommended initial lifecycle: %s\n", r.Lifecycle)
			for _, s := range r.NextSteps {
				fmt.Fprintf(out, "  - %s\n", s)
			}
		}
		fmt.Fprintln(out, "\nNothing was saved or enabled by this command.")
		if f["out"] != "" && len(r.Rule) > 0 {
			fmt.Fprintf(out, "Rule JSON written to %s (local file only).\n", f["out"])
		}
	}
	if code >= 300 {
		if r.Error != "" {
			return fmt.Errorf("HTTP %d: %s", code, r.Error)
		}
		return fmt.Errorf("synthesized rule failed validation (HTTP %d)", code)
	}
	return nil
}
