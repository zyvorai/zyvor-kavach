// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func statusCmd(args []string, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	asJSON := false
	wait := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--wait":
			wait = true
		case "-h", "--help":
			fmt.Fprintln(out, "kavachctl status [--json] [--wait]")
			return nil
		default:
			return fmt.Errorf("unknown status flag: %s", a)
		}
	}
	if !asJSON {
		maybeBanner()
	}

	deadline := time.Now().Add(2 * time.Minute)
	for {
		rep, err := collectStatusReport()
		if err != nil {
			if !wait || time.Now().After(deadline) {
				return err
			}
			fmt.Fprintf(os.Stderr, "waiting for controller: %v\n", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if asJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		formatStatusReport(out, rep)
		if wait && !rep.Healthy {
			if time.Now().After(deadline) {
				return fmt.Errorf("controller not healthy after --wait")
			}
			time.Sleep(3 * time.Second)
			continue
		}
		if !rep.Healthy {
			return fmt.Errorf("controller unhealthy: %s", rep.Summary)
		}
		return nil
	}
}

type statusReport struct {
	URL         string         `json:"url"`
	Healthy     bool           `json:"healthy"`
	HealthBody  string         `json:"health,omitempty"`
	Findings    int            `json:"findings"`
	High        int            `json:"highSeverity"`
	Critical    int            `json:"criticalSeverity"`
	Hosts       int            `json:"hosts"`
	FleetOnline int            `json:"fleetOnline"`
	FleetTotal  int            `json:"fleetTotal"`
	Agents      []statusAgent  `json:"agents,omitempty"`
	Summary     string         `json:"summary"`
	RawSummary  map[string]any `json:"rawSummary,omitempty"`
}

type statusAgent struct {
	Host   string `json:"host"`
	Online bool   `json:"online"`
	Seen   string `json:"lastSeen,omitempty"`
}

func collectStatusReport() (*statusReport, error) {
	ensureConfig()
	rep := &statusReport{URL: base}

	hb, code, err := doRequest("GET", "/healthz", nil, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("healthz HTTP %d: %s", code, strings.TrimSpace(string(hb)))
	}
	rep.HealthBody = strings.TrimSpace(string(hb))
	rep.Healthy = strings.EqualFold(rep.HealthBody, "ok") || code == 200

	sb, code, err := doRequest("GET", "/v1/summary", nil, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("summary HTTP %d: %s", code, truncate(string(sb), 200))
	}
	var sum map[string]any
	_ = json.Unmarshal(sb, &sum)
	rep.RawSummary = sum
	rep.Findings = intFrom(sum, "findings", "Findings", "count")
	rep.High = intFrom(sum, "high", "high_severity", "High")
	rep.Critical = intFrom(sum, "critical", "critical_severity", "Critical")
	rep.Hosts = intFrom(sum, "hosts", "Hosts", "host_count")

	fb, code, err := doRequest("GET", "/v1/fleet", nil, nil)
	if err == nil && code < 300 {
		var fleet any
		_ = json.Unmarshal(fb, &fleet)
		switch v := fleet.(type) {
		case []any:
			rep.FleetTotal = len(v)
			for _, item := range v {
				m, _ := item.(map[string]any)
				if m == nil {
					continue
				}
				online := boolFrom(m, "online", "Online")
				if online {
					rep.FleetOnline++
				}
				rep.Agents = append(rep.Agents, statusAgent{
					Host:   strFrom(m, "host", "hostname", "Host", "id"),
					Online: online,
					Seen:   strFrom(m, "last_seen", "lastSeen", "seen"),
				})
			}
		case map[string]any:
			if arr, ok := v["agents"].([]any); ok {
				rep.FleetTotal = len(arr)
				for _, item := range arr {
					m, _ := item.(map[string]any)
					if m == nil {
						continue
					}
					online := boolFrom(m, "online", "Online")
					if online {
						rep.FleetOnline++
					}
					rep.Agents = append(rep.Agents, statusAgent{
						Host:   strFrom(m, "host", "hostname", "Host", "id"),
						Online: online,
						Seen:   strFrom(m, "last_seen", "lastSeen", "seen"),
					})
				}
			}
		}
	}

	if rep.Healthy {
		rep.Summary = fmt.Sprintf("ok · %d findings · fleet %d/%d online", rep.Findings, rep.FleetOnline, rep.FleetTotal)
	} else {
		rep.Summary = "controller not healthy"
	}
	return rep, nil
}

func formatStatusReport(out io.Writer, rep *statusReport) {
	fmt.Fprintf(out, "%s\n", colorize(os.Stdout, ansiBold, "Kavach status"))
	fmt.Fprintf(out, "  URL        %s\n", rep.URL)
	health := rep.HealthBody
	if health == "" {
		health = "unknown"
	}
	fmt.Fprintf(out, "  Health     %s\n", colorize(os.Stdout, ansiGreen, health))
	fmt.Fprintf(out, "  Findings   %d  (high %d · critical %d)\n", rep.Findings, rep.High, rep.Critical)
	fmt.Fprintf(out, "  Hosts      %d\n", rep.Hosts)
	fmt.Fprintf(out, "  Fleet      %d/%d online\n", rep.FleetOnline, rep.FleetTotal)
	if len(rep.Agents) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s\n", colorize(os.Stdout, ansiDim, "Agents"))
		for _, a := range rep.Agents {
			mark := "·"
			if a.Online {
				mark = colorize(os.Stdout, ansiGreen, "●")
			}
			extra := a.Seen
			if extra != "" {
				extra = "  " + colorize(os.Stdout, ansiDim, extra)
			}
			fmt.Fprintf(out, "  %s %s%s\n", mark, a.Host, extra)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s\n", rep.Summary)
}

func intFrom(m map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			case json.Number:
				i, _ := n.Int64()
				return int(i)
			}
		}
	}
	// nested summary shapes
	for _, nest := range []string{"counts", "summary", "metrics"} {
		if child, ok := m[nest].(map[string]any); ok {
			if n := intFrom(child, keys...); n != 0 {
				return n
			}
		}
	}
	return 0
}

func strFrom(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch s := v.(type) {
			case string:
				if s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func boolFrom(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch b := v.(type) {
			case bool:
				return b
			case string:
				return strings.EqualFold(b, "true") || b == "1" || strings.EqualFold(b, "online")
			}
		}
	}
	if s := strFrom(m, "status", "state"); s != "" {
		return strings.EqualFold(s, "online") || strings.EqualFold(s, "active")
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
