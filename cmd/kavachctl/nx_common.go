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
	"strings"
)

// nxDispatch claims only the new subcommands of validate, vulns, hunt seq,
// feedback, competitive, chains, casetemplates, case (workflow subcommands),
// content (versions) and coverage (blindspots). Anything else returns
// (false, nil) so existing handlers keep working. Observation only.
func nxDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	in := func(names ...string) bool {
		for _, n := range names {
			if sub == n {
				return true
			}
		}
		return false
	}
	rest := []string{}
	if len(args) > 2 {
		rest = args[2:]
	}
	switch args[0] {
	case "validate":
		if in("scenarios", "show", "run", "coverage") {
			return true, nxValidate(out, sub, rest)
		}
	case "vulns":
		if in("priority", "show", "status", "refresh") {
			return true, nxVulns(out, sub, rest)
		}
	case "hunt":
		if sub == "seq" {
			return true, nxHuntSeq(out, rest)
		}
		if in("fields", "explain", "examples") {
			return true, nxHuntSeq(out, args[1:])
		}
	case "feedback":
		return true, nxFeedback(out, args[1:])
	case "competitive":
		return true, nxCompetitive(out, args[1:])
	case "chains":
		return true, nxChains(out, args[1:])
	case "casetemplates":
		return true, nxCaseTemplates(out, args[1:])
	case "case":
		if in("assign", "apply-template", "checklist", "workflow", "journal") {
			return true, nxCaseWorkflow(out, sub, rest)
		}
	case "content":
		if in("versions", "changes", "changelog") {
			return true, nxContent(out, sub, rest)
		}
	case "coverage":
		if in("blindspots", "telemetry") {
			return true, nxCoverage(out, sub, rest)
		}
	}
	return false, nil
}

type nxMap = map[string]any

// nxDo performs a request and returns body and status; err only for transport faults.
func nxDo(method, path string, body any) ([]byte, int, error) {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	return doRequest(method, path, payload, nil)
}

func nxHTTPErr(code int, raw []byte) error {
	return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
}

func nxCall(method, path string, body any) ([]byte, error) {
	raw, code, err := nxDo(method, path, body)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, nxHTTPErr(code, raw)
	}
	return raw, nil
}

func nxDecode(raw []byte) (nxMap, error) {
	var m nxMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("unexpected response: %v", err)
	}
	return m, nil
}

// nxEmit prints raw JSON untouched when asJSON is set.
func nxEmit(out io.Writer, raw []byte, asJSON bool) bool {
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
	}
	return asJSON
}

func nxPretty(out io.Writer, v any) {
	var buf bytes.Buffer
	b, _ := json.Marshal(v)
	if json.Indent(&buf, b, "", "  ") == nil {
		fmt.Fprintln(out, buf.String())
	}
}

func nxQ(path string, flags map[string]string, pairs ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if flags[pairs[i]] != "" {
			v.Set(pairs[i+1], flags[pairs[i]])
		}
	}
	if e := v.Encode(); e != "" {
		return path + "?" + e
	}
	return path
}

func nxPath(parts ...string) string {
	for i := 1; i < len(parts); i++ {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// nxS renders any JSON value as text; null or missing is "unknown".
func nxS(v any) string {
	switch x := v.(type) {
	case nil:
		return "unknown"
	case string:
		if x == "" {
			return "-"
		}
		return x
	case float64:
		return fmt.Sprintf("%g", x)
	case bool:
		return fmt.Sprint(x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func nxJoin(v any) string {
	l, _ := v.([]any)
	parts := make([]string, 0, len(l))
	for _, e := range l {
		parts = append(parts, nxS(e))
	}
	return strings.Join(parts, ",")
}

func nxList(m nxMap, k string) []nxMap { return listOf(m, k) }

func nxSub(m nxMap, k string) nxMap {
	x, _ := m[k].(map[string]any)
	return x
}

func nxStrs(m nxMap, k string) []string {
	l, _ := m[k].([]any)
	out := []string{}
	for _, e := range l {
		out = append(out, nxS(e))
	}
	return out
}

func nxNum(m nxMap, k string) float64 {
	f, _ := m[k].(float64)
	return f
}

// nxConfirm gates mutating commands: --yes, or an interactive y/N prompt.
func nxConfirm(yes bool, name, warn string) error {
	if yes {
		return nil
	}
	if !mlInteractive() {
		return fmt.Errorf("%s is mutating; re-run with --yes to confirm", name)
	}
	fmt.Fprintf(os.Stderr, "%s Continue? [y/N] ", warn)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}
