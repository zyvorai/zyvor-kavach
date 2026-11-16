// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

// parityExempt lists GET routes that intentionally have no dedicated kavachctl
// command. Keys are "/normalised/path" with path params written as {}. Every
// entry needs a reason; stale entries (route gone, or now covered) fail the
// test. Documented in docs/cli-reference.md.
var parityExempt = map[string]string{
	"/":                   "console HTML shell, not an API",
	"/c/{}":               "console deep-link redirect, not an API",
	"/zyvor-logomark.svg": "static console asset",
	"/zyvor-mark.svg":     "static console asset",
}

var (
	parLit    = regexp.MustCompile(`\.Handle(?:Func)?\(\s*"GET (/[^"]*)"\s*,`)
	parHelper = regexp.MustCompile(`(?:registerJSONList\(mux,\s*token,\s*"GET (/[^"]*)"|\bget\("(/v1/[^"]*)")`)
	parParam  = regexp.MustCompile(`\{[^}]*\}`)
	parCLILit = regexp.MustCompile(`"(/[a-z][^" ]*)"`)
)

func parNorm(p string) string {
	return parParam.ReplaceAllString(strings.TrimSuffix(p, "{$}"), "{}")
}

// parityGETRoutes scans internal/edr sources for GET route registrations.
func parityGETRoutes(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob("../../internal/edr/*.go")
	set := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if m := parLit.FindStringSubmatch(line); m != nil {
				set[parNorm(m[1])] = true
			}
			for _, m := range parHelper.FindAllStringSubmatch(line, -1) {
				p := m[1]
				if p == "" {
					p = m[2]
				}
				set[parNorm(p)] = true
			}
		}
	}
	for _, ty := range edr.TelemetryTypes {
		set["/v1/events/"+ty] = true
	}
	var out []string
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// parityCLIPaths collects every path literal used by kavachctl sources.
func parityCLIPaths(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range parCLILit.FindAllStringSubmatch(string(b), -1) {
			out = append(out, strings.SplitN(m[1], "?", 2)[0])
		}
	}
	return out
}

// parityCovered: a literal covers a route when equal, when it is the route's
// static prefix before a {param}, or when it ends in "/" (a prefix the code
// extends dynamically, e.g. "/v1/vulns/"+sub).
func parityCovered(lits []string, route string) bool {
	pre := strings.Split(route, "{}")[0]
	for _, l := range lits {
		if l == route {
			return true
		}
		if strings.Contains(route, "{}") && (l == pre || l == strings.TrimSuffix(pre, "/")) {
			return true
		}
		if strings.HasSuffix(l, "/") && strings.HasPrefix(route, l) {
			return true
		}
	}
	return false
}

// TestEveryGETRouteHasCLICommandOrExemption fails when a GET route registered
// in internal/edr has no kavachctl command and no documented exemption.
func TestEveryGETRouteHasCLICommandOrExemption(t *testing.T) {
	routes := parityGETRoutes(t)
	lits := parityCLIPaths(t)
	if len(routes) < 300 || len(lits) < 100 {
		t.Fatalf("extraction looks broken: routes=%d literals=%d", len(routes), len(lits))
	}
	have := map[string]bool{}
	var missing []string
	for _, r := range routes {
		have[r] = true
		if parityCovered(lits, r) {
			continue
		}
		if _, ok := parityExempt[r]; ok {
			continue
		}
		missing = append(missing, r)
	}
	if len(missing) > 0 {
		t.Errorf("GET routes with no kavachctl command and no entry in parityExempt (add a command, or an exemption with a reason, and update docs/cli-reference.md):\n  %s", strings.Join(missing, "\n  "))
	}
	for r, why := range parityExempt {
		if why == "" {
			t.Errorf("exemption %q has no reason", r)
		}
		if !have[r] {
			t.Errorf("stale exemption %q: route no longer registered", r)
		} else if parityCovered(lits, r) {
			t.Errorf("stale exemption %q: route is now covered by a command", r)
		}
	}
}
