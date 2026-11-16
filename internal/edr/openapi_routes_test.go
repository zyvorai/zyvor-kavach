package edr

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// openapiAllowlist lists routes that are intentionally absent from
// docs/openapi.yaml. Keys are "METHOD /normalised/path" (path params as {}).
// Every entry needs a reason; stale entries fail the test.
var openapiAllowlist = map[string]string{}

var (
	reLiteralRoute = regexp.MustCompile(`\.Handle(?:Func)?\(\s*"([A-Z]+) (/[^"]*)"\s*,`)
	reHelperRoute  = regexp.MustCompile(`(?:registerJSONList\(mux,\s*token,\s*"([A-Z]+) (/[^"]*)"|\bget\("(/v1/[^"]*)")`)
	reParam        = regexp.MustCompile(`\{[^}]*\}`)
)

func normRoute(method, path string) string {
	path = strings.TrimSuffix(path, "{$}")
	return method + " " + reParam.ReplaceAllString(path, "{}")
}

// registeredRoutes scans non-test sources of this package for route
// registrations, including helper wrappers and loop-registered families.
func registeredRoutes(t *testing.T) map[string]string {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	out := map[string]string{}
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
			if m := reLiteralRoute.FindStringSubmatch(line); m != nil {
				out[normRoute(m[1], m[2])] = f
			}
			for _, m := range reHelperRoute.FindAllStringSubmatch(line, -1) {
				if m[3] != "" {
					// get("/v1/..") closures are GET-only wherever defined.
					out[normRoute("GET", m[3])] = f
				} else {
					out[normRoute(m[1], m[2])] = f
				}
			}
		}
	}
	// Loop-registered families (telemetry_types.go, inspect_contract.go,
	// detect_sched_http.go) whose literal is built with string concatenation.
	for _, ty := range TelemetryTypes {
		out["POST /v1/events/"+ty] = "telemetry_types.go"
		out["GET /v1/events/"+ty] = "telemetry_types.go"
	}
	for _, k := range inspectKinds {
		out["POST /v1/inspect/"+k] = "inspect_contract.go"
	}
	for _, s := range []string{"dryrun", "run"} {
		out["POST /v1/detections/scheduled/{}/"+s] = "detect_sched_http.go"
	}
	return out
}

// openapiOps parses the paths section of docs/openapi.yaml (stdlib only).
func openapiOps(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]bool{}
	inPaths := false
	cur := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if inPaths && line != "" && line[0] != ' ' && line[0] != '#' {
			break
		}
		if !inPaths {
			continue
		}
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(strings.TrimRight(line, " "), ":") {
			cur = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") && cur != "" {
			k := strings.TrimSuffix(strings.TrimSpace(line), ":")
			switch k {
			case "get", "post", "put", "delete", "patch":
				ops[normRoute(strings.ToUpper(k), cur)] = true
			}
		}
	}
	return ops
}

func TestOpenAPICoversRegisteredRoutes(t *testing.T) {
	routes := registeredRoutes(t)
	ops := openapiOps(t)
	if len(routes) < 300 || len(ops) < 100 {
		t.Fatalf("extraction looks broken: routes=%d ops=%d", len(routes), len(ops))
	}
	var missing []string
	for r, f := range routes {
		if ops[r] {
			continue
		}
		if _, ok := openapiAllowlist[r]; ok {
			continue
		}
		missing = append(missing, r+"  ("+f+")")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d registered routes missing from docs/openapi.yaml (add them or allowlist with a reason):\n%s", len(missing), strings.Join(missing, "\n"))
	}
	for r, why := range openapiAllowlist {
		if why == "" {
			t.Errorf("allowlist entry %q needs a reason", r)
		}
		if _, ok := routes[r]; !ok {
			t.Errorf("allowlist entry %q is not a registered route (stale)", r)
		}
	}
}
