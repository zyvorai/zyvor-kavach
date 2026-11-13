package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func customSetup(t *testing.T, dir string) (*http.ServeMux, *Store) {
	t.Helper()
	st, err := testStore(t, filepath.Join(dir, "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCustomContent(mux, "tok", st)
	t.Cleanup(func() { (&customStore{rules: map[string]*ContentRule{}}).apply() })
	return mux, st
}

func customDo(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

const customGood = `{"id":"acme-evil-tool","name":"Evil tool","description":"acme internal evil tool run","tactic":"Execution","technique":"T1059",
"severity":"high","os":"any","event_type":"process","match":{"field":"command","op":"contains","pattern":"acme-evil-tool --pwn"},
"tests":{"positive":[{"command":"/opt/acme-evil-tool --pwn now"}],"negative":[{"command":"/opt/acme-good-tool --run"}]}}`

func TestCustomLifecycle(t *testing.T) {
	dir := t.TempDir()
	mux, st := customSetup(t, dir)
	for _, p := range []string{"GET /v1/content/custom", "POST /v1/content/custom", "POST /v1/content/export", "POST /v1/content/import"} {
		m, path, _ := strings.Cut(p, " ")
		r := httptest.NewRequest(m, path, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("%s unauthenticated: %d", p, w.Code)
		}
	}
	if w := customDo(mux, "POST", "/v1/content/custom", customGood); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	var list struct {
		Count int           `json:"count"`
		Rules []ContentRule `json:"rules"`
	}
	w := customDo(mux, "GET", "/v1/content/custom", "")
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if list.Count != 1 || list.Rules[0].Source != "custom" {
		t.Fatalf("list: %s", w.Body)
	}

	// Live evaluation + ATT&CK matrix.
	fs := contentEvaluate("process", LabEvent{Command: "x acme-evil-tool --pwn"}, Finding{Host: "h", Time: time.Now()})
	if len(fs) != 1 || fs[0].Rule != "acme-evil-tool" {
		t.Fatalf("live eval: %+v", fs)
	}
	mx, _ := json.Marshal(BuildATTACKMatrix(nil))
	if !strings.Contains(string(mx), `"custom_rules":["acme-evil-tool"]`) {
		t.Fatalf("matrix lacks custom rule: %s", mx)
	}

	// Dry run records nothing.
	before := len(st.List())
	w = customDo(mux, "POST", "/v1/content/custom/acme-evil-tool/dryrun", `{"events":[{"command":"acme-evil-tool --pwn"},{"command":"ls"}]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"matched":1`) || len(st.List()) != before {
		t.Fatalf("dryrun: %d %s", w.Code, w.Body)
	}
	if w := customDo(mux, "POST", "/v1/content/custom/nope/dryrun", `{"events":[{}]}`); w.Code != 404 {
		t.Fatal(w.Code)
	}

	// Export then validate-only import, then real import into a second instance.
	exp := customDo(mux, "POST", "/v1/content/export", `{}`)
	if exp.Code != 200 || !strings.Contains(exp.Body.String(), "acme-evil-tool") {
		t.Fatalf("export: %s", exp.Body)
	}

	// Persistence across restart.
	mux2, _ := customSetup(t, dir)
	if w := customDo(mux2, "GET", "/v1/content/custom", ""); !strings.Contains(w.Body.String(), "acme-evil-tool") {
		t.Fatalf("not persisted: %s", w.Body)
	}
	mux3, _ := customSetup(t, t.TempDir())
	if w := customDo(mux3, "POST", "/v1/content/import?validate_only=true", exp.Body.String()); w.Code != 200 || !strings.Contains(w.Body.String(), `"valid":1`) {
		t.Fatalf("validate-only: %d %s", w.Code, w.Body)
	}
	if w := customDo(mux3, "GET", "/v1/content/custom", ""); strings.Contains(w.Body.String(), "acme-evil-tool") {
		t.Fatal("validate-only stored a rule")
	}
	if w := customDo(mux3, "POST", "/v1/content/import", exp.Body.String()); w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}

	// Delete.
	if w := customDo(mux3, "DELETE", "/v1/content/custom/acme-evil-tool", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := customDo(mux3, "DELETE", "/v1/content/custom/acme-evil-tool", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if fs := contentEvaluate("process", LabEvent{Command: "acme-evil-tool --pwn"}, Finding{Host: "h", Time: time.Now()}); len(fs) != 0 {
		t.Fatal("deleted rule still evaluates")
	}
}

func TestCustomRejects(t *testing.T) {
	mux, _ := customSetup(t, t.TempDir())
	var embedded string
	for id := range embeddedRuleIDs() {
		embedded = id
		break
	}
	mut := func(from, to string) string { return strings.Replace(customGood, from, to, 1) }
	cases := map[string]struct {
		body string
		code int
		want string
	}{
		"embedded id":     {mut(`"acme-evil-tool","name"`, `"`+embedded+`","name"`), 409, "embedded"},
		"builtin id":      {mut(`"acme-evil-tool","name"`, `"download-execute","name"`), 400, "built-in"},
		"no negatives":    {mut(`"negative":[{"command":"/opt/acme-good-tool --run"}]`, `"negative":[]`), 400, "negative"},
		"positive misses": {mut(`/opt/acme-evil-tool --pwn now`, `nothing`), 400, "positive sample"},
		"negative hits":   {mut(`/opt/acme-good-tool --run`, `acme-evil-tool --pwn`), 400, "negative sample"},
		"baseline":        {strings.Replace(mut(`"pattern":"acme-evil-tool --pwn"`, `"pattern":"a"`), `/opt/acme-good-tool --run`, `zzz`, 1), 400, "baseline"},
		"unknown field":   {mut(`"severity":"high"`, `"severity":"high","bogus":1`), 400, "bogus"},
		"bad regex":       {mut(`"op":"contains","pattern":"acme-evil-tool --pwn"`, `"op":"regex","pattern":"(x"`), 400, "regex"},
	}
	for name, c := range cases {
		w := customDo(mux, "POST", "/v1/content/custom", c.body)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := customDo(mux, "DELETE", "/v1/content/custom/"+embedded, ""); w.Code != 400 {
		t.Fatalf("delete embedded: %d", w.Code)
	}
}

const sigmaOK = `
title: Acme Suspicious Whoami
id: 1234
description: whoami from a temp dir
status: test
level: medium
tags:
  - attack.discovery
  - attack.t1033
logsource:
  category: process_creation
  product: linux
detection:
  selection_img:
    Image|endswith:
      - '/whoami'
      - '/id'
  selection_cmd:
    CommandLine|contains|all:
      - '--acme'
      - '--probe'
  filter:
    ParentImage|startswith: '/usr/bin/trusted'
  condition: selection_img and selection_cmd and not filter
tests:
  positive:
    - executable: /tmp/whoami
      command: whoami --acme --probe
  negative:
    - executable: /tmp/whoami
      command: whoami
    - executable: /tmp/whoami
      parent_exe: /usr/bin/trusted-x
      command: whoami --acme --probe
`

func TestSigmaImport(t *testing.T) {
	mux, _ := customSetup(t, t.TempDir())
	w := customDo(mux, "POST", "/v1/content/import?format=sigma&validate_only=true", sigmaOK)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"valid":1`) {
		t.Fatalf("sigma validate: %d %s", w.Code, w.Body)
	}
	w = customDo(mux, "POST", "/v1/content/import?format=sigma", sigmaOK)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
		t.Fatalf("sigma import: %d %s", w.Code, w.Body)
	}
	if fs := contentEvaluate("process", LabEvent{Executable: "/x/id", Command: "id --acme --probe"}, Finding{Host: "h", Time: time.Now()}); len(fs) != 1 || fs[0].Rule != "sigma-acme-suspicious-whoami" {
		t.Fatalf("sigma rule not live: %+v", fs)
	}

	bad := strings.Replace(sigmaOK, "Image|endswith:", "Image|base64offset|contains:", 1)
	bad = strings.Replace(bad, "title: Acme Suspicious Whoami", "title: Bad One", 1)
	bad = strings.Replace(bad, "condition: selection_img and selection_cmd and not filter", "condition: 1 of selection_*", 1)
	w = customDo(mux, "POST", "/v1/content/import?format=sigma", bad)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"unsupported":1`) || !strings.Contains(w.Body.String(), "not supported") {
		t.Fatalf("unsupported: %d %s", w.Code, w.Body)
	}
	// Only the first unsupported construct per rule is guaranteed; modifier case separately.
	bad2 := strings.Replace(strings.Replace(sigmaOK, "Image|endswith:", "Image|base64offset|contains:", 1), "Acme Suspicious Whoami", "Bad Two", 1)
	w = customDo(mux, "POST", "/v1/content/import?format=sigma", bad2)
	if !strings.Contains(w.Body.String(), "base64offset") || w.Code != 400 {
		t.Fatalf("modifier: %d %s", w.Code, w.Body)
	}
	// JSON form and wildcard values.
	js := `{"title":"Json Rule","level":"high","tags":["attack.execution","attack.t1059"],"logsource":{"category":"process_creation"},
"detection":{"s":{"CommandLine":"*evil*"},"condition":"s"}}`
	w = customDo(mux, "POST", "/v1/content/import?format=sigma", js)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "wildcard") {
		t.Fatalf("wildcard: %d %s", w.Code, w.Body)
	}
	// Valid conversion but no samples: harness rejects it.
	nt := strings.Split(sigmaOK, "tests:")[0]
	w = customDo(mux, "POST", "/v1/content/import?format=sigma", nt)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "tests") {
		t.Fatalf("no tests: %d %s", w.Code, w.Body)
	}
}

func TestMiniYAML(t *testing.T) {
	v, err := miniYAMLParse("a: 1\nb:\n  - x\n  - 'it''s'\n  - k: v\n    j: [1, \"two\"]\nc: |\n  line1\n  line2\n# c\n")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	want := `{"a":"1","b":["x","it's",{"j":["1","two"],"k":"v"}],"c":"line1\nline2"}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	if _, err := miniYAMLParse("a: &anchor x\n"); err == nil {
		t.Fatal("anchors must be rejected")
	}
}
