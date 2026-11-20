package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContentCustomCtl(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	h := func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		omJSON(w, map[string]any{"ok": true, "pack": "export", "rules": []any{}})
	}
	for _, p := range []string{"GET /v1/content/custom", "POST /v1/content/custom", "DELETE /v1/content/custom/{id}",
		"POST /v1/content/custom/{id}/dryrun", "POST /v1/content/export", "POST /v1/content/import"} {
		mux.HandleFunc(p, h)
	}
	setupMock(t, mux)
	dir := t.TempDir()
	rule := filepath.Join(dir, "r.json")
	if err := os.WriteFile(rule, []byte(`{"id":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	exp := filepath.Join(dir, "out.json")
	run := func(args ...string) {
		t.Helper()
		var buf strings.Builder
		ok, err := ccDispatch(append([]string{"content", "custom"}, args...), &buf)
		if !ok || err != nil {
			t.Fatalf("%v: handled=%v err=%v", args, ok, err)
		}
	}
	run("list")
	run("put", rule)
	run("rm", "x")
	run("dryrun", "x", rule)
	run("export", "--source", "all", "--ids", "a,b", "--tactic", "Execution")
	run("export", "--out", exp)
	run("import", rule, "--validate-only", "--format", "sigma")
	want := []string{"GET /v1/content/custom ", `POST /v1/content/custom {"id":"x"}`, "DELETE /v1/content/custom/x ",
		`POST /v1/content/custom/x/dryrun {"id":"x"}`, `"ids":["a","b"]`, "POST /v1/content/export {}",
		"POST /v1/content/import?format=sigma&validate_only=true"}
	for i, w := range want {
		if i >= len(got) || !strings.Contains(got[i], w) {
			t.Fatalf("request %d = %q, want containing %q", i, got[i], w)
		}
	}
	if _, err := os.Stat(exp); err != nil {
		t.Fatal("export --out did not write file")
	}
	var buf strings.Builder
	if ok, err := ccDispatch([]string{"content", "custom", "bogus"}, &buf); !ok || err == nil {
		t.Fatal("usage error expected")
	}
	if ok, _ := ccDispatch([]string{"findings"}, &buf); ok {
		t.Fatal("must not claim other commands")
	}
}
