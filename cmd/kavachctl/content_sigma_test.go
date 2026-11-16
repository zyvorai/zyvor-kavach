package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContentSigmaCtl(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	mux.HandleFunc("POST /v1/content/import/sigma", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		omJSON(w, map[string]any{"dry_run": r.URL.Query().Get("dry_run") != "false", "results": []any{}})
	})
	mux.HandleFunc("POST /v1/content/export/sigma", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, "EXPORT "+string(b))
		omJSON(w, map[string]any{"yaml": "title: x\n", "skipped": []any{map[string]any{"id": "a", "reason": "r"}}})
	})
	setupMock(t, mux)
	dir := t.TempDir()
	for _, n := range []string{"a.yml", "b.yaml", "c.json", "skip.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("title: "+n), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) string {
		t.Helper()
		var buf strings.Builder
		ok, err := sigmaDispatch(append([]string{"content"}, args...), &buf)
		if !ok || err != nil {
			t.Fatalf("%v: handled=%v err=%v", args, ok, err)
		}
		return buf.String()
	}
	out := run("import-sigma", dir)
	if !strings.Contains(out, "dry run") || len(got) != 3 {
		t.Fatalf("dir dry run: %q %v", out, got)
	}
	for _, g := range got {
		if !strings.Contains(g, "dry_run=true") {
			t.Fatalf("default must be dry run: %s", g)
		}
	}
	got = nil
	run("import-sigma", filepath.Join(dir, "a.yml"), "--apply")
	if len(got) != 1 || !strings.Contains(got[0], "dry_run=false") || !strings.Contains(got[0], "title: a.yml") {
		t.Fatalf("apply: %v", got)
	}
	out = run("export-sigma", "--ids", "a,b", "--out", filepath.Join(dir, "o.yml"))
	if !strings.Contains(out, "wrote") || !strings.Contains(got[1], `"ids":["a","b"]`) {
		t.Fatalf("export: %q %v", out, got)
	}
	var buf strings.Builder
	if ok, err := sigmaDispatch([]string{"content", "import-sigma"}, &buf); !ok || err == nil {
		t.Fatal("usage error expected")
	}
	if ok, _ := sigmaDispatch([]string{"content", "custom", "list"}, &buf); ok {
		t.Fatal("must not claim custom commands")
	}
}
