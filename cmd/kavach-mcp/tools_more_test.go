package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func listTools(t *testing.T, allow bool) string {
	t.Helper()
	srv, err := buildServer(&client{base: "http://127.0.0.1:1"}, allow)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Serve(ctx, in, &buf)
	return buf.String()
}

func TestMoreToolsGating(t *testing.T) {
	ro := listTools(t, false)
	rw := listTools(t, true)
	for _, tl := range moreReadTools() {
		if tl.method != "GET" {
			t.Fatalf("read tool %s not GET", tl.name)
		}
		if !strings.Contains(ro, `"name":"`+tl.name+`"`) {
			t.Fatalf("missing read tool %s", tl.name)
		}
	}
	for _, tl := range moreMutateTools() {
		if strings.Contains(ro, `"name":"`+tl.name+`"`) {
			t.Fatalf("mutation %s leaked into read-only", tl.name)
		}
		if !strings.Contains(rw, `"name":"`+tl.name+`"`) {
			t.Fatalf("missing mutation %s", tl.name)
		}
		if strings.Contains(tl.path, "retention") || strings.Contains(tl.name, "purge") {
			t.Fatalf("forbidden tool %s", tl.name)
		}
	}
}
