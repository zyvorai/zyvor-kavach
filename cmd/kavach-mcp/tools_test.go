package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

func TestKavachMCPToolsListAndCall(t *testing.T) {
	dir := t.TempDir()
	store, err := edr.NewStore(filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	token := "test-token-12345678"
	_ = store.Append(edr.Finding{
		ID: "f1", Time: time.Now().UTC(), Host: "h1", Rule: "download-execute",
		Severity: "high", Description: "test", Evidence: edr.Event{Host: "h1", Executable: "/bin/curl", PID: 1},
	})
	api := edr.APIWithCredentials(token, store, nil)
	ts := httptest.NewServer(api)
	defer ts.Close()

	c := &client{base: ts.URL, token: token, http: ts.Client(), actor: "test"}
	srv, err := buildServer(c, true)
	if err != nil {
		t.Fatal(err)
	}

	// tools/list
	var buf bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Serve(ctx, in, &buf); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "kavach_findings") || !strings.Contains(out, "kavach_ai_capabilities") {
		t.Fatalf("missing tools in list: %s", out)
	}
	if !strings.Contains(out, "kavach_ai_chat") {
		t.Fatalf("mutations should be registered: %s", out)
	}

	// tools/call findings
	var callOut bytes.Buffer
	callIn := bytes.NewBufferString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kavach_findings","arguments":{}}}` + "\n")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_ = srv.Serve(ctx2, callIn, &callOut)
	if !strings.Contains(callOut.String(), "download-execute") {
		t.Fatalf("findings call: %s", callOut.String())
	}

	// read-only server should omit mutate tools
	srvRO, err := buildServer(c, false)
	if err != nil {
		t.Fatal(err)
	}
	var roBuf bytes.Buffer
	roIn := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	_ = srvRO.Serve(ctx3, roIn, &roBuf)
	if strings.Contains(roBuf.String(), `"name":"kavach_ai_chat"`) {
		t.Fatalf("mutate tool leaked into read-only: %s", roBuf.String())
	}
}
