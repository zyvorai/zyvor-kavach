package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestServeInitializeAndToolsList(t *testing.T) {
	srv := New("kavach-mcp", "0.1.0")
	if err := srv.Register(Tool{
		Name: "ping", Description: "ping", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(ctx context.Context, args json.RawMessage) (any, bool, error) {
			return map[string]string{"ok": "pong"}, false, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}` + "\n")
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Serve(ctx, in, &out)
	s := out.String()
	if !strings.Contains(s, "protocolVersion") || !strings.Contains(s, "ping") || !strings.Contains(s, "pong") {
		t.Fatalf("unexpected: %s", s)
	}
}
