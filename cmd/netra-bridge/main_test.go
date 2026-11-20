package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBridge(t *testing.T) {
	token := strings.Repeat("a", 20)
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing token")
		}
		count++
		w.Write([]byte(`{"correlations":0}`))
	}))
	defer srv.Close()
	stream := `{"time":"2026-11-12T00:00:00Z","host":"node-1","pid":42,"destination":"10.0.0.2:443","verdict":"deny"}`
	if err := run(context.Background(), strings.NewReader(stream), srv.URL, token, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("got %d events", count)
	}
	if err := run(context.Background(), strings.NewReader(`{"host":"","pid":42}`), srv.URL, token, srv.Client()); err == nil {
		t.Fatal("invalid stream accepted")
	}
}
