package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAIPlatformBeyondFalcon(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	token := "test-token-12345678"
	_ = store.Append(Finding{
		ID: "f-ai-1", Time: time.Now().UTC(), Host: "h1", Rule: "ransomware-burst",
		Severity: "high", Description: "burst", Evidence: Event{Host: "h1", Executable: "/tmp/x", Command: "encrypt", PID: 9},
	})
	h := APIWithCredentials(token, store, nil)

	gets := []string{
		"/v1/ai/capabilities", "/v1/ai/chat", "/v1/ai/cluster", "/v1/ai/forecast",
		"/v1/ai/classify", "/v1/ai/anomaly", "/v1/ai/agents", "/v1/ai/briefing",
		"/v1/ai/stream", "/v1/ai/guardian", "/v1/ai/xdr-fusion", "/v1/ai/embeddings",
		"/v1/ai/attack-path?id=f-ai-1", "/v1/ai/narrative?id=f-ai-1",
		"/v1/ai/similarity?id=f-ai-1", "/v1/ai/fp-score?id=f-ai-1",
		"/v1/ai/remediation?id=f-ai-1", "/v1/ai/report?id=f-ai-1",
		"/v1/ai/playbook-suggest?id=f-ai-1", "/v1/ai/memory",
	}
	for _, p := range gets {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d %s", p, rec.Code, rec.Body.String())
		}
	}

	posts := []struct {
		path string
		body any
	}{
		{"/v1/ai/chat", map[string]string{"message": "Give me a ransomware briefing"}},
		{"/v1/ai/nl-hunt", map[string]string{"text": "high severity ransomware on h1"}},
		{"/v1/ai/agents/run", map[string]string{"agent": "hunt", "input": "find shells"}},
		{"/v1/ai/what-if", map[string]string{"scenario": "ransomware", "host": "h1"}},
		{"/v1/ai/autopilot", map[string]string{}},
		{"/v1/ai/memory", map[string]string{"preferred_view": "detections"}},
	}
	for _, p := range posts {
		b, _ := json.Marshal(p.body)
		req := httptest.NewRequest(http.MethodPost, p.path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("POST %s -> %d %s", p.path, rec.Code, rec.Body.String())
		}
	}

	if len(AICapabilities()) < 20 {
		t.Fatalf("expected 20+ AI capabilities, got %d", len(AICapabilities()))
	}
	cls := classifyBehavior(Finding{Rule: "ransomware-burst", Description: "x"})
	if cls.Family != "ransomware" {
		t.Fatalf("class %s", cls.Family)
	}
}
