package edr

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func telHandler(t *testing.T) http.Handler {
	store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	return API("tok", store)
}

func telDo(h http.Handler, method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestTelemetryRoundTripSummaryView(t *testing.T) {
	h := telHandler(t)
	long := strings.Repeat("x", 1000)
	bodies := map[string]string{
		"registry": `{"host":"h1","time":"2026-01-01T00:00:00Z","key":"HKLM\\Run","value_data":"` + long + `","operation":"set"}`,
		"dns":      `[{"host":"h1","time":"2026-01-01T00:00:00Z","query":"a.example","qtype":"A","answers":["1.2.3.4"]},{"host":"h2","time":"2026-01-01T00:00:00Z","query":"b.example"}]`,
		"auth":     `{"host":"h1","time":"2026-01-01T00:00:00Z","user":"u","source_ip":"10.0.0.1","method":"ssh","outcome":"failure"}`,
		"module":   `{"host":"h1","time":"2026-01-01T00:00:00Z","module_path":"/lib/x.so","kind":"so","signed":true}`,
	}
	for typ, b := range bodies {
		if w := telDo(h, "POST", "/v1/events/"+typ, b, "tok"); w.Code != 200 {
			t.Fatalf("%s: %d %s", typ, w.Code, w.Body)
		}
	}
	w := telDo(h, "GET", "/v1/events/dns?host=h1&limit=10", "", "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "a.example") || strings.Contains(w.Body.String(), "b.example") {
		t.Fatalf("dns get: %d %s", w.Code, w.Body)
	}
	w = telDo(h, "GET", "/v1/events/registry", "", "tok")
	if strings.Contains(w.Body.String(), long) {
		t.Fatal("value_data not truncated")
	}
	w = telDo(h, "GET", "/v1/events/summary", "", "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"dns":2`) {
		t.Fatalf("summary: %s", w.Body)
	}
	if len(RecentTelemetry("module", "h1", 5)) != 1 {
		t.Fatal("RecentTelemetry")
	}
	e := TelemetryEvent{Host: "h", Key: "k", Operation: "set", Signed: true}
	if v := TelemetryMatchView("registry", e); v["key"] != "k" || v["operation"] != "set" {
		t.Fatal(v)
	}
	if v := TelemetryMatchView("module", e); v["signed"] != "true" {
		t.Fatal(v)
	}
}

func TestTelemetryRejects(t *testing.T) {
	h := telHandler(t)
	ok := `{"host":"h","time":"2026-01-01T00:00:00Z","user":"u","method":"ssh","outcome":"success"}`
	cases := []struct {
		name, path, body, auth string
		want                   int
	}{
		{"unauth", "/v1/events/auth", ok, "", 401},
		{"bad token", "/v1/events/auth", ok, "nope", 401},
		{"bad enum", "/v1/events/auth", strings.Replace(ok, "ssh", "telnet", 1), "tok", 400},
		{"bad ip", "/v1/events/auth", strings.Replace(ok, `"user"`, `"source_ip":"zz","user"`, 1), "tok", 400},
		{"unknown field", "/v1/events/auth", strings.Replace(ok, `"user"`, `"x":1,"user"`, 1), "tok", 400},
		{"no host", "/v1/events/dns", `{"time":"2026-01-01T00:00:00Z","query":"a"}`, "tok", 400},
		{"long query", "/v1/events/dns", `{"host":"h","time":"2026-01-01T00:00:00Z","query":"` + strings.Repeat("a", 300) + `"}`, "tok", 400},
		{"oversize body", "/v1/events/dns", `{"host":"` + strings.Repeat("a", 2<<20) + `"}`, "tok", 400},
		{"empty batch", "/v1/events/dns", `[]`, "tok", 400},
		{"garbage", "/v1/events/module", `nope`, "tok", 400},
	}
	for _, c := range cases {
		if w := telDo(h, "POST", c.path, c.body, c.auth); w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, w.Code, c.want)
		}
	}
	big := "[" + strings.Repeat(`{"host":"h","time":"2026-01-01T00:00:00Z","query":"a"},`, telemetryBatchMax) + `{"host":"h","time":"2026-01-01T00:00:00Z","query":"a"}]`
	if w := telDo(h, "POST", "/v1/events/dns", big, "tok"); w.Code != 400 {
		t.Errorf("batch bound: %d", w.Code)
	}
	if w := telDo(h, "GET", "/v1/events/dns", "", ""); w.Code != 401 {
		t.Errorf("unauth get: %d", w.Code)
	}
	if w := telDo(h, "GET", "/v1/events/dns?limit=99999", "", "tok"); w.Code != 400 {
		t.Errorf("limit: %d", w.Code)
	}
}

func TestTelemetryPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.jsonl")
	s, _ := NewTelemetryStore(p, 3)
	for i := 0; i < 5; i++ {
		if err := s.Add("dns", []TelemetryEvent{{Host: "h", Query: "q"}}); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := NewTelemetryStore(p, 3)
	if err != nil || len(s2.Recent("dns", "", 10)) != 3 {
		t.Fatal("reload", err)
	}
}
