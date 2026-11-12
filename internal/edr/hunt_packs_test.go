package edr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHuntPacks(t *testing.T) {
	if len(huntPacks) < 25 {
		t.Fatalf("packs=%d", len(huntPacks))
	}
	store, err := NewStore(t.TempDir()+"/f.jsonl", 100)
	if err != nil {
		t.Fatal(err)
	}
	store.recentEvents = []Event{
		{Host: "h1", Executable: "/usr/bin/nmap", Command: "nmap -sS 10.0.0.0/24"},
		{Host: "h2", Executable: "/bin/mount", Command: "mount /dev/sdb1 /media/usb"},
	}
	mux := http.NewServeMux()
	RegisterHuntPacks(mux, "tok", store)
	do := func(method, url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if rr := do("POST", "/v1/hunts/packs/network-scan/run", ""); !strings.Contains(rr.Body.String(), `"event_hits":1`) {
		t.Fatal(rr.Body.String())
	}
	if rr := do("POST", "/v1/hunts/run-all", ""); !strings.Contains(rr.Body.String(), `"packs_with_hits"`) {
		t.Fatal(rr.Body.String())
	}
	if rr := do("POST", "/v1/hunts/schedules", `{"pack_id":"network-scan","interval_sec":10}`); rr.Code != 201 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if do("POST", "/v1/hunts/schedules", `{"pack_id":"nope"}`).Code != 400 {
		t.Fatal("expected 400")
	}
	if do("POST", "/v1/hunts/packs/zzz/run", "").Code != 404 {
		t.Fatal("expected 404")
	}
	if !strings.Contains(do("GET", "/v1/devices/removable", "").Body.String(), "/dev/sdb1") {
		t.Fatal("removable")
	}
	if do("DELETE", "/v1/hunts/schedules?id=hs-1", "").Code != 200 {
		t.Fatal("delete")
	}
	h := &huntState{schedules: []HuntSchedule{{ID: "x", PackID: "network-scan", IntervalSec: 10}}}
	h.tick(store, time.Now())
	if len(h.history) != 1 || h.history[0].ScheduleID != "x" {
		t.Fatal("tick")
	}
	r2 := httptest.NewRecorder()
	mux.ServeHTTP(r2, httptest.NewRequest("GET", "/v1/hunts/packs", nil))
	if r2.Code == 200 {
		t.Fatal("auth")
	}
}
