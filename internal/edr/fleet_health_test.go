// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
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

const fleetHTestToken = "fleet-health-admin-secret-token"

// fleetHSeed builds: a (ebpf, fresh, events), b (proc, fresh, events 3h ago => blind),
// c (pending, no events), d (offline 30m, events), e (revoked); shadow host "ghost" seen in events.
func fleetHSeed(t *testing.T) (http.Handler, *Store, *CredentialRegistry, time.Time) {
	t.Helper()
	dir := t.TempDir()
	store, err := testStore(t, filepath.Join(dir, "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := OpenCredentialRegistry(filepath.Join(dir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, h := range []string{"a", "b", "c", "d", "e"} {
		if _, err := reg.Issue(h); err != nil {
			t.Fatal(err)
		}
	}
	reg.mu.Lock()
	set := func(h string, seen time.Time, sensor string, q int) {
		c := reg.agents[h]
		c.LastSeen, c.Sensor, c.Queued = seen, sensor, q
		reg.agents[h] = c
	}
	set("a", now.Add(-10*time.Second), "ebpf-sched-process-exec", 0)
	set("b", now.Add(-20*time.Second), "proc-poll", 500)
	set("d", now.Add(-30*time.Minute), "proc-poll", 0)
	c := reg.agents["e"]
	c.Revoked = true
	reg.agents["e"] = c
	reg.mu.Unlock()
	store.mu.Lock()
	store.recentEvents = []Event{{Host: "a", Time: now.Add(-time.Minute)}, {Host: "b", Time: now.Add(-3 * time.Hour)}, {Host: "d", Time: now.Add(-40 * time.Minute)}}
	store.networkEvents = []NetworkEvent{{Host: "ghost", Time: now.Add(-time.Minute)}}
	store.mu.Unlock()
	return APIWithCredentials(fleetHTestToken, store, reg), store, reg, now
}

func fleetHGet(t *testing.T, h http.Handler, path string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer "+fleetHTestToken)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestFleetHealthScoreMath(t *testing.T) {
	_, store, reg, now := fleetHSeed(t)
	rep := fleetHBuild(store, reg, now)
	// active = a,b,c,d (e revoked). online: a,b =2/4 -> 20. data: a,b,d =3/4 -> 18.75.
	// strong: a =1/4 -> 3.75. backlog ok: a,c,d =3/4 -> 7.5. shadow: 5/6 -> 8.33. total 58.33 -> 58
	if rep.Score != 58 {
		t.Fatalf("score %d factors %+v", rep.Score, rep.Factors)
	}
	if len(rep.Factors) != 5 || rep.Counts["active"] != 4 || rep.Counts["shadow_hosts"] != 1 {
		t.Fatalf("%+v", rep.Counts)
	}
	sum := 0
	for _, f := range rep.Factors {
		sum += f.Weight
	}
	if sum != 100 {
		t.Fatal("weights")
	}
}

func TestFleetHealthBlindAndNeverReported(t *testing.T) {
	_, store, reg, now := fleetHSeed(t)
	by := map[string]fleetHAgent{}
	for _, a := range fleetHBuild(store, reg, now).Agents {
		by[a.Host] = a
	}
	if !by["b"].SensorBlindSuspected || by["a"].SensorBlindSuspected {
		t.Fatal("blind heuristic")
	}
	if by["d"].SensorBlindSuspected {
		t.Fatal("offline host is not 'blind' (heartbeat not continuing)")
	}
	if !by["c"].NeverReportedEvents || by["a"].NeverReportedEvents || by["e"].NeverReportedEvents {
		t.Fatal("never reported")
	}
	if by["a"].SensorKind != "ebpf" || by["b"].SensorKind != "proc-poll" || !by["b"].BacklogHigh {
		t.Fatalf("%+v", by["b"])
	}
}

func TestFleetHealthEndpointsAndAuth(t *testing.T) {
	h, _, _, _ := fleetHSeed(t)
	for _, p := range []string{"/v1/fleet/health", "/v1/fleet/coverage-gaps", "/v1/fleet/stale", "/v1/fleet/health/a"} {
		if rr := fleetHGet(t, h, p, false); rr.Code != 401 {
			t.Fatalf("%s unauth %d", p, rr.Code)
		}
		if rr := fleetHGet(t, h, p, true); rr.Code != 200 {
			t.Fatalf("%s auth %d", p, rr.Code)
		}
	}
	rr := fleetHGet(t, h, "/v1/fleet/coverage-gaps", true)
	var gaps struct {
		Shadow []string `json:"shadow_hosts"`
		NoData []string `json:"agents_without_data"`
		Weak   []string `json:"agents_on_polling_sensor"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &gaps); err != nil {
		t.Fatal(err)
	}
	if len(gaps.Shadow) != 1 || gaps.Shadow[0] != "ghost" || len(gaps.NoData) != 1 || gaps.NoData[0] != "c" || len(gaps.Weak) != 2 {
		t.Fatalf("%+v", gaps)
	}
}

func TestFleetStaleCutoff(t *testing.T) {
	h, _, _, _ := fleetHSeed(t)
	count := func(path string) (int, int) {
		var out struct {
			Stale []fleetHAgent `json:"stale"`
			Never []fleetHAgent `json:"never_seen"`
		}
		rr := fleetHGet(t, h, path, true)
		if rr.Code != 200 {
			t.Fatalf("%s %d", path, rr.Code)
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return len(out.Stale), len(out.Never)
	}
	if s, n := count("/v1/fleet/stale"); s != 1 || n != 1 {
		t.Fatalf("default 15m: %d %d", s, n)
	}
	if s, _ := count("/v1/fleet/stale?minutes=60"); s != 0 {
		t.Fatal("60m cutoff should exclude d")
	}
	if rr := fleetHGet(t, h, "/v1/fleet/stale?minutes=abc", true); rr.Code != 400 {
		t.Fatal("bad minutes")
	}
}

func TestFleetHealthHost(t *testing.T) {
	h, _, _, _ := fleetHSeed(t)
	if rr := fleetHGet(t, h, "/v1/fleet/health/nosuch", true); rr.Code != 404 {
		t.Fatalf("404 expected, got %d", rr.Code)
	}
	rr := fleetHGet(t, h, "/v1/fleet/health/b", true)
	body := rr.Body.String()
	if !strings.Contains(body, "recommendations") || !strings.Contains(body, "sensor is blind") || !strings.Contains(body, "500 queued") {
		t.Fatalf("%s", body)
	}
	rr = fleetHGet(t, h, "/v1/fleet/health/ghost", true)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"enrolled":false`) {
		t.Fatalf("shadow host: %d %s", rr.Code, rr.Body.String())
	}
}

func TestFleetHealthEmptyFleet(t *testing.T) {
	store, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 10)
	if err != nil {
		t.Fatal(err)
	}
	h := API(fleetHTestToken, store)
	rr := fleetHGet(t, h, "/v1/fleet/health", true)
	var rep fleetHReport
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &rep) != nil || rep.Score != 0 || len(rep.Agents) != 0 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"agents":[]`) {
		t.Fatal("agents must be an empty array")
	}
	if g := fleetHGauges(store, nil, time.Now()); !strings.Contains(g, "kavach_fleet_coverage_score 0") || !strings.Contains(g, "kavach_fleet_stale_agents 0") {
		t.Fatal(g)
	}
}

func TestFleetHealthGauges(t *testing.T) {
	_, store, reg, now := fleetHSeed(t)
	g := fleetHGauges(store, reg, now)
	if !strings.Contains(g, "kavach_fleet_coverage_score 58") || !strings.Contains(g, "kavach_fleet_stale_agents 1") {
		t.Fatal(g)
	}
}
