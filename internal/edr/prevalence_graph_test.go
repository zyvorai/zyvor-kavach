// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func prevSeed(t *testing.T) (*httptest.Server, *Store, string) {
	t.Helper()
	srv, s, tok := obsServer(t)
	now := time.Now().UTC()
	ev := func(h, exe, cmd string, pid int, ago time.Duration) {
		if _, err := s.Ingest(Event{ID: fmt.Sprintf("%s-%s-%d-%d", h, exe, pid, ago), Time: now.Add(-ago), Host: h, PID: pid, UID: 1000, Executable: exe, ParentExe: "/bin/bash", Command: cmd}); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []string{"h1", "h2", "h3", "h4"} {
		ev(h, "/usr/bin/ls", "ls -la /tmp/"+h+" 1234", 100, time.Hour)
	}
	ev("h1", "/tmp/evil", "evil --id 550e8400-e29b-41d4-a716-446655440000", 7, time.Hour)
	ev("h2", "/tmp/evil", "evil --id 550e8400-e29b-41d4-a716-446655441111", 8, time.Hour)
	ev("h3", "/opt/<b>solo", "solo 0xdeadbeef", 9, time.Hour)
	ev("h4", "/usr/bin/old", "old", 10, 48*time.Hour)
	ev("h4", "/usr/bin/newtool", "newtool", 11, time.Hour)
	ev("h4", "/usr/bin/old", "old", 12, time.Hour)
	nw := func(h, d string, ago time.Duration, id string) {
		if _, err := s.IngestNetwork(NetworkEvent{ID: id, Time: now.Add(-ago), Host: h, PID: 1, Destination: d}); err != nil {
			t.Fatal(err)
		}
	}
	nw("h1", "203.0.113.9:443", time.Hour, "n1")
	nw("h3", "203.0.113.9:443", time.Hour, "n2")
	nw("h4", "198.51.100.1:80", 48*time.Hour, "n3")
	nw("h4", "198.51.100.2:80", time.Hour, "n4")
	return srv, s, tok
}

func TestPrevalenceNormalise(t *testing.T) {
	got := prevNormalise("curl  -o /tmp/x 12345 0xDEADBEEF abcdef0123456789 550e8400-e29b-41d4-a716-446655440000")
	want := "curl -o /tmp/x <n> <hex> <hex> <uuid>"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(prevNormalise(strings.Repeat("a ", 500))) > prevMaxStr {
		t.Fatal("not clipped")
	}
}

func TestPrevalenceExecutables(t *testing.T) {
	srv, _, tok := prevSeed(t)
	_, body := get(t, srv.URL+"/v1/prevalence/executables?min_hosts=2", tok)
	var out struct {
		Executables []PrevalenceEntry `json:"executables"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Executables) != 2 {
		t.Fatalf("want ls and evil, got %+v", out.Executables)
	}
	if out.Executables[0].Executable != "/tmp/evil" || out.Executables[0].Hosts != 2 || out.Executables[1].Hosts != 4 {
		t.Fatalf("host counting/order: %+v", out.Executables)
	}
	if !strings.Contains(out.Executables[0].CommandShape, "<uuid>") || out.Executables[0].Parents[0] != "/bin/bash" {
		t.Fatalf("shape/parents: %+v", out.Executables[0])
	}
	_, body = get(t, srv.URL+"/v1/prevalence/executables?max_hosts=1&limit=1", tok)
	if !strings.Contains(body, `"count":1`) {
		t.Fatalf("limit: %s", body)
	}
}

func TestPrevalenceRare(t *testing.T) {
	srv, s, tok := prevSeed(t)
	if err := s.Append(Finding{ID: "f1", Time: time.Now().UTC(), Host: "h3", Rule: "r1", Severity: "high", Evidence: Event{Executable: "/opt/<b>solo"}}); err != nil {
		t.Fatal(err)
	}
	r, body := get(t, srv.URL+"/v1/prevalence/rare?hours=24", tok)
	var out struct {
		Rare  []PrevalenceRare `json:"rare"`
		Fleet int              `json:"fleet_hosts"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || r.StatusCode != 200 {
		t.Fatal(err, body)
	}
	if out.Fleet != 4 {
		t.Fatalf("fleet %d", out.Fleet)
	}
	names := map[string]PrevalenceRare{}
	for _, x := range out.Rare {
		names[x.Executable] = x
	}
	if _, ok := names["/tmp/evil"]; ok {
		t.Fatal("2-host exe must not be rare at default fraction")
	}
	if !names["/opt/<b>solo"].InFindings || names["/usr/bin/newtool"].InFindings || names["/usr/bin/newtool"].Rarity != 1 {
		t.Fatalf("rare: %+v", out.Rare)
	}
	if out.Rare[0].Executable != "/opt/<b>solo" {
		t.Fatalf("findings-backed first: %+v", out.Rare)
	}
	if strings.Contains(body, "<b>") {
		t.Fatalf("output not escaped: %s", body)
	}
	_, body = get(t, srv.URL+"/v1/prevalence/rare?fraction=0.5", tok)
	if !strings.Contains(body, "/tmp/evil") {
		t.Fatalf("fraction should include 2-host exe: %s", body)
	}
}

func TestPrevalenceFirstSeen(t *testing.T) {
	srv, _, tok := prevSeed(t)
	if r, _ := get(t, srv.URL+"/v1/prevalence/first-seen", tok); r.StatusCode != 400 {
		t.Fatalf("host required: %d", r.StatusCode)
	}
	_, body := get(t, srv.URL+"/v1/prevalence/first-seen?host=h4&hours=24", tok)
	var out struct {
		Exes  []prevFirst `json:"new_executables"`
		Dests []prevFirst `json:"new_destinations"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Exes) != 2 { // ls + newtool; old was seen before window
		t.Fatalf("exes: %+v", out.Exes)
	}
	for _, e := range out.Exes {
		if e.Value == "/usr/bin/old" {
			t.Fatal("old exe is not first-seen")
		}
	}
	if len(out.Dests) != 1 || out.Dests[0].Value != "198.51.100.2:80" {
		t.Fatalf("dests: %+v", out.Dests)
	}
}

func TestPrevalenceBlastRadius(t *testing.T) {
	srv, s, tok := prevSeed(t)
	if err := s.Append(Finding{ID: "f2", Time: time.Now().UTC(), Host: "h1", Rule: "r1", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := get(t, srv.URL+"/v1/graph/blast-radius", tok); r.StatusCode != 400 {
		t.Fatalf("host required: %d", r.StatusCode)
	}
	_, body := get(t, srv.URL+"/v1/graph/blast-radius?host=h1&depth=9", tok)
	var out struct {
		Depth  int                `json:"depth"`
		Nodes  []PrevalenceNode   `json:"nodes"`
		Edges  []PrevalenceEdge   `json:"edges"`
		Likely []PrevalenceLikely `json:"likely_affected"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Depth != prevMaxDepth {
		t.Fatalf("depth cap: %d", out.Depth)
	}
	// h2 shares evil with h1; h3 shares a destination with h1; h4 is not linked.
	got := map[string]bool{}
	for _, l := range out.Likely {
		got[l.Host] = true
	}
	if !got["h2"] || !got["h3"] || got["h4"] {
		t.Fatalf("likely: %+v", out.Likely)
	}
	if out.Likely[0].Host != "h2" || !strings.Contains(strings.Join(out.Likely[0].Reasons, ";"), "shared-rare-executable: /tmp/evil") {
		t.Fatalf("ranking/reasons: %+v", out.Likely)
	}
	if out.Nodes[0].ID != "h1" || out.Nodes[0].Risk == 0 {
		t.Fatalf("seed node: %+v", out.Nodes[0])
	}
	_, body2 := get(t, srv.URL+"/v1/graph/blast-radius?host=h1&depth=9", tok)
	if body != body2 {
		t.Fatal("non-deterministic output")
	}
	_, body = get(t, srv.URL+"/v1/graph/blast-radius?host=h1&depth=1", tok)
	if strings.Contains(body, `"depth":2`) {
		t.Fatalf("depth 1 exceeded: %s", body)
	}
}

func TestPrevalenceBlastDepthAndNodeCaps(t *testing.T) {
	now := time.Now().UTC()
	var sn prevSnapshot
	// chain hosts c0-c1-c2-c3-c4 via distinct rare exes
	for i := 0; i < 4; i++ {
		exe := fmt.Sprintf("/x/chain%d", i)
		for _, h := range []string{fmt.Sprintf("c%d", i), fmt.Sprintf("c%d", i+1)} {
			sn.events = append(sn.events, Event{Time: now, Host: h, Executable: exe})
		}
	}
	res := prevBlast(sn, now, "c0", 24, 3)
	if n := res["nodes"].([]PrevalenceNode); len(n) != 4 {
		t.Fatalf("depth 3 should reach 4 nodes: %+v", n)
	}
	// star: 600 hosts sharing one exe is too common (> prevSharedExeMax); use per-host unique pair exes instead.
	sn = prevSnapshot{}
	for i := 0; i < 700; i++ {
		exe := fmt.Sprintf("/y/e%d", i)
		sn.events = append(sn.events, Event{Time: now, Host: "hub", Executable: exe}, Event{Time: now, Host: fmt.Sprintf("s%03d", i), Executable: exe})
	}
	res = prevBlast(sn, now, "hub", 24, 1)
	if n := res["nodes"].([]PrevalenceNode); len(n) != prevMaxNodes || res["truncated"] != true {
		t.Fatalf("node cap: %d truncated=%v", len(n), res["truncated"])
	}
}

func TestPrevalenceEmptyStoreAndAuth(t *testing.T) {
	srv, _, tok := obsServer(t)
	for _, p := range []string{"/v1/prevalence/executables", "/v1/prevalence/rare", "/v1/prevalence/first-seen?host=x", "/v1/graph/blast-radius?host=x"} {
		if r, _ := get(t, srv.URL+p, ""); r.StatusCode != 401 {
			t.Fatalf("%s must require auth: %d", p, r.StatusCode)
		}
		r, body := get(t, srv.URL+p, tok)
		if r.StatusCode != 200 || !json.Valid([]byte(body)) {
			t.Fatalf("%s: %d %s", p, r.StatusCode, body)
		}
	}
	_, body := get(t, srv.URL+"/v1/prevalence/executables", tok)
	if !strings.Contains(body, `"executables":[]`) {
		t.Fatalf("empty: %s", body)
	}
}
