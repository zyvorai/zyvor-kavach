// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"testing"
	"time"
)

func socFinding(t *testing.T, s *Store, id, host, rule, sev string, at time.Time, pid int) {
	t.Helper()
	if err := s.Append(Finding{ID: id, Time: at, Host: host, PID: pid, Rule: rule, Severity: sev, Description: id}); err != nil {
		t.Fatal(err)
	}
}

func TestSOCMetricsMath(t *testing.T) {
	srv, s, tok := obsServer(t)
	now := time.Now().UTC()
	socFinding(t, s, "soc-a", "h1", "noisy", "critical", now.Add(-3*time.Hour), 1)
	socFinding(t, s, "soc-b", "h1", "noisy", "high", now.Add(-2*time.Hour), 2)
	socFinding(t, s, "soc-c", "h2", "other", "low", now.Add(-48*time.Hour), 3)
	socFinding(t, s, "soc-d", "h2", "other", "critical", now.Add(-10*time.Minute), 4)
	// a: ack after 30m (breaches 15m target), resolved after 120m as true_positive.
	recordTransitionAt(Transition{FindingID: "soc-a", Source: "detection", Status: "in_progress", Time: now.Add(-150 * time.Minute)})
	recordTransitionAt(Transition{FindingID: "soc-a", Source: "detection", Status: "true_positive", Time: now.Add(-60 * time.Minute)})
	// b: ack after 10m, false positive after 20m.
	recordTransitionAt(Transition{FindingID: "soc-b", Source: "detection", Status: "in_progress", Time: now.Add(-110 * time.Minute)})
	recordTransitionAt(Transition{FindingID: "soc-b", Source: "detection", Status: "false_positive", Time: now.Add(-100 * time.Minute)})
	t.Setenv("KAVACH_SLA_ACK_MIN", "")
	m := SOCMetrics(s.List(), allTransitions(s), now, 30)
	if *(m["mtta_minutes"].(*float64)) != 20 {
		t.Fatalf("mtta %v", *(m["mtta_minutes"].(*float64)))
	}
	if *(m["mttr_minutes"].(*float64)) != 70 {
		t.Fatalf("mttr %v", *(m["mttr_minutes"].(*float64)))
	}
	if m["open_backlog"].(int) != 2 {
		t.Fatalf("backlog %v", m["open_backlog"])
	}
	bl := m["backlog_by_severity"].(map[string]map[string]int)
	if bl["low"]["1d_7d"] != 1 || bl["critical"]["lt_1h"] != 1 {
		t.Fatalf("buckets %v", bl)
	}
	br := m["sla_breaches"].(map[string]*socBreach)
	// critical: a acked at 30m > 15; d unacked 10m < 15 -> 1 ack breach. Resolve target 4h: none.
	if br["critical"].Ack != 1 || br["critical"].Resolve != 0 {
		t.Fatalf("critical breaches %+v", br["critical"])
	}
	if br["low"].Ack != 1 || br["low"].Resolve != 0 { // 48h unacked > 24h; 48h < 168h
		t.Fatalf("low breaches %+v", br["low"])
	}
	rules := m["false_positive_rules"].([]socRuleRow)
	if rules[0].Rule != "noisy" || rules[0].FalsePositiveRate != 50 {
		t.Fatalf("fp rules %+v", rules)
	}
	if m["top_noisy_rules"].([]socRuleRow)[0].Total != 2 {
		t.Fatal("noisy")
	}
	// days window excludes the 48h-old finding.
	if SOCMetrics(s.List(), allTransitions(s), now, 1)["tickets"].(int) != 3 {
		t.Fatal("window")
	}
	// HTTP path
	r, body := get(t, srv.URL+"/v1/soc/metrics?days=7", tok)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, body)
	}
}

func TestSLATargetEnv(t *testing.T) {
	t.Setenv("KAVACH_SLA_ACK_MIN", "critical=5,high=7")
	got := slaTargets("KAVACH_SLA_ACK_MIN", defaultAckMin)
	if got["critical"] != 5 || got["high"] != 7 || got["low"] != 1440 {
		t.Fatalf("%v", got)
	}
	t.Setenv("KAVACH_SLA_ACK_MIN", "9")
	if slaTargets("KAVACH_SLA_ACK_MIN", defaultAckMin)["low"] != 9 {
		t.Fatal("uniform")
	}
}

func TestSOCResolveBreachAndIncidentLedger(t *testing.T) {
	_, s, _ := obsServer(t)
	now := time.Now().UTC()
	socFinding(t, s, "soc-r", "h", "x", "critical", now.Add(-6*time.Hour), 0)
	if err := appendRecord(s.path+".incidents", IncidentAction{FindingID: "soc-r", Status: "investigating", Actor: "a", Time: now.Add(-5 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	m := SOCMetrics(s.List(), allTransitions(s), now, 30)
	br := m["sla_breaches"].(map[string]*socBreach)
	if br["critical"].Resolve != 1 { // unresolved for 6h > 4h
		t.Fatalf("%+v", br["critical"])
	}
	if *(m["mtta_minutes"].(*float64)) != 60 {
		t.Fatal("incident ack")
	}
}

func TestStorylineOrderingAndBursts(t *testing.T) {
	srv, s, tok := obsServer(t)
	now := time.Now().UTC().Add(-3 * time.Hour)
	socFinding(t, s, "st-1", "box", "ransomware-burst", "critical", now.Add(20*time.Minute), 77)
	socFinding(t, s, "st-2", "box", "ioa-credential-dump", "high", now.Add(2*time.Minute), 66)
	socFinding(t, s, "st-other", "elsewhere", "ransomware-burst", "high", now, 1)
	if _, err := s.Ingest(Event{Time: now, Host: "box", PID: 66, Executable: "/bin/x", Command: "x --dump"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestNetwork(NetworkEvent{Time: now.Add(21 * time.Minute), Host: "box", PID: 5, Destination: "1.2.3.4:443"}); err != nil {
		t.Fatal(err)
	}
	r, body := get(t, srv.URL+"/v1/storyline/host?host=BOX&hours=24", tok)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, body)
	}
	var out struct {
		Steps  []StorylineStep
		Bursts []storyBurst
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Steps) != 4 {
		t.Fatalf("steps %d %s", len(out.Steps), body)
	}
	for i := 1; i < len(out.Steps); i++ {
		if out.Steps[i].Time.Before(out.Steps[i-1].Time) {
			t.Fatal("unordered")
		}
	}
	if out.Steps[0].Kind != "process" || out.Steps[0].TacticSource != "pid-correlation" || out.Steps[0].Tactic != "Credential Access" {
		t.Fatalf("first %+v", out.Steps[0])
	}
	if out.Steps[0].Phase != 8 {
		t.Fatalf("phase %d", out.Steps[0].Phase)
	}
	if len(out.Bursts) != 2 || out.Bursts[0].Steps != 2 || out.Bursts[1].Steps != 2 {
		t.Fatalf("bursts %+v", out.Bursts)
	}
	if out.Steps[2].Burst != 2 || out.Steps[2].GapSeconds < 15*60 {
		t.Fatalf("gap %+v", out.Steps[2])
	}
	if out.Steps[3].Kind != "network" || out.Steps[3].Tactic != "Command and Control" {
		t.Fatalf("net %+v", out.Steps[3])
	}
	if r, _ := get(t, srv.URL+"/v1/storyline/host", tok); r.StatusCode != 400 {
		t.Fatal("host required")
	}
}

func TestShiftReport(t *testing.T) {
	srv, s, tok := obsServer(t)
	now := time.Now().UTC()
	socFinding(t, s, "sh-1", "alpha", "ransomware-burst", "critical", now.Add(-time.Hour), 1)
	socFinding(t, s, "sh-2", "beta", "x", "low", now.Add(-2*time.Hour), 2)
	recordTransitionAt(Transition{FindingID: "sh-2", Source: "detection", Status: "closed", Time: now.Add(-time.Hour)})
	r, body := get(t, srv.URL+"/v1/soc/shift-report?hours=6", tok)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	var out struct {
		Counts    map[string]int
		Criticals []shiftCritical `json:"unresolved_criticals"`
		Hosts     []HostRisk      `json:"highest_risk_hosts"`
		Qs        []string        `json:"recommended_questions"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Counts["new"] != 2 || out.Counts["open"] != 1 || out.Counts["closed"] != 1 {
		t.Fatalf("%v", out.Counts)
	}
	if len(out.Criticals) != 1 || len(out.Hosts) == 0 || len(out.Qs) < 2 {
		t.Fatalf("%s", body)
	}
}

func TestSOCEmptyStoreAndAuth(t *testing.T) {
	srv, _, tok := obsServer(t)
	for _, p := range []string{"/v1/soc/metrics", "/v1/storyline/host?host=a", "/v1/soc/shift-report"} {
		if r, _ := get(t, srv.URL+p, ""); r.StatusCode != 401 {
			t.Fatalf("%s unauth: %d", p, r.StatusCode)
		}
		if r, body := get(t, srv.URL+p, tok); r.StatusCode != 200 {
			t.Fatalf("%s: %d %s", p, r.StatusCode, body)
		}
	}
	_, body := get(t, srv.URL+"/v1/soc/metrics", tok)
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil || m["mtta_minutes"] != nil || m["open_backlog"].(float64) != 0 {
		t.Fatal(body)
	}
	_, body = get(t, srv.URL+"/v1/storyline/host?host=a", tok)
	if json.Unmarshal([]byte(body), &m) != nil || len(m["steps"].([]any)) != 0 {
		t.Fatal(body)
	}
}
