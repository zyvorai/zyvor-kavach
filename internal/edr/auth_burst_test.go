package edr

import (
	"testing"
	"time"
)

func TestAuthBurstDetector(t *testing.T) {
	d := &AuthBurstDetector{}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := func(i int, user, ip, out string) TelemetryEvent {
		return TelemetryEvent{Time: t0.Add(time.Duration(i) * time.Second), Host: "h", User: user, SourceIP: ip, Method: "ssh", Outcome: out}
	}
	var fired []string
	for i := 0; i < 12; i++ {
		for _, f := range d.Observe(ev(i, "root", "198.51.100.1", "failure")) {
			fired = append(fired, f.Rule)
		}
	}
	if len(fired) != 1 || fired[0] != "auth-failed-login-burst" {
		t.Fatalf("want exactly one burst finding (cooldown), got %v", fired)
	}
	// slow failures, successes and other sources never fire
	d = &AuthBurstDetector{}
	for i := 0; i < 20; i++ {
		if fs := d.Observe(ev(i*10, "root", "198.51.100.2", "failure")); len(fs) > 0 {
			t.Fatalf("slow failures (one per 10s) must not fire: %v", fs)
		}
	}
	for i := 0; i < 30; i++ {
		if fs := d.Observe(ev(i, "ann", "10.0.0.1", "success")); len(fs) > 0 {
			t.Fatal("successes must not fire")
		}
	}
	// spray: many accounts
	d = &AuthBurstDetector{}
	var spray bool
	for i, u := range []string{"a", "b", "c", "d", "e"} {
		for _, f := range d.Observe(ev(i, u, "203.0.113.9", "failure")) {
			spray = spray || f.Rule == "auth-password-spray"
		}
	}
	if !spray {
		t.Fatal("password spray not detected")
	}
	if m, ok := ruleMITRE["auth-failed-login-burst"]; !ok || m.ID != "T1110" {
		t.Fatal("burst rule not mapped to T1110")
	}
}
