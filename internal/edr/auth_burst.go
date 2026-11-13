// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"fmt"
	"sync"
	"time"
)

// Failed-login burst detector (T1110). Observation-only: it counts failed auth telemetry events per
// (host, source_ip) in a sliding window and raises one finding when a threshold is crossed. The
// per-event content framework cannot express counting, so this is a small built-in detector fed by
// the same auth telemetry path (IngestTelemetry). It never blocks or locks anything.

const (
	authBurstWindow     = 60 * time.Second
	authBurstFailures   = 8 // failures from one source in the window
	authSprayUsers      = 5 // distinct usernames from one source in the window
	authBurstCooldown   = 5 * time.Minute
	authBurstMaxKeys    = 10000
	authBurstMaxSamples = 256
)

func init() {
	ruleMITRE["auth-failed-login-burst"] = struct{ Tactic, Technique, ID string }{"Credential Access", "Brute Force", "T1110"}
	ruleMITRE["auth-password-spray"] = struct{ Tactic, Technique, ID string }{"Credential Access", "Brute Force: Password Spraying", "T1110.003"}
}

type authFail struct {
	t    time.Time
	user string
}

type authBurstState struct {
	fails   []authFail
	alerted map[string]time.Time // rule -> last alert
}

// AuthBurstDetector keeps bounded per-source failure windows.
type AuthBurstDetector struct {
	mu  sync.Mutex
	src map[string]*authBurstState
}

var defaultAuthBurst = &AuthBurstDetector{}

// authBurstFindings feeds a batch of accepted telemetry events to the process-wide detector.
func authBurstFindings(typ string, evs []TelemetryEvent) []Finding {
	if typ != "auth" {
		return nil
	}
	var out []Finding
	for _, e := range evs {
		out = append(out, defaultAuthBurst.Observe(e)...)
	}
	return out
}

// Observe records one auth event and returns any finding it triggers.
func (d *AuthBurstDetector) Observe(e TelemetryEvent) []Finding {
	if e.Outcome != "failure" || e.SourceIP == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.src == nil {
		d.src = map[string]*authBurstState{}
	}
	key := e.Host + "|" + e.SourceIP
	st := d.src[key]
	if st == nil {
		if len(d.src) >= authBurstMaxKeys {
			for k, v := range d.src { // evict stale entries first, else one arbitrary entry
				if len(v.fails) == 0 || e.Time.Sub(v.fails[len(v.fails)-1].t) > authBurstWindow {
					delete(d.src, k)
				}
			}
			if len(d.src) >= authBurstMaxKeys {
				for k := range d.src {
					delete(d.src, k)
					break
				}
			}
		}
		st = &authBurstState{alerted: map[string]time.Time{}}
		d.src[key] = st
	}
	cut := e.Time.Add(-authBurstWindow)
	kept := st.fails[:0]
	for _, f := range st.fails {
		if f.t.After(cut) {
			kept = append(kept, f)
		}
	}
	kept = append(kept, authFail{t: e.Time, user: e.User})
	if len(kept) > authBurstMaxSamples {
		kept = kept[len(kept)-authBurstMaxSamples:]
	}
	st.fails = kept
	users := map[string]bool{}
	for _, f := range kept {
		users[f.user] = true
	}
	var out []Finding
	emit := func(rule, sev, desc string) {
		if last, ok := st.alerted[rule]; ok && e.Time.Sub(last) < authBurstCooldown {
			return
		}
		st.alerted[rule] = e.Time
		out = append(out, Finding{
			ID:   fmt.Sprintf("%s:%s:%s:%d", e.Host, rule, e.SourceIP, e.Time.UnixNano()),
			Time: e.Time, Host: e.Host, Rule: rule, Severity: sev, Description: desc,
			Tags: []string{"T1110", "auth", "observe-only"},
			Evidence: Event{Time: e.Time, Host: e.Host,
				Command: fmt.Sprintf("auth %s failures=%d users=%d src=%s", e.Method, len(kept), len(users), e.SourceIP)},
		})
	}
	if len(users) >= authSprayUsers && len(kept) >= authSprayUsers {
		emit("auth-password-spray", "high", fmt.Sprintf("%d distinct accounts failed to authenticate from %s within %s (password spraying pattern; investigate, not proof of compromise)", len(users), e.SourceIP, authBurstWindow))
	}
	if len(kept) >= authBurstFailures {
		emit("auth-failed-login-burst", "medium", fmt.Sprintf("%d failed logins from %s within %s (brute-force pattern; investigate, not proof of compromise)", len(kept), e.SourceIP, authBurstWindow))
	}
	return out
}
