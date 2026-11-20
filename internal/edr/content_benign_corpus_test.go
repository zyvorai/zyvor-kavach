// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// benignCorpusEvent is one realistic, non-malicious event from testdata/benign_corpus.json.
type benignCorpusEvent struct {
	LabEvent
	OS   string `json:"os"`
	Note string `json:"note,omitempty"`
}

// TestContentBenignCorpus is the false-positive guard: every embedded rule is evaluated against
// every corpus event of the rule's event_type (the OS is deliberately not used to filter, because
// the live path does not filter on it either). A hit by any rule of severity medium, high or
// critical fails the test with a per-rule report. Rules deliberately kept at severity "low" are
// informational audit signals for actions that are routine for admins but still worth recording
// (shell-profile edits, per-user crontabs, ...); their hits are logged, not failed.
func TestContentBenignCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/benign_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []benignCorpusEvent
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 500 {
		t.Fatalf("benign corpus too small: %d events, want at least 500", len(corpus))
	}
	kinds := map[string]int{}
	oses := map[string]int{}
	for _, ev := range corpus {
		kinds[ev.Kind]++
		oses[ev.OS]++
	}
	for _, k := range []string{"process", "file", "network", "registry", "dns", "auth", "module"} {
		if kinds[k] < 20 {
			t.Errorf("corpus has only %d %s events", kinds[k], k)
		}
	}
	for _, o := range []string{"linux", "macos", "windows"} {
		if oses[o] < 50 {
			t.Errorf("corpus has only %d %s events", oses[o], o)
		}
	}
	reg := loadTestRegistry(t)
	offenders := map[string][]string{}
	lowHits := map[string]int{}
	for _, r := range reg.rules {
		for _, ev := range corpus {
			if ev.Kind != r.EventType {
				continue
			}
			if r.Matches(ev.LabEvent) {
				if r.Severity == "low" {
					lowHits[r.ID]++
					continue
				}
				offenders[r.ID] = append(offenders[r.ID], fmt.Sprintf("[%s] %s | %s | %s | %s", ev.OS, ev.Executable, ev.Command, ev.Path, ev.Destination))
			}
		}
	}
	if len(lowHits) > 0 {
		lows := make([]string, 0, len(lowHits))
		n := 0
		for id, c := range lowHits {
			lows = append(lows, fmt.Sprintf("%s=%d", id, c))
			n += c
		}
		sort.Strings(lows)
		t.Logf("%d low-severity audit rules fired %d times on the corpus (allowed): %s", len(lows), n, strings.Join(lows, " "))
	}
	if len(offenders) == 0 {
		return
	}
	ids := make([]string, 0, len(offenders))
	total := 0
	for id, hits := range offenders {
		ids = append(ids, id)
		total += len(hits)
	}
	sort.Strings(ids)
	var b strings.Builder
	fmt.Fprintf(&b, "%d rules of severity medium or higher fire on the benign corpus (%d hits, %d events, %d rules):\n", len(ids), total, len(corpus), len(reg.rules))
	for _, id := range ids {
		hits := offenders[id]
		fmt.Fprintf(&b, "  %s (%d hits)\n", id, len(hits))
		for i, h := range hits {
			if i == 3 {
				fmt.Fprintf(&b, "      ... %d more\n", len(hits)-3)
				break
			}
			fmt.Fprintf(&b, "      %s\n", h)
		}
	}
	t.Error(b.String())
}
