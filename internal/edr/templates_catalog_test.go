package edr

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var bannedAction = regexp.MustCompile(`(?i)\b(kill|block|blocks|blocking|terminate|quarantine|isolate host|auto-?contain|automatically)\b`)

func TestBuiltinPlaybooksSafe(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range append(defaultPlaybooks(), builtinPlaybooks()...) {
		if seen[p.ID] {
			t.Fatalf("duplicate playbook id %s", p.ID)
		}
		seen[p.ID] = true
		if p.Name == "" || len(p.Actions) == 0 {
			t.Fatalf("incomplete playbook %s", p.ID)
		}
	}
	for _, p := range builtinPlaybooks() {
		for _, a := range append([]string{p.Name, p.Description}, p.Actions...) {
			if m := bannedAction.FindString(a); m != "" {
				t.Errorf("playbook %s uses banned word %q: %s", p.ID, m, a)
			}
			if !strings.HasPrefix(a, "analyst:") && !strings.HasPrefix(a, "ledger:") && a != p.Name && a != p.Description {
				t.Errorf("playbook %s action not analyst/ledger: %s", p.ID, a)
			}
		}
	}
	if len(builtinPlaybooks()) < 50 {
		t.Errorf("expected at least 50, got %d", len(builtinPlaybooks()))
	}
}

func TestReportTemplatesRenderEmpty(t *testing.T) {
	store, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tp := range ReportTemplates() {
		if seen[tp.ID] {
			t.Fatalf("duplicate template id %s", tp.ID)
		}
		seen[tp.ID] = true
		if out := RenderReportTemplate(tp, store, nil); !strings.Contains(out, tp.Title) {
			t.Errorf("%s render missing title", tp.ID)
		}
		_ = RenderReportTemplate(tp, nil, nil)
	}
	if len(seen) < 30 {
		t.Errorf("expected at least 30 templates, got %d", len(seen))
	}
}
