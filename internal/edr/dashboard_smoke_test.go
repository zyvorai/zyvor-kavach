package edr

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Lightweight static smoke checks for the single-file console. They catch the
// classic "added a page id but forgot the section / loader / label" breakage
// without needing a browser. See docs/console-qa.md for the browser pass.

func dashSrc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dashPages(t *testing.T, src string) []string {
	t.Helper()
	m := regexp.MustCompile(`const pages = \[(.*?)\];`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("pages array not found")
	}
	var out []string
	for _, s := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(m[1], -1) {
		out = append(out, s[1])
	}
	if len(out) < 60 {
		t.Fatalf("suspiciously few pages: %d", len(out))
	}
	return out
}

func TestDashboardEveryPageResolves(t *testing.T) {
	src := dashSrc(t)
	labels := regexp.MustCompile(`const pageLabels = \{(.*?)\};`).FindStringSubmatch(src)
	if labels == nil {
		t.Fatal("pageLabels not found")
	}
	seen := map[string]bool{}
	for _, p := range dashPages(t, src) {
		if seen[p] {
			t.Errorf("duplicate page id %q", p)
		}
		seen[p] = true
		if !strings.Contains(src, `id="page-`+p+`"`) {
			t.Errorf("page %q has no <section id=\"page-%s\">", p, p)
		}
		if !regexp.MustCompile(`(?m)data-page="` + regexp.QuoteMeta(p) + `"`).MatchString(src) {
			t.Errorf("page %q has no nav button", p)
		}
		if !regexp.MustCompile(`(^|[ ,'])'?` + regexp.QuoteMeta(p) + `'?\s*:`).MatchString(labels[1]) {
			t.Errorf("page %q has no pageLabels entry", p)
		}
	}
	// Every loader referenced from showPage must be a real function: the call
	// is guarded by typeof, so a typo silently renders an empty page.
	for _, m := range regexp.MustCompile(`current === '([^']+)' && typeof (load\w+) === 'function'`).FindAllStringSubmatch(src, -1) {
		if !seen[m[1]] {
			t.Errorf("showPage references unknown page %q", m[1])
		}
		if !regexp.MustCompile(`(function|const|let|var)\s+` + m[2] + `\b`).MatchString(src) {
			t.Errorf("loader %s for page %q is not defined", m[2], m[1])
		}
	}
	// g-key targets must be real pages.
	g := regexp.MustCompile(`const gKeys = \{(.*?)\};`).FindStringSubmatch(src)
	if g == nil {
		t.Fatal("gKeys not found")
	}
	for _, m := range regexp.MustCompile(`:\s*'([a-z-]+)'`).FindAllStringSubmatch(g[1], -1) {
		if !seen[m[1]] {
			t.Errorf("gKeys targets unknown page %q", m[1])
		}
	}
}

func TestDashboardInlineScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := dashSrc(t)
	scripts := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(src, -1)
	if len(scripts) == 0 {
		t.Fatal("no inline script found")
	}
	dir := t.TempDir()
	for i, s := range scripts {
		f := filepath.Join(dir, "s"+string(rune('0'+i))+".js")
		if err := os.WriteFile(f, []byte(s[1]), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(node, "--check", f).CombinedOutput(); err != nil {
			t.Fatalf("dashboard script %d does not parse: %v\n%s", i, err, out)
		}
	}
}
