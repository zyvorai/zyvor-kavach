package edr

import (
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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

// Every Models tab and Inspector mode button must have a pane, and every pane
// must be listed in its handler, or the tab silently shows nothing.
func TestDashboardModelsAndInspectorTabs(t *testing.T) {
	src := dashSrc(t)
	list := regexp.MustCompile(`\['status', 'lineage'[^\]]*\]\.forEach`).FindString(src)
	if list == "" {
		t.Fatal("models tab list not found")
	}
	for _, m := range regexp.MustCompile(`data-md-tab="([a-z]+)"`).FindAllStringSubmatch(src, -1) {
		if !strings.Contains(src, `id="md-pane-`+m[1]+`"`) {
			t.Errorf("models tab %q has no pane", m[1])
		}
		if !strings.Contains(list, `'`+m[1]+`'`) {
			t.Errorf("models tab %q missing from the tab handler list", m[1])
		}
	}
	modes := regexp.MustCompile(`\['file', 'script'[^\]]*\]\.forEach`).FindString(src)
	if modes == "" {
		t.Fatal("inspector mode list not found")
	}
	for _, m := range regexp.MustCompile(`data-in-mode="([a-z]+)"`).FindAllStringSubmatch(src, -1) {
		if !strings.Contains(src, `id="in-mode-`+m[1]+`"`) {
			t.Errorf("inspector mode %q has no pane", m[1])
		}
		if !strings.Contains(modes, `'`+m[1]+`'`) {
			t.Errorf("inspector mode %q missing from the mode handler", m[1])
		}
		if m[1] != "file" && !strings.Contains(src, m[1]+`: 'in-`) {
			t.Errorf("inspector mode %q has no input id mapping", m[1])
		}
	}
	lede := regexp.MustCompile(`(?s)<section id="page-inspector".*?class="lede">(.*?)</p>`).FindStringSubmatch(src)
	if lede == nil {
		t.Fatal("inspector lede not found")
	}
	for _, w := range []string{"file", "script", "command line", "domain", "configuration", "lockfile", "URL", "email"} {
		if !strings.Contains(lede[1], w) {
			t.Errorf("inspector intro does not mention %q", w)
		}
	}
}

// Text colour tokens must stay readable (4.5:1) on the light page and surface.
func TestDashboardLightTextTokensContrast(t *testing.T) {
	src := dashSrc(t)
	lum := func(hex string) float64 {
		var c [3]float64
		for i := 0; i < 3; i++ {
			v, _ := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
			f := float64(v) / 255
			if f <= 0.03928 {
				c[i] = f / 12.92
			} else {
				c[i] = math.Pow((f+0.055)/1.055, 2.4)
			}
		}
		return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
	}
	root := regexp.MustCompile(`(?s):root \{(.*?)\n\}`).FindStringSubmatch(src)
	if root == nil {
		t.Fatal(":root block not found")
	}
	for _, name := range []string{"text-secondary", "text-tertiary", "text-faint", "danger-text"} {
		m := regexp.MustCompile(`--` + name + `:\s*(#[0-9a-fA-F]{6})`).FindStringSubmatch(root[1])
		if m == nil {
			t.Errorf("--%s not defined as hex in :root", name)
			continue
		}
		bg := "#ffffff"
		if name == "danger-text" {
			bg = "#fff1f0"
		}
		a, b := lum(m[1]), lum(bg)
		if a > b {
			a, b = b, a
		}
		if r := (b + 0.05) / (a + 0.05); r < 4.5 {
			t.Errorf("--%s %s on %s is %.2f:1, below 4.5", name, m[1], bg, r)
		}
	}
}
