package edr

import (
	"regexp"
	"strings"
	"testing"
)

// The usability block (table sort/columns/export, saved views, palette
// lookups) must keep its safety rules: tokens only, no innerHTML, storage
// access wrapped in try/catch, and the user-facing hooks present.
func TestDashboardUsabilityFeatures(t *testing.T) {
	src := dashSrc(t)
	css := between(t, src, "/* === console usability: table tools", "/* === end console usability === */")
	if regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|rgba?\(`).MatchString(css) {
		t.Error("usability CSS must use tokens, not literal colours")
	}
	js := between(t, src, "/* === console usability: table sort", "/* === end console usability === */")
	if strings.Contains(js, "innerHTML") || strings.Contains(js, "insertAdjacentHTML") {
		t.Error("usability script must not use innerHTML")
	}
	for _, w := range []string{"aria-sort", "tblCsvCell", "kavach-views-", "palLookups", "enhancePage", "'text/csv'", "'application/json'"} {
		if !strings.Contains(src, w) {
			t.Errorf("missing %q", w)
		}
	}
	for _, fn := range []string{"viewsLoad", "viewsStore"} {
		body := regexp.MustCompile(`function ` + fn + `\(.*`).FindString(js)
		if !strings.Contains(body, "try {") || !strings.Contains(body, "catch") {
			t.Errorf("%s must wrap localStorage in try/catch", fn)
		}
	}
	if regexp.MustCompile(`(?i)(\?|&)(token|access_token|bearer)=`).MatchString(src) {
		t.Error("a token appears in a URL query")
	}
	for _, w := range []string{"Open command palette", "Show this help", "Sort a table column", "Look up "} {
		if !strings.Contains(src, w) {
			t.Errorf("palette/help text %q missing", w)
		}
	}
	if !strings.Contains(js, `/^[=+@\t]/`) {
		t.Error("CSV export lacks formula-injection guard")
	}
}

// Theme and phone-width rules that were fixed after a real-browser pass.
func TestDashboardThemeAndPhoneRules(t *testing.T) {
	src := dashSrc(t)
	for _, w := range []string{"prefers-color-scheme: dark", "nextThemeChoice", "themeChoice === 'auto'", "t === 'light' || t === 'dark' || t === 'auto'"} {
		if !strings.Contains(src, w) {
			t.Errorf("theme logic missing %q", w)
		}
	}
	if !strings.Contains(src, "try { const t = localStorage.getItem('kavach-theme')") || !strings.Contains(src, "try { localStorage.setItem('kavach-theme'") {
		t.Error("theme storage access must be inside try/catch")
	}
	// The Browse dropdown must not live inside the scrolling tab strip (overflow clips it).
	strip := between(t, src, `<div class="navlinks"`, `<div class="nav-browse"`)
	if strings.Contains(strip, `class="nav-browse"`) || !strings.Contains(strip, `data-page="world"`) {
		t.Error("nav-browse must follow the navlinks strip, not sit inside it")
	}
	if !strings.Contains(between(t, src, `<div class="navlinks"`, `<div class="nav-actions"`), `id="nav-browse-menu"`) {
		t.Error("browse menu must sit between the tab strip and the nav actions")
	}
	for _, w := range []string{".nav-inner { flex-wrap: wrap;", "white-space: nowrap;", "textarea.input-field { border-radius: var(--radius-md); }", "max-height: calc(100vh - 120px);"} {
		if !strings.Contains(src, w) {
			t.Errorf("CSS rule missing %q", w)
		}
	}
	dark := between(t, src, `[data-theme="dark"] {`, "*, *::before")
	for _, w := range []string{"--text-tertiary: #98989d;", "--danger-text: #ff6961;"} {
		if !strings.Contains(dark, w) {
			t.Errorf("dark token regressed: %q", w)
		}
	}
}

func between(t *testing.T, s, a, b string) string {
	t.Helper()
	i := strings.Index(s, a)
	if i < 0 {
		t.Fatalf("marker %q not found", a)
	}
	j := strings.Index(s[i:], b)
	if j < 0 {
		t.Fatalf("marker %q not found", b)
	}
	return s[i : i+j]
}
