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
