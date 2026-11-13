// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

func TestDomainParse(t *testing.T) {
	cases := []struct {
		in, norm, suffix, sld string
		subs                  int
		ipLike, err           string
	}{
		{in: "Example.COM.", norm: "example.com", suffix: "com", sld: "example"},
		{in: "a.b.example.co.uk", norm: "a.b.example.co.uk", suffix: "co.uk", sld: "example", subs: 2},
		{in: "https://User@Host.Example.com:8080/p?q#f", norm: "host.example.com", suffix: "com", sld: "example", subs: 1},
		{in: "foo.github.io", norm: "foo.github.io", suffix: "github.io", sld: "foo"},
		{in: "co.uk", norm: "co.uk", suffix: "co.uk"},
		{in: "localhost", norm: "localhost", suffix: "localhost"},
		{in: "127.0.0.1", norm: "127.0.0.1", ipLike: "ipv4"},
		{in: "[::1]:80", norm: "::1", ipLike: "ipv6"},
		{in: "3232235777", norm: "3232235777", ipLike: "decimal"},
		{in: "0x7f000001", norm: "0x7f000001", ipLike: "hex"},
		{in: "10.0.0.1.5", norm: "10.0.0.1.5", ipLike: "numeric-labels"},
		{in: "", err: "empty"},
		{in: "   ", err: "empty"},
		{in: "a..b.com", norm: "a..b.com", err: "empty label"},
		{in: ".a.com", norm: ".a.com", err: "empty label"},
		{in: "-a.com", norm: "-a.com", err: "hyphen"},
		{in: "a-.com", norm: "a-.com", err: "hyphen"},
		{in: "a b.com", norm: "a b.com", err: "illegal"},
		{in: strings.Repeat("a", 64) + ".com", err: "longer than 63"},
		{in: strings.Repeat("abcdefgh.", 40) + "com", err: "longer than 253"},
		{in: "bad\xffutf8.com", err: "UTF-8"},
		{in: "xn--.com", err: "hyphen"},
		{in: "xn--zz9.com", err: "punycode"},
		{in: "_dmarc.example.com", norm: "_dmarc.example.com", suffix: "com", sld: "example", subs: 1},
	}
	for _, c := range cases {
		p := ParseDomain(c.in)
		if c.err != "" {
			if !strings.Contains(p.Err, c.err) {
				t.Errorf("%q: want error containing %q, got %q", c.in, c.err, p.Err)
			}
			continue
		}
		if p.Err != "" {
			t.Errorf("%q: unexpected error %q", c.in, p.Err)
			continue
		}
		if p.Normalized != c.norm || p.Suffix != c.suffix || p.SLD != c.sld || len(p.Subdomains) != c.subs || p.IPLike != c.ipLike {
			t.Errorf("%q: got norm=%q suffix=%q sld=%q subs=%d ip=%q", c.in, p.Normalized, p.Suffix, p.SLD, len(p.Subdomains), p.IPLike)
		}
	}
}

func TestDomainPunycode(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"xn--mnchen-3ya", "münchen"},
		{"xn--maana-pta", "mañana"},
		{"xn--bcher-kva", "bücher"},
		{"xn--e1afmkfd", "пример"},
		{"xn--80ak6aa92e", "аррӏе"},
	} {
		got, err := punycodeDecode(strings.TrimPrefix(c.in, "xn--"))
		if err != nil || got != c.want {
			t.Errorf("%s: got %q err=%v want %q", c.in, got, err, c.want)
		}
	}
	p := ParseDomain("xn--mnchen-3ya.de")
	if !p.HasPunycode || p.Unicode != "münchen.de" || p.SLD != "münchen" {
		t.Errorf("parse punycode: %+v", p)
	}
	for _, bad := range []string{"zz9", "a-\x80", "99999999999999999"} {
		if _, err := punycodeDecode(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func domainFindings(t *testing.T, name string) (map[string]InspectFinding, *InspectReport) {
	t.Helper()
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindDomain, Text: name})
	m := map[string]InspectFinding{}
	for _, f := range r.Findings {
		if f.Analyzer == "domain" {
			m[f.ID] = f
		}
	}
	if len(r.Errors) > 0 {
		t.Fatalf("analyzer errors: %v", r.Errors)
	}
	return m, r
}

func TestDomainAnalyzerFindings(t *testing.T) {
	cases := []struct {
		name string
		want []string
		not  []string
	}{
		{"kqwxzjvbn.xyz", []string{"dom-dga-likeness", "dom-suspicious-tld"}, nil},
		{"paypa1.com", []string{"dom-typosquat"}, nil},
		{"goggle.com", []string{"dom-typosquat"}, nil},
		{"paypal.com", nil, []string{"dom-typosquat", "dom-brand-embedded"}},
		{"secure-paypal-login.com", []string{"dom-brand-embedded"}, nil},
		{"paypal.evil-example.com", []string{"dom-brand-subdomain"}, nil},
		{"pаypal.com", []string{"dom-mixed-script"}, nil}, // Cyrillic a
		{"xn--pypal-4ve.com", []string{"dom-punycode", "dom-mixed-script"}, nil},
		{"a.b.c.d.e.f.example.com", []string{"dom-deep-subdomain"}, nil},
		{"mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiqq.example.com", []string{"dom-encoded-subdomain"}, nil},
		{"4a6f686e20446f6520776173206865.example.com", []string{"dom-encoded-subdomain"}, nil},
		{"192.168.1.1", []string{"dom-ip-host"}, nil},
		{"not a domain", []string{"dom-invalid"}, nil},
		{"mountain-weather.com", nil, []string{"dom-dga-likeness", "dom-typosquat", "dom-suspicious-tld"}},
	}
	for _, c := range cases {
		m, _ := domainFindings(t, c.name)
		for _, id := range c.want {
			if _, ok := m[id]; !ok {
				t.Errorf("%q: missing %s (have %v)", c.name, id, keysOf(m))
			}
		}
		for _, id := range c.not {
			if _, ok := m[id]; ok {
				t.Errorf("%q: unexpected %s", c.name, id)
			}
		}
		for id, f := range m {
			if !strings.HasPrefix(id, "dom-") {
				t.Errorf("finding id %q lacks dom- prefix", id)
			}
			if f.Weight > 35 {
				t.Errorf("%q: weight %d too high for a single weak signal (%s)", c.name, f.Weight, id)
			}
		}
	}
}

func keysOf(m map[string]InspectFinding) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

// No single weak signal may produce the "suspicious" verdict by itself.
func TestDomainNoVerdictFromOneSignal(t *testing.T) {
	for _, name := range []string{"kqwxzjvbn.com", "goggle.com", "example.top", "a.b.c.d.e.f.example.com", "pаypal.com", "192.168.1.1"} {
		_, r := domainFindings(t, name)
		if r.Level == "suspicious" || r.Level == "malicious-likely" {
			t.Errorf("%q: single-signal verdict %s (score %d, %v)", name, r.Level, r.Score, r.Factors)
		}
	}
}

func TestDomainDeterministic(t *testing.T) {
	for _, n := range []string{"kqwxzjvbn.xyz", "google.com", "xn--mnchen-3ya.de", "a.b.c.d.e.f.g.example.org"} {
		a, b := ScoreDomain(n), ScoreDomain(n)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: ScoreDomain not deterministic", n)
		}
		m1, _ := domainFindings(t, n)
		m2, _ := domainFindings(t, n)
		if !reflect.DeepEqual(m1, m2) {
			t.Errorf("%s: findings not deterministic", n)
		}
	}
	m1, m2 := buildDomainModel(), buildDomainModel()
	if !reflect.DeepEqual(m1.tri, m2.tri) || !reflect.DeepEqual(m1.words, m2.words) {
		t.Error("model build not deterministic")
	}
}

func TestDomainScoreEdges(t *testing.T) {
	for _, n := range []string{"", "a", "ab.com", "xn--.com", "bücher.de", "1.2.3.4", strings.Repeat("a", 70) + ".com"} {
		s := ScoreDomain(n)
		if s.Score < 0 || s.Score > 100 {
			t.Errorf("%q: score %d out of range", n, s.Score)
		}
	}
	if s := ScoreDomain("bücher.de"); s.Applicable {
		t.Error("non-ASCII label must not be scored by the Latin model")
	}
	if s := ScoreDomain("abc.com"); s.Applicable || s.Score != 0 {
		t.Error("short labels must not be scored")
	}
}

func FuzzParseDomain(f *testing.F) {
	for _, s := range []string{"example.com", "xn--mnchen-3ya.de", "a..b", "xn--", "xn--zz9", "[::1]", "http://a.b/c", "\xff", "0x7f.1", strings.Repeat("a.", 130), "xn--" + strings.Repeat("9", 80) + ".com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := ParseDomain(s)
		if p.Err == "" && p.IPLike == "" {
			if p.Normalized != strings.ToLower(p.Normalized) {
				t.Fatalf("not lowercased: %q", p.Normalized)
			}
			if strings.HasSuffix(p.Normalized, ".") {
				t.Fatalf("trailing dot kept: %q", p.Normalized)
			}
			if len(p.Normalized) > domainMaxLen {
				t.Fatalf("overlong accepted")
			}
		}
		if ds := ScoreDomain(s); ds.Score < 0 || ds.Score > 100 {
			t.Fatalf("score out of range")
		}
	})
}

// ---- evaluation ----

// Documented thresholds (see docs/domain-inspector.md). The test fails if the
// scorer regresses below them on the synthetic fixture corpus.
const (
	domainEvalMinRecall    = 0.75
	domainEvalMinPrecision = 0.95
)

func readDomainCorpus(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestDomainEvaluation(t *testing.T) {
	benign := readDomainCorpus(t, "testdata/domain_benign.txt")
	dga := readDomainCorpus(t, "testdata/domain_dga.txt")
	if len(benign) < 300 || len(dga) < 300 {
		t.Fatalf("corpus too small: benign=%d dga=%d", len(benign), len(dga))
	}
	tp, fn, fp, tn := 0, 0, 0, 0
	var fps []string
	for _, d := range dga {
		if ScoreDomain(d).Score >= DomainDGAThreshold {
			tp++
		} else {
			fn++
		}
	}
	for _, d := range benign {
		if s := ScoreDomain(d); s.Score >= DomainDGAThreshold {
			fp++
			fps = append(fps, d)
		} else {
			tn++
		}
	}
	prec := float64(tp) / float64(tp+fp)
	rec := float64(tp) / float64(tp+fn)
	f1 := 2 * prec * rec / (prec + rec)
	t.Logf("threshold=%d benign=%d dga=%d TP=%d FN=%d FP=%d TN=%d precision=%.3f recall=%.3f F1=%.3f",
		DomainDGAThreshold, len(benign), len(dga), tp, fn, fp, tn, prec, rec, f1)
	t.Logf("false positives: %v", fps)
	if rec < domainEvalMinRecall {
		t.Errorf("recall %.3f below documented minimum %.2f", rec, domainEvalMinRecall)
	}
	if prec < domainEvalMinPrecision {
		t.Errorf("precision %.3f below documented minimum %.2f", prec, domainEvalMinPrecision)
	}
}

func TestDomainCorpusIsLabelledSynthetic(t *testing.T) {
	b, _ := os.ReadFile("testdata/domain_dga.txt")
	if !strings.Contains(string(b), "SYNTHETIC") {
		t.Error("DGA corpus must be labelled synthetic")
	}
	_ = unicode.MaxASCII
}
