// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Evaluation of the URL analyzer on a SYNTHETIC corpus: 300 benign-style and
// 300 phishing-style URLs produced by the generators below from a fixed seed.
// None of these URLs is real, none is fetched, and the "phishing" shapes are
// written by the same author as the analyzer, so the numbers overstate real
// accuracy (see docs/url-email-inspection.md). The floor only guards against
// regressions.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

const urlEvalN = 300

func pick(r *rand.Rand, xs []string) string { return xs[r.Intn(len(xs))] }

func randWord(r *rand.Rand, n int) string {
	const al = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = al[r.Intn(len(al))]
	}
	return string(b)
}

func randTok(r *rand.Rand, n int) string {
	const al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = al[r.Intn(len(al))]
	}
	return string(b)
}

var evalWords = []string{"harbor", "meadow", "lantern", "orchard", "summit", "copper", "willow", "granite", "falcon", "maple", "river", "stone", "cedar", "bright", "garden", "studio", "market", "journal", "atlas", "beacon", "compass", "ember", "forge", "glacier", "horizon", "island", "juniper", "kitchen", "library", "mountain", "northern", "ocean", "pioneer", "quartz", "rocket", "silver", "timber", "union", "valley", "wonder"}
var evalBrands = []string{"paypal", "microsoft", "amazon", "apple", "google", "netflix", "facebook", "instagram", "dropbox", "docusign", "linkedin", "chase", "wellsfargo", "dhl", "fedex"}
var evalLoginWords = []string{"login", "signin", "verify", "secure", "account", "update", "confirm", "password", "billing", "recover", "unlock"}

// genBenignURL builds one benign-style URL.
func genBenignURL(r *rand.Rand) string {
	tlds := []string{"com", "org", "net", "io", "co.uk", "dev", "edu", "de", "info"}
	host := pick(r, evalWords) + pick(r, []string{"", "-" + pick(r, evalWords), pick(r, evalWords)})
	reg := host + "." + pick(r, tlds)
	sub := pick(r, []string{"www.", "www.", "docs.", "blog.", "shop.", "support.", "news.", "", "api."})
	scheme := "https"
	if r.Intn(12) == 0 {
		scheme = "http"
	}
	h := sub + reg
	switch r.Intn(10) {
	case 0:
		// well-known-brand legitimate pages
		h = pick(r, []string{"www.", "support.", "docs.", ""}) + pick(r, evalBrands) + ".com"
	case 1:
		h = pick(r, []string{"bit.ly", "t.co", "tinyurl.com"})
		return scheme + "://" + h + "/" + randTok(r, 7)
	}
	port := ""
	if r.Intn(25) == 0 {
		port = ":8443"
	}
	segs := []string{"docs", "blog", "products", "articles", "news", "about", "pricing", "download", "help", "careers", "events"}
	p := "/" + pick(r, segs)
	for i := r.Intn(3); i > 0; i-- {
		p += "/" + pick(r, evalWords) + "-" + pick(r, evalWords)
	}
	if r.Intn(3) == 0 {
		p += fmt.Sprintf("/%d", 1000+r.Intn(90000))
	}
	if r.Intn(4) == 0 {
		p += pick(r, []string{".html", ".pdf", "/index.php"})
	}
	q := ""
	switch r.Intn(6) {
	case 0:
		q = "?page=" + fmt.Sprint(1+r.Intn(30)) + "&sort=" + pick(r, []string{"date", "name", "price"})
	case 1:
		q = "?utm_source=" + pick(r, []string{"newsletter", "twitter", "email"}) + "&utm_medium=social&utm_campaign=" + pick(r, evalWords) + fmt.Sprint(r.Intn(99))
	case 2:
		q = "?q=" + pick(r, evalWords) + "%20" + pick(r, evalWords)
	case 3:
		q = "?id=" + randTok(r, 8) + "&ref=" + randTok(r, 6)
	case 4: // same-site redirect after login (benign pattern)
		q = "?next=/" + pick(r, segs) + "/" + pick(r, evalWords)
	}
	if r.Intn(10) == 0 {
		p = "/" + pick(r, []string{"login", "signin", "account"}) // legitimate login pages exist
		q = ""
	}
	return scheme + "://" + h + port + p + q
}

// genPhishURL builds one phishing-style URL from a rotating set of shapes.
func genPhishURL(r *rand.Rand) string {
	brand := pick(r, evalBrands)
	badTLD := pick(r, []string{"xyz", "top", "click", "icu", "buzz", "support", "work", "live", "shop", "cfd"})
	login := "/" + pick(r, evalLoginWords) + pick(r, []string{"", ".php", "/", "/index.html"}) + pick(r, []string{"", "?id=" + randTok(r, 10), "?session=" + randTok(r, 24)})
	rnd := randWord(r, 9+r.Intn(8))
	switch r.Intn(14) {
	case 0: // userinfo trick
		return "http://" + brand + ".com@" + rnd + "." + badTLD + login
	case 1: // raw IP + login path
		return fmt.Sprintf("http://%d.%d.%d.%d%s", 11+r.Intn(200), r.Intn(255), r.Intn(255), 1+r.Intn(254), "/"+brand+login)
	case 2: // obfuscated IP
		if r.Intn(2) == 0 {
			return fmt.Sprintf("http://%d/%s", 3000000000+r.Int63n(900000000), pick(r, evalLoginWords))
		}
		return fmt.Sprintf("http://0x%02X%02X%02X%02X/%s", 11+r.Intn(200), r.Intn(255), r.Intn(255), 1+r.Intn(254), pick(r, evalLoginWords))
	case 3: // brand as subdomain of unrelated domain
		return "https://" + brand + "." + pick(r, evalLoginWords) + "-" + rnd[:6] + "." + badTLD + login
	case 4: // brand-in-registrable with hyphens
		return "https://" + pick(r, evalLoginWords) + "-" + brand + "-" + pick(r, evalLoginWords) + "." + badTLD + login
	case 5: // typosquat
		b := []byte(brand)
		i := 1 + r.Intn(len(b)-2)
		switch r.Intn(3) {
		case 0:
			b[i] = '1'
		case 1:
			b[i], b[i+1] = b[i+1], b[i]
		default:
			b = append(b[:i], b[i+1:]...)
		}
		return "https://www." + string(b) + "." + pick(r, []string{"com", "net", "co", badTLD}) + login
	case 6: // punycode homograph
		return "https://xn--" + randWord(r, 5) + "-" + randWord(r, 3) + "." + pick(r, []string{"com", badTLD}) + login
	case 7: // deep subdomain chain
		return "https://" + brand + "." + pick(r, evalLoginWords) + "." + randWord(r, 5) + "." + randWord(r, 6) + "." + randWord(r, 5) + "." + rnd + "." + badTLD + login
	case 8: // nested redirect to an attacker host
		return "https://" + pick(r, evalWords) + "-" + randWord(r, 4) + ".com/redirect?url=https%3A%2F%2F" + rnd + "." + badTLD + "%2F" + pick(r, evalLoginWords)
	case 9: // keyword-heavy path on an odd host
		return "http://" + rnd + "." + badTLD + "/" + pick(r, evalLoginWords) + "/" + pick(r, evalLoginWords) + "/" + brand + "/" + pick(r, evalLoginWords) + ".php"
	case 10: // percent-encoded host / double encoding
		return "http://" + rnd[:5] + "%2e" + badTLD + "/" + pick(r, evalLoginWords) + "%252f" + randTok(r, 6)
	case 11: // script / data schemes
		if r.Intn(2) == 0 {
			return "javascript:window.location='http://" + rnd + "." + badTLD + "/" + pick(r, evalLoginWords) + "'"
		}
		return "data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0iaHR0cDovL2V2aWwuZXhhbXBsZS8iPC9zY3JpcHQ+"
	case 12: // DGA-ish domain, odd port
		return fmt.Sprintf("http://%s.%s:%d%s", randWord(r, 14), badTLD, 8000+r.Intn(1500), login)
	default: // compromised-site style: plain domain, plausible path; hardest case, mostly missed
		return "https://" + pick(r, evalWords) + pick(r, evalWords) + "." + pick(r, []string{"com", "org", "net"}) + "/wp-content/" + pick(r, []string{"uploads", "plugins", "themes"}) + "/" + randWord(r, 6) + login
	}
}

type urlEvalResult struct{ tp, fp, tn, fn int }

func (e urlEvalResult) precision() float64 { return float64(e.tp) / float64(max(1, e.tp+e.fp)) }
func (e urlEvalResult) recall() float64    { return float64(e.tp) / float64(max(1, e.tp+e.fn)) }

func runURLEval(seed int64) (urlEvalResult, []string, []string) {
	r := rand.New(rand.NewSource(seed))
	var e urlEvalResult
	var fps, fns []string
	for i := 0; i < urlEvalN; i++ {
		u := genBenignURL(r)
		if RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindURL, Text: u}).Score >= URLPhishThreshold {
			e.fp++
			fps = append(fps, u)
		} else {
			e.tn++
		}
	}
	for i := 0; i < urlEvalN; i++ {
		u := genPhishURL(r)
		if RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindURL, Text: u}).Score >= URLPhishThreshold {
			e.tp++
		} else {
			e.fn++
			fns = append(fns, u)
		}
	}
	return e, fps, fns
}

func TestURLEvaluationSynthetic(t *testing.T) {
	e, fps, fns := runURLEval(20261113)
	t.Logf("SYNTHETIC corpus: %d benign + %d phishing-style, threshold score>=%d: TP=%d FP=%d TN=%d FN=%d precision=%.3f recall=%.3f",
		urlEvalN, urlEvalN, URLPhishThreshold, e.tp, e.fp, e.tn, e.fn, e.precision(), e.recall())
	for i, u := range fps {
		if i < 8 {
			t.Logf("FP: %s", u)
		}
	}
	for i, u := range fns {
		if i < 8 {
			t.Logf("FN: %s", u)
		}
	}
	// Failing floors (regression guard on synthetic data, not a quality claim).
	if e.precision() < 0.90 {
		t.Errorf("precision %.3f below floor 0.90", e.precision())
	}
	if e.recall() < 0.60 {
		t.Errorf("recall %.3f below floor 0.60", e.recall())
	}
}

func TestURLEvalCorpusIsLabelledSynthetic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		u := genPhishURL(r)
		if strings.Contains(u, "paypal.com/") && strings.HasPrefix(u, "https://www.paypal.com/") {
			t.Fatalf("generator emitted a real brand URL: %s", u)
		}
	}
}
