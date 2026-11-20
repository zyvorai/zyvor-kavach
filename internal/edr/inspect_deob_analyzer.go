// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Inspector analyzer "deobfuscation" for kinds script and cmdline. It decodes
// layered obfuscation (see inspect_deob_decode.go), extracts IOCs from every
// layer, and reports which existing live process content rules would fire on
// the decoded text. It evaluates rules only; findings are never recorded
// anywhere else and nothing is executed.

import (
	"context"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
)

const (
	deobObfWeightBudget = 35 // obfuscation-only findings can never sum past this (verdict needs 40)
	deobMaxRuleFindings = 8
)

func init() {
	RegisterAnalyzer("deobfuscation", []string{InspectKindScript, InspectKindCmdline}, analyzeDeob)
}

var deobSeverityWeight = map[string]int{"critical": 35, "high": 28, "medium": 16, "low": 6, "info": 2}

type deobCradle struct {
	id, title, technique string
	weight               int
	re                   *regexp.Regexp
}

var deobCradles = []deobCradle{
	{"deob-cradle-downloadstring", "Download cradle (DownloadString/DownloadFile/DownloadData)", "T1105", 12, regexp.MustCompile(`(?i)\.download(?:string|file|data)\b`)},
	{"deob-cradle-webrequest", "Web request cmdlet or WebClient", "T1105", 10, regexp.MustCompile(`(?i)invoke-webrequest|invoke-restmethod|net\.webclient|start-bitstransfer|\biwr\s+https?:`)},
	{"deob-cradle-curl-sh", "Download piped into a shell or interpreter", "T1105", 15, regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:python3?|perl|ruby)\b`)},
	{"deob-cradle-certutil", "certutil -urlcache download", "T1105", 15, regexp.MustCompile(`(?i)certutil(?:\.exe)?\s[^\r\n]*-urlcache`)},
	{"deob-cradle-bitsadmin", "bitsadmin /transfer download", "T1197", 12, regexp.MustCompile(`(?i)bitsadmin(?:\.exe)?\s[^\r\n]*/transfer`)},
	{"deob-cradle-iex-remote", "Invoke-Expression of remote or decoded content", "T1059.001", 12, regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^\r\n]{0,200}(?:https?://|downloadstring|frombase64string)`)},
}

var (
	deobURLRe  = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>)\]}|^` + "`" + `]+`)
	deobIPRe   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	deobHostRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|tk|ml|ga|cf|gq|cc|pw|su|onion|me|us|uk|de|in|site|online|club|shop|live|icu|app|dev)\b`)
	deobExeRe  = regexp.MustCompile(`(?i)\b([a-z0-9_-]+\.exe)\b`)
	deobUnixRe = regexp.MustCompile(`\b(curl|wget|nc|ncat|python3?|perl|bash|sh|base64|openssl|ruby|php)\b`)
)

func deobIOCs(b *InspectBuilder, text string, seenURLHosts map[string]bool) {
	if len(text) > 1<<20 {
		text = text[:1<<20]
	}
	for _, u := range deobURLRe.FindAllString(text, 100) {
		u = strings.TrimRight(u, ".,;:!?")
		b.IOC("url", u)
		h := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(u), "https://"), "http://"), "ftp://")
		if i := strings.IndexAny(h, "/:?#"); i >= 0 {
			h = h[:i]
		}
		seenURLHosts[h] = true
	}
	for _, ip := range deobIPRe.FindAllString(text, 100) {
		if net.ParseIP(ip) != nil {
			b.IOC("ipv4", ip)
			seenURLHosts[ip] = true
		}
	}
	for _, d := range deobHostRe.FindAllString(text, 100) {
		d = strings.ToLower(d)
		if !seenURLHosts[d] {
			b.IOC("domain", d)
		}
	}
}

// deobRuleHits evaluates the live process content rules on text as if it were
// a command line. Several plausible executables are tried because the input
// carries none; rule ids are returned. Nothing is recorded.
func deobRuleHits(text string) map[string]*ContentRule {
	reg := contentReg.Load()
	if reg == nil {
		_ = LoadContentPacks()
		reg = contentReg.Load()
	}
	hits := map[string]*ContentRule{}
	if reg == nil || len(reg.byType["process"]) == 0 {
		return hits
	}
	if len(text) > labMaxInputLen {
		text = text[:labMaxInputLen]
	}
	exes := []string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Windows\System32\cmd.exe`,
		`/bin/bash`,
		`/usr/bin/python3`,
	}
	seen := map[string]bool{}
	for _, m := range deobExeRe.FindAllStringSubmatch(text, 6) {
		e := strings.ToLower(m[1])
		if !seen[e] {
			seen[e] = true
			exes = append(exes, `C:\Windows\System32\`+e)
		}
	}
	for _, m := range deobUnixRe.FindAllStringSubmatch(text, 6) {
		if !seen[m[1]] {
			seen[m[1]] = true
			exes = append(exes, "/usr/bin/"+m[1])
		}
	}
	for _, exe := range exes {
		base := exe[strings.LastIndexAny(exe, `\/`)+1:]
		cmd := text
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), strings.ToLower(strings.TrimSuffix(base, ".exe"))) {
			cmd = base + " " + text
		}
		ctx := newEvalCtx(LabEvent{Kind: "process", Executable: exe, Command: cmd})
		for _, r := range reg.byType["process"] {
			if hits[r.ID] != nil {
				continue
			}
			if r.matchCtx(ctx, true) {
				hits[r.ID] = r
			}
		}
	}
	return hits
}

func deobEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var cnt [256]int
	for i := 0; i < len(s); i++ {
		cnt[s[i]]++
	}
	e := 0.0
	n := float64(len(s))
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

var deobBlobRe = regexp.MustCompile(`[A-Za-z0-9+/_=-]{200,}`)

func previewOf(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func analyzeDeob(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	text := in.Text
	res := deobRun(ctx, text)
	for _, l := range res.Limits {
		b.LimitHit(l)
	}

	baseline := deobRuleHits(text)
	urlHosts := map[string]bool{}
	deobIOCs(b, text, urlHosts)

	methodSet := map[string]bool{}
	type ruleHit struct {
		rule  *ContentRule
		depth int
		text  string
	}
	var newHits []ruleHit
	seenRule := map[string]bool{}
	var obf []InspectFinding
	cradleSeen := map[string]bool{}
	scanCradles := func(t string, depth int) {
		for _, c := range deobCradles {
			if cradleSeen[c.id] {
				continue
			}
			if loc := c.re.FindStringIndex(t); loc != nil {
				cradleSeen[c.id] = true
				ev := t[loc[0]:loc[1]]
				obf = append(obf, InspectFinding{ID: c.id, Title: c.title, Severity: "medium", Technique: c.technique,
					Evidence: fmt.Sprintf("layer %d: %s", depth, previewOf(ev)), Weight: c.weight})
			}
		}
	}
	scanCradles(text, 0)

	for _, l := range res.Layers {
		if ctx.Err() != nil {
			b.LimitHit("time")
			break
		}
		b.Layer(InspectLayer{Depth: l.Depth, Method: strings.Join(l.Methods, "+"), Bytes: len(l.Text), Preview: previewOf(l.Text)})
		for _, m := range l.Methods {
			methodSet[m] = true
		}
		deobIOCs(b, l.Text, urlHosts)
		scanCradles(l.Text, l.Depth)
		for id, r := range deobRuleHits(l.Text) {
			if baseline[id] != nil || seenRule[id] {
				continue
			}
			seenRule[id] = true
			newHits = append(newHits, ruleHit{r, l.Depth, l.Text})
		}
	}

	// structural findings about the obfuscation itself
	if n := len(res.Layers); n >= 2 {
		w := 4 * n
		if w > 16 {
			w = 16
		}
		obf = append(obf, InspectFinding{ID: "deob-layers", Title: fmt.Sprintf("Input is obfuscated in %d decoding layers", n),
			Severity: "low", Technique: "T1027", Weight: w})
	}
	if n := len(methodSet); n >= 3 {
		names := make([]string, 0, n)
		for m := range methodSet {
			names = append(names, m)
		}
		sort.Strings(names)
		obf = append(obf, InspectFinding{ID: "deob-mixed-techniques", Title: "Several obfuscation techniques combined",
			Severity: "low", Technique: "T1027", Evidence: strings.Join(names, ", "), Weight: 6})
	}
	for m := range methodSet {
		switch {
		case strings.Contains(m, "xor-"):
			obf = append(obf, InspectFinding{ID: "deob-xor-payload", Title: "Payload hidden with single-byte XOR", Severity: "medium",
				Technique: "T1027", Evidence: m, Weight: 8})
		}
	}
	if methodSet["gzip"] || methodSet["deflate"] || methodSet["zlib"] {
		obf = append(obf, InspectFinding{ID: "deob-compressed-payload", Title: "Compressed payload embedded in the text", Severity: "low",
			Technique: "T1027.015", Weight: 6})
	}
	for _, l := range res.Limits {
		if l == "decompression-cap" {
			obf = append(obf, InspectFinding{ID: "deob-decompression-bomb", Title: "Embedded compressed data exceeds the decompression cap (possible bomb); not expanded further",
				Severity: "medium", Technique: "T1027", Weight: 10})
		}
	}
	for _, blob := range deobBlobRe.FindAllString(text, 20) {
		if deobEntropy(blob) >= 5.0 {
			obf = append(obf, InspectFinding{ID: "deob-high-entropy-blob", Title: fmt.Sprintf("Very high entropy blob (%d chars)", len(blob)),
				Severity: "low", Technique: "T1027", Evidence: previewOf(blob), Weight: 6})
			break
		}
	}

	// obfuscation evidence alone must never reach a verdict
	sort.SliceStable(obf, func(i, j int) bool { return obf[i].Weight > obf[j].Weight })
	budget := deobObfWeightBudget
	for _, f := range obf {
		if f.Weight > budget {
			f.Weight = budget
		}
		budget -= f.Weight
		b.Finding(f)
	}

	// rules that fire only because of decoding (strongest first)
	sort.SliceStable(newHits, func(i, j int) bool {
		wi, wj := deobSeverityWeight[newHits[i].rule.Severity], deobSeverityWeight[newHits[j].rule.Severity]
		if wi != wj {
			return wi > wj
		}
		return newHits[i].rule.ID < newHits[j].rule.ID
	})
	for i, h := range newHits {
		if i >= deobMaxRuleFindings {
			b.LimitHit("rule-findings")
			break
		}
		b.Finding(InspectFinding{
			ID:        "deob-" + h.rule.ID,
			Title:     fmt.Sprintf("Decoded layer %d would trigger rule %s: %s", h.depth, h.rule.ID, h.rule.Name),
			Severity:  h.rule.Severity,
			Technique: h.rule.Technique,
			Evidence:  previewOf(h.text),
			Weight:    deobSeverityWeight[h.rule.Severity],
		})
	}
	if len(res.Layers) > 0 {
		b.Format("obfuscated-text")
	}
	b.Meta("layers", len(res.Layers))
	return nil
}
