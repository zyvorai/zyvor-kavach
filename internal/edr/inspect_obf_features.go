// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Statistical obfuscation features for the "obfuscation-stats" inspector
// analyzer. Every feature is a plain, documented measurement (no hidden
// state); see docs/research-obfuscation.md for the literature they follow.
// Nothing here executes or decodes input.

import (
	"embed"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed testdata/obf/reference/*.txt
var obfRefFS embed.FS

// Languages the analyzer knows reference distributions for.
const (
	obfLangPS   = "powershell"
	obfLangCmd  = "cmd"
	obfLangBash = "bash"
	obfLangJS   = "javascript"
	obfLangPy   = "python"
	obfLangVBA  = "vba"
)

var obfLangs = []string{obfLangPS, obfLangCmd, obfLangBash, obfLangJS, obfLangPy, obfLangVBA}

// obfFeatureNames fixes the order of the feature vector. The trained weights
// (inspect_obf_weights.go) are indexed in this order.
var obfFeatureNames = []string{
	"cos_dist",         // 1 - cosine similarity of the printable-ASCII frequency vector to the language reference (Revoke-Obfuscation's character-frequency idea)
	"class_dist",       // half L1 distance of the 5-class vector (lower, upper, digit, space, punct) to the reference
	"entropy",          // Shannon entropy of bytes, bits/char
	"nonalnum",         // share of non-alphanumeric, non-space characters
	"tick_density",     // backticks between letters, per 100 chars
	"caret_density",    // carets inside words/commands, per 100 chars
	"quote_split",      // empty quote pairs between letters (c''a't), per 100 chars
	"tok_len_mean",     // mean identifier-token length (capped at 40)
	"tok_len_std",      // standard deviation of identifier-token length
	"tok_len_p90",      // 90th percentile identifier-token length (capped at 64)
	"long_token_ratio", // share of chars inside whitespace-free runs of >= 40 chars
	"case_irregular",   // share of alphabetic words (len>=4) with irregular (random) case
	"case_flip_rate",   // case flips per adjacent letter pair inside words
	"var_surprisal",    // mean bigram surprisal (bits/char) of identifiers under the benign bigram model
	"var_random_frac",  // share of identifiers that look machine generated
	"concat_density",   // string concatenation operators between literals, per 100 chars
	"format_density",   // {0}{1} format placeholders and -f, per 100 chars
	"blob_ratio",       // share of chars in high-entropy base64/hex runs
	"pat_charcode",     // log1p count of [char]NN, chr(, fromCharCode, \xNN, \uNNNN escapes
	"pat_dynexec",      // log1p count of iex/Invoke-Expression/eval/exec/Function( dynamic execution forms
	"pat_envsub",       // log1p count of %X:~a,b%, ${IFS}, ${v:a:b}, $env:comspec[..] substring tricks
	"pat_join",         // log1p count of -join, join(, split+join, [char[]]
	"pat_dollarbrace",  // log1p count of ${...} forms that are not plain variable names
	"pat_b64decode",    // log1p count of FromBase64String, atob, base64 -d, b64decode, -enc
	"pat_reverse",      // log1p count of string reversal idioms
	"log_len",          // log(length), so scale is explicit
}

var obfFeatureIndex = func() map[string]int {
	m := map[string]int{}
	for i, n := range obfFeatureNames {
		m[n] = i
	}
	return m
}()

// ObfFeatures is the measured vector plus context.
type ObfFeatures struct {
	Lang   string
	Length int
	V      []float64 // ordered as obfFeatureNames
}

// Get returns a feature by name.
func (f ObfFeatures) Get(name string) float64 { return f.V[obfFeatureIndex[name]] }

type obfRef struct {
	asciiVec [95]float64 // normalized frequency of printable ASCII
	classVec [5]float64
}

var (
	obfRefOnce sync.Once
	obfRefs    map[string]*obfRef
	obfBigram  [27][27]float64 // log2 P(next|prev), index 26 = boundary
)

// obfCommonWords seeds the bigram model with ordinary identifier vocabulary
// in addition to every identifier and word in the embedded reference scripts.
const obfCommonWords = `get set new add remove delete list item items name names value values count total sum index
path file files folder directory user users server client host port address result results response request status
error errors message messages config configuration settings options option param params parameter parameters
string number integer boolean array object function method class module package import export return print write
read open close start stop restart install update upgrade backup restore copy move rename create build test
deploy release version source target output input buffer cache timer timeout retry handler callback event events
service services process processes system network connection session token key keys data info debug warning
length size width height first last next previous current default enable disable check validate parse format
sort filter map reduce each loop while begin end then else when match replace split join trim lower upper
local global public private static final temp tmp log logs report summary account account password
query table column row rows record records field fields group groups role roles policy rules action actions
computer domain active directory service package manager command script shell terminal window display`

var (
	obfWordRe  = regexp.MustCompile(`[A-Za-z]{3,}`)
	obfIdentRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{2,}`)
)

func obfLoadRefs() {
	obfRefOnce.Do(func() {
		obfRefs = map[string]*obfRef{}
		var counts [27][27]float64
		feed := func(w string) {
			prev := 26
			for _, c := range strings.ToLower(w) {
				if c < 'a' || c > 'z' {
					continue
				}
				counts[prev][c-'a']++
				prev = int(c - 'a')
			}
			counts[prev][26]++
		}
		for _, w := range strings.Fields(obfCommonWords) {
			feed(w)
		}
		for _, lang := range obfLangs {
			b, err := obfRefFS.ReadFile("testdata/obf/reference/" + lang + ".txt")
			if err != nil {
				continue
			}
			var all strings.Builder
			for _, s := range strings.Split(string(b), "\n-----\n") {
				all.WriteString(s)
				all.WriteByte('\n')
			}
			text := all.String()
			r := &obfRef{}
			r.asciiVec, r.classVec = obfCharVectors(text)
			obfRefs[lang] = r
			for _, w := range obfWordRe.FindAllString(text, -1) {
				// split camelCase so bigram stats reflect word parts
				for _, p := range obfSplitCamel(w) {
					feed(p)
				}
			}
		}
		for i := 0; i < 27; i++ {
			var tot float64
			for j := 0; j < 27; j++ {
				tot += counts[i][j] + 0.1
			}
			for j := 0; j < 27; j++ {
				obfBigram[i][j] = math.Log2((counts[i][j] + 0.1) / tot)
			}
		}
	})
}

func obfSplitCamel(w string) []string {
	var out []string
	start := 0
	for i := 1; i < len(w); i++ {
		if w[i] >= 'A' && w[i] <= 'Z' && w[i-1] >= 'a' && w[i-1] <= 'z' {
			out = append(out, w[start:i])
			start = i
		}
	}
	return append(out, w[start:])
}

// obfCharVectors returns the normalized printable-ASCII frequency vector and
// the 5-class vector. Tabs, CR and LF count as space.
func obfCharVectors(s string) ([95]float64, [5]float64) {
	var a [95]float64
	var c [5]float64
	var n float64
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\n' || ch == '\r' || ch == '\t':
			ch = ' '
		case ch < 32 || ch > 126:
			continue
		}
		a[ch-32]++
		n++
		switch {
		case ch >= 'a' && ch <= 'z':
			c[0]++
		case ch >= 'A' && ch <= 'Z':
			c[1]++
		case ch >= '0' && ch <= '9':
			c[2]++
		case ch == ' ':
			c[3]++
		default:
			c[4]++
		}
	}
	if n > 0 {
		for i := range a {
			a[i] /= n
		}
		for i := range c {
			c[i] /= n
		}
	}
	return a, c
}

func obfCosine(a, b [95]float64) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// ---- language detection ----------------------------------------------------

var obfLangMarkers = map[string][]string{
	obfLangPS:   {"$_", "write-host", "get-", "set-", "new-object", "-eq ", "-ne ", "invoke-", "powershell", "pwsh", "[char]", "-join", "iex", "param(", "foreach (", "$env:", "-enc", "[string]", "[int]", "-replace", "out-null", "-f "},
	obfLangCmd:  {"@echo", "cmd /c", "cmd.exe", "%~", "setlocal", "goto ", "if exist", "for /f", "robocopy", "xcopy", "schtasks", "net stop", "net start", "%comspec%", "%temp%", "&&", "start /", "certutil", "rem "},
	obfLangBash: {"#!/bin", "$(", "sudo ", "apt-get", "| grep", "| awk", "echo ", " fi", "; then", "done", "mkdir -p", "chmod ", "/dev/null", "curl ", "wget ", "base64 -d", "${ifs}", "export ", "xargs"},
	obfLangJS:   {"function", "const ", "let ", "var ", "=>", "console.", "document.", "require(", "fromcharcode", "eval(", "window.", "module.exports", "settimeout", "atob(", "unescape("},
	obfLangPy:   {"def ", "import ", "print(", "self.", "__name__", "elif ", "exec(", "chr(", "b64decode", "lambda ", "subprocess", "os.system", "range(", ":\n"},
	obfLangVBA:  {"sub ", "end sub", "dim ", "as string", "createobject", "chr(", "function ", "end function", "set ", "msgbox", "wscript.shell", "chrw(", "application."},
}

var obfExtLang = map[string]string{
	".ps1": obfLangPS, ".psm1": obfLangPS, ".psd1": obfLangPS,
	".bat": obfLangCmd, ".cmd": obfLangCmd,
	".sh": obfLangBash, ".bash": obfLangBash,
	".js": obfLangJS, ".mjs": obfLangJS, ".jse": obfLangJS,
	".py":  obfLangPy,
	".vba": obfLangVBA, ".vbs": obfLangVBA, ".bas": obfLangVBA, ".vbe": obfLangVBA,
}

// obfDetectLang returns the best-guess language or "" when unclear.
func obfDetectLang(name, text string) string {
	lname := strings.ToLower(name)
	if i := strings.LastIndexByte(lname, '.'); i >= 0 {
		if l, ok := obfExtLang[lname[i:]]; ok {
			return l
		}
	}
	head := text
	if len(head) > 16384 {
		head = head[:16384]
	}
	low := strings.ToLower(head)
	trim := strings.TrimSpace(low)
	switch {
	case strings.HasPrefix(trim, "#!") && (strings.Contains(trim[:min(40, len(trim))], "sh") || strings.Contains(trim[:min(40, len(trim))], "bash")):
		return obfLangBash
	case strings.HasPrefix(trim, "powershell") || strings.HasPrefix(trim, "pwsh"):
		return obfLangPS
	case strings.HasPrefix(trim, "cmd") || strings.HasPrefix(trim, "@echo") || strings.HasPrefix(trim, "%comspec%"):
		return obfLangCmd
	}
	best, bestScore, second := "", 0, 0
	for _, lang := range obfLangs {
		s := 0
		for _, m := range obfLangMarkers[lang] {
			if strings.Contains(low, m) {
				s++
			}
		}
		if s > bestScore {
			best, second, bestScore = lang, bestScore, s
		} else if s > second {
			second = s
		}
	}
	if bestScore == 0 || bestScore == second {
		return ""
	}
	return best
}

// ---- feature extraction ----------------------------------------------------

var (
	obfTickRe      = regexp.MustCompile("[A-Za-z]`[A-Za-z0-9]")
	obfCaretRe     = regexp.MustCompile(`\^[^\s^]|\^\^`)
	obfQuoteSplit  = regexp.MustCompile(`[A-Za-z0-9](?:''|"")[A-Za-z0-9]`)
	obfTokenRe     = regexp.MustCompile(`[A-Za-z0-9_]+`)
	obfAlphaWordRe = regexp.MustCompile(`[A-Za-z]{4,}`)
	obfConcatRe    = regexp.MustCompile(`['"]\s*[+&]\s*['"]|['"]\s*\.\s*['"]|\)\s*\+\s*['"]`)
	obfFormatRe    = regexp.MustCompile(`\{\d{1,2}\}`)
	obfFormatOpRe  = regexp.MustCompile(`['"]\s*-f\s*['"$(\w]`)
	obfB64RunRe    = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	obfHexRunRe    = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[ ,\-]?){24,}`)
	obfCamelRe     = regexp.MustCompile(`^(?:[a-z]+(?:[A-Z][a-z0-9]*)+|[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)*|[A-Z]+[a-z]*|[A-Z]{2,}[a-z]*[A-Z]*)$`)
	obfVarDeclRe   = regexp.MustCompile(`(?i)(?:\$\{?([A-Za-z_][A-Za-z0-9_]{2,})\}?\s*=|\b(?:var|let|const|dim|set)\s+([A-Za-z_][A-Za-z0-9_]{2,})|^\s*([A-Za-z_][A-Za-z0-9_]{2,})\s*=[^=]|\bset\s+"?([A-Za-z_][A-Za-z0-9_]{2,})=|(?:^|[;\s])([A-Za-z_][A-Za-z0-9_]{2,})=)`)

	obfPatCharcode = regexp.MustCompile(`(?i)\[char\]\s*\(?\s*(?:0x)?[0-9a-f]{2,3}|\bchrw?\s*\(|fromcharcode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\[0-7]{3}|\bord\s*\(`)
	obfPatDynexec  = regexp.MustCompile(`(?i)(?:^|[^\w-])(?:iex|invoke-expression)\b|\.\s*\(\s*\$|&\s*\(\s*\$|\beval\s*\(|\bexec\s*\(|\bnew\s+function\s*\(|\bfunction\s*\(\s*['"]|\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bexecute(?:global)?\s*\(|\bcallbyname\b|\|\s*iex\b`)
	obfPatEnvsub   = regexp.MustCompile(`(?i)%[a-z0-9_]+:~-?\d+(?:,-?\d+)?%|\$\{ifs\}|\$ifs|\$\{[a-z_]+:\d+:\d+\}|\$env:comspec\[|\$env:public\[|\$\{?[a-z_]+\}?\[\d+(?:,\d+)+\]|%[a-z_]+:[^%~\s]{1,8}=[^%\s]{0,8}%`)
	obfPatJoin     = regexp.MustCompile(`(?i)-join\b|\bjoin\s*\(|\[char\[\]\]|\[string\]::join|\.join\s*\(|-split\b`)
	obfPatBrace    = regexp.MustCompile(`\$\{[^}A-Za-z_:]|\$\{[A-Za-z_]*[^}A-Za-z0-9_:\-]|\$\{[^}]{20,}\}`)
	obfPatB64      = regexp.MustCompile(`(?i)frombase64string|\batob\s*\(|base64\s+(?:-d|--decode)|b64decode|\s-e(?:nc|ncodedcommand|nco\w*)?\s+[A-Za-z0-9+/=]{12,}|decodefrombase64|certutil[^\n]*-decode`)
	obfPatReverse  = regexp.MustCompile(`(?i)\[array\]::reverse|\[-1\.\.|\[::-1\]|\.reverse\(\)|\bstrreverse\b|\brev\b\s*[|<]|-1\)\]|\[\s*\d+\.\.0\s*\]`)
)

func obfCount(re *regexp.Regexp, s string) float64 {
	return float64(len(re.FindAllStringIndex(s, 2000)))
}

// ObfExtract computes the feature vector for text under the given language
// (empty means unknown: the closest reference distribution is used).
func ObfExtract(text, lang string) ObfFeatures {
	obfLoadRefs()
	if len(text) > 256<<10 {
		text = text[:256<<10]
	}
	n := float64(len(text))
	f := ObfFeatures{Lang: lang, Length: len(text), V: make([]float64, len(obfFeatureNames))}
	set := func(name string, v float64) {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			v = 0
		}
		f.V[obfFeatureIndex[name]] = v
	}
	if n == 0 {
		return f
	}
	per100 := func(c float64) float64 { return c * 100 / n }

	// character-class vectors and distance to the reference
	av, cv := obfCharVectors(text)
	bestCos, bestClass := -1.0, 0.0
	for _, l := range obfLangs {
		if lang != "" && l != lang {
			continue
		}
		r := obfRefs[l]
		if r == nil {
			continue
		}
		if c := obfCosine(av, r.asciiVec); c > bestCos {
			bestCos = c
			var d float64
			for i := range cv {
				d += math.Abs(cv[i] - r.classVec[i])
			}
			bestClass = d / 2
		}
	}
	if bestCos < 0 {
		bestCos = 0
	}
	set("cos_dist", 1-bestCos)
	set("class_dist", bestClass)

	// entropy and non-alphanumeric share
	var freq [256]float64
	nonAlnum := 0.0
	for i := 0; i < len(text); i++ {
		c := text[i]
		freq[c]++
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			nonAlnum++
		}
	}
	set("entropy", obfEntropy(freq[:], n))
	set("nonalnum", nonAlnum/n)

	set("tick_density", per100(obfCount(obfTickRe, text)))
	set("caret_density", per100(obfCount(obfCaretRe, text)))
	set("quote_split", per100(obfCount(obfQuoteSplit, text)))

	// token-length distribution
	toks := obfTokenRe.FindAllString(text, 20000)
	if len(toks) > 0 {
		lens := make([]float64, len(toks))
		var sum float64
		for i, t := range toks {
			l := float64(len(t))
			if l > 40 {
				l = 40
			}
			lens[i] = l
			sum += l
		}
		mean := sum / float64(len(lens))
		var vr float64
		for _, l := range lens {
			vr += (l - mean) * (l - mean)
		}
		sort.Float64s(lens)
		p90 := lens[int(0.9*float64(len(lens)-1))]
		set("tok_len_mean", mean)
		set("tok_len_std", math.Sqrt(vr/float64(len(lens))))
		set("tok_len_p90", p90)
	}

	// long unbroken runs
	var long float64
	for _, run := range strings.Fields(text) {
		if len(run) >= 40 {
			long += float64(len(run))
		}
	}
	set("long_token_ratio", long/n)

	// case alternation
	words := obfAlphaWordRe.FindAllString(text, 20000)
	if len(words) > 0 {
		var irregular, flips, pairs float64
		for _, w := range words {
			hasU, hasL := false, false
			for i := 0; i < len(w); i++ {
				if w[i] >= 'A' && w[i] <= 'Z' {
					hasU = true
				} else {
					hasL = true
				}
				if i > 0 {
					pairs++
					if (w[i] >= 'A' && w[i] <= 'Z') != (w[i-1] >= 'A' && w[i-1] <= 'Z') {
						flips++
					}
				}
			}
			if hasU && hasL && !obfCamelRe.MatchString(w) {
				irregular++
			}
		}
		set("case_irregular", irregular/float64(len(words)))
		set("case_flip_rate", flips/pairs)
	}

	// identifier randomness
	idents := map[string]bool{}
	for _, m := range obfVarDeclRe.FindAllStringSubmatch(text, 2000) {
		for _, g := range m[1:] {
			if g != "" {
				idents[g] = true
			}
		}
	}
	if len(idents) > 0 {
		var tot float64
		var rnd float64
		for id := range idents {
			tot += obfSurprisal(id)
			if obfLooksGenerated(id) {
				rnd++
			}
		}
		set("var_surprisal", tot/float64(len(idents)))
		set("var_random_frac", rnd/float64(len(idents)))
	}

	set("concat_density", per100(obfCount(obfConcatRe, text)))
	fmtN := obfCount(obfFormatRe, text) + 3*obfCount(obfFormatOpRe, text)
	set("format_density", per100(fmtN))

	// encoded blobs
	var blob float64
	for _, r := range obfB64RunRe.FindAllString(text, 200) {
		if obfRunEntropy(r) >= 4.3 {
			blob += float64(len(r))
		}
	}
	for _, r := range obfHexRunRe.FindAllString(text, 200) {
		blob += float64(len(r))
	}
	set("blob_ratio", math.Min(blob/n, 1))

	lg := func(re *regexp.Regexp) float64 { return math.Log1p(obfCount(re, text)) }
	set("pat_charcode", lg(obfPatCharcode))
	set("pat_dynexec", lg(obfPatDynexec))
	set("pat_envsub", lg(obfPatEnvsub))
	set("pat_join", lg(obfPatJoin))
	set("pat_dollarbrace", lg(obfPatBrace))
	set("pat_b64decode", lg(obfPatB64))
	set("pat_reverse", lg(obfPatReverse))
	set("log_len", math.Log(n))
	return f
}

func obfEntropy(freq []float64, n float64) float64 {
	var h float64
	for _, c := range freq {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func obfRunEntropy(s string) float64 {
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	return obfEntropy(freq[:], float64(len(s)))
}

// obfSurprisal is the mean bigram surprisal in bits per letter of an
// identifier under the benign bigram model (digits and underscores dropped,
// camelCase split so word boundaries are modeled).
func obfSurprisal(id string) float64 {
	obfLoadRefs()
	var bits, cnt float64
	for _, part := range obfSplitCamel(id) {
		prev := 26
		seen := false
		for _, c := range strings.ToLower(part) {
			if c < 'a' || c > 'z' {
				prev = 26
				continue
			}
			bits -= obfBigram[prev][c-'a']
			cnt++
			prev = int(c - 'a')
			seen = true
		}
		if seen {
			bits -= obfBigram[prev][26]
			cnt++
		}
	}
	if cnt == 0 {
		return 0
	}
	return bits / cnt
}

var obfGenIdentRe = regexp.MustCompile(`^_?0x[0-9a-fA-F]{3,}$|^[A-Za-z]{1,2}\d{3,}$|^_{1,3}[A-Za-z0-9]{6,}$`)

func obfLooksGenerated(id string) bool {
	if obfGenIdentRe.MatchString(id) {
		return true
	}
	letters, vowels, digits := 0, 0, 0
	for _, c := range strings.ToLower(id) {
		switch {
		case c >= 'a' && c <= 'z':
			letters++
			if strings.ContainsRune("aeiouy", c) {
				vowels++
			}
		case c >= '0' && c <= '9':
			digits++
		}
	}
	if letters >= 6 && vowels*6 < letters {
		return true
	}
	return digits >= 3 && letters >= 3 && len(id) >= 8
}
