// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Domain inspector: DGA-likeness scorer.
//
// ScoreDomain is reusable by other code. It is deterministic, offline and has
// no hidden state beyond the n-gram model built once at init() from the
// embedded word lists in domaindata/.
//
// The score (0-100) is a sum of capped, individually visible points:
//
//	ngram     0-40  character tri-gram (interpolated with bi-gram) log-likelihood
//	                of the label against the word model; lower likelihood = more points
//	coverage  0-12  share of letters NOT explained by a greedy dictionary segmentation
//	entropy   0-10  Shannon entropy above 3.3 bits/char on labels of 10+ chars
//	length    0-8   labels longer than 11 chars
//	digits    0-12  digit ratio above 0.25
//	consonant 0-12  longest consonant run of 5+ letters
//	vowel     0-8   vowel ratio below 0.2 or above 0.65 on labels of 7+ chars
//	concat    0-10  fully dictionary-covered but 3+ words and 16+ chars (dictionary DGA shape)
//
// The documented decision threshold for "DGA-like" is DomainDGAThreshold.
// Labels shorter than 6 characters are not scored (too little signal).

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
)

// DomainDGAThreshold is the score at or above which a name is called DGA-like.
const DomainDGAThreshold = 40

// DomainScore is the result of ScoreDomain.
type DomainScore struct {
	Name        string         `json:"name"`
	Registrable string         `json:"registrable"`
	Label       string         `json:"label"` // the scored label
	Score       int            `json:"score"` // 0-100
	DGALike     bool           `json:"dga_like"`
	Applicable  bool           `json:"applicable"` // false when the label is too short or not Latin
	Factors     []string       `json:"factors"`    // e.g. "ngram +22"
	Features    DomainFeatures `json:"features"`
	Parse       DomainParts    `json:"parse"`
}

// DomainFeatures are the raw measurements behind the points.
type DomainFeatures struct {
	Length     int      `json:"length"`
	AvgLogProb float64  `json:"avg_log2_prob"` // per char, tri-gram model
	Entropy    float64  `json:"entropy_bits"`
	DigitRatio float64  `json:"digit_ratio"`
	VowelRatio float64  `json:"vowel_ratio"`
	ConsRun    int      `json:"max_consonant_run"`
	Coverage   float64  `json:"dict_coverage"`
	Words      []string `json:"words,omitempty"`
}

type domainModel struct {
	tri   map[[3]byte]float64
	bi    map[[2]byte]float64
	biCtx map[[2]byte]float64 // count of bigram as context
	uni   map[byte]float64
	uniN  float64
	words map[string]bool
	maxW  int
}

var domModel *domainModel

func init() {
	domModel = buildDomainModel()
}

const domAlpha = 28.0 // a-z, digit class, end marker

func domainSym(c byte) byte {
	if c >= '0' && c <= '9' {
		return '0'
	}
	return c
}

func buildDomainModel() *domainModel {
	m := &domainModel{
		tri: map[[3]byte]float64{}, bi: map[[2]byte]float64{},
		biCtx: map[[2]byte]float64{}, uni: map[byte]float64{}, words: map[string]bool{},
	}
	seen := map[string]bool{}
	var list []string
	add := func(w string) {
		if w == "" || seen[w] {
			return
		}
		for i := 0; i < len(w); i++ {
			if w[i] < 'a' || w[i] > 'z' {
				return
			}
		}
		seen[w] = true
		list = append(list, w)
	}
	for _, f := range []string{"words_en.txt", "words_intl.txt", "words_tokens.txt"} {
		b, err := domainDataFS.ReadFile("domaindata/" + f)
		if err != nil {
			continue
		}
		for _, w := range strings.Fields(string(b)) {
			w = strings.ToLower(w)
			add(w)
			// Light inflection so the model is not too brittle; English only.
			if f == "words_en.txt" && len(w) >= 4 {
				add(w + "s")
				add(w + "ing")
				add(w + "er")
				add(w + "ed")
				if strings.HasSuffix(w, "e") {
					add(w[:len(w)-1] + "ing")
				}
			}
		}
	}
	sort.Strings(list)
	for _, w := range list {
		if len(w) >= 3 {
			m.words[w] = true
			if len(w) > m.maxW {
				m.maxW = len(w)
			}
		}
		p := "^^" + w + "$"
		for i := 0; i+2 < len(p); i++ {
			m.tri[[3]byte{p[i], p[i+1], p[i+2]}]++
			m.bi[[2]byte{p[i+1], p[i+2]}]++
			m.biCtx[[2]byte{p[i], p[i+1]}]++
			m.uni[p[i+2]]++
			m.uniN++
		}
	}
	return m
}

// logProb is the interpolated log2 probability of c after context (a,b).
func (m *domainModel) logProb(a, b, c byte) float64 {
	pu := (m.uni[c] + 0.5) / (m.uniN + 0.5*domAlpha)
	pb := 1 / domAlpha
	if den := m.uni[b]; den > 0 {
		pb = (m.bi[[2]byte{b, c}] + 0.1) / (den + 0.1*domAlpha)
	}
	pt := 0.0
	if den := m.biCtx[[2]byte{a, b}]; den > 0 {
		pt = m.tri[[3]byte{a, b, c}] / den
	}
	p := 0.6*pt + 0.3*pb + 0.1*pu
	return math.Log2(p)
}

// avgLogProb scores parts (hyphen-separated pieces) per character.
func (m *domainModel) avgLogProb(parts []string) float64 {
	sum, n := 0.0, 0
	for _, part := range parts {
		p := "^^"
		for i := 0; i < len(part); i++ {
			p += string(domainSym(part[i]))
		}
		p += "$"
		for i := 0; i+2 < len(p); i++ {
			sum += m.logProb(p[i], p[i+1], p[i+2])
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// segment greedily (dynamic programming, max coverage, then fewest words)
// explains s with dictionary words of 3+ letters.
func (m *domainModel) segment(s string) (covered int, words []string) {
	n := len(s)
	type cell struct {
		cov, nw, prev int
		word          bool
	}
	best := make([]cell, n+1)
	for i := 1; i <= n; i++ {
		best[i] = cell{best[i-1].cov, best[i-1].nw, i - 1, false}
		for l := 3; l <= m.maxW && l <= i; l++ {
			if !m.words[s[i-l:i]] {
				continue
			}
			c := cell{best[i-l].cov + l, best[i-l].nw + 1, i - l, true}
			if c.cov > best[i].cov || (c.cov == best[i].cov && c.nw < best[i].nw) {
				best[i] = c
			}
		}
	}
	for i := n; i > 0; {
		c := best[i]
		if c.word {
			words = append([]string{s[c.prev:i]}, words...)
		}
		i = c.prev
	}
	return best[n].cov, words
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var cnt [256]int
	for i := 0; i < len(s); i++ {
		cnt[s[i]]++
	}
	h := 0.0
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

func isVowelByte(c byte) bool { return strings.IndexByte("aeiou", c) >= 0 }

func clampF(x, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, x)) }

// ScoreDomain parses name and scores its registrable label for DGA-likeness.
// It never panics and never touches the network.
func ScoreDomain(name string) DomainScore {
	p := ParseDomain(name)
	ds := DomainScore{Name: name, Registrable: p.Registrable, Parse: p, Factors: []string{}}
	if p.Err != "" || p.IPLike != "" || p.SLD == "" {
		ds.Factors = append(ds.Factors, "not scored: no scorable registrable label")
		return ds
	}
	label := p.SLD
	ds.Label = label
	for _, r := range label {
		if r > unicode.MaxASCII {
			ds.Factors = append(ds.Factors, "not scored: non-ASCII label (model is Latin-only)")
			return ds
		}
	}
	parts := strings.Split(label, "-")
	var letters, core strings.Builder
	digits, vowels := 0, 0
	for _, part := range parts {
		for i := 0; i < len(part); i++ {
			c := part[i]
			core.WriteByte(c)
			switch {
			case c >= '0' && c <= '9':
				digits++
			case c >= 'a' && c <= 'z':
				letters.WriteByte(c)
				if isVowelByte(c) {
					vowels++
				}
			}
		}
	}
	s := core.String()
	ds.Features.Length = len(s)
	if len(s) < 6 {
		ds.Factors = append(ds.Factors, "not scored: label shorter than 6 chars")
		return ds
	}
	ds.Applicable = true
	f := &ds.Features
	f.DigitRatio = float64(digits) / float64(len(s))
	nl := letters.Len()
	if nl > 0 {
		f.VowelRatio = float64(vowels) / float64(nl)
	}
	f.Entropy = shannon(s)
	f.AvgLogProb = domModel.avgLogProb(parts)

	// Longest consonant run (letters only; digits break runs).
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' && !isVowelByte(c) {
			run++
			if run > f.ConsRun {
				f.ConsRun = run
			}
		} else {
			run = 0
		}
	}
	// Dictionary coverage over each hyphen part (digits count as unexplained).
	cov, tot := 0, 0
	for _, part := range parts {
		c, w := domModel.segment(part)
		cov += c
		tot += len(part)
		f.Words = append(f.Words, w...)
	}
	if tot > 0 {
		f.Coverage = float64(cov) / float64(tot)
	}

	pts := 0.0
	add := func(name string, v, max float64) {
		v = clampF(v, 0, max)
		if v >= 0.5 {
			ds.Factors = append(ds.Factors, fmt.Sprintf("%s +%d", name, int(math.Round(v))))
			pts += v
		}
	}
	// ngram: calibrated on the dev corpus, about 3.6 bits/char for dictionary
	// text and 6.5+ for random text (see docs/domain-inspector.md).
	add("ngram", (-f.AvgLogProb-3.6)/(6.5-3.6)*40, 40)
	add("coverage", (1-f.Coverage)*12, 12)
	if len(s) >= 10 {
		add("entropy", (f.Entropy-3.3)/0.6*10, 10)
	}
	add("length", float64(len(s)-11)*1.0, 8)
	add("digits", (f.DigitRatio-0.25)/0.25*12, 12)
	add("consonant", float64(f.ConsRun-4)*4, 12)
	if len(s) >= 7 && nl > 0 {
		switch {
		case f.VowelRatio < 0.2:
			add("vowel", (0.2-f.VowelRatio)/0.2*8+2, 8)
		case f.VowelRatio > 0.65:
			add("vowel", (f.VowelRatio-0.65)/0.15*8+2, 8)
		}
	}
	if f.Coverage >= 0.95 && len(f.Words) >= 3 && len(s) >= 16 {
		add("concat", float64(len(s)-14), 10)
	}
	ds.Score = int(math.Round(clampF(pts, 0, 100)))
	ds.DGALike = ds.Score >= DomainDGAThreshold
	return ds
}
