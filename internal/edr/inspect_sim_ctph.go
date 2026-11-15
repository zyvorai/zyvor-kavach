// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// kavach-ctph: a context-triggered piecewise fuzzy digest.
//
// Written from the published description of the technique (Kornblum, DFRWS
// 2006, as restated by Breitinger and Baier 2012): a rolling hash over a short
// window marks trigger points, the bytes between triggers form chunks, each
// chunk is reduced to one base64 character, and two digests are compared by
// edit distance. The constants, rolling function, chunk hash and scoring here
// are Kavach's own. The digest is NOT byte-compatible with ssdeep and its
// scores must not be compared with ssdeep scores.
//
// Cost: two linear passes over the input (count triggers for five block
// sizes, then build two signatures). Memory: O(1) beyond the input.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	ctphPrefix    = "kavach-ctph1"
	ctphWindow    = 7
	ctphMinBlock  = 3
	ctphSigMax    = 64
	ctphSigMin    = 32
	ctphMinInput  = 512 // below this the digest is too short to mean anything
	ctphTargetSig = 64
	ctphCommonLen = 7 // two signatures must share a substring this long
	ctphCtxStep   = 1 << 20
	ctphB64       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

var errSimTooSmall = errors.New("input too small for digest")

// simMix is a 32-bit integer finaliser (xorshift-multiply) used to spread the
// rolling-hash value so the low bits are usable as a modulus.
func simMix(x uint32) uint32 {
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	x *= 0x846ca68b
	x ^= x >> 16
	return x
}

type ctphRoller struct {
	win [ctphWindow]byte
	pos int
	h   uint32
	pw  uint32 // K^window
}

const ctphK = 0x01000193

func newCTPHRoller() *ctphRoller {
	// The window starts as W zero bytes, each contributing (0+1)*K^i, so that
	// h is always a pure function of the last W bytes.
	pw, h := uint32(1), uint32(0)
	for i := 0; i < ctphWindow; i++ {
		h += pw
		pw *= ctphK
	}
	return &ctphRoller{pw: pw, h: h}
}

// push slides the window by one byte and returns the mixed hash.
func (r *ctphRoller) push(c byte) uint32 {
	out := r.win[r.pos]
	r.win[r.pos] = c
	r.pos++
	if r.pos == ctphWindow {
		r.pos = 0
	}
	r.h = r.h*ctphK + uint32(c) + 1 - (uint32(out)+1)*r.pw
	return simMix(r.h)
}

func ctphInitialBlock(n int) int {
	b := ctphMinBlock
	for b*ctphTargetSig < n {
		b *= 2
	}
	return b
}

// CTPHDigest computes the kavach-ctph digest of data.
func CTPHDigest(ctx context.Context, data []byte) (string, error) {
	n := len(data)
	if n < ctphMinInput {
		return "", errSimTooSmall
	}
	// Candidate block sizes: b0*2 .. b0/8 (never below the minimum).
	b0 := ctphInitialBlock(n)
	var cand []int
	for _, m := range []float64{2, 1, 0.5, 0.25, 0.125} {
		b := int(float64(b0) * m)
		if b >= ctphMinBlock {
			cand = append(cand, b)
		}
	}
	counts := make([]int, len(cand))
	r := newCTPHRoller()
	for i, c := range data {
		if i%ctphCtxStep == 0 && ctx.Err() != nil {
			return "", ctx.Err()
		}
		m := r.push(c)
		for j, b := range cand {
			if m%uint32(b) == uint32(b-1) {
				counts[j]++
			}
		}
	}
	// Largest block size that still yields enough signature characters.
	bs := cand[len(cand)-1]
	for j, b := range cand {
		if counts[j]+1 >= ctphSigMin {
			bs = b
			break
		}
	}
	bs2 := bs * 2
	r = newCTPHRoller()
	var s1, s2 []byte
	h1, h2 := uint32(2166136261), uint32(2166136261)
	open1, open2 := false, false
	for i, c := range data {
		if i%ctphCtxStep == 0 && ctx.Err() != nil {
			return "", ctx.Err()
		}
		m := r.push(c)
		h1 = (h1 ^ uint32(c)) * 16777619
		h2 = (h2 ^ uint32(c)) * 16777619
		open1, open2 = true, true
		if m%uint32(bs) == uint32(bs-1) && len(s1) < ctphSigMax-1 {
			s1 = append(s1, ctphB64[simMix(h1)&63])
			h1, open1 = 2166136261, false
		}
		if m%uint32(bs2) == uint32(bs2-1) && len(s2) < ctphSigMax-1 {
			s2 = append(s2, ctphB64[simMix(h2)&63])
			h2, open2 = 2166136261, false
		}
	}
	if open1 {
		s1 = append(s1, ctphB64[simMix(h1)&63])
	}
	if open2 {
		s2 = append(s2, ctphB64[simMix(h2)&63])
	}
	return fmt.Sprintf("%s:%d:%s:%s", ctphPrefix, bs, s1, s2), nil
}

type ctphParsed struct {
	bs     int
	s1, s2 string
}

func parseCTPH(d string) (ctphParsed, bool) {
	p := strings.Split(d, ":")
	if len(p) != 4 || p[0] != ctphPrefix {
		return ctphParsed{}, false
	}
	bs, err := strconv.Atoi(p[1])
	if err != nil || bs < ctphMinBlock || bs > 1<<28 {
		return ctphParsed{}, false
	}
	if len(p[2]) == 0 || len(p[2]) > ctphSigMax || len(p[3]) > ctphSigMax {
		return ctphParsed{}, false
	}
	return ctphParsed{bs, p[2], p[3]}, true
}

// ctphSquash collapses runs of more than three identical characters so a long
// run (low-entropy padding) cannot dominate the comparison.
func ctphSquash(s string) string {
	out := make([]byte, 0, len(s))
	run := 0
	for i := 0; i < len(s); i++ {
		if i > 0 && s[i] == s[i-1] {
			run++
			if run >= 3 {
				continue
			}
		} else {
			run = 0
		}
		out = append(out, s[i])
	}
	return string(out)
}

func ctphShareSubstr(a, b string) bool {
	if len(a) < ctphCommonLen || len(b) < ctphCommonLen {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for i := 0; i+ctphCommonLen <= len(a); i++ {
		set[a[i:i+ctphCommonLen]] = struct{}{}
	}
	for i := 0; i+ctphCommonLen <= len(b); i++ {
		if _, ok := set[b[i:i+ctphCommonLen]]; ok {
			return true
		}
	}
	return false
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := prev[j-1]
			if a[i-1] != b[j-1] {
				c++
			}
			if prev[j]+1 < c {
				c = prev[j] + 1
			}
			if cur[j-1]+1 < c {
				c = cur[j-1] + 1
			}
			cur[j] = c
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// ctphPair scores two signatures made with the same block size: 100 for equal,
// 0 when they share no 7-character run, otherwise 100*(1 - editdist/maxlen).
func ctphPair(a, b string) int {
	a, b = ctphSquash(a), ctphSquash(b)
	if a == b {
		return 100
	}
	if !ctphShareSubstr(a, b) {
		return 0
	}
	m := len(a)
	if len(b) > m {
		m = len(b)
	}
	return 100 - levenshtein(a, b)*100/m
}

// CTPHCompare returns 0-100 similarity between two kavach-ctph digests, or -1
// when either digest is malformed. Digests whose block sizes differ by more
// than a factor of two are not comparable and score 0.
func CTPHCompare(x, y string) int {
	a, ok1 := parseCTPH(x)
	b, ok2 := parseCTPH(y)
	if !ok1 || !ok2 {
		return -1
	}
	best := 0
	up := func(s int) {
		if s > best {
			best = s
		}
	}
	switch {
	case a.bs == b.bs:
		up(ctphPair(a.s1, b.s1))
		if a.s2 != "" && b.s2 != "" {
			up(ctphPair(a.s2, b.s2))
		}
	case a.bs == b.bs*2: // a.s1 and b.s2 share a block size
		if b.s2 != "" {
			up(ctphPair(a.s1, b.s2))
		}
	case b.bs == a.bs*2:
		if a.s2 != "" {
			up(ctphPair(a.s2, b.s1))
		}
	}
	return best
}
