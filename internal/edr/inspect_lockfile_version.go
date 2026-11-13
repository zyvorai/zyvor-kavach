// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Version comparison for the lockfile analyzer. Each ecosystem gets a
// documented SUBSET of its real scheme. lfCompare returns ok=false when either
// version is outside the subset; callers must then report "unknown" rather
// than guess. See docs/lockfile-inspection.md.

import (
	"regexp"
	"strings"
)

// lfScheme names the comparison scheme used for an ecosystem.
func lfScheme(eco string) string {
	switch eco {
	case "npm", "cargo", "go", "nuget", "composer":
		return "semver"
	case "pypi":
		return "pep440"
	case "maven":
		return "maven"
	case "deb":
		return "deb"
	case "rpm":
		return "rpm"
	case "apk":
		return "apk"
	case "gem":
		return "gem"
	}
	return ""
}

// lfCompare compares a and b under eco's scheme: -1, 0, 1 and ok.
func lfCompare(eco, a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" || len(a) > 128 || len(b) > 128 {
		return 0, false
	}
	switch lfScheme(eco) {
	case "semver":
		return lfCmpSemver(a, b)
	case "pep440":
		return lfCmpPEP440(a, b)
	case "maven":
		return lfCmpMaven(a, b)
	case "deb":
		return lfCmpDeb(a, b)
	case "rpm":
		return lfCmpRPM(a, b)
	case "apk":
		return lfCmpApk(a, b)
	case "gem":
		return lfCmpGem(a, b)
	}
	return 0, false
}

func lfSign(i int) int {
	switch {
	case i < 0:
		return -1
	case i > 0:
		return 1
	}
	return 0
}

// lfNumCmp compares two digit strings of any length (no overflow).
func lfNumCmp(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return lfSign(len(a) - len(b))
	}
	return lfSign(strings.Compare(a, b))
}

func lfIsDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func lfIsAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func lfIsDigit(c byte) bool { return c >= '0' && c <= '9' }

// ---- semver (npm, cargo, go, nuget, composer) ----
// Supported: optional leading v/=, 1-4 numeric core parts (missing parts are
// 0), -prerelease with SemVer 2.0 precedence, +build ignored (also Go's
// +incompatible). Not supported: ranges, dev-branches, anything non-numeric
// in the core.

func lfParseSemver(v string) (core []string, pre []string, ok bool) {
	v = strings.TrimLeft(v, "=v ")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		p := v[i+1:]
		v = v[:i]
		if p == "" {
			return nil, nil, false
		}
		pre = strings.Split(p, ".")
		for _, id := range pre {
			if id == "" {
				return nil, nil, false
			}
		}
	}
	core = strings.Split(v, ".")
	if len(core) > 4 {
		return nil, nil, false
	}
	for _, c := range core {
		if !lfIsDigits(c) {
			return nil, nil, false
		}
	}
	return core, pre, true
}

func lfCmpSemver(a, b string) (int, bool) {
	ca, pa, ok1 := lfParseSemver(a)
	cb, pb, ok2 := lfParseSemver(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		x, y := "0", "0"
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if c := lfNumCmp(x, y); c != 0 {
			return c, true
		}
	}
	switch {
	case len(pa) == 0 && len(pb) == 0:
		return 0, true
	case len(pa) == 0:
		return 1, true
	case len(pb) == 0:
		return -1, true
	}
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, y := pa[i], pb[i]
		xn, yn := lfIsDigits(x), lfIsDigits(y)
		switch {
		case xn && yn:
			if c := lfNumCmp(x, y); c != 0 {
				return c, true
			}
		case xn:
			return -1, true
		case yn:
			return 1, true
		default:
			if c := strings.Compare(x, y); c != 0 {
				return lfSign(c), true
			}
		}
	}
	return lfSign(len(pa) - len(pb)), true
}

// ---- PEP 440 ----
// Supported: epoch, release segments, a/b/rc (alpha, beta, c, pre, preview
// spellings), .postN (and -N), .devN, local version (+x) ignored. Not
// supported: legacy non-PEP-440 versions.

var lfPEPRe = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d*))?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

type lfPEP struct {
	epoch   string
	rel     []string
	preRank int // 0 = dev-only (-inf), 1 = has pre, 2 = none (+inf)
	prePh   int
	preN    string
	hasPost bool
	postN   string
	hasDev  bool
	devN    string
}

func lfParsePEP440(v string) (p lfPEP, ok bool) {
	m := lfPEPRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return p, false
	}
	num := func(s string) string {
		if s == "" {
			return "0"
		}
		return s
	}
	p.epoch = num(m[1])
	p.rel = strings.Split(m[2], ".")
	hasPre := m[3] != ""
	if hasPre {
		switch m[3] {
		case "a", "alpha":
			p.prePh = 0
		case "b", "beta":
			p.prePh = 1
		default:
			p.prePh = 2
		}
		p.preN = num(m[4])
	}
	if m[5] != "" {
		p.hasPost, p.postN = true, m[5]
	} else if m[6] != "" {
		p.hasPost, p.postN = true, num(m[7])
	}
	if m[8] != "" {
		p.hasDev, p.devN = true, num(m[9])
	}
	switch {
	case hasPre:
		p.preRank = 1
	case !p.hasPost && p.hasDev:
		p.preRank = 0
	default:
		p.preRank = 2
	}
	return p, true
}

func lfCmpPEP440(a, b string) (int, bool) {
	x, ok1 := lfParsePEP440(a)
	y, ok2 := lfParsePEP440(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := lfNumCmp(x.epoch, y.epoch); c != 0 {
		return c, true
	}
	trim := func(r []string) []string {
		for len(r) > 1 && strings.TrimLeft(r[len(r)-1], "0") == "" {
			r = r[:len(r)-1]
		}
		return r
	}
	ra, rb := trim(x.rel), trim(y.rel)
	for i := 0; i < len(ra) || i < len(rb); i++ {
		s1, s2 := "0", "0"
		if i < len(ra) {
			s1 = ra[i]
		}
		if i < len(rb) {
			s2 = rb[i]
		}
		if c := lfNumCmp(s1, s2); c != 0 {
			return c, true
		}
	}
	if x.preRank != y.preRank {
		return lfSign(x.preRank - y.preRank), true
	}
	if x.preRank == 1 {
		if x.prePh != y.prePh {
			return lfSign(x.prePh - y.prePh), true
		}
		if c := lfNumCmp(x.preN, y.preN); c != 0 {
			return c, true
		}
	}
	if x.hasPost != y.hasPost {
		if x.hasPost {
			return 1, true
		}
		return -1, true
	}
	if x.hasPost {
		if c := lfNumCmp(x.postN, y.postN); c != 0 {
			return c, true
		}
	}
	if x.hasDev != y.hasDev {
		if x.hasDev {
			return -1, true
		}
		return 1, true
	}
	if x.hasDev {
		if c := lfNumCmp(x.devN, y.devN); c != 0 {
			return c, true
		}
	}
	return 0, true
}

// ---- Maven (subset of ComparableVersion) ----
// Supported: numeric and qualifier items split on . - and digit/letter
// transitions; qualifiers alpha(a) < beta(b) < milestone(m) < rc(cr) <
// snapshot < release(""/ga/final/release) < sp. Unknown qualifiers make the
// comparison "unknown". The 1-1 vs 1.1 distinction of real Maven is not
// modelled.

type lfMvnItem struct {
	num  string // digits when numeric
	rank int    // qualifier rank when !isN
	isN  bool
}

const lfMvnRelease = 5

func lfMvnRank(s string) int {
	switch s {
	case "alpha", "a":
		return 1
	case "beta", "b":
		return 2
	case "milestone", "m":
		return 3
	case "rc", "cr", "snapshot":
		return 4
	case "ga", "final", "release":
		return lfMvnRelease
	case "sp":
		return 6
	}
	return -1
}

func lfMvnTokens(v string) ([]lfMvnItem, bool) {
	v = strings.ToLower(v)
	var items []lfMvnItem
	var cur strings.Builder
	kind := 0
	flush := func() bool {
		if cur.Len() == 0 {
			return true
		}
		s := cur.String()
		cur.Reset()
		if lfIsDigits(s) {
			items = append(items, lfMvnItem{num: s, isN: true})
			return true
		}
		r := lfMvnRank(s)
		if r < 0 {
			return false
		}
		items = append(items, lfMvnItem{rank: r})
		return true
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.' || c == '-':
			if !flush() {
				return nil, false
			}
			kind = 0
		case lfIsDigit(c):
			if kind == 2 && !flush() {
				return nil, false
			}
			kind = 1
			cur.WriteByte(c)
		case lfIsAlpha(c):
			if kind == 1 && !flush() {
				return nil, false
			}
			kind = 2
			cur.WriteByte(c)
		default:
			return nil, false
		}
	}
	if !flush() || len(items) == 0 {
		return nil, false
	}
	return items, true
}

func lfCmpMaven(a, b string) (int, bool) {
	x, ok1 := lfMvnTokens(a)
	y, ok2 := lfMvnTokens(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	null := lfMvnItem{num: "0", isN: true}
	for i := 0; i < len(x) || i < len(y); i++ {
		p, q := null, null
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if i >= len(x) && !q.isN {
			p = lfMvnItem{rank: lfMvnRelease}
		}
		if i >= len(y) && !p.isN {
			q = lfMvnItem{rank: lfMvnRelease}
		}
		switch {
		case p.isN && q.isN:
			if c := lfNumCmp(p.num, q.num); c != 0 {
				return c, true
			}
		case p.isN:
			return 1, true
		case q.isN:
			return -1, true
		default:
			if p.rank != q.rank {
				return lfSign(p.rank - q.rank), true
			}
		}
	}
	return 0, true
}

// ---- Debian (full dpkg algorithm, epoch:upstream-revision) ----

func lfDebSplit(v string) (epoch, up, rev string, ok bool) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if !lfIsDigits(v[:i]) {
			return "", "", "", false
		}
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		up, rev = v[:i], v[i+1:]
	} else {
		up = v
	}
	if up == "" || strings.ContainsAny(v, " \t") {
		return "", "", "", false
	}
	return epoch, up, rev, true
}

func lfDebOrder(c byte) int {
	switch {
	case lfIsDigit(c):
		return 0
	case lfIsAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func lfDebPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !lfIsDigit(a[i])) || (j < len(b) && !lfIsDigit(b[j])) {
			var ac, bc int
			if i < len(a) && !lfIsDigit(a[i]) {
				ac = lfDebOrder(a[i])
			}
			if j < len(b) && !lfIsDigit(b[j]) {
				bc = lfDebOrder(b[j])
			}
			if ac != bc {
				return lfSign(ac - bc)
			}
			if i < len(a) && !lfIsDigit(a[i]) {
				i++
			}
			if j < len(b) && !lfIsDigit(b[j]) {
				j++
			}
		}
		si := i
		for i < len(a) && lfIsDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && lfIsDigit(b[j]) {
			j++
		}
		if c := lfNumCmp(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

func lfCmpDeb(a, b string) (int, bool) {
	ea, ua, ra, ok1 := lfDebSplit(a)
	eb, ub, rb, ok2 := lfDebSplit(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := lfNumCmp(ea, eb); c != 0 {
		return c, true
	}
	if c := lfDebPart(ua, ub); c != 0 {
		return c, true
	}
	return lfDebPart(ra, rb), true
}

// ---- RPM (rpmvercmp over [epoch:]version-release) ----

func lfRPMSeg(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !lfIsAlpha(a[i]) && !lfIsDigit(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !lfIsAlpha(b[j]) && !lfIsDigit(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		at, bt := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if at || bt {
			if !at {
				return 1
			}
			if !bt {
				return -1
			}
			i++
			j++
			continue
		}
		ac, bc := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ac || bc {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !ac {
				return 1
			}
			if !bc {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		isNum := lfIsDigit(a[i])
		if isNum {
			for i < len(a) && lfIsDigit(a[i]) {
				i++
			}
			for j < len(b) && lfIsDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && lfIsAlpha(a[i]) {
				i++
			}
			for j < len(b) && lfIsAlpha(b[j]) {
				j++
			}
		}
		x, y := a[si:i], b[sj:j]
		if y == "" {
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			if c := lfNumCmp(x, y); c != 0 {
				return c
			}
		} else if c := strings.Compare(x, y); c != 0 {
			return lfSign(c)
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

func lfCmpRPM(a, b string) (int, bool) {
	split := func(v string) (string, string, string, bool) {
		e := "0"
		if i := strings.IndexByte(v, ':'); i >= 0 {
			if !lfIsDigits(v[:i]) {
				return "", "", "", false
			}
			e, v = v[:i], v[i+1:]
		}
		ver, rel := v, ""
		if i := strings.LastIndexByte(v, '-'); i >= 0 {
			ver, rel = v[:i], v[i+1:]
		}
		return e, ver, rel, ver != "" && !strings.ContainsAny(v, " \t")
	}
	ea, va, ra, ok1 := split(a)
	eb, vb, rb, ok2 := split(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := lfNumCmp(ea, eb); c != 0 {
		return c, true
	}
	if c := lfRPMSeg(va, vb); c != 0 {
		return c, true
	}
	if ra == "" || rb == "" { // release absent on one side: compare versions only
		return 0, true
	}
	return lfRPMSeg(ra, rb), true
}

// ---- Alpine apk (subset) ----
// Supported: numeric dotted core, optional single letter, _alpha/_beta/_pre/
// _rc (before release) and _cvs/_svn/_git/_hg/_p (after), -rN revision.

type lfApkVer struct {
	core   []string
	letter byte
	suf    [][2]string // name, number
	rev    string
}

var lfApkSufRank = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

func lfParseApk(v string) (p lfApkVer, ok bool) {
	p.rev = "0"
	if i := strings.LastIndex(v, "-r"); i >= 0 && lfIsDigits(v[i+2:]) {
		p.rev, v = v[i+2:], v[:i]
	}
	parts := strings.Split(v, "_")
	core := parts[0]
	if n := len(core); n > 0 && lfIsAlpha(core[n-1]) {
		p.letter = core[n-1]
		core = core[:n-1]
	}
	p.core = strings.Split(core, ".")
	for _, c := range p.core {
		if !lfIsDigits(c) {
			return p, false
		}
	}
	for _, s := range parts[1:] {
		j := 0
		for j < len(s) && lfIsAlpha(s[j]) {
			j++
		}
		name, n := s[:j], s[j:]
		if _, known := lfApkSufRank[name]; !known || (n != "" && !lfIsDigits(n)) {
			return p, false
		}
		if n == "" {
			n = "0"
		}
		p.suf = append(p.suf, [2]string{name, n})
	}
	return p, true
}

func lfCmpApk(a, b string) (int, bool) {
	x, ok1 := lfParseApk(a)
	y, ok2 := lfParseApk(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(x.core) || i < len(y.core); i++ {
		s1, s2 := "0", "0"
		if i < len(x.core) {
			s1 = x.core[i]
		}
		if i < len(y.core) {
			s2 = y.core[i]
		}
		if c := lfNumCmp(s1, s2); c != 0 {
			return c, true
		}
	}
	if x.letter != y.letter {
		return lfSign(int(x.letter) - int(y.letter)), true
	}
	for i := 0; i < len(x.suf) || i < len(y.suf); i++ {
		rx, ry := 0, 0
		nx, ny := "0", "0"
		if i < len(x.suf) {
			rx, nx = lfApkSufRank[x.suf[i][0]], x.suf[i][1]
		}
		if i < len(y.suf) {
			ry, ny = lfApkSufRank[y.suf[i][0]], y.suf[i][1]
		}
		if rx != ry {
			return lfSign(rx - ry), true
		}
		if c := lfNumCmp(nx, ny); c != 0 {
			return c, true
		}
	}
	return lfNumCmp(x.rev, y.rev), true
}

// ---- RubyGems ----
// Supported: dot-separated numeric and alphabetic segments; any alphabetic
// segment marks a prerelease which sorts before the release.

func lfGemSegs(v string) ([]string, bool) {
	v = strings.ReplaceAll(strings.ReplaceAll(v, "-", ".pre."), "_", ".")
	var out []string
	for _, seg := range strings.Split(v, ".") {
		var cur strings.Builder
		kind := 0
		for i := 0; i < len(seg); i++ {
			k := 2
			if lfIsDigit(seg[i]) {
				k = 1
			} else if !lfIsAlpha(seg[i]) {
				return nil, false
			}
			if kind != 0 && k != kind {
				out = append(out, cur.String())
				cur.Reset()
			}
			kind = k
			cur.WriteByte(seg[i])
		}
		if cur.Len() == 0 {
			return nil, false
		}
		out = append(out, cur.String())
	}
	return out, len(out) > 0
}

func lfCmpGem(a, b string) (int, bool) {
	x, ok1 := lfGemSegs(a)
	y, ok2 := lfGemSegs(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		s1, s2 := "0", "0"
		if i < len(x) {
			s1 = x[i]
		}
		if i < len(y) {
			s2 = y[i]
		}
		n1, n2 := lfIsDigits(s1), lfIsDigits(s2)
		switch {
		case n1 && n2:
			if c := lfNumCmp(s1, s2); c != 0 {
				return c, true
			}
		case n1:
			return 1, true
		case n2:
			return -1, true
		default:
			if c := strings.Compare(strings.ToLower(s1), strings.ToLower(s2)); c != 0 {
				return lfSign(c), true
			}
		}
	}
	return 0, true
}
