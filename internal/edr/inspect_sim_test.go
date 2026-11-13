// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- synthetic corpus ----

func simRNG(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) }

// simBlob builds a "binary-like" blob: alternating random runs, repeated
// structure (tables) and low-entropy fill, so it is not pure noise.
func simBlob(r *rand.Rand, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		k := 64 + r.IntN(900)
		switch r.IntN(4) {
		case 0, 1:
			for i := 0; i < k; i++ {
				out = append(out, byte(r.Uint32()))
			}
		case 2:
			rec := make([]byte, 8+r.IntN(24))
			for i := range rec {
				rec[i] = byte(r.Uint32())
			}
			for i := 0; i < k/len(rec)+1; i++ {
				c := append([]byte(nil), rec...)
				c[0] = byte(i)
				out = append(out, c...)
			}
		default:
			b := byte(r.Uint32() % 4)
			for i := 0; i < k/4; i++ {
				out = append(out, b, 0, 0, byte(r.Uint32()%8))
			}
		}
	}
	return out[:n]
}

var simVocab = func() []string {
	r := simRNG(7)
	v := make([]string, 400)
	for i := range v {
		w := make([]byte, 3+r.IntN(7))
		for j := range w {
			w[j] = byte('a' + r.IntN(26))
		}
		v[i] = string(w)
	}
	return v
}()

// simText builds text-like data from a shared vocabulary: statistically alike
// across unrelated blobs, the hard negative case for n-gram digests.
func simText(r *rand.Rand, n int) []byte {
	var sb strings.Builder
	for sb.Len() < n {
		sb.WriteString(simVocab[r.IntN(len(simVocab))])
		sb.WriteByte(' ')
	}
	return []byte(sb.String()[:n])
}

type simVariant struct {
	name string
	fn   func(r *rand.Rand, base []byte) []byte
}

func simInsert(r *rand.Rand, b []byte, k, maxLen int) []byte {
	out := append([]byte(nil), b...)
	for i := 0; i < k; i++ {
		p := r.IntN(len(out))
		ins := simBlob(r, 8+r.IntN(maxLen))
		out = append(out[:p], append(ins, out[p:]...)...)
	}
	return out
}

func simDelete(r *rand.Rand, b []byte, k, maxLen int) []byte {
	out := append([]byte(nil), b...)
	for i := 0; i < k; i++ {
		l := 8 + r.IntN(maxLen)
		p := r.IntN(len(out) - l)
		out = append(out[:p], out[p+l:]...)
	}
	return out
}

func simShuffle(r *rand.Rand, b []byte, blk int) []byte {
	out := append([]byte(nil), b...)
	a := r.IntN(len(out)/2 - blk)
	c := len(out)/2 + r.IntN(len(out)/2-blk)
	x, y := append([]byte(nil), out[a:a+blk]...), append([]byte(nil), out[c:c+blk]...)
	copy(out[a:], y)
	copy(out[c:], x)
	return out
}

var simVariants = []simVariant{
	{"insert-3x<=200B", func(r *rand.Rand, b []byte) []byte { return simInsert(r, b, 3, 200) }},
	{"delete-3x<=200B", func(r *rand.Rand, b []byte) []byte { return simDelete(r, b, 3, 200) }},
	{"insert+delete-10x", func(r *rand.Rand, b []byte) []byte { return simDelete(r, simInsert(r, b, 5, 100), 5, 100) }},
	{"swap-two-2KiB-blocks", func(r *rand.Rand, b []byte) []byte { return simShuffle(r, b, 2048) }},
	{"pad-4KiB-zeros-tail", func(r *rand.Rand, b []byte) []byte { return append(append([]byte(nil), b...), make([]byte, 4096)...) }},
	{"prepend-1KiB", func(r *rand.Rand, b []byte) []byte { return append(simBlob(r, 1024), b...) }},
	{"point-edits-0.1%", func(r *rand.Rand, b []byte) []byte {
		out := append([]byte(nil), b...)
		for i := 0; i < len(out)/1000; i++ {
			out[r.IntN(len(out))] ^= byte(1 + r.IntN(255))
		}
		return out
	}},
	{"heavy-rewrite-25%", func(r *rand.Rand, b []byte) []byte {
		out := append([]byte(nil), b...)
		for i := 0; i < 8; i++ {
			l := len(out) / 32
			p := r.IntN(len(out) - l)
			copy(out[p:], simBlob(r, l))
		}
		return out
	}},
}

type simEval struct {
	name                       string
	ctphHit, lshHit, eitherHit int
	n                          int
	ctphSum, lshSum            float64
}

// TestSimilarityEvaluation measures detection rate per variant class and the
// false-match rate on unrelated pairs for both digests, using synthetic data.
func TestSimilarityEvaluation(t *testing.T) {
	r := simRNG(2024)
	const nBase = 24
	bases := make([][]byte, nBase)
	bd := make([]SimDigests, nBase)
	for i := range bases {
		sz := 24<<10 + r.IntN(200<<10)
		bases[i] = simBlob(r, sz)
		bd[i] = ComputeDigests(bases[i])
		if bd[i].CTPH == "" || bd[i].LSH == "" {
			t.Fatalf("no digest for base %d", i)
		}
	}
	for _, v := range simVariants {
		e := simEval{name: v.name}
		maxL := 0
		for i, b := range bases {
			for k := 0; k < 3; k++ {
				d := ComputeDigests(v.fn(r, b))
				c := CTPHCompare(bd[i].CTPH, d.CTPH)
				l := LSHDistance(bd[i].LSH, d.LSH)
				e.n++
				maxL = max(maxL, l)
				e.ctphSum += float64(c)
				e.lshSum += float64(l)
				ch, lh := c >= SimCTPHThreshold, l >= 0 && l <= SimLSHThreshold
				if ch {
					e.ctphHit++
				}
				if lh {
					e.lshHit++
				}
				if ch || lh {
					e.eitherHit++
				}
			}
		}
		t.Logf("DETECT %-22s n=%d ctph=%3.0f%% (mean score %.0f)  lsh=%3.0f%% (mean dist %.0f)  either=%3.0f%%",
			e.name, e.n, 100*float64(e.ctphHit)/float64(e.n), e.ctphSum/float64(e.n),
			100*float64(e.lshHit)/float64(e.n), e.lshSum/float64(e.n), 100*float64(e.eitherHit)/float64(e.n))
		t.Logf("   %s: max lsh distance %d", e.name, maxL)
		switch v.name {
		case "insert-3x<=200B", "delete-3x<=200B", "pad-4KiB-zeros-tail", "prepend-1KiB":
			if float64(e.ctphHit)/float64(e.n) < 0.9 {
				t.Errorf("%s: CTPH detection %d/%d below 90%%", v.name, e.ctphHit, e.n)
			}
			if float64(e.lshHit)/float64(e.n) < 0.9 {
				t.Errorf("%s: LSH detection %d/%d below 90%%", v.name, e.lshHit, e.n)
			}
		}
	}

	// Unrelated pairs: random blobs, and text from a shared vocabulary.
	for _, kind := range []string{"random-binary", "shared-vocab-text"} {
		var ds []SimDigests
		for i := 0; i < 60; i++ {
			sz := 24<<10 + r.IntN(200<<10)
			if kind == "random-binary" {
				ds = append(ds, ComputeDigests(simBlob(r, sz)))
			} else {
				ds = append(ds, ComputeDigests(simText(r, sz)))
			}
		}
		pairs, cfp, lfp := 0, 0, 0
		minD, sumD := 1<<30, 0
		for i := range ds {
			for j := i + 1; j < len(ds); j++ {
				pairs++
				if CTPHCompare(ds[i].CTPH, ds[j].CTPH) >= SimCTPHThreshold {
					cfp++
				}
				l := LSHDistance(ds[i].LSH, ds[j].LSH)
				minD, sumD = min(minD, l), sumD+l
				if l >= 0 && l <= SimLSHThreshold {
					lfp++
				}
			}
		}
		t.Logf("FALSE-MATCH %-18s pairs=%d ctph=%d (%.3f%%) lsh=%d (%.3f%%) [unrelated lsh dist: min %d mean %.0f]", kind, pairs, cfp, 100*float64(cfp)/float64(pairs), lfp, 100*float64(lfp)/float64(pairs), minD, float64(sumD)/float64(pairs))
		if cfp != 0 {
			t.Errorf("%s: CTPH false matches %d", kind, cfp)
		}
		if kind == "random-binary" && lfp != 0 {
			t.Errorf("%s: LSH false matches %d", kind, lfp)
		}
	}
}

func TestSimilarityScoreSeparation(t *testing.T) {
	r := simRNG(99)
	var rel, unrel []int
	for i := 0; i < 20; i++ {
		b := simBlob(r, 40<<10+r.IntN(100<<10))
		db := ComputeDigests(b)
		rel = append(rel, CTPHCompare(db.CTPH, ComputeDigests(simInsert(r, b, 2, 150)).CTPH))
		unrel = append(unrel, CTPHCompare(db.CTPH, ComputeDigests(simBlob(r, len(b))).CTPH))
	}
	minRel, maxUn := 100, 0
	for _, s := range rel {
		minRel = min(minRel, s)
	}
	for _, s := range unrel {
		maxUn = max(maxUn, s)
	}
	t.Logf("related min=%d unrelated max=%d (threshold %d)", minRel, maxUn, SimCTPHThreshold)
	if minRel < SimCTPHThreshold || maxUn >= SimCTPHThreshold {
		t.Fatalf("threshold does not separate: related min %d, unrelated max %d", minRel, maxUn)
	}
}

// ---- properties ----

func TestSimilarityDeterministicAndBounded(t *testing.T) {
	r := simRNG(5)
	b := simBlob(r, 100<<10)
	d1, d2 := ComputeDigests(b), ComputeDigests(b)
	if d1 != d2 {
		t.Fatal("digests not deterministic")
	}
	if CTPHCompare(d1.CTPH, d1.CTPH) != 100 || LSHDistance(d1.LSH, d1.LSH) != 0 {
		t.Fatal("identity should score 100 / distance 0")
	}
	o := ComputeDigests(simBlob(r, 100<<10))
	if LSHDistance(d1.LSH, o.LSH) != LSHDistance(o.LSH, d1.LSH) {
		t.Fatal("LSH distance not symmetric")
	}
	if d := LSHDistance(d1.LSH, o.LSH); d < 0 || d > LSHMaxDistance {
		t.Fatalf("distance %d out of bounds", d)
	}
	if CTPHCompare(d1.CTPH, o.CTPH) != CTPHCompare(o.CTPH, d1.CTPH) {
		t.Fatal("CTPH compare not symmetric")
	}
	if len(d1.CTPH) > len(ctphPrefix)+12+2*ctphSigMax+3 {
		t.Fatalf("ctph digest too long: %d", len(d1.CTPH))
	}
	// Extremes: tiny, all-zero and all-0xff inputs must not panic.
	for _, in := range [][]byte{nil, {1}, make([]byte, 600), []byte(strings.Repeat("\xff", 5000))} {
		_ = ComputeDigests(in)
	}
	if CTPHCompare("garbage", d1.CTPH) != -1 || LSHDistance("x", d1.LSH) != -1 {
		t.Fatal("malformed digests should return -1")
	}
}

func TestSimilarityWorstCaseSizeRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	big := make([]byte, InspectMaxBytes)
	x := uint64(88172645463325252)
	for i := range big {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		big[i] = byte(x)
	}
	ctx, cancel := context.WithTimeout(context.Background(), InspectAnalyzerTime)
	defer cancel()
	d := computeDigestsCtx(ctx, big)
	if ctx.Err() != nil {
		t.Fatalf("32 MiB digest exceeded the analyzer budget (%v)", InspectAnalyzerTime)
	}
	if d.CTPH == "" || d.LSH == "" {
		t.Fatal("expected digests for 32 MiB input")
	}
}

// ---- structure hashes ----

func simPE(imports []string, seed uint64) []byte {
	return fileBuildPE(filePESpec{ts: 1700000000, entry: 0x1000, imports: imports, secs: []filePESec{
		{".text", 0x1000, fileScnCode, filePrand(20000, seed)},
		{".data", 0x6000, fileScnData, make([]byte, 3000)},
	}})
}

func TestImpHash(t *testing.T) {
	imps := []string{"CreateFileA", "WriteFile", "ExitProcess", "GetProcAddress"}
	a := ComputeDigests(simPE(imps, 1))
	b := ComputeDigests(simPE(imps, 2)) // different code, same imports
	c := ComputeDigests(simPE([]string{"CreateFileA", "WriteFile", "ExitProcess", "VirtualAlloc"}, 1))
	if a.Format != "PE" || a.ImpHash == "" {
		t.Fatalf("no imphash: %+v", a)
	}
	// Public convention: lowercased "dll.function" joined by commas, md5; the
	// fixture's single library is kernel32.dll.
	sum := md5.Sum([]byte("kernel32.createfilea,kernel32.writefile,kernel32.exitprocess,kernel32.getprocaddress"))
	if a.ImpHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("imphash %s does not follow the convention (%x)", a.ImpHash, sum)
	}
	if a.ImpHash != b.ImpHash {
		t.Fatal("same imports must share imphash")
	}
	if a.ImpHash == c.ImpHash {
		t.Fatal("different imports must differ")
	}
	if a.CTPH == b.CTPH {
		t.Fatal("different code should change the CTPH")
	}
	if len(a.EntropyVec) != 3 { // .text, .data, .idata
		t.Fatalf("entropy vector %q", a.EntropyVec)
	}
	if a.EntropyVec[0] <= a.EntropyVec[1] && a.EntropyVec[0] != 'f' {
		t.Fatalf("random .text should out-rank zero .data: %q", a.EntropyVec)
	}
}

func TestImpHashFamilies(t *testing.T) {
	r := simRNG(31)
	pool := []string{"CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "VirtualAlloc", "LoadLibraryA", "GetProcAddress", "ExitProcess", "Sleep", "GetTickCount", "CreateThread", "HeapAlloc", "HeapFree", "GetLastError", "lstrcpyA", "WaitForSingleObject"}
	fam := func() []string {
		p := append([]string(nil), pool...)
		r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
		return p[:8]
	}
	seen := map[string]int{}
	same := 0
	for f := 0; f < 12; f++ {
		imps := fam()
		h0 := ComputeDigests(simPE(imps, uint64(f)*10+1)).ImpHash
		h1 := ComputeDigests(simPE(imps, uint64(f)*10+2)).ImpHash
		if h0 == h1 {
			same++
		}
		seen[h0]++
	}
	t.Logf("imphash: %d/12 same-import pairs matched; %d distinct hashes over 12 random import sets", same, len(seen))
	if same != 12 {
		t.Fatalf("same-import pairs matched %d/12", same)
	}
	if len(seen) < 11 {
		t.Fatalf("too many imphash collisions across different import sets: %d distinct", len(seen))
	}
}

func TestELFAndMachOHashes(t *testing.T) {
	e1 := ComputeDigests(fileBuildELF(fileELFSpec{interp: "/lib64/ld.so", loadFlag: 5, secFlags: 6, imports: []string{"printf", "malloc"}, text: filePrand(3000, 1)}))
	e2 := ComputeDigests(fileBuildELF(fileELFSpec{interp: "/lib64/ld.so", loadFlag: 5, secFlags: 6, imports: []string{"malloc", "printf"}, text: filePrand(3000, 2)}))
	e3 := ComputeDigests(fileBuildELF(fileELFSpec{interp: "/lib64/ld.so", loadFlag: 5, secFlags: 6, imports: []string{"printf", "socket"}, text: filePrand(3000, 1)}))
	if e1.Format != "ELF" || e1.ELFSymHash == "" {
		t.Fatalf("no ELF symbol hash: %+v", e1)
	}
	if e1.ELFSymHash != e2.ELFSymHash {
		t.Fatal("symbol hash must ignore import order")
	}
	if e1.ELFSymHash == e3.ELFSymHash {
		t.Fatal("different symbols must differ")
	}
	m1 := ComputeDigests(fileBuildMachO(fileMachoSpec{arm64: true, dylibs: []string{"/usr/lib/libSystem.B.dylib", "/usr/lib/libz.1.dylib"}}))
	m2 := ComputeDigests(fileBuildMachO(fileMachoSpec{arm64: true, dylibs: []string{"/usr/lib/libz.1.dylib", "/usr/lib/libSystem.B.dylib"}}))
	m3 := ComputeDigests(fileBuildMachO(fileMachoSpec{arm64: true, dylibs: []string{"/usr/lib/libSystem.B.dylib"}}))
	if m1.Format != "Mach-O" || m1.MachOHash == "" {
		t.Fatalf("no Mach-O hash: %+v", m1)
	}
	if m1.MachOHash != m2.MachOHash || m1.MachOHash == m3.MachOHash {
		t.Fatal("Mach-O dylib hash should be order-insensitive and set-sensitive")
	}
}

// ---- analyzer and endpoint ----

func TestSimilarityAnalyzerAndEndpoint(t *testing.T) {
	r := simRNG(1234)
	base := simBlob(r, 80<<10)
	variant := simInsert(r, base, 2, 120)
	other := simBlob(r, 80<<10)

	run := func(name string, data []byte) *InspectReport {
		rep := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindFile, Name: name, Data: data})
		storeInspectReport(rep)
		return rep
	}
	r0 := run("base.bin", base)
	if _, ok := r0.Meta["similarity.digests"]; !ok {
		t.Fatalf("digests missing from Meta: %v", r0.Meta)
	}
	for _, f := range r0.Findings {
		if strings.HasPrefix(f.ID, "sim-") && f.ID != "" {
			// base may only match earlier tests' data by chance; it must not.
			t.Fatalf("first-seen file produced a similarity finding: %+v", f)
		}
	}
	r1 := run("variant.bin", variant)
	var near *InspectFinding
	for i, f := range r1.Findings {
		if f.ID == "sim-near-duplicate" {
			near = &r1.Findings[i]
		}
	}
	if near == nil {
		t.Fatalf("variant not flagged similar: %+v", r1.Findings)
	}
	if near.Weight > 15 || !strings.Contains(near.Evidence, r0.SHA256) {
		t.Fatalf("unexpected weight/evidence: %+v", near)
	}
	r2 := run("other.bin", other)
	for _, f := range r2.Findings {
		if strings.HasPrefix(f.ID, "sim-") {
			t.Fatalf("unrelated file flagged: %+v", f)
		}
	}
	r3 := run("again.bin", base) // identical bytes: same sha, no self-match finding
	for _, f := range r3.Findings {
		if f.ID == "sim-near-duplicate" && strings.Contains(f.Evidence, r0.SHA256) {
			t.Fatalf("identical file reported as similar to itself: %+v", f)
		}
	}

	mux := http.NewServeMux()
	RegisterInspectSimilar(mux, "tok")
	get := func(q string, auth bool) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest("GET", "/v1/inspect/similar?"+q, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}
	if w, _ := get("sha256="+r1.SHA256, false); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated request got %d", w.Code)
	}
	w, out := get("sha256="+r1.SHA256, true)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	ms, _ := out["matches"].([]any)
	if len(ms) == 0 || ms[0].(map[string]any)["sha256"] != r0.SHA256 {
		t.Fatalf("nearest of variant should be base: %s", w.Body)
	}
	d := ComputeDigests(variant)
	for _, dg := range []string{d.CTPH, d.LSH} {
		w, out = get("digest="+dg, true)
		ms, _ = out["matches"].([]any)
		if w.Code != 200 || len(ms) == 0 {
			t.Fatalf("digest query %q: %d %s", dg[:12], w.Code, w.Body)
		}
	}
	if w, _ := get("", true); w.Code != 400 {
		t.Fatalf("missing params: %d", w.Code)
	}
	if w, _ := get("digest=nope", true); w.Code != 400 {
		t.Fatalf("bad digest: %d", w.Code)
	}
	if w, _ := get("sha256=deadbeef", true); w.Code != 404 {
		t.Fatalf("unknown sha: %d", w.Code)
	}
}

func TestSimilarityIndexBounded(t *testing.T) {
	for i := 0; i < SimIndexCapacity+50; i++ {
		simRemember(simEntry{SHA256: fmt.Sprintf("%064d", i)})
	}
	simMu.Lock()
	n := len(simIndex)
	simMu.Unlock()
	if n > SimIndexCapacity {
		t.Fatalf("index grew to %d", n)
	}
}

// TestSimilarityWeakAgainstPacking documents a limit: the same payload
// transformed by two different keystreams (a stand-in for per-sample packing
// or encryption) shares no byte structure, so neither digest links them.
func TestSimilarityWeakAgainstPacking(t *testing.T) {
	r := simRNG(77)
	linked, n := 0, 20
	for i := 0; i < n; i++ {
		base := simBlob(r, 64<<10)
		a, b := append([]byte(nil), base...), append([]byte(nil), base...)
		ka, kb := simRNG(uint64(i)*2+1000), simRNG(uint64(i)*2+1001)
		for j := range base {
			a[j] ^= byte(ka.Uint32())
			b[j] ^= byte(kb.Uint32())
		}
		da, db := ComputeDigests(a), ComputeDigests(b)
		if CTPHCompare(da.CTPH, db.CTPH) >= SimCTPHThreshold || LSHDistance(da.LSH, db.LSH) <= SimLSHThreshold {
			linked++
		}
	}
	t.Logf("same payload, different keystream: %d/%d linked (expected ~0)", linked, n)
	if linked > 1 {
		t.Fatalf("unexpectedly linked %d/%d", linked, n)
	}
}

// ---- fuzz ----

func FuzzCTPH(f *testing.F) {
	f.Add(simBlob(simRNG(1), 2048))
	f.Add(make([]byte, 700))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := CTPHDigest(context.Background(), b)
		if err != nil {
			return
		}
		if CTPHCompare(d, d) != 100 {
			t.Fatalf("self score != 100 for %q", d)
		}
		if _, ok := parseCTPH(d); !ok {
			t.Fatalf("own digest does not parse: %q", d)
		}
	})
}

func FuzzLSH(f *testing.F) {
	f.Add(simBlob(simRNG(2), 2048))
	f.Add(make([]byte, 300))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := LSHDigest(context.Background(), b)
		if err != nil {
			return
		}
		if LSHDistance(d, d) != 0 {
			t.Fatalf("self distance != 0 for %q", d)
		}
		o, _ := LSHDigest(context.Background(), append(append([]byte(nil), b...), 1, 2, 3))
		if x := LSHDistance(d, o); x < 0 || x > LSHMaxDistance {
			t.Fatalf("distance %d out of range", x)
		}
	})
}

func FuzzCompareParsers(f *testing.F) {
	f.Add("kavach-ctph1:3:abc:def", "kavach-lsh1:00")
	f.Fuzz(func(t *testing.T, a, b string) {
		_ = CTPHCompare(a, b)
		_ = LSHDistance(a, b)
	})
}

func FuzzStructureParsers(f *testing.F) {
	f.Add(simPE([]string{"A", "B"}, 1))
	f.Add(fileBenignELF())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_ = ComputeDigests(b)
	})
}
