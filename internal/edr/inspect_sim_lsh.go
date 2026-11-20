// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// kavach-lsh: a locality-sensitive digest over byte n-gram buckets.
//
// Written from the published idea behind Nilsimsa and TLSH (Oliver et al.,
// 2013): slide a small window over the input, hash byte triplets drawn from
// the window into a fixed bucket array, quantise the bucket counts by their
// quartiles into 2 bits each, and prepend a coarse length and a quartile-shape
// header. Distances are computed on the quantised values. The bucket function,
// triplet selection, header layout and distance weights here are Kavach's own;
// the digest is NOT compatible with TLSH and its distances are not TLSH scores.
//
// Cost: one linear pass (six triplet hashes per byte); memory O(1).

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strings"
)

const (
	lshPrefix   = "kavach-lsh1"
	lshWindow   = 5
	lshBuckets  = 128
	lshMinInput = 256
	lshHexLen   = 2 * (2 + lshBuckets/4)
	// LSHMaxDistance is the largest value LSHDistance can return.
	LSHMaxDistance = lshBuckets*3 + lshMaxLenDiff + 2*15
	lshMaxLenDiff  = 64
)

var errLSHFormat = errors.New("malformed kavach-lsh digest")

// Triplet index sets inside the 5-byte window: the six of the ten possible
// triplets that contain the oldest byte, so each byte-triple shape is counted
// once as the window slides.
var lshTriplets = [6][3]int{{0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 2, 3}, {0, 2, 4}, {0, 3, 4}}

// LSHDigest computes the kavach-lsh digest of data.
func LSHDigest(ctx context.Context, data []byte) (string, error) {
	n := len(data)
	if n < lshMinInput {
		return "", errSimTooSmall
	}
	var bucket [lshBuckets]uint32
	for e := lshWindow - 1; e < n; e++ {
		if e%ctphCtxStep == 0 && ctx.Err() != nil {
			return "", ctx.Err()
		}
		w := data[e-lshWindow+1 : e+1]
		for t, tr := range lshTriplets {
			k := uint32(w[tr[0]]) | uint32(w[tr[1]])<<8 | uint32(w[tr[2]])<<16 | uint32(t+1)<<24
			bucket[simMix(k^0x9e3779b9)%lshBuckets]++
		}
	}
	sorted := bucket
	s := sorted[:]
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q1, q2, q3 := s[lshBuckets/4-1], s[lshBuckets/2-1], s[3*lshBuckets/4-1]
	ratio := func(q uint32) byte {
		if q3 == 0 {
			return 0
		}
		return byte(uint64(q) * 15 / uint64(q3))
	}
	lv := int(math.Log2(float64(n)) * 8)
	if lv > 255 {
		lv = 255
	}
	out := make([]byte, 2+lshBuckets/4)
	out[0] = byte(lv)
	out[1] = ratio(q1)<<4 | ratio(q2)
	for i, c := range bucket {
		var v byte
		switch {
		case c <= q1:
			v = 0
		case c <= q2:
			v = 1
		case c <= q3:
			v = 2
		default:
			v = 3
		}
		out[2+i/4] |= v << (uint(i%4) * 2)
	}
	return lshPrefix + ":" + hex.EncodeToString(out), nil
}

func parseLSH(d string) ([]byte, bool) {
	if !strings.HasPrefix(d, lshPrefix+":") {
		return nil, false
	}
	h := d[len(lshPrefix)+1:]
	if len(h) != lshHexLen {
		return nil, false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, false
	}
	return b, true
}

func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

// LSHDistance is the distance between two kavach-lsh digests: 0 for
// identical, growing with difference, never above LSHMaxDistance. It is the
// sum of the bucket-level differences (0-3 each), the length difference
// (capped at 64 steps of 1/8 octave) and the two quartile-shape differences.
// It returns -1 for malformed input. The distance is symmetric.
func LSHDistance(x, y string) int {
	a, ok1 := parseLSH(x)
	b, ok2 := parseLSH(y)
	if !ok1 || !ok2 {
		return -1
	}
	d := absInt(int(a[0]) - int(b[0]))
	if d > lshMaxLenDiff {
		d = lshMaxLenDiff
	}
	d += absInt(int(a[1]>>4) - int(b[1]>>4))
	d += absInt(int(a[1]&15) - int(b[1]&15))
	for i := 0; i < lshBuckets; i++ {
		va := int(a[2+i/4]>>(uint(i%4)*2)) & 3
		vb := int(b[2+i/4]>>(uint(i%4)*2)) & 3
		d += absInt(va - vb)
	}
	return d
}
