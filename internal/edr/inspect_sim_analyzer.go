// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// The "similarity" analyzer for kind file. It records the similarity digests
// in the report Meta and compares them to digests of earlier submissions held
// in a small bounded in-memory index (digests only, never bytes) plus the
// capped report ring. A finding is emitted only when the file resembles an
// earlier submission (above documented thresholds) or shares its import hash.
// A similarity finding says "looks like something seen before"; it does not
// say the earlier file was malicious, so weights are small.

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SimCTPHThreshold: kavach-ctph scores at or above this count as similar.
	SimCTPHThreshold = 55
	// SimLSHThreshold: kavach-lsh distances at or below this count as similar.
	SimLSHThreshold = 24
	// SimIndexCapacity bounds the digest index (each entry a few hundred bytes).
	SimIndexCapacity = 1024
)

type simEntry struct {
	SHA256   string     `json:"sha256"`
	ReportID string     `json:"report_id"`
	Name     string     `json:"name,omitempty"`
	Size     int64      `json:"size"`
	Time     time.Time  `json:"time"`
	D        SimDigests `json:"digests"`
}

var (
	simMu    sync.Mutex
	simIndex []simEntry // oldest first
)

func simRemember(e simEntry) {
	simMu.Lock()
	defer simMu.Unlock()
	for i := range simIndex {
		if simIndex[i].SHA256 == e.SHA256 {
			simIndex = append(simIndex[:i], simIndex[i+1:]...)
			break
		}
	}
	simIndex = append(simIndex, e)
	if len(simIndex) > SimIndexCapacity {
		simIndex = simIndex[len(simIndex)-SimIndexCapacity:]
	}
}

// simCandidates returns index entries plus ring reports not already indexed.
func simCandidates() []simEntry {
	simMu.Lock()
	out := append([]simEntry(nil), simIndex...)
	simMu.Unlock()
	seen := make(map[string]bool, len(out))
	for _, e := range out {
		seen[e.SHA256] = true
	}
	for _, r := range RecentInspectReports(0) {
		if r.Kind != InspectKindFile || seen[r.SHA256] || r.Meta == nil {
			continue
		}
		d, ok := r.Meta["similarity.digests"].(SimDigests)
		if !ok {
			continue
		}
		seen[r.SHA256] = true
		out = append(out, simEntry{SHA256: r.SHA256, ReportID: r.ID, Name: r.Name, Size: r.Size, Time: r.Time, D: d})
	}
	return out
}

// SimMatch is one nearest-neighbour result.
type SimMatch struct {
	SHA256       string    `json:"sha256"`
	ReportID     string    `json:"report_id"`
	Name         string    `json:"name,omitempty"`
	Time         time.Time `json:"time"`
	CTPHScore    int       `json:"ctph_score"`      // 0-100, -1 if not comparable
	LSHDistance  int       `json:"lsh_distance"`    // 0..LSHMaxDistance, -1 if not comparable
	ImpHashMatch bool      `json:"imphash_match"`   // identical PE import hash
	SymHashMatch bool      `json:"symhash_match"`   // identical ELF/Mach-O symbol hash
	Similar      bool      `json:"similar"`         // above documented thresholds
	Basis        string    `json:"basis,omitempty"` // which signal fired
}

func simCompare(q SimDigests, e simEntry) SimMatch {
	m := SimMatch{SHA256: e.SHA256, ReportID: e.ReportID, Name: e.Name, Time: e.Time, CTPHScore: -1, LSHDistance: -1}
	if q.CTPH != "" && e.D.CTPH != "" {
		m.CTPHScore = CTPHCompare(q.CTPH, e.D.CTPH)
	}
	if q.LSH != "" && e.D.LSH != "" {
		m.LSHDistance = LSHDistance(q.LSH, e.D.LSH)
	}
	m.ImpHashMatch = q.ImpHash != "" && q.ImpHash == e.D.ImpHash
	m.SymHashMatch = (q.ELFSymHash != "" && q.ELFSymHash == e.D.ELFSymHash) || (q.MachOHash != "" && q.MachOHash == e.D.MachOHash)
	var basis []string
	if m.CTPHScore >= SimCTPHThreshold {
		basis = append(basis, "ctph")
	}
	if m.LSHDistance >= 0 && m.LSHDistance <= SimLSHThreshold {
		basis = append(basis, "lsh")
	}
	if m.ImpHashMatch {
		basis = append(basis, "imphash")
	}
	m.Similar = len(basis) > 0
	m.Basis = strings.Join(basis, "+")
	return m
}

// simNearest ranks candidates (excluding the query's own sha256) best first.
func simNearest(q SimDigests, self string, limit int, onlySimilar bool) []SimMatch {
	var res []SimMatch
	for _, e := range simCandidates() {
		if e.SHA256 == self {
			continue
		}
		m := simCompare(q, e)
		if onlySimilar && !m.Similar {
			continue
		}
		if m.CTPHScore <= 0 && m.LSHDistance < 0 && !m.ImpHashMatch && !m.SymHashMatch {
			continue
		}
		res = append(res, m)
	}
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].CTPHScore != res[j].CTPHScore {
			return res[i].CTPHScore > res[j].CTPHScore
		}
		di, dj := res[i].LSHDistance, res[j].LSHDistance
		if di < 0 {
			di = 1 << 20
		}
		if dj < 0 {
			dj = 1 << 20
		}
		return di < dj
	})
	if limit > 0 && len(res) > limit {
		res = res[:limit]
	}
	return res
}

// SimAnalyzerWindow is how many leading bytes of a submitted file the
// similarity analyzer digests. Larger files are digested on this prefix only,
// so two large files that differ only after the window can look identical;
// the report says so with the limit "similarity:digest-window".
const SimAnalyzerWindow = 8 << 20

func init() {
	RegisterAnalyzer("similarity", []string{InspectKindFile}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
		if len(in.Data) == 0 {
			return nil
		}
		// Digest only a bounded prefix so the analyzer stays inside its time
		// budget whatever the input size (the digests are about 10x slower under
		// the race detector, and a busy host is slower too). Headers, import
		// tables and symbol tables sit near the start of PE/ELF/Mach-O files.
		data := in.Data
		if len(data) > SimAnalyzerWindow {
			data = data[:SimAnalyzerWindow]
			b.LimitHit("digest-window")
		}
		d := computeDigestsCtx(ctx, data)
		b.Meta("digests", d)
		self, rid := b.r.SHA256, b.r.ID
		for _, m := range simNearest(d, self, 3, true) {
			w := 4
			sev := "info"
			if prior := simPriorScore(m.ReportID); prior >= 40 {
				w, sev = 12, "low"
			}
			if m.CTPHScore >= SimCTPHThreshold || (m.LSHDistance >= 0 && m.LSHDistance <= SimLSHThreshold) {
				b.Finding(InspectFinding{
					ID: "sim-near-duplicate", Title: "Similar to an earlier submission", Severity: sev, Weight: w,
					Evidence: "report " + m.ReportID + " sha256 " + m.SHA256 + " ctph=" + strconv.Itoa(m.CTPHScore) + " lsh-distance=" + strconv.Itoa(m.LSHDistance),
				})
			}
			if m.ImpHashMatch || m.SymHashMatch {
				id, title := "sim-imphash-match", "Import table identical to an earlier submission"
				if !m.ImpHashMatch {
					id, title = "sim-symhash-match", "Dynamic symbol set identical to an earlier submission"
				}
				b.Finding(InspectFinding{ID: id, Title: title, Severity: sev, Weight: w + 2,
					Evidence: "report " + m.ReportID + " sha256 " + m.SHA256})
			}
		}
		simRemember(simEntry{SHA256: self, ReportID: rid, Name: truncInspect(in.Name), Size: int64(len(in.Data)), Time: time.Now().UTC(), D: d})
		return nil
	})
}

// simPriorScore returns the stored report's score, or 0 if it has left the ring.
func simPriorScore(id string) int {
	for _, r := range RecentInspectReports(0) {
		if r.ID == id {
			return r.Score
		}
	}
	return 0
}

// RegisterInspectSimilar serves GET /v1/inspect/similar?sha256=|digest=&limit=
// returning the nearest earlier submissions (digests only; no bytes are kept).
func RegisterInspectSimilar(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/inspect/similar", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		limit := 10
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 50 {
			limit = n
		}
		var qd SimDigests
		self := strings.ToLower(strings.TrimSpace(q.Get("sha256")))
		digest := strings.TrimSpace(q.Get("digest"))
		switch {
		case self != "":
			found := false
			for _, e := range simCandidates() {
				if e.SHA256 == self {
					qd, found = e.D, true
					break
				}
			}
			if !found {
				http.Error(w, "unknown sha256 (not in the digest index or report ring)", http.StatusNotFound)
				return
			}
		case digest != "":
			switch {
			case strings.HasPrefix(digest, ctphPrefix+":"):
				if _, ok := parseCTPH(digest); !ok {
					http.Error(w, "malformed kavach-ctph digest", http.StatusBadRequest)
					return
				}
				qd.CTPH = digest
			case strings.HasPrefix(digest, lshPrefix+":"):
				if _, ok := parseLSH(digest); !ok {
					http.Error(w, "malformed kavach-lsh digest", http.StatusBadRequest)
					return
				}
				qd.LSH = digest
			default:
				http.Error(w, "unsupported digest (want kavach-ctph1:... or kavach-lsh1:...)", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "give sha256= or digest=", http.StatusBadRequest)
			return
		}
		ms := simNearest(qd, self, limit, false)
		if ms == nil {
			ms = []SimMatch{}
		}
		writeJSON(w, map[string]any{
			"count": len(ms), "matches": ms, "mode": "observe-only",
			"thresholds": map[string]int{"ctph_min_score": SimCTPHThreshold, "lsh_max_distance": SimLSHThreshold},
			"note":       "kavach-native digests; not compatible with ssdeep/TLSH. Similarity is not maliciousness.",
		})
	})
}
