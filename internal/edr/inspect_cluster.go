// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Cross-report correlation for the artifact inspector. It clusters the stored
// reports (the capped in-memory ring; no input bytes exist to read) by the
// factors they share: indicators of compromise, embedded or own sha256 values,
// import/symbol/entropy hashes, identical fuzzy digests and matched IOC-store
// entries. It is single-linkage: two reports are linked when the weights of the
// factors they share reach a threshold, and a cluster is a connected set of
// links. Every cluster lists the shared factors and the pairwise links that
// justify it, so the grouping can be audited. Read-only; nothing is scored,
// stored or sent anywhere.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Caps for the clustering pass.
const (
	ClusterMaxReports      = InspectRingCapacity
	ClusterMaxFactorsEach  = 300   // factors considered per report
	ClusterMaxPosting      = 40    // a factor shared by more reports than this is treated as common
	ClusterMaxPairs        = 20000 // pairwise links tracked
	ClusterMaxOut          = 50    // clusters returned
	ClusterMaxMembers      = 50
	ClusterMaxSharedOut    = 30
	ClusterMaxLinksOut     = 40
	ClusterDefaultMinScore = 1.0
)

// ClusterMember is a report in a cluster (summary only).
type ClusterMember struct {
	ID     string    `json:"id"`
	SHA256 string    `json:"sha256"`
	Name   string    `json:"name,omitempty"`
	Kind   string    `json:"kind"`
	Format string    `json:"format,omitempty"`
	Score  int       `json:"score"`
	Level  string    `json:"level"`
	Time   time.Time `json:"time"`
}

// ClusterFactor is one shared factor and which cluster members carry it.
type ClusterFactor struct {
	Factor  string   `json:"factor"`
	Type    string   `json:"type"`
	Weight  float64  `json:"weight"`
	Count   int      `json:"count"`
	Reports []string `json:"reports"`
}

// ClusterLink explains why two members are connected.
type ClusterLink struct {
	A      string   `json:"a"`
	B      string   `json:"b"`
	Score  float64  `json:"score"`
	Shared []string `json:"shared"`
}

// InspectCluster is a group of related reports.
type InspectCluster struct {
	ID            string          `json:"id"`
	Size          int             `json:"size"`
	MaxScore      int             `json:"max_score"`
	MaxLevel      string          `json:"max_level"`
	Members       []ClusterMember `json:"members"`
	SharedFactors []ClusterFactor `json:"shared_factors"`
	Links         []ClusterLink   `json:"links"`
	Explanation   string          `json:"explanation"`
}

// InspectClusterResult is the clusters response.
type InspectClusterResult struct {
	Count      int              `json:"count"`
	Clusters   []InspectCluster `json:"clusters"`
	Considered int              `json:"considered"`
	Singletons int              `json:"singletons"`
	Common     []string         `json:"ignored_common_factors,omitempty"`
	LimitsHit  []string         `json:"limits_hit,omitempty"`
	MinScore   float64          `json:"min_score"`
	Mode       string           `json:"mode"`
	Note       string           `json:"note"`
}

// ClusterOptions tunes a clustering pass.
type ClusterOptions struct {
	MinScore float64 // weight needed to link two reports (default 1.0)
	Limit    int     // clusters returned (default 20, max ClusterMaxOut)
	Kind     string  // restrict to one inspect kind
}

var clusterNoise = map[string]bool{
	"www.w3.org": true, "schemas.microsoft.com": true, "schemas.openxmlformats.org": true, "purl.org": true,
	"schemas.xmlsoap.org": true, "localhost": true, "127.0.0.1": true, "0.0.0.0": true, "::1": true,
	"example.com": true, "www.example.com": true, "ns.adobe.com": true, "www.microsoft.com": true, "go.microsoft.com": true,
}

func clusterWeight(typ string) float64 {
	switch typ {
	case "path", "registry", "entropy-vec":
		return 0.4
	}
	return 1.0
}

// reportFactors returns the explainable factors of a report (key -> type).
func reportFactors(r *InspectReport) map[string]string {
	f := map[string]string{}
	add := func(typ, v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || len(f) >= ClusterMaxFactorsEach {
			return
		}
		host := v
		if typ == "url" {
			if i := strings.Index(host, "://"); i >= 0 {
				host = host[i+3:]
			}
			if i := strings.IndexAny(host, "/:?#"); i >= 0 {
				host = host[:i]
			}
		}
		if clusterNoise[host] || clusterNoise[v] {
			return
		}
		f[typ+":"+v] = typ
	}
	for _, i := range r.IOCs {
		add(i.Type, i.Value)
	}
	if r.SHA256 != "" {
		add("sha256", r.SHA256) // an own hash links to any report that embeds or references it
	}
	for _, id := range r.KnownIOCs {
		add("known-ioc", id)
	}
	if v, ok := r.Meta["similarity.digests"]; ok {
		var d SimDigests
		switch t := v.(type) {
		case SimDigests:
			d = t
		default:
			if raw, err := json.Marshal(v); err == nil {
				_ = json.Unmarshal(raw, &d)
			}
		}
		add("imphash", d.ImpHash)
		add("elf-symhash", d.ELFSymHash)
		add("macho-hash", d.MachOHash)
		add("ctph", d.CTPH)
		add("lsh", d.LSH)
		add("entropy-vec", d.EntropyVecH)
	}
	return f
}

type clusterPair struct{ a, b int }

// ClusterInspectReports groups reps by shared factors. It never mutates reps.
func ClusterInspectReports(reps []*InspectReport, opt ClusterOptions) *InspectClusterResult {
	if opt.MinScore <= 0 {
		opt.MinScore = ClusterDefaultMinScore
	}
	if opt.Limit <= 0 {
		opt.Limit = 20
	}
	if opt.Limit > ClusterMaxOut {
		opt.Limit = ClusterMaxOut
	}
	res := &InspectClusterResult{Clusters: []InspectCluster{}, MinScore: opt.MinScore, Mode: "observe-only",
		Note: "Clusters group stored reports that share indicators or digests; they show shared evidence, not a common author or campaign. Only reports still in the in-memory ring are considered and no input bytes are kept."}
	var in []*InspectReport
	for _, r := range reps {
		if r == nil || (opt.Kind != "" && r.Kind != opt.Kind) {
			continue
		}
		if len(in) >= ClusterMaxReports {
			res.LimitsHit = appendUnique(res.LimitsHit, "reports")
			break
		}
		in = append(in, r)
	}
	res.Considered = len(in)
	n := len(in)
	posting := map[string][]int{}
	ftype := map[string]string{}
	for i, r := range in {
		for k, t := range reportFactors(r) {
			posting[k] = append(posting[k], i)
			ftype[k] = t
		}
	}
	commonCut := ClusterMaxPosting
	if n >= 6 && n/2 < commonCut {
		commonCut = n / 2
	}
	keys := make([]string, 0, len(posting))
	for k := range posting {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	edges := map[clusterPair]*ClusterLink{}
	for _, k := range keys {
		p := posting[k]
		if len(p) < 2 {
			continue
		}
		if len(p) > commonCut {
			if len(res.Common) < 20 {
				res.Common = append(res.Common, k)
			}
			continue
		}
		w := clusterWeight(ftype[k])
		for x := 0; x < len(p); x++ {
			for y := x + 1; y < len(p); y++ {
				pr := clusterPair{p[x], p[y]}
				e := edges[pr]
				if e == nil {
					if len(edges) >= ClusterMaxPairs {
						res.LimitsHit = appendUnique(res.LimitsHit, "pairs")
						continue
					}
					e = &ClusterLink{A: in[pr.a].ID, B: in[pr.b].ID}
					edges[pr] = e
				}
				e.Score += w
				if len(e.Shared) < 12 {
					e.Shared = append(e.Shared, k)
				}
			}
		}
	}
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	linked := map[clusterPair]*ClusterLink{}
	for pr, e := range edges {
		if e.Score+1e-9 >= opt.MinScore {
			linked[pr] = e
			if ra, rb := find(pr.a), find(pr.b); ra != rb {
				parent[rb] = ra
			}
		}
	}
	groups := map[int][]int{}
	for i := 0; i < n; i++ {
		r := find(i)
		groups[r] = append(groups[r], i)
	}
	var clusters []InspectCluster
	for _, g := range groups {
		if len(g) < 2 {
			res.Singletons++
			continue
		}
		clusters = append(clusters, buildCluster(in, g, posting, ftype, linked, opt.MinScore))
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].Size != clusters[j].Size {
			return clusters[i].Size > clusters[j].Size
		}
		if clusters[i].MaxScore != clusters[j].MaxScore {
			return clusters[i].MaxScore > clusters[j].MaxScore
		}
		return clusters[i].ID < clusters[j].ID
	})
	if len(clusters) > opt.Limit {
		clusters = clusters[:opt.Limit]
		res.LimitsHit = appendUnique(res.LimitsHit, "clusters")
	}
	if clusters != nil {
		res.Clusters = clusters
	}
	res.Count = len(res.Clusters)
	return res
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func buildCluster(in []*InspectReport, g []int, posting map[string][]int, ftype map[string]string, linked map[clusterPair]*ClusterLink, minScore float64) InspectCluster {
	sort.Slice(g, func(i, j int) bool { return in[g[i]].ID < in[g[j]].ID })
	inG := map[int]bool{}
	for _, i := range g {
		inG[i] = true
	}
	c := InspectCluster{Size: len(g), MaxLevel: "clean"}
	rank := map[string]int{"clean": 0, "not_scored": 0, "low": 1, "suspicious": 2, "malicious-likely": 3}
	h := sha256.New()
	for _, i := range g {
		r := in[i]
		h.Write([]byte(r.SHA256 + "\n"))
		if r.Score > c.MaxScore {
			c.MaxScore = r.Score
		}
		if rank[r.Level] > rank[c.MaxLevel] {
			c.MaxLevel = r.Level
		}
		if len(c.Members) < ClusterMaxMembers {
			c.Members = append(c.Members, ClusterMember{ID: r.ID, SHA256: r.SHA256, Name: r.Name, Kind: r.Kind, Format: r.Format, Score: r.Score, Level: r.Level, Time: r.Time})
		}
	}
	c.ID = "clu-" + hex.EncodeToString(h.Sum(nil))[:12]
	// Shared factors: carried by >= 2 members of this cluster only.
	var facs []ClusterFactor
	for k, p := range posting {
		var ids []string
		for _, i := range p {
			if inG[i] {
				ids = append(ids, in[i].ID)
			}
		}
		if len(ids) < 2 || len(p) > ClusterMaxPosting {
			continue
		}
		sort.Strings(ids)
		facs = append(facs, ClusterFactor{Factor: k, Type: ftype[k], Weight: clusterWeight(ftype[k]), Count: len(ids), Reports: ids})
	}
	sort.Slice(facs, func(i, j int) bool {
		if facs[i].Count != facs[j].Count {
			return facs[i].Count > facs[j].Count
		}
		if facs[i].Weight != facs[j].Weight {
			return facs[i].Weight > facs[j].Weight
		}
		return facs[i].Factor < facs[j].Factor
	})
	total := len(facs)
	if len(facs) > ClusterMaxSharedOut {
		facs = facs[:ClusterMaxSharedOut]
	}
	c.SharedFactors = facs
	var links []ClusterLink
	for pr, e := range linked {
		if inG[pr.a] && inG[pr.b] {
			l := *e
			l.Score = float64(int(l.Score*100+0.5)) / 100
			links = append(links, l)
		}
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].Score != links[j].Score {
			return links[i].Score > links[j].Score
		}
		if links[i].A != links[j].A {
			return links[i].A < links[j].A
		}
		return links[i].B < links[j].B
	})
	if len(links) > ClusterMaxLinksOut {
		links = links[:ClusterMaxLinksOut]
	}
	c.Links = links
	top := ""
	if len(facs) > 0 {
		top = "; strongest shared factor " + facs[0].Factor + " (" + strconv.Itoa(facs[0].Count) + " reports)"
	}
	c.Explanation = strconv.Itoa(len(g)) + " reports linked by " + strconv.Itoa(total) + " shared factor(s) (link threshold " + strconv.FormatFloat(minScore, 'f', -1, 64) + ")" + top + ". Shared evidence only; not proof of one actor."
	return c
}

// RegisterInspectClusters serves the read-only correlation endpoint:
//
//	GET /v1/inspect/clusters?min_score=&limit=&kind=
func RegisterInspectClusters(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/inspect/clusters", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		opt := ClusterOptions{}
		if f, err := strconv.ParseFloat(q.Get("min_score"), 64); err == nil && f > 0 && f <= 100 {
			opt.MinScore = f
		}
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
			opt.Limit = n
		}
		if k := q.Get("kind"); k != "" {
			ok := false
			for _, x := range inspectKinds {
				ok = ok || x == k
			}
			if !ok {
				http.Error(w, "unknown kind", http.StatusBadRequest)
				return
			}
			opt.Kind = k
		}
		writeJSON(w, ClusterInspectReports(RecentInspectReports(0), opt))
	})
}
