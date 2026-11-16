// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"sort"
	"strings"
)

// Model 3: peer-group outlier. Each host keeps capped counts of executable basenames and of
// destinations. At query time every ready host's normalised mix is compared with the equal-weight
// mean of all OTHER ready hosts (leave-one-out) by Jensen-Shannon divergence (log2, range 0..1). The
// divergences are turned into robust z-scores (median / MAD) across hosts. The peer group is the
// whole fleet: there is no role or OS grouping, which is the main caveat (a lone database server
// among web servers will look odd).

const (
	mlPeerMinProc   = 50  // process events per host for the process view
	mlPeerMinDest   = 20  // network events per host for the destination view
	mlPeerMinHosts  = 5   // ready hosts needed in a view
	mlPeerZ         = 3.5 // outlier threshold on the robust z-score
	mlPeerMinSD     = 0.02
	mlPeerTopItems  = 5
	mlPeerDestLimit = 96
)

type mlPeerHost struct {
	Proc   map[string]int `json:"proc"`
	ProcN  int            `json:"proc_n"`
	POther int            `json:"proc_other,omitempty"`
	Dest   map[string]int `json:"dest"`
	DestN  int            `json:"dest_n"`
	DOther int            `json:"dest_other,omitempty"`
}

func (e *mlExtEngine) peerHost(host string) *mlPeerHost {
	p := e.st.Peers[host]
	if p == nil {
		if host == "" || len(e.st.Peers) >= mlExtMaxHosts {
			e.st.Dropped["peer_hosts"]++
			return nil
		}
		p = &mlPeerHost{Proc: map[string]int{}, Dest: map[string]int{}}
		e.st.Peers[host] = p
	}
	return p
}

func (e *mlExtEngine) learnPeerProc(ev Event) {
	b := mlBase(ev.Executable)
	if b == "" {
		return
	}
	p := e.peerHost(ev.Host)
	if p == nil {
		return
	}
	p.ProcN++
	if _, ok := p.Proc[b]; ok || len(p.Proc) < mlExtMaxItems {
		p.Proc[b]++
	} else {
		p.POther++
	}
}

func (e *mlExtEngine) learnPeerDest(n NetworkEvent) {
	d := strings.ToLower(strings.TrimSpace(n.Destination))
	if d == "" {
		return
	}
	if len(d) > mlPeerDestLimit {
		d = strings.ToValidUTF8(d[:mlPeerDestLimit], "")
	}
	p := e.peerHost(n.Host)
	if p == nil {
		return
	}
	p.DestN++
	if _, ok := p.Dest[d]; ok || len(p.Dest) < mlExtMaxItems {
		p.Dest[d]++
	} else {
		p.DOther++
	}
}

type mlPeerItem struct {
	Item      string  `json:"item"`
	HostShare float64 `json:"host_share"`
	PeerShare float64 `json:"peer_share"`
}

type mlPeerView struct {
	View     string       `json:"view"` // process | destination
	Samples  int          `json:"sample_count"`
	Status   string       `json:"status"`
	JSD      float64      `json:"jsd_bits,omitempty"`
	Z        float64      `json:"robust_z,omitempty"`
	Outlier  bool         `json:"outlier"`
	Distinct []mlPeerItem `json:"most_distinct_items,omitempty"`
}

// peerScores computes, for one view, the JSD of every ready host against its leave-one-out peers.
func peerScores(counts map[string]map[string]int, totals map[string]int, min int) (jsd, z map[string]float64, ready []string, ok bool) {
	for _, h := range mlSortedKeys(counts) {
		if totals[h] >= min {
			ready = append(ready, h)
		}
	}
	if len(ready) < mlPeerMinHosts {
		return nil, nil, ready, false
	}
	vocab := map[string]bool{}
	dist := map[string]map[string]float64{}
	for _, h := range ready {
		d := map[string]float64{}
		for k, v := range counts[h] {
			d[k] = float64(v) / float64(totals[h])
			vocab[k] = true
		}
		dist[h] = d
	}
	words := mlSortedKeys(vocab)
	sum := map[string]float64{}
	for _, h := range ready {
		for k, v := range dist[h] {
			sum[k] += v
		}
	}
	jsd = map[string]float64{}
	n := float64(len(ready) - 1)
	for _, h := range ready {
		var s float64
		for _, w := range words {
			p := dist[h][w]
			q := (sum[w] - p) / n
			m := (p + q) / 2
			if p > 0 {
				s += 0.5 * p * math.Log2(p/m)
			}
			if q > 0 {
				s += 0.5 * q * math.Log2(q/m)
			}
		}
		jsd[h] = s
	}
	vals := make([]float64, 0, len(ready))
	for _, h := range ready {
		vals = append(vals, jsd[h])
	}
	med := mlMedian(vals)
	dev := make([]float64, len(vals))
	for i, v := range vals {
		dev[i] = math.Abs(v - med)
	}
	sd := math.Max(1.4826*mlMedian(dev), mlPeerMinSD)
	z = map[string]float64{}
	for _, h := range ready {
		z[h] = (jsd[h] - med) / sd
	}
	return jsd, z, ready, true
}

func mlMedian(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

type mlPeerResult struct {
	Host   string
	Views  []mlPeerView
	MaxZ   float64
	Status string
}

// peerCompute evaluates every host; the caller holds e.mu.
func (e *mlExtEngine) peerCompute() (map[string]*mlPeerResult, map[string]any) {
	pc, pt, dc, dt := map[string]map[string]int{}, map[string]int{}, map[string]map[string]int{}, map[string]int{}
	for h, p := range e.st.Peers {
		pc[h], pt[h], dc[h], dt[h] = p.Proc, p.ProcN, p.Dest, p.DestN
	}
	pj, pz, pr, pok := peerScores(pc, pt, mlPeerMinProc)
	dj, dz, dr, dok := peerScores(dc, dt, mlPeerMinDest)
	meta := map[string]any{"hosts_tracked": len(e.st.Peers),
		"process_view":     map[string]any{"ready_hosts": len(pr), "min_hosts": mlPeerMinHosts, "min_events_per_host": mlPeerMinProc, "status": mlReady(pok)},
		"destination_view": map[string]any{"ready_hosts": len(dr), "min_hosts": mlPeerMinHosts, "min_events_per_host": mlPeerMinDest, "status": mlReady(dok)},
		"z_threshold":      mlPeerZ}
	out := map[string]*mlPeerResult{}
	for _, h := range mlSortedKeys(e.st.Peers) {
		p := e.st.Peers[h]
		r := &mlPeerResult{Host: h, Status: "not_enough_data"}
		build := func(view string, n, min int, ok bool, jsd, z map[string]float64, counts map[string]map[string]int, tot map[string]int, ready []string) {
			v := mlPeerView{View: view, Samples: n, Status: "not_enough_data"}
			if ok && n >= min {
				v.Status, v.JSD, v.Z = "ok", mlRound(jsd[h], 4), mlRound(z[h], 2)
				v.Outlier = z[h] >= mlPeerZ
				v.Distinct = peerDistinct(h, counts, tot, ready)
				r.Status = "ok"
				if z[h] > r.MaxZ {
					r.MaxZ = z[h]
				}
			}
			r.Views = append(r.Views, v)
		}
		build("process", p.ProcN, mlPeerMinProc, pok, pj, pz, pc, pt, pr)
		build("destination", p.DestN, mlPeerMinDest, dok, dj, dz, dc, dt, dr)
		out[h] = r
	}
	return out, meta
}

// peerDistinct lists items whose share on the host most exceeds the peer mean share.
func peerDistinct(h string, counts map[string]map[string]int, tot map[string]int, ready []string) []mlPeerItem {
	var items []mlPeerItem
	for k, v := range counts[h] {
		hs := float64(v) / float64(tot[h])
		var ps float64
		for _, o := range ready {
			if o != h {
				ps += float64(counts[o][k]) / float64(tot[o])
			}
		}
		ps /= float64(len(ready) - 1)
		if hs > ps {
			items = append(items, mlPeerItem{k, mlRound(hs, 4), mlRound(ps, 4)})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i].HostShare-items[i].PeerShare, items[j].HostShare-items[j].PeerShare
		if a != b {
			return a > b
		}
		return items[i].Item < items[j].Item
	})
	if len(items) > mlPeerTopItems {
		items = items[:mlPeerTopItems]
	}
	return items
}

func (e *mlExtEngine) peerView(host string, limit int) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	all, meta := e.peerCompute()
	res := map[string]any{"method": mlMethod, "model": "peer-outlier-v1", "peer_group": "all other hosts with enough data (no role grouping)",
		"distance": "Jensen-Shannon divergence (log2) of the host's mix vs leave-one-out mean of peers; robust z over hosts (median/MAD)"}
	for k, v := range meta {
		res[k] = v
	}
	if host != "" {
		res["host"] = host
		r := all[host]
		if r == nil {
			res["status"], res["sample_count"] = "not_enough_data", 0
			return res
		}
		res["status"] = r.Status
		res["views"] = r.Views
		res["max_z"] = mlRound(r.MaxZ, 2)
		res["outlier"] = r.MaxZ >= mlPeerZ
		res["score"] = peerScore(r)
		return res
	}
	rows := []*mlPeerResult{}
	for _, h := range mlSortedKeys(all) {
		rows = append(rows, all[h])
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].MaxZ > rows[j].MaxZ })
	res["total"] = len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	type row struct {
		Host    string       `json:"host"`
		Status  string       `json:"status"`
		MaxZ    float64      `json:"max_z"`
		Score   float64      `json:"score"`
		Outlier bool         `json:"outlier"`
		Views   []mlPeerView `json:"views"`
	}
	outRows := []row{}
	for _, r := range rows {
		outRows = append(outRows, row{r.Host, r.Status, mlRound(r.MaxZ, 2), peerScore(r), r.MaxZ >= mlPeerZ, r.Views})
	}
	res["hosts"] = outRows
	return res
}

func peerScore(r *mlPeerResult) float64 {
	if r.Status != "ok" {
		return 0
	}
	return mlRound(100*clamp01(r.MaxZ/8), 1)
}

func (e *mlExtEngine) peerFactor(c *priorityCtx, host string) (float64, string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.st.Peers[host]; !ok {
		return 0, "host has no peer profile", false
	}
	if c.peer == nil {
		c.peer, _ = e.peerCompute()
	}
	r := c.peer[host]
	if r == nil || r.Status != "ok" {
		return 0, "not enough hosts/events for a peer comparison", false
	}
	return clamp01(r.MaxZ / 8), "peer-group divergence robust z " + f2(r.MaxZ) + " (outlier at " + f2(mlPeerZ) + "); fleet-wide peer group", true
}
