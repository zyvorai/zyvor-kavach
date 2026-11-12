package edr

import (
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// Ransomware early-warning, container visibility and lateral-movement
// summaries. Report-only: derived from telemetry already in the Store; no
// response action is ever taken.

// RCIndicator is one ransomware or container signal.
type RCIndicator struct {
	Time   time.Time `json:"time"`
	Host   string    `json:"host"`
	Kind   string    `json:"kind"`
	Weight int       `json:"weight"`
	Detail string    `json:"detail"`
}

// RansomwareHostRisk is the per-host score and timeline.
type RansomwareHostRisk struct {
	Host       string        `json:"host"`
	Score      int           `json:"score"`
	Level      string        `json:"level"`
	Timeline   []RCIndicator `json:"timeline"`
	ReportOnly bool          `json:"report_only"`
}

// ContainerRisk summarises container posture for a host.
type ContainerRisk struct {
	Host       string        `json:"host"`
	Score      int           `json:"score"`
	Level      string        `json:"level"`
	Indicators []RCIndicator `json:"indicators"`
	ReportOnly bool          `json:"report_only"`
}

// LateralEdge is a remote logon edge between hosts.
type LateralEdge struct {
	Source   string    `json:"source"`
	Target   string    `json:"target"`
	Protocol string    `json:"protocol"`
	Count    int       `json:"count"`
	Last     time.Time `json:"last"`
}

var rcNoteNames = []string{"readme.txt", "how_to_decrypt", "decrypt_instructions", "restore_files", "recover_files", "how_to_recover", "your_files_are_encrypted"}
var rcCryptExt = []string{".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".lockbit", ".ryuk", ".wncry", ".conti", ".akira", ".blackcat"}
var rcShadowCmds = []string{"vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog", "delete shadows /all", "vssadmin resize shadowstorage", "tmutil deletelocalsnapshots", "tmutil delete"}

func rcSnapshot(s *Store) ([]Event, []NetworkEvent, []FileEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.recentEvents...), append([]NetworkEvent(nil), s.networkEvents...), append([]FileEvent(nil), s.fileEvents...)
}

func rcLevel(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 15:
		return "medium"
	}
	return "low"
}

func rcContains(s string, subs []string) (string, bool) {
	l := strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(l, x) {
			return x, true
		}
	}
	return "", false
}

// ComputeRansomwareRisk scores every host from process and file telemetry.
func ComputeRansomwareRisk(events []Event, files []FileEvent) []RansomwareHostRisk {
	by := map[string][]RCIndicator{}
	for _, e := range events {
		if m, ok := rcContains(e.Command, rcShadowCmds); ok {
			by[e.Host] = append(by[e.Host], RCIndicator{e.Time, e.Host, "backup_deletion", 40, "command matches " + m})
		}
	}
	bursts := map[string]map[int64]int{}
	for _, f := range files {
		base := strings.ToLower(path.Base(strings.ReplaceAll(f.Path, "\\", "/")))
		for _, n := range rcNoteNames {
			if strings.Contains(base, n) {
				by[f.Host] = append(by[f.Host], RCIndicator{f.Time, f.Host, "ransom_note", 35, "file " + base})
				break
			}
		}
		for _, x := range rcCryptExt {
			if strings.HasSuffix(base, x) {
				by[f.Host] = append(by[f.Host], RCIndicator{f.Time, f.Host, "extension_change", 10, "encrypted-style extension " + x})
				break
			}
		}
		op := strings.ToLower(f.Operation)
		if strings.Contains(op, "rename") || strings.Contains(op, "modif") || strings.Contains(op, "write") || strings.Contains(op, "change") {
			if bursts[f.Host] == nil {
				bursts[f.Host] = map[int64]int{}
			}
			bursts[f.Host][f.Time.Unix()/60]++
		}
	}
	for h, m := range bursts {
		for k, n := range m {
			if n >= 50 {
				by[h] = append(by[h], RCIndicator{time.Unix(k*60, 0).UTC(), h, "mass_file_change", 30, "mass rename/modify burst within one minute"})
			}
		}
	}
	out := []RansomwareHostRisk{}
	for h, ind := range by {
		sort.Slice(ind, func(i, j int) bool { return ind[i].Time.Before(ind[j].Time) })
		seen := map[string]int{}
		score := 0
		for _, i := range ind {
			if seen[i.Kind] < 3 {
				score += i.Weight
			}
			seen[i.Kind]++
		}
		if score > 100 {
			score = 100
		}
		out = append(out, RansomwareHostRisk{h, score, rcLevel(score), ind, true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// ComputeContainerRisk inspects process command lines for container posture issues.
func ComputeContainerRisk(events []Event) []ContainerRisk {
	by := map[string][]RCIndicator{}
	images := map[string]map[string]map[string]bool{}
	for _, e := range events {
		c := strings.ToLower(e.Command)
		add := func(kind string, w int, d string) {
			by[e.Host] = append(by[e.Host], RCIndicator{e.Time, e.Host, kind, w, d})
		}
		if strings.Contains(c, "docker run") || strings.Contains(c, "podman run") || strings.Contains(c, "nerdctl run") {
			if strings.Contains(c, "--privileged") {
				add("privileged_container", 40, "container started with --privileged")
			}
			for _, m := range []string{"-v /:/", "-v /etc", "-v /var/run/docker.sock", "-v /proc", "--volume /:/", "-v /root"} {
				if strings.Contains(c, m) {
					add("host_mount", 25, "sensitive host mount "+m)
					break
				}
			}
			for _, m := range []string{"--user root", "-u root", "--user 0", "-u 0"} {
				if strings.Contains(c, m) {
					add("root_container", 15, "container running as root")
					break
				}
			}
			if strings.Contains(c, "--pid=host") || strings.Contains(c, "--net=host") || strings.Contains(c, "--network=host") {
				add("host_namespace", 25, "container shares host namespace")
			}
			for _, f := range strings.Fields(c) {
				if !strings.HasPrefix(f, "-") && strings.Contains(f, ":") && !strings.Contains(f, "/") && !strings.Contains(f, "=") {
					n, t, _ := strings.Cut(f, ":")
					if images[e.Host] == nil {
						images[e.Host] = map[string]map[string]bool{}
					}
					if images[e.Host][n] == nil {
						images[e.Host][n] = map[string]bool{}
					}
					images[e.Host][n][t] = true
				}
			}
		}
		for _, x := range []string{"docker exec", "kubectl exec", "podman exec", "crictl exec"} {
			if strings.Contains(c, x) {
				add("container_exec", 20, "exec into container")
				break
			}
		}
	}
	for h, names := range images {
		for n, tags := range names {
			if len(tags) > 1 {
				by[h] = append(by[h], RCIndicator{Host: h, Kind: "image_drift", Weight: 10, Detail: "image " + n + " seen with multiple tags"})
			}
		}
	}
	out := []ContainerRisk{}
	for h, ind := range by {
		score := 0
		for _, i := range ind {
			score += i.Weight
		}
		if score > 100 {
			score = 100
		}
		out = append(out, ContainerRisk{h, score, rcLevel(score), ind, true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func rcHostOf(dest string) string {
	if i := strings.LastIndex(dest, ":"); i > 0 {
		dest = dest[:i]
	}
	return strings.Trim(dest, "[]")
}

// ComputeLateralEdges builds remote-logon edges (rdp/ssh/smb) between hosts.
func ComputeLateralEdges(events []Event, nets []NetworkEvent) []LateralEdge {
	ports := map[string]string{"22": "ssh", "3389": "rdp", "445": "smb", "139": "smb", "5985": "winrm", "5986": "winrm"}
	agg := map[string]*LateralEdge{}
	add := func(src, dst, proto string, t time.Time) {
		if src == "" || dst == "" || src == dst {
			return
		}
		k := src + "|" + dst + "|" + proto
		if agg[k] == nil {
			agg[k] = &LateralEdge{Source: src, Target: dst, Protocol: proto}
		}
		agg[k].Count++
		if t.After(agg[k].Last) {
			agg[k].Last = t
		}
	}
	for _, n := range nets {
		i := strings.LastIndex(n.Destination, ":")
		if i < 0 {
			continue
		}
		if p, ok := ports[n.Destination[i+1:]]; ok {
			add(n.Host, rcHostOf(n.Destination), p, n.Time)
		}
	}
	for _, e := range events {
		f := strings.Fields(e.Command)
		if len(f) < 2 {
			continue
		}
		switch path.Base(f[0]) {
		case "ssh", "scp", "sftp":
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if _, h, ok := strings.Cut(a, "@"); ok {
					add(e.Host, strings.SplitN(h, ":", 2)[0], "ssh", e.Time)
					break
				}
			}
		case "xfreerdp", "mstsc", "rdesktop":
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "/v:") {
					add(e.Host, strings.TrimPrefix(a, "/v:"), "rdp", e.Time)
				}
			}
		}
	}
	out := []LateralEdge{}
	for _, e := range agg {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Source+out[i].Target < out[j].Source+out[j].Target
	})
	return out
}

// RegisterRansomwareCloud wires the report-only endpoints.
func RegisterRansomwareCloud(mux *http.ServeMux, token string, store *Store) {
	h := func(fn func(w http.ResponseWriter, r *http.Request, ev []Event, nt []NetworkEvent, fl []FileEvent)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			ev, nt, fl := rcSnapshot(store)
			fn(w, r, ev, nt, fl)
		}
	}
	mux.HandleFunc("GET /v1/ransomware/risk", h(func(w http.ResponseWriter, r *http.Request, ev []Event, _ []NetworkEvent, fl []FileEvent) {
		writeJSON(w, map[string]any{"hosts": ComputeRansomwareRisk(ev, fl), "report_only": true})
	}))
	mux.HandleFunc("GET /v1/ransomware/host/{host}", h(func(w http.ResponseWriter, r *http.Request, ev []Event, _ []NetworkEvent, fl []FileEvent) {
		host := r.PathValue("host")
		for _, x := range ComputeRansomwareRisk(ev, fl) {
			if x.Host == host {
				writeJSON(w, x)
				return
			}
		}
		writeJSON(w, RansomwareHostRisk{Host: host, Level: "low", Timeline: []RCIndicator{}, ReportOnly: true})
	}))
	mux.HandleFunc("GET /v1/containers/risk", h(func(w http.ResponseWriter, r *http.Request, ev []Event, _ []NetworkEvent, _ []FileEvent) {
		writeJSON(w, map[string]any{"hosts": ComputeContainerRisk(ev), "report_only": true})
	}))
	mux.HandleFunc("GET /v1/lateral/edges", h(func(w http.ResponseWriter, r *http.Request, ev []Event, nt []NetworkEvent, _ []FileEvent) {
		writeJSON(w, map[string]any{"edges": ComputeLateralEdges(ev, nt), "report_only": true})
	}))
}
