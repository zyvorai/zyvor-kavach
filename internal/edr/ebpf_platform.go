// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Observation-only eBPF platform — Falco/Tracee/Tetragon-observe style signals.
// Never kill, isolate, drop packets, or LSM-deny.

type EBPFEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Host      string    `json:"host"`
	PID       int       `json:"pid,omitempty"`
	PPID      int       `json:"ppid,omitempty"`
	UID       int       `json:"uid,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Path      string    `json:"path,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	CgroupID  uint64    `json:"cgroup_id,omitempty"`
	DAddr     string    `json:"daddr,omitempty"`
	DPort     int       `json:"dport,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Source    string    `json:"source"` // ebpf|proc|netra|derived
	Timestamp time.Time `json:"timestamp"`
}

type EBPFFeature struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Hook    string `json:"hook"`
	Object  string `json:"object"`
	Mode    string `json:"mode"` // auto|on|off
	Status  string `json:"status"`
	Note    string `json:"note"`
	Enforce bool   `json:"enforce"` // always false
}

type EBPFAttachment struct {
	Program string `json:"program"`
	Type    string `json:"type"`
	Pin     string `json:"pin,omitempty"`
	Object  string `json:"object,omitempty"`
	Present bool   `json:"present"`
	Missing bool   `json:"missing"`
}

type EBPFMapInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Pin     string `json:"pin,omitempty"`
	Present bool   `json:"present"`
	Max     int    `json:"max_entries,omitempty"`
	Note    string `json:"note,omitempty"`
}

var (
	ebpfMu       sync.Mutex
	ebpfEvents   []EBPFEvent
	ebpfFeatures map[string]string // id -> mode
	ebpfLost     int
)

func init() {
	ebpfFeatures = defaultEBPFFeatureModes()
	seedEBPFDemoEvents()
}

func defaultEBPFFeatureModes() map[string]string {
	return map[string]string{
		"exec": "auto", "fork": "auto", "exit": "auto", "file": "auto",
		"priv": "auto", "memfd": "auto", "ptrace": "auto", "module": "auto",
		"bpf": "auto", "net": "auto", "netra-mirror": "auto",
	}
}

func EBPFCapabilities() []map[string]any {
	return []map[string]any{
		{"id": "exec", "hook": "tp_btf/sched_process_exec", "object": "kavach_exec.o"},
		{"id": "fork", "hook": "tp_btf/sched_process_fork", "object": "kavach_process.o"},
		{"id": "exit", "hook": "tp_btf/sched_process_exit", "object": "kavach_process.o"},
		{"id": "file", "hook": "tracepoint/syscalls/sys_enter_openat", "object": "kavach_file.o"},
		{"id": "priv", "hook": "sys_enter_setuid", "object": "kavach_priv.o"},
		{"id": "memfd", "hook": "sys_enter_memfd_create", "object": "kavach_priv.o"},
		{"id": "ptrace", "hook": "sys_enter_ptrace", "object": "kavach_priv.o"},
		{"id": "module", "hook": "sys_enter_init_module", "object": "kavach_priv.o"},
		{"id": "bpf", "hook": "sys_enter_bpf", "object": "kavach_priv.o"},
		{"id": "net", "hook": "sys_enter_connect", "object": "kavach_net.o"},
		{"id": "netra-mirror", "hook": "HTTP poll", "object": ""},
	}
}

func EBPFFeatureList() []EBPFFeature {
	ebpfMu.Lock()
	defer ebpfMu.Unlock()
	out := []EBPFFeature{}
	meta := map[string]EBPFFeature{
		"exec":         {ID: "exec", Name: "Process exec", Hook: "sched_process_exec", Object: "kavach_exec.o", Note: "Binary exec with path/comm"},
		"fork":         {ID: "fork", Name: "Process fork", Hook: "sched_process_fork", Object: "kavach_process.o", Note: "Parent/child lineage"},
		"exit":         {ID: "exit", Name: "Process exit", Hook: "sched_process_exit", Object: "kavach_process.o", Note: "Exit codes"},
		"file":         {ID: "file", Name: "File open", Hook: "sys_enter_openat", Object: "kavach_file.o", Note: "Metadata only — no content"},
		"priv":         {ID: "priv", Name: "Setuid", Hook: "sys_enter_setuid", Object: "kavach_priv.o", Note: "Privilege change observe"},
		"memfd":        {ID: "memfd", Name: "Memfd create", Hook: "sys_enter_memfd_create", Object: "kavach_priv.o", Note: "Fileless loader signal"},
		"ptrace":       {ID: "ptrace", Name: "Ptrace", Hook: "sys_enter_ptrace", Object: "kavach_priv.o", Note: "Injection observe"},
		"module":       {ID: "module", Name: "Kernel module", Hook: "sys_enter_init_module", Object: "kavach_priv.o", Note: "Module load observe"},
		"bpf":          {ID: "bpf", Name: "BPF syscall", Hook: "sys_enter_bpf", Object: "kavach_priv.o", Note: "Self-defense / abuse"},
		"net":          {ID: "net", Name: "Connect", Hook: "sys_enter_connect", Object: "kavach_net.o", Note: "Host connect — never drop"},
		"netra-mirror": {ID: "netra-mirror", Name: "Netra mirror", Hook: "poller", Object: "", Note: "XDR drops/flows proxy"},
	}
	order := []string{"exec", "fork", "exit", "file", "priv", "memfd", "ptrace", "module", "bpf", "net", "netra-mirror"}
	for _, id := range order {
		f := meta[id]
		f.Mode = ebpfFeatures[id]
		if f.Mode == "" {
			f.Mode = "auto"
		}
		f.Enforce = false
		f.Status = featureRuntimeStatus(id, f.Mode)
		out = append(out, f)
	}
	return out
}

func featureRuntimeStatus(id, mode string) string {
	if mode == "off" {
		return "disabled"
	}
	if id == "netra-mirror" {
		st := NetraPollerStatus()
		if cfg, _ := st["configured"].(bool); cfg {
			return "active"
		}
		return "idle"
	}
	obj := bpfObjectPath(id)
	if obj != "" {
		return "object-present"
	}
	if pinPresent(bpfPinFor(id)) {
		return "pinned"
	}
	backend := ProbeSensor()
	if backend == SensorEBPF && (id == "exec" || id == "fork" || id == "exit") {
		return "active-fallback"
	}
	return "userspace-fallback"
}

func bpfObjectPath(id string) string {
	name := map[string]string{
		"exec": "kavach_exec.o", "fork": "kavach_process.o", "exit": "kavach_process.o",
		"file": "kavach_file.o", "priv": "kavach_priv.o", "memfd": "kavach_priv.o",
		"ptrace": "kavach_priv.o", "module": "kavach_priv.o", "bpf": "kavach_priv.o",
		"net": "kavach_net.o",
	}[id]
	if name == "" {
		return ""
	}
	for _, dir := range []string{os.Getenv("KAVACH_BPF_OBJ"), "bpf", "/usr/lib/kavach/bpf"} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func bpfPinFor(id string) string {
	root := firstNonEmpty(os.Getenv("KAVACH_BPF_PIN_ROOT"), "/sys/fs/bpf/kavach")
	switch id {
	case "exec":
		return filepath.Join(root, "events")
	case "fork", "exit":
		return filepath.Join(root, "process_events")
	case "file":
		return filepath.Join(root, "file_events")
	case "priv", "memfd", "ptrace", "module", "bpf":
		return filepath.Join(root, "priv_events")
	case "net":
		return filepath.Join(root, "net_events")
	default:
		return ""
	}
}

func pinPresent(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func EBPFAttachments() []EBPFAttachment {
	specs := []EBPFAttachment{
		{Program: "kavach_sched_process_exec", Type: "tp_btf", Object: "kavach_exec.o", Pin: bpfPinFor("exec")},
		{Program: "kavach_sched_process_fork", Type: "tp_btf", Object: "kavach_process.o", Pin: bpfPinFor("fork")},
		{Program: "kavach_sched_process_exit", Type: "tp_btf", Object: "kavach_process.o", Pin: bpfPinFor("exit")},
		{Program: "kavach_openat", Type: "tracepoint", Object: "kavach_file.o", Pin: bpfPinFor("file")},
		{Program: "kavach_setuid", Type: "tracepoint", Object: "kavach_priv.o", Pin: bpfPinFor("priv")},
		{Program: "kavach_memfd", Type: "tracepoint", Object: "kavach_priv.o", Pin: bpfPinFor("priv")},
		{Program: "kavach_ptrace", Type: "tracepoint", Object: "kavach_priv.o", Pin: bpfPinFor("priv")},
		{Program: "kavach_init_module", Type: "tracepoint", Object: "kavach_priv.o", Pin: bpfPinFor("priv")},
		{Program: "kavach_bpf_syscall", Type: "tracepoint", Object: "kavach_priv.o", Pin: bpfPinFor("priv")},
		{Program: "kavach_connect", Type: "tracepoint", Object: "kavach_net.o", Pin: bpfPinFor("net")},
	}
	for i := range specs {
		obj := specs[i].Object
		src := strings.Replace(obj, ".o", ".bpf.c", 1)
		objOK := fileExists(filepath.Join("bpf", obj)) ||
			fileExists(filepath.Join("bpf", src)) ||
			fileExists(filepath.Join(os.Getenv("KAVACH_BPF_OBJ"), obj)) ||
			bpfObjectPath(strings.TrimSuffix(obj, ".o")) != ""
		// Map object names that share a .o (process/priv) to feature ids.
		switch obj {
		case "kavach_process.o":
			objOK = objOK || bpfObjectPath("fork") != "" || fileExists("bpf/kavach_process.bpf.c")
		case "kavach_priv.o":
			objOK = objOK || bpfObjectPath("priv") != "" || fileExists("bpf/kavach_priv.bpf.c")
		case "kavach_exec.o":
			objOK = objOK || bpfObjectPath("exec") != "" || fileExists("bpf/kavach_exec.bpf.c")
		case "kavach_file.o":
			objOK = objOK || fileExists("bpf/kavach_file.bpf.c")
		case "kavach_net.o":
			objOK = objOK || fileExists("bpf/kavach_net.bpf.c")
		}
		pinOK := pinPresent(specs[i].Pin)
		specs[i].Present = objOK || pinOK
		specs[i].Missing = !pinOK
	}
	return specs
}

func EBPFMaps() []EBPFMapInfo {
	return []EBPFMapInfo{
		{Name: "events", Type: "ringbuf", Pin: bpfPinFor("exec"), Present: pinPresent(bpfPinFor("exec")), Max: 1 << 24, Note: "exec/process events"},
		{Name: "lost_events", Type: "percpu_array", Present: false, Max: 1, Note: "ringbuf drop counter"},
		{Name: "process_events", Type: "ringbuf", Pin: bpfPinFor("fork"), Present: pinPresent(bpfPinFor("fork")), Max: 1 << 24},
		{Name: "file_events", Type: "ringbuf", Pin: bpfPinFor("file"), Present: pinPresent(bpfPinFor("file")), Max: 1 << 24},
		{Name: "priv_events", Type: "ringbuf", Pin: bpfPinFor("priv"), Present: pinPresent(bpfPinFor("priv")), Max: 1 << 22},
		{Name: "net_events", Type: "ringbuf", Pin: bpfPinFor("net"), Present: pinPresent(bpfPinFor("net")), Max: 1 << 24},
	}
}

func EBPFStatus(store *Store, registry *CredentialRegistry) map[string]any {
	backend := string(ProbeSensor())
	atts := EBPFAttachments()
	present, missing := 0, 0
	for _, a := range atts {
		if a.Present {
			present++
		}
		if a.Missing {
			missing++
		}
	}
	host, _ := os.Hostname()
	return map[string]any{
		"product":          "kavach",
		"mode":             "observe-only",
		"enforce":          false,
		"backend":          backend,
		"goos":             runtime.GOOS,
		"goarch":           runtime.GOARCH,
		"btf":              pinPresent("/sys/kernel/btf/vmlinux"),
		"bpffs":            pinPresent("/sys/fs/bpf"),
		"pin_root":         firstNonEmpty(os.Getenv("KAVACH_BPF_PIN_ROOT"), "/sys/fs/bpf/kavach"),
		"attachments_ok":   present,
		"attachments_miss": missing,
		"features":         EBPFFeatureList(),
		"lost_events":      ebpfLostCount(),
		"event_count":      len(listEBPFEvents("")),
		"host":             host,
		"netra":            NetraPollerStatus(),
		"note":             "Kavach eBPF never kills, isolates, or drops packets. Netra owns network datapath enforce.",
	}
}

func EBPFHealth(store *Store, registry *CredentialRegistry) map[string]any {
	st := EBPFStatus(store, registry)
	score := 100
	miss, _ := st["attachments_miss"].(int)
	if miss > 0 {
		score -= miss * 5
	}
	if runtime.GOOS != "linux" {
		score -= 20
	}
	if st["backend"] == string(SensorProcPoll) {
		score -= 15
	}
	lost := ebpfLostCount()
	if lost > 0 {
		score -= min(30, lost)
	}
	if score < 0 {
		score = 0
	}
	level := "healthy"
	if score < 70 {
		level = "degraded"
	}
	if score < 40 {
		level = "critical"
	}
	return map[string]any{
		"score":       score,
		"level":       level,
		"lost_events": lost,
		"backend":     st["backend"],
		"missing":     miss,
		"summary":     level + " · observation-only eBPF platform",
	}
}

func EBPFCoverage(registry *CredentialRegistry) []map[string]any {
	hosts := []string{}
	if registry != nil {
		for _, a := range registry.Status(time.Now(), 90*time.Second) {
			hosts = append(hosts, a.Host)
		}
	}
	if len(hosts) == 0 {
		if h, _ := os.Hostname(); h != "" {
			hosts = append(hosts, h)
		}
	}
	out := []map[string]any{}
	for _, h := range hosts {
		out = append(out, map[string]any{
			"host":       h,
			"exec":       featureRuntimeStatus("exec", featureMode("exec")),
			"file":       featureRuntimeStatus("file", featureMode("file")),
			"net":        featureRuntimeStatus("net", featureMode("net")),
			"priv":       featureRuntimeStatus("priv", featureMode("priv")),
			"backend":    string(ProbeSensor()),
			"observation": true,
			"enforce":    false,
		})
	}
	return out
}

func featureMode(id string) string {
	ebpfMu.Lock()
	defer ebpfMu.Unlock()
	if m, ok := ebpfFeatures[id]; ok {
		return m
	}
	return "auto"
}

func EBPFCensus() map[string]any {
	maps := EBPFMaps()
	present := 0
	for _, m := range maps {
		if m.Present {
			present++
		}
	}
	return map[string]any{
		"maps":         len(maps),
		"maps_present": present,
		"events":       len(listEBPFEvents("")),
		"lost":         ebpfLostCount(),
		"objects":      []string{"kavach_exec.o", "kavach_process.o", "kavach_file.o", "kavach_priv.o", "kavach_net.o"},
	}
}

func EBPFSummary(store *Store) map[string]any {
	byType := map[string]int{}
	for _, e := range listEBPFEvents("") {
		byType[e.Type]++
	}
	findings := 0
	if store != nil {
		findings = len(store.List())
	}
	return map[string]any{
		"events_by_type": byType,
		"findings":       findings,
		"health":         EBPFHealth(store, nil),
		"mode":           "observe-only",
	}
}

func EBPFDrops() map[string]any {
	return map[string]any{
		"kind":        "ringbuf_lost",
		"lost_events": ebpfLostCount(),
		"note":        "Userspace/ringbuf sample loss — not packet drops. Packet drops belong to Netra observe APIs.",
		"netra":       NetraPollerStatus(),
	}
}

func EBPFProcesses() []map[string]any {
	// Derived from recent eBPF/exec events (observation snapshot).
	seen := map[int]map[string]any{}
	for _, e := range listEBPFEvents("") {
		if e.PID <= 0 {
			continue
		}
		seen[e.PID] = map[string]any{
			"pid": e.PID, "ppid": e.PPID, "uid": e.UID, "comm": e.Comm,
			"path": e.Path, "host": e.Host, "last_type": e.Type, "source": e.Source,
		}
	}
	out := make([]map[string]any, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	if len(out) == 0 {
		out = append(out, map[string]any{
			"pid": 1, "comm": "init", "host": hostnameOr("controller"),
			"note": "No live eBPF process tree yet — userspace fallback active", "source": "derived",
		})
	}
	return out
}

func hostnameOr(fallback string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return fallback
}

func ebpfLostCount() int {
	ebpfMu.Lock()
	defer ebpfMu.Unlock()
	return ebpfLost
}

func RecordEBPFLost(n int) {
	ebpfMu.Lock()
	ebpfLost += n
	ebpfMu.Unlock()
}

func IngestEBPFEvents(events []EBPFEvent) int {
	ebpfMu.Lock()
	defer ebpfMu.Unlock()
	n := 0
	for _, e := range events {
		if e.Type == "" {
			continue
		}
		if e.ID == "" {
			e.ID = "ebpf-" + time.Now().UTC().Format("20060102T150405.000000000")
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}
		if e.Source == "" {
			e.Source = "ebpf"
		}
		if e.Host == "" {
			e.Host = hostnameOr("unknown")
		}
		ebpfEvents = append(ebpfEvents, e)
		n++
	}
	if len(ebpfEvents) > 5000 {
		ebpfEvents = ebpfEvents[len(ebpfEvents)-5000:]
	}
	return n
}

func listEBPFEvents(typ string) []EBPFEvent {
	ebpfMu.Lock()
	defer ebpfMu.Unlock()
	out := make([]EBPFEvent, 0, len(ebpfEvents))
	for _, e := range ebpfEvents {
		if typ != "" && !strings.EqualFold(e.Type, typ) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func seedEBPFDemoEvents() {
	host := hostnameOr("controller")
	now := time.Now().UTC()
	_ = IngestEBPFEvents([]EBPFEvent{
		{ID: "ebpf-seed-exec", Type: "exec", Host: host, PID: 4242, PPID: 1, UID: 0, Comm: "kavach-agent", Path: "/usr/local/bin/kavach", Source: "derived", Timestamp: now.Add(-2 * time.Minute)},
		{ID: "ebpf-seed-fork", Type: "fork", Host: host, PID: 4243, PPID: 4242, UID: 0, Comm: "kavach-agent", Source: "derived", Timestamp: now.Add(-90 * time.Second)},
		{ID: "ebpf-seed-file", Type: "file", Host: host, PID: 4242, UID: 0, Comm: "kavach-agent", Path: "/etc/passwd", Detail: "openat observe", Source: "derived", Timestamp: now.Add(-60 * time.Second)},
		{ID: "ebpf-seed-net", Type: "net", Host: host, PID: 4242, Comm: "kavach-agent", Protocol: "tcp", DAddr: "1.1.1.1", DPort: 443, Source: "derived", Timestamp: now.Add(-45 * time.Second)},
		{ID: "ebpf-seed-priv", Type: "priv", Host: host, PID: 9001, UID: 1000, Comm: "sudo", Detail: "setuid observe", Source: "derived", Timestamp: now.Add(-30 * time.Second)},
		{ID: "ebpf-seed-memfd", Type: "memfd", Host: host, PID: 9002, UID: 0, Comm: "loader", Detail: "memfd_create", Source: "derived", Timestamp: now.Add(-20 * time.Second)},
	})
}

func netraEBPFProxy(path string) map[string]any {
	st := NetraPollerStatus()
	return map[string]any{
		"source":     "netra-mirror",
		"path":       path,
		"configured": st["configured"],
		"url":        st["url"],
		"last_ok":    st["last_ok"],
		"last_error": st["last_error"],
		"note":       "Kavach mirrors Netra observation APIs as XDR inputs; it never writes Netra BPF maps or enables enforce.",
		"suggested":  []string{"/api/v1/ebpf/health", "/api/v1/ebpf/attachments", "/api/v1/ebpf/drops", "/api/v1/flows/summary"},
	}
}

// RegisterEBPFPlatform wires /v1/ebpf/* observation APIs.
func RegisterEBPFPlatform(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/ebpf/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFStatus(store, registry))
	})
	mux.HandleFunc("GET /v1/ebpf/health", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFHealth(store, registry))
	})
	mux.HandleFunc("GET /v1/ebpf/coverage", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFCoverage(registry))
	})
	mux.HandleFunc("GET /v1/ebpf/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, map[string]any{"capabilities": EBPFCapabilities(), "enforce": false})
	})
	mux.HandleFunc("GET /v1/ebpf/attachments", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFAttachments())
	})
	mux.HandleFunc("GET /v1/ebpf/maps", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFMaps())
	})
	mux.HandleFunc("GET /v1/ebpf/census", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFCensus())
	})
	mux.HandleFunc("GET /v1/ebpf/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFSummary(store))
	})
	mux.HandleFunc("GET /v1/ebpf/drops", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFDrops())
	})
	mux.HandleFunc("GET /v1/ebpf/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, listEBPFEvents(r.URL.Query().Get("type")))
	})
	mux.HandleFunc("POST /v1/ebpf/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var body struct {
			Events []EBPFEvent `json:"events"`
			Lost   int         `json:"lost"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if body.Lost > 0 {
			RecordEBPFLost(body.Lost)
		}
		n := IngestEBPFEvents(body.Events)
		writeJSON(w, map[string]any{"ingested": n, "lost": body.Lost})
	})
	mux.HandleFunc("GET /v1/ebpf/processes", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFProcesses())
	})
	mux.HandleFunc("GET /v1/ebpf/features", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, EBPFFeatureList())
	})
	mux.HandleFunc("POST /v1/ebpf/features/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		mode := strings.ToLower(strings.TrimSpace(body.Mode))
		if mode != "auto" && mode != "on" && mode != "off" {
			http.Error(w, "mode must be auto|on|off", 400)
			return
		}
		ebpfMu.Lock()
		if _, ok := ebpfFeatures[id]; !ok {
			ebpfMu.Unlock()
			http.Error(w, "unknown feature", 404)
			return
		}
		ebpfFeatures[id] = mode
		ebpfMu.Unlock()
		writeJSON(w, map[string]any{"id": id, "mode": mode, "enforce": false, "note": "Observation sensor gate only — never packet/process enforce"})
	})
	mux.HandleFunc("GET /v1/ebpf/netra/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, netraEBPFProxy("/api/v1/ebpf/health"))
	})
	mux.HandleFunc("GET /v1/ebpf/netra/drops", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, netraEBPFProxy("/api/v1/ebpf/drops"))
	})
	mux.HandleFunc("GET /v1/ebpf/netra/flows", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, netraEBPFProxy("/api/v1/flows/summary"))
	})
	mux.HandleFunc("GET /v1/ebpf/netra/attachments", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, netraEBPFProxy("/api/v1/ebpf/attachments"))
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
