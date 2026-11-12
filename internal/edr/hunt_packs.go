package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// HuntPack is a named, ATT&CK-mapped hunt over existing findings and process events.
// Observation only: hunts read telemetry and never act on hosts.
type HuntPack struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Technique string   `json:"technique"`
	Tactic    string   `json:"tactic"`
	Terms     []string `json:"terms"` // case-insensitive substrings over exe+command+rule+description
}

// HuntResult is the outcome of one pack run.
type HuntResult struct {
	PackID      string    `json:"pack_id"`
	Name        string    `json:"name"`
	Technique   string    `json:"technique"`
	Time        time.Time `json:"time"`
	FindingHits int       `json:"finding_hits"`
	EventHits   int       `json:"event_hits"`
	Total       int       `json:"total"`
	Hosts       []string  `json:"hosts"`
	FindingIDs  []string  `json:"finding_ids,omitempty"`
	ScheduleID  string    `json:"schedule_id,omitempty"`
}

// HuntSchedule runs a pack periodically.
type HuntSchedule struct {
	ID          string    `json:"id"`
	PackID      string    `json:"pack_id"`
	IntervalSec int       `json:"interval_sec"`
	Created     time.Time `json:"created"`
	LastRun     time.Time `json:"last_run"`
}

var baseHuntPacks = []HuntPack{
	{"mimikatz-lsass", "Credential dumping tools", "T1003", "credential-access", []string{"mimikatz", "procdump", "lsass", "sekurlsa"}},
	{"shadow-file", "Shadow/passwd access", "T1003.008", "credential-access", []string{"/etc/shadow", "/etc/passwd"}},
	{"ssh-key-theft", "SSH private key access", "T1552.004", "credential-access", []string{"id_rsa", ".ssh/"}},
	{"curl-pipe-shell", "Download piped to shell", "T1059.004", "execution", []string{"| sh", "| bash", "curl http", "wget http"}},
	{"base64-decode-exec", "Base64 decode execution", "T1027", "defense-evasion", []string{"base64 -d", "base64 --decode", "frombase64string"}},
	{"powershell-encoded", "PowerShell encoded command", "T1059.001", "execution", []string{"powershell -enc", "-encodedcommand", "powershell -e "}},
	{"reverse-shell", "Reverse shell patterns", "T1059", "execution", []string{"/dev/tcp/", "nc -e", "bash -i", "mkfifo"}},
	{"cron-persistence", "Cron persistence", "T1053.003", "persistence", []string{"crontab", "/etc/cron"}},
	{"systemd-persistence", "Systemd unit persistence", "T1543.002", "persistence", []string{"systemctl enable", "/etc/systemd/system"}},
	{"launchd-persistence", "LaunchAgent/Daemon persistence", "T1543.001", "persistence", []string{"launchctl load", "launchagents", "launchdaemons"}},
	{"bashrc-persistence", "Shell profile modification", "T1546.004", "persistence", []string{".bashrc", ".zshrc", ".profile"}},
	{"sudo-abuse", "Sudo/su privilege use", "T1548.003", "privilege-escalation", []string{"sudo ", "su -"}},
	{"setuid-change", "SetUID/SetGID changes", "T1548.001", "privilege-escalation", []string{"chmod u+s", "chmod 4755", "chmod +s"}},
	{"log-clearing", "Log clearing", "T1070.002", "defense-evasion", []string{"rm /var/log", "truncate -s 0", "wevtutil cl", "history -c"}},
	{"timestomp", "Timestomping", "T1070.006", "defense-evasion", []string{"touch -t", "touch -r"}},
	{"disable-security", "Security tooling tampering", "T1562.001", "defense-evasion", []string{"setenforce 0", "systemctl stop auditd", "ufw disable", "spctl --master-disable"}},
	{"discovery-recon", "Account/system discovery", "T1082", "discovery", []string{"whoami", "uname -a", "id -a", "sw_vers"}},
	{"network-scan", "Network scanning", "T1046", "discovery", []string{"nmap", "masscan", "zmap"}},
	{"archive-staging", "Data archive staging", "T1560.001", "collection", []string{"tar czf", "zip -r", "7z a"}},
	{"exfil-tools", "Exfil tooling", "T1048", "exfiltration", []string{"scp ", "rclone", "curl --upload-file"}},
	{"tunnel-proxy", "Tunneling and proxies", "T1090", "command-and-control", []string{"ngrok", "chisel", "socat", "ssh -r", "ssh -d"}},
	{"crypto-miner", "Cryptominer activity", "T1496", "impact", []string{"xmrig", "minerd", "stratum+tcp"}},
	{"ransomware-notes", "Ransomware indicators", "T1486", "impact", []string{"openssl enc", "gpg -c", "readme_decrypt", "vssadmin delete"}},
	{"container-escape", "Container escape tooling", "T1611", "privilege-escalation", []string{"nsenter", "docker.sock", "--privileged", "unshare"}},
	{"usb-mount", "Removable media mounting", "T1091", "initial-access", []string{"/media/", "/volumes/", "udisks", "diskutil mount", "mount /dev/sd"}},
}

func huntText(exe, cmd, rule, desc string) string {
	return strings.ToLower(exe + " " + cmd + " " + rule + " " + desc)
}

func huntMatchTerms(text string, terms []string) bool {
	for _, t := range terms {
		if strings.Contains(text, t) {
			return true
		}
	}
	return false
}

// RunHuntPack evaluates a pack against the store.
func RunHuntPack(store *Store, p HuntPack) HuntResult {
	res := HuntResult{PackID: p.ID, Name: p.Name, Technique: p.Technique, Time: time.Now().UTC(), Hosts: []string{}}
	hosts := map[string]struct{}{}
	for _, f := range store.List() {
		if huntMatchTerms(huntText(f.Evidence.Executable, f.Evidence.Command, f.Rule, f.Description), p.Terms) {
			res.FindingHits++
			res.FindingIDs = append(res.FindingIDs, f.ID)
			hosts[f.Host] = struct{}{}
		}
	}
	store.mu.Lock()
	for _, e := range store.recentEvents {
		if huntMatchTerms(huntText(e.Executable, e.Command, "", ""), p.Terms) {
			res.EventHits++
			hosts[e.Host] = struct{}{}
		}
	}
	store.mu.Unlock()
	for h := range hosts {
		res.Hosts = append(res.Hosts, h)
	}
	sort.Strings(res.Hosts)
	res.Total = res.FindingHits + res.EventHits
	return res
}

func findHuntPack(id string) (HuntPack, bool) {
	for _, p := range huntPacks {
		if p.ID == id {
			return p, true
		}
	}
	return HuntPack{}, false
}

// RemovableSummary is a USB/removable-media and new-device observation summary.
type RemovableSummary struct {
	Time       time.Time      `json:"time"`
	Events     int            `json:"events"`
	Hosts      []string       `json:"hosts"`
	ByHost     map[string]int `json:"by_host"`
	NewDevices []string       `json:"new_devices"`
	Samples    []string       `json:"samples"`
	Note       string         `json:"note"`
}

var removableTerms = []string{"/media/", "/volumes/", "udisks", "diskutil", "mount /dev/", "usbmuxd", "lsusb", "usb", "hdiutil"}

// SummarizeRemovable derives removable-media activity from recent process telemetry.
func SummarizeRemovable(store *Store) RemovableSummary {
	s := RemovableSummary{Time: time.Now().UTC(), ByHost: map[string]int{}, Hosts: []string{}, NewDevices: []string{}, Samples: []string{},
		Note: "observation only; derived from process telemetry"}
	devs := map[string]struct{}{}
	store.mu.Lock()
	for _, e := range store.recentEvents {
		low := strings.ToLower(e.Executable + " " + e.Command)
		if !huntMatchTerms(low, removableTerms) {
			continue
		}
		s.Events++
		s.ByHost[e.Host]++
		if len(s.Samples) < 10 {
			s.Samples = append(s.Samples, e.Host+": "+e.Command)
		}
		for _, tok := range strings.Fields(e.Command) {
			l := strings.ToLower(tok)
			if strings.HasPrefix(l, "/dev/sd") || strings.HasPrefix(l, "/dev/disk") || strings.HasPrefix(l, "/volumes/") || strings.HasPrefix(l, "/media/") {
				devs[e.Host+":"+tok] = struct{}{}
			}
		}
	}
	store.mu.Unlock()
	for h := range s.ByHost {
		s.Hosts = append(s.Hosts, h)
	}
	for d := range devs {
		s.NewDevices = append(s.NewDevices, d)
	}
	sort.Strings(s.Hosts)
	sort.Strings(s.NewDevices)
	return s
}

type huntState struct {
	mu        sync.Mutex
	path      string
	schedules []HuntSchedule
	history   []HuntResult
	seq       int
}

type huntDisk struct {
	Schedules []HuntSchedule `json:"schedules"`
	History   []HuntResult   `json:"history"`
	Seq       int            `json:"seq"`
}

func (h *huntState) load() {
	if h.path == "" {
		return
	}
	b, err := os.ReadFile(h.path)
	if err != nil {
		return
	}
	var d huntDisk
	if json.Unmarshal(b, &d) == nil {
		h.schedules, h.history, h.seq = d.Schedules, d.History, d.Seq
	}
}

func (h *huntState) saveLocked() {
	if h.path == "" {
		return
	}
	b, _ := json.Marshal(huntDisk{h.schedules, h.history, h.seq})
	_ = os.WriteFile(h.path, b, 0600)
}

func (h *huntState) record(r HuntResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.history = append(h.history, r)
	if len(h.history) > 500 {
		h.history = h.history[len(h.history)-500:]
	}
	h.saveLocked()
}

// tick runs all due schedules.
func (h *huntState) tick(store *Store, now time.Time) {
	h.mu.Lock()
	var scheds []HuntSchedule
	for i, s := range h.schedules {
		if now.Sub(s.LastRun) >= time.Duration(s.IntervalSec)*time.Second {
			h.schedules[i].LastRun = now
			scheds = append(scheds, h.schedules[i])
		}
	}
	h.mu.Unlock()
	for _, s := range scheds {
		if p, ok := findHuntPack(s.PackID); ok {
			r := RunHuntPack(store, p)
			r.ScheduleID = s.ID
			h.record(r)
		}
	}
}

// RegisterHuntPacks wires hunt pack, schedule, history and removable-device routes.
func RegisterHuntPacks(mux *http.ServeMux, token string, store *Store) {
	h := &huntState{}
	if store.path != "" {
		h.path = store.path + ".hunts"
	}
	h.load()
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for now := range t.C {
			h.tick(store, now.UTC())
		}
	}()
	out := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	auth := func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if requireAuth(w, r, token) {
				f(w, r)
			}
		}
	}
	mux.HandleFunc("GET /v1/hunts/packs", auth(func(w http.ResponseWriter, r *http.Request) {
		out(w, map[string]any{"count": len(huntPacks), "packs": huntPacks})
	}))
	mux.HandleFunc("POST /v1/hunts/packs/{id}/run", auth(func(w http.ResponseWriter, r *http.Request) {
		p, ok := findHuntPack(r.PathValue("id"))
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		res := RunHuntPack(store, p)
		h.record(res)
		out(w, res)
	}))
	mux.HandleFunc("POST /v1/hunts/run-all", auth(func(w http.ResponseWriter, r *http.Request) {
		results := make([]HuntResult, 0, len(huntPacks))
		hits := 0
		for _, p := range huntPacks {
			res := RunHuntPack(store, p)
			h.record(res)
			if res.Total > 0 {
				hits++
			}
			results = append(results, res)
		}
		out(w, map[string]any{"packs_run": len(results), "packs_with_hits": hits, "results": results})
	}))
	mux.HandleFunc("GET /v1/hunts/schedules", auth(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		out(w, map[string]any{"schedules": append([]HuntSchedule{}, h.schedules...)})
	}))
	mux.HandleFunc("POST /v1/hunts/schedules", auth(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var b struct {
			PackID      string `json:"pack_id"`
			IntervalSec int    `json:"interval_sec"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if _, ok := findHuntPack(b.PackID); !ok {
			http.Error(w, "unknown pack", 400)
			return
		}
		if b.IntervalSec < 10 {
			b.IntervalSec = 10
		}
		h.mu.Lock()
		h.seq++
		s := HuntSchedule{ID: fmt.Sprintf("hs-%d", h.seq), PackID: b.PackID, IntervalSec: b.IntervalSec, Created: time.Now().UTC()}
		h.schedules = append(h.schedules, s)
		h.saveLocked()
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(s)
	}))
	mux.HandleFunc("DELETE /v1/hunts/schedules", auth(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		h.mu.Lock()
		defer h.mu.Unlock()
		for i, s := range h.schedules {
			if s.ID == id {
				h.schedules = append(h.schedules[:i], h.schedules[i+1:]...)
				h.saveLocked()
				out(w, map[string]any{"deleted": id})
				return
			}
		}
		http.Error(w, "not found", 404)
	}))
	mux.HandleFunc("GET /v1/hunts/history", auth(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		out(w, map[string]any{"count": len(h.history), "history": append([]HuntResult{}, h.history...)})
	}))
	mux.HandleFunc("GET /v1/devices/removable", auth(func(w http.ResponseWriter, r *http.Request) {
		out(w, SummarizeRemovable(store))
	}))
}
