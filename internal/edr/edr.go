package edr

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID           string    `json:"id,omitempty"`
	ProcessStart string    `json:"process_start,omitempty"`
	Time         time.Time `json:"time"`
	Host         string    `json:"host"`
	PID          int       `json:"pid"`
	PPID         int       `json:"ppid"`
	UID          int       `json:"uid"`
	Executable   string    `json:"executable"`
	ParentExe    string    `json:"parent_exe,omitempty"`
	Command      string    `json:"command"`
}
type Finding struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Host        string    `json:"host"`
	PID         int       `json:"pid"`
	Rule        string    `json:"rule"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    Event     `json:"evidence"`
	Tags        []string  `json:"tags,omitempty"`
	Destination string    `json:"destination,omitempty"`
}
type Process struct {
	PID, PPID, UID        int
	Exe, Cmd, Start, PExe string
}
type Scanner struct {
	Root string
	Host string
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewScanner(root, host string) *Scanner {
	return &Scanner{Root: root, Host: host, seen: map[string]struct{}{}}
}

// Scan reports newly observed processes. Polling is a fallback, not kernel-level EDR.
func (s *Scanner) Scan(now time.Time) []Event {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil
	}
	current := map[string]struct{}{}
	events := []Event{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid < 1 {
			continue
		}
		p, err := readProcess(s.Root, pid)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d:%s", pid, p.Start)
		current[key] = struct{}{}
		if _, ok := s.seen[key]; ok {
			continue
		}
		events = append(events, Event{Time: now.UTC(), Host: s.Host, PID: pid, PPID: p.PPID, UID: p.UID, Executable: p.Exe, ParentExe: p.PExe, Command: p.Cmd, ProcessStart: p.Start})
	}
	s.seen = current
	return events
}

// ScanPID enriches a kernel process-exec notification using /proc.
// Unlike polling, it can discover short-lived processes while they still exist.
func (s *Scanner) ScanPID(pid int, now time.Time) (Event, bool) {
	p, err := readProcess(s.Root, pid)
	if err != nil {
		return Event{}, false
	}
	key := fmt.Sprintf("%d:%s", pid, p.Start)
	s.mu.Lock()
	_, already := s.seen[key]
	if !already {
		s.seen[key] = struct{}{}
	}
	s.mu.Unlock()
	if already {
		return Event{}, false
	}
	return Event{Time: now.UTC(), Host: s.Host, PID: pid, PPID: p.PPID, UID: p.UID, Executable: p.Exe, ParentExe: p.PExe, Command: p.Cmd, ProcessStart: p.Start}, true
}
func readProcess(root string, pid int) (Process, error) {
	dir := filepath.Join(root, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Process{}, err
	}
	// comm can include spaces and parentheses; locate the final closing parenthesis.
	right := strings.LastIndexByte(string(stat), ')')
	if right < 0 || right+2 >= len(stat) {
		return Process{}, errors.New("bad proc stat")
	}
	fields := strings.Fields(string(stat[right+2:]))
	if len(fields) < 20 {
		return Process{}, errors.New("short proc stat")
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return Process{}, err
	}
	exe, _ := os.Readlink(filepath.Join(dir, "exe"))
	raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return Process{}, err
	}
	cmd := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
	if len(cmd) > 2048 {
		cmd = cmd[:2048]
	}
	uid := -1
	f, err := os.Open(filepath.Join(dir, "status"))
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "Uid:") {
				parts := strings.Fields(sc.Text())
				if len(parts) > 1 {
					uid, _ = strconv.Atoi(parts[1])
				}
				break
			}
		}
		f.Close()
	}
	parentExe := ""
	if ppid > 0 {
		parentExe, _ = os.Readlink(filepath.Join(root, strconv.Itoa(ppid), "exe"))
	}
	return Process{PID: pid, PPID: ppid, UID: uid, Exe: exe, Cmd: cmd, Start: fields[19], PExe: parentExe}, nil
}
func Detect(e Event) []Finding {
	cmd := strings.ToLower(e.Command)
	base := strings.ToLower(filepath.Base(e.Executable))
	result := []Finding{}
	add := func(rule, severity, description string, tags ...string) {
		result = append(result, Finding{
			ID: fmt.Sprintf("%s:%d:%s:%d", e.Host, e.PID, rule, e.Time.UnixNano()),
			Time: e.Time, Host: e.Host, PID: e.PID, Rule: rule, Severity: severity,
			Description: description, Evidence: e, Tags: tags,
		})
	}
	if (base == "bash" || base == "sh" || base == "zsh") && (strings.Contains(cmd, "/dev/tcp/") || strings.Contains(cmd, " -i >&")) {
		add("shell-network-redirection", "high", "Shell command contains a potential reverse-shell network redirection")
	}
	if (base == "curl" || base == "wget") && (strings.Contains(cmd, "| sh") || strings.Contains(cmd, "| bash") || strings.Contains(cmd, "-o- |")) {
		add("download-execute", "high", "Command resembles download-and-execute")
	}
	if strings.Contains(cmd, "chmod 777 /etc/") || strings.Contains(cmd, "chmod -r 777 /etc/") {
		add("unsafe-permissions", "medium", "Command may make sensitive system configuration writable")
	}
	// Expanded LOLBin / persistence heuristics (observation-only).
	lolbins := map[string]string{
		"python": "script-interpreter", "python3": "script-interpreter", "perl": "script-interpreter",
		"ruby": "script-interpreter", "node": "script-interpreter", "php": "script-interpreter",
		"nc": "netcat", "ncat": "netcat", "socat": "netcat",
		"crontab": "persistence", "systemctl": "persistence", "at": "persistence",
		"ssh": "remote-access", "scp": "remote-access", "sftp": "remote-access",
	}
	if tag, ok := lolbins[base]; ok {
		if tag == "netcat" && (strings.Contains(cmd, "-e") || strings.Contains(cmd, "-c ") || strings.Contains(cmd, "/bin/sh")) {
			add("lolbin-netcat-shell", "high", "Netcat-style binary invoked with shell-execution flags")
		}
		if tag == "persistence" && (strings.Contains(cmd, "enable") || strings.Contains(cmd, "crontab") || strings.Contains(cmd, "/etc/cron")) {
			add("persistence-attempt", "medium", "Command resembles persistence via cron/systemd")
		}
		if tag == "script-interpreter" && (strings.Contains(cmd, "-c ") || strings.Contains(cmd, "base64") || strings.Contains(cmd, "/dev/tcp/")) {
			add("script-inline-execution", "medium", "Interpreter invoked with inline or network-backed payload patterns")
		}
	}
	if strings.Contains(cmd, "curl ") && strings.Contains(cmd, "chmod +x") {
		add("download-chmod-execute", "high", "Download followed by chmod +x pattern")
	}
	if e.UID == 0 && (base == "bash" || base == "sh") && strings.Contains(cmd, "history -c") {
		add("root-history-clear", "medium", "Root shell clearing history")
	}

	haystack := strings.Join([]string{e.Command, e.Executable, e.ParentExe, e.Host}, " ")
	for _, ioc := range MatchIOCs(haystack) {
		sev := ioc.Severity
		if sev == "" {
			sev = "medium"
		}
		add("ioc-"+ioc.Type, sev, "IOC match ("+ioc.Type+"): "+ioc.Value+" — "+ioc.Description, "ioc", ioc.Source)
	}
	for _, ioa := range MatchIOAs(haystack) {
		sev := ioa.Severity
		if sev == "" {
			sev = "high"
		}
		desc := "IOA " + ioa.Name
		if ioa.TechniqueID != "" {
			desc += " [" + ioa.TechniqueID + "]"
		}
		if ioa.Description != "" {
			desc += " — " + ioa.Description
		}
		add("ioa-"+ioa.ID, sev, desc, "ioa", ioa.TechniqueID)
	}
	for _, rule := range MatchCustomRules(haystack) {
		name, _ := rule["name"].(string)
		if name == "" {
			name = "custom-rule"
		}
		sev, _ := rule["severity"].(string)
		if sev == "" {
			sev = "medium"
		}
		q, _ := rule["query"].(string)
		add("custom-"+name, sev, "Custom detection rule matched: "+name+" ("+q+")", "custom-rule")
	}
	result = append(result, contentProcessFindings(e)...) // data-driven content packs; no-op when none loaded
	return FilterExcluded(result)
}

type Store struct {
	seen          map[string]struct{}
	eventPath     string
	recentEvents  []Event
	networkEvents []NetworkEvent
	fileEvents    []FileEvent
	mu            sync.Mutex
	path          string
	findings      []Finding
	max           int
}

func NewStore(path string, max int) (*Store, error) {
	if max < 1 {
		max = 1000
	}
	s := &Store{path: path, max: max, seen: map[string]struct{}{}, eventPath: path + ".events"}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := s.loadEvents(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		var x Finding
		if json.Unmarshal(sc.Bytes(), &x) == nil {
			s.findings = append(s.findings, x)
		}
	}
	if len(s.findings) > max {
		s.findings = s.findings[len(s.findings)-max:]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := s.loadEvents(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) Append(x Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	s.findings = append(s.findings, x)
	if len(s.findings) > s.max {
		s.findings = s.findings[len(s.findings)-s.max:]
	}
	return nil
}
func (s *Store) List() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

func (s *Store) ListFiles() []FileEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FileEvent, len(s.fileEvents))
	copy(out, s.fileEvents)
	return out
}
func API(token string, store *Store) http.Handler { return APIWithCredentials(token, store, nil) }

func APIWithCredentials(token string, store *Store, registry *CredentialRegistry) http.Handler {
	mux := http.NewServeMux()
	registerDashboard(mux, token, store)
	RegisterFileRoutes(mux, token, store, registry)
	RegisterTelemetryRoutes(mux, token, store, registry)
	incidents, incidentErr := NewIncidentStore(store)
	if incidentErr != nil {
		panic(incidentErr)
	}
	incidents.Register(mux, token)
	siem := NewSIEMExporterFromEnv()
	DefaultSIEM = siem
	siem.RegisterRoutes(mux, token, store)
	RegisterAIRoutes(mux, token, store)
	RegisterInventoryIngest(mux, token)
	BootstrapLivePlatform(store, registry, store.path)
	RegisterFalconPlatform(mux, token, store, registry)
	mux.HandleFunc("GET /v1/sensor", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"backend": string(ProbeSensor()),
			"product": "kavach",
			"netra":   NetraPollerStatus(),
			"siem":    siem.Status(),
		})
	})
	fleetHandler := func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !validSession(r, token) && subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var out []AgentStatus
		if registry != nil {
			out = registry.Status(time.Now(), 90*time.Second)
		}
		seen := map[string]struct{}{}
		for _, a := range out {
			seen[a.Host] = struct{}{}
		}
		// Observed hosts from findings/events even before enrollment.
		for _, f := range store.List() {
			if _, ok := seen[f.Host]; ok || f.Host == "" {
				continue
			}
			seen[f.Host] = struct{}{}
			out = append(out, AgentStatus{Host: f.Host, State: "observed", Sensor: "derived", Queued: 0})
		}
		store.mu.Lock()
		for _, e := range store.recentEvents {
			if _, ok := seen[e.Host]; ok || e.Host == "" {
				continue
			}
			seen[e.Host] = struct{}{}
			out = append(out, AgentStatus{Host: e.Host, State: "observed", Sensor: string(ProbeSensor()), Queued: 0})
		}
		store.mu.Unlock()
		if len(out) == 0 {
			if h, _ := os.Hostname(); h != "" {
				out = append(out, AgentStatus{Host: h, State: "controller", Sensor: string(ProbeSensor()), LastSeen: time.Now().UTC()})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
	mux.HandleFunc("GET /v1/fleet", fleetHandler)
	if registry != nil {
		registry.RegisterRoutes(mux, token)
	}
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) == 0 || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /v1/findings", func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r, token) && !authorized(w, r) {
			return
		}
		sev := strings.ToLower(r.URL.Query().Get("severity"))
		rule := strings.ToLower(r.URL.Query().Get("rule"))
		host := strings.ToLower(r.URL.Query().Get("host"))
		out := store.List()
		if sev != "" || rule != "" || host != "" {
			filtered := out[:0]
			for _, f := range out {
				if sev != "" && strings.ToLower(f.Severity) != sev {
					continue
				}
				if rule != "" && !strings.Contains(strings.ToLower(f.Rule), rule) {
					continue
				}
				if host != "" && !strings.Contains(strings.ToLower(f.Host), host) {
					continue
				}
				filtered = append(filtered, f)
			}
			out = filtered
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if registry == nil && !authorized(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		defer r.Body.Close()
		var e Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if registry != nil {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			admin := subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
			if !admin && !registry.Verify(e.Host, got) {
				http.Error(w, "unauthorized for host", 401)
				return
			}
		}
		if e.PID <= 0 || e.Host == "" || e.Time.IsZero() {
			http.Error(w, "missing event fields", 400)
			return
		}
		findings, err := store.Ingest(e)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"findings": len(findings)})
	})
	mux.HandleFunc("POST /v1/network-events", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		defer r.Body.Close()
		var n NetworkEvent
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil || n.Host == "" || n.Time.IsZero() || n.PID <= 0 {
			http.Error(w, "invalid network event", 400)
			return
		}
		findings, err := store.IngestNetwork(n)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"correlations": len(findings)})
	})
	metrics := NewMetrics()
	RegisterHealth(mux, store)
	RegisterATTACK(mux, token, store)
	RegisterComplianceScore(mux, token, store, registry)
	RegisterStream(mux, token, store)
	RegisterRiskTrends(mux, token, store)
	RegisterFleetHealth(mux, token, store, registry)
	RegisterPrevalenceGraph(mux, token, store)
	RegisterIntelFeeds(mux, token, store)
	alertDispatcher := RegisterAlerts(mux, token, store)
	RegisterComplianceEvidence(mux, token, store, registry, incidents, alertDispatcher)
	RegisterExport(mux, token, store, registry)
	analystWS := RegisterAnalystWorkspace(mux, token, store)
	alertDispatcher.ws = analystWS
	RegisterCaseManagement(mux, token, store, analystWS)
	RegisterDetectionLab(mux, token, store)
	RegisterCustomContent(mux, token, store)
	RegisterSOCOps(mux, token, store)
	RegisterTuningDigest(mux, token, store, alertDispatcher)
	RegisterPosturePlus(mux, token, store)
	SetVulnCachePath(store.path + ".vulncache.json")
	RegisterVulnMgmt(mux, token)
	RegisterDeceptionTokens(mux, token, store)
	RegisterDataGovernance(mux, token, store, registry)
	RegisterHuntPacks(mux, token, store)
	RegisterQueryLibrary(mux, token, analystWS)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		metrics.Write(w, store, registry)
	})
	return Harden(metrics.Middleware(mux))
}
func Poll(ctx context.Context, scanner *Scanner, endpoint, token string, interval time.Duration, client *http.Client) error {
	if interval < time.Second {
		return errors.New("interval must be >= 1s")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	send := func() error {
		for _, e := range scanner.Scan(time.Now()) {
			b, _ := json.Marshal(e)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/events", strings.NewReader(string(b)))
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("ingest returned %d", resp.StatusCode)
			}
		}
		return nil
	}
	if err := send(); err != nil {
		return err
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if err := send(); err != nil {
				return err
			}
		}
	}
}
