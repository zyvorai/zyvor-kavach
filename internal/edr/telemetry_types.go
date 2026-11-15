package edr

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Telemetry types beyond process/network/file. Observation only: events are
// recorded and exposed for rule matching; nothing is blocked or killed.

const (
	telemetryBatchMax  = 500
	telemetryBodyMax   = 1 << 20
	telemetryRingMax   = 5000
	telemetryValueMax  = 256 // registry value_data truncation
	telemetryFieldMax  = 1024
	telemetryAnswerMax = 64
)

// TelemetryTypes lists the supported event types.
var TelemetryTypes = []string{"registry", "dns", "auth", "module"}

// TelemetryEvent is the union wire shape; per-type validation decides which fields apply.
type TelemetryEvent struct {
	Time       time.Time `json:"time"`
	Host       string    `json:"host"`
	PID        int       `json:"pid,omitempty"`
	User       string    `json:"user,omitempty"`
	Key        string    `json:"key,omitempty"`
	ValueName  string    `json:"value_name,omitempty"`
	ValueData  string    `json:"value_data,omitempty"`
	Operation  string    `json:"operation,omitempty"`
	Query      string    `json:"query,omitempty"`
	QType      string    `json:"qtype,omitempty"`
	Answers    []string  `json:"answers,omitempty"`
	Resolver   string    `json:"resolver,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	Method     string    `json:"method,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	ModulePath string    `json:"module_path,omitempty"`
	Hash       string    `json:"hash,omitempty"`
	Signed     bool      `json:"signed,omitempty"`
	Signer     string    `json:"signer,omitempty"`
	Kind       string    `json:"kind,omitempty"`
}

var telemetryEnums = map[string]map[string][]string{
	"registry": {"operation": {"set", "create", "delete", "rename"}},
	"dns":      {},
	"auth": {
		"method":  {"ssh", "sudo", "rdp", "console", "kerberos", "ntlm", "oauth"},
		"outcome": {"success", "failure"},
	},
	"module": {"kind": {"dll", "so", "kext", "driver"}},
}

func inList(v string, l []string) bool {
	for _, x := range l {
		if v == x {
			return true
		}
	}
	return false
}

func badStr(s string, max int) bool {
	return len(s) > max || strings.ContainsRune(s, 0)
}

// Validate checks e for the given type and normalizes it (truncation, UTC time).
func (e *TelemetryEvent) Validate(typ string) error {
	enums, ok := telemetryEnums[typ]
	if !ok {
		return fmt.Errorf("unknown type")
	}
	if e.Host == "" || badStr(e.Host, 255) {
		return fmt.Errorf("invalid host")
	}
	if e.Time.IsZero() {
		return fmt.Errorf("time required")
	}
	if e.PID < 0 {
		return fmt.Errorf("invalid pid")
	}
	for _, s := range []string{e.User, e.Key, e.ValueName, e.Query, e.QType, e.Resolver, e.SourceIP, e.Method, e.Outcome, e.ModulePath, e.Hash, e.Signer, e.Kind, e.Operation} {
		if badStr(s, 4096) {
			return fmt.Errorf("field too long")
		}
	}
	if len(e.Answers) > telemetryAnswerMax {
		return fmt.Errorf("too many answers")
	}
	for _, a := range e.Answers {
		if badStr(a, telemetryFieldMax) {
			return fmt.Errorf("invalid answer")
		}
	}
	if len(e.ValueData) > telemetryValueMax {
		e.ValueData = e.ValueData[:telemetryValueMax]
	}
	if strings.ContainsRune(e.ValueData, 0) {
		return fmt.Errorf("invalid value_data")
	}
	for field, allowed := range enums {
		var v string
		switch field {
		case "operation":
			v = e.Operation
		case "method":
			v = e.Method
		case "outcome":
			v = e.Outcome
		case "kind":
			v = e.Kind
		}
		if !inList(v, allowed) {
			return fmt.Errorf("invalid %s", field)
		}
	}
	switch typ {
	case "registry":
		if e.Key == "" {
			return fmt.Errorf("key required")
		}
	case "dns":
		if e.Query == "" || len(e.Query) > 253 {
			return fmt.Errorf("invalid query")
		}
	case "auth":
		if e.User == "" {
			return fmt.Errorf("user required")
		}
		if e.SourceIP != "" && net.ParseIP(e.SourceIP) == nil {
			return fmt.Errorf("invalid source_ip")
		}
	case "module":
		if e.ModulePath == "" {
			return fmt.Errorf("module_path required")
		}
	}
	e.Time = e.Time.UTC()
	return nil
}

// TelemetryStore keeps bounded per-type ring buffers with optional JSONL persistence.
type TelemetryStore struct {
	mu   sync.Mutex
	max  int
	ring map[string][]TelemetryEvent
	path string
}

var telemetryCounters = map[string]*atomic.Int64{}

func init() {
	for _, t := range TelemetryTypes {
		telemetryCounters[t] = new(atomic.Int64)
	}
}

// TelemetryMetrics renders Prometheus lines for ingested telemetry.
func TelemetryMetrics() string {
	var b strings.Builder
	b.WriteString("# HELP kavach_telemetry_events_total Telemetry events accepted by type.\n# TYPE kavach_telemetry_events_total counter\n")
	for _, t := range TelemetryTypes {
		fmt.Fprintf(&b, "kavach_telemetry_events_total{type=%q} %d\n", t, telemetryCounters[t].Load())
	}
	b.WriteString("# HELP kavach_telemetry_eval_skipped_total Telemetry events accepted but not evaluated against content rules (time budget).\n# TYPE kavach_telemetry_eval_skipped_total counter\n")
	fmt.Fprintf(&b, "kavach_telemetry_eval_skipped_total %d\n", telemetryEvalSkipped.Load())
	return b.String()
}

// DefaultTelemetry is used by RecentTelemetry; set by RegisterTelemetryRoutes.
var (
	defaultTelemetryMu sync.RWMutex
	DefaultTelemetry   *TelemetryStore
)

// NewTelemetryStore creates a store; path "" disables persistence.
func NewTelemetryStore(path string, max int) (*TelemetryStore, error) {
	if max <= 0 || max > telemetryRingMax {
		max = telemetryRingMax
	}
	s := &TelemetryStore{max: max, ring: map[string][]TelemetryEvent{}, path: path}
	if path == "" {
		return s, nil
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		var rec struct {
			Type string `json:"type"`
			TelemetryEvent
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || telemetryCounters[rec.Type] == nil {
			return nil, fmt.Errorf("corrupt telemetry ledger %s at line %d", path, line)
		}
		s.addLocked(rec.Type, rec.TelemetryEvent)
	}
	return s, sc.Err()
}

func (s *TelemetryStore) addLocked(typ string, e TelemetryEvent) {
	r := append(s.ring[typ], e)
	if len(r) > s.max {
		r = append([]TelemetryEvent(nil), r[len(r)-s.max:]...)
	}
	s.ring[typ] = r
}

// Add persists (if configured) then stores validated events.
func (s *TelemetryStore) Add(typ string, evs []TelemetryEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range evs {
		if s.path != "" {
			if err := appendRecord(s.path, struct {
				Type string `json:"type"`
				TelemetryEvent
			}{typ, e}); err != nil {
				return err
			}
		}
		s.addLocked(typ, e)
		telemetryCounters[typ].Add(1)
	}
	return nil
}

// Recent returns up to n newest events (newest first), optionally filtered by host.
func (s *TelemetryStore) Recent(typ, host string, n int) []TelemetryEvent {
	if n <= 0 || n > 1000 {
		n = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ring[typ]
	out := []TelemetryEvent{}
	for i := len(r) - 1; i >= 0 && len(out) < n; i-- {
		if host == "" || r[i].Host == host {
			out = append(out, r[i])
		}
	}
	return out
}

// Summary returns counts per type and per host within each type.
func (s *TelemetryStore) Summary() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[string]int{}
	hosts := map[string]map[string]int{}
	for _, t := range TelemetryTypes {
		counts[t] = len(s.ring[t])
		hosts[t] = map[string]int{}
		for _, e := range s.ring[t] {
			hosts[t][e.Host]++
		}
	}
	return map[string]any{"counts": counts, "hosts": hosts}
}

// TelemetryMatchView flattens an event into field name -> value for uniform rule matching.
// Always includes "type", "host", "time" (RFC3339). Booleans are "true"/"false";
// answers are joined with ",". Empty fields are omitted.
func TelemetryMatchView(typ string, e TelemetryEvent) map[string]string {
	m := map[string]string{"type": typ, "host": e.Host, "time": e.Time.UTC().Format(time.RFC3339)}
	put := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	if e.PID > 0 {
		m["pid"] = strconv.Itoa(e.PID)
	}
	put("user", e.User)
	switch typ {
	case "registry":
		put("key", e.Key)
		put("value_name", e.ValueName)
		put("value_data", e.ValueData)
		put("operation", e.Operation)
	case "dns":
		put("query", e.Query)
		put("qtype", e.QType)
		put("answers", strings.Join(e.Answers, ","))
		put("resolver", e.Resolver)
	case "auth":
		put("source_ip", e.SourceIP)
		put("method", e.Method)
		put("outcome", e.Outcome)
	case "module":
		put("module_path", e.ModulePath)
		put("hash", e.Hash)
		m["signed"] = strconv.FormatBool(e.Signed)
		put("signer", e.Signer)
		put("kind", e.Kind)
	}
	return m
}

func telemetryToMap(typ string, e TelemetryEvent) map[string]any {
	b, _ := json.Marshal(e)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	m["type"] = typ
	if typ == "module" {
		m["signed"] = e.Signed
	}
	return m
}

// RecentTelemetry returns up to n recent events of a type (optionally per host) as maps.
func RecentTelemetry(typ string, host string, n int) []map[string]any {
	defaultTelemetryMu.RLock()
	s := DefaultTelemetry
	defaultTelemetryMu.RUnlock()
	out := []map[string]any{}
	if s == nil || telemetryCounters[typ] == nil {
		return out
	}
	for _, e := range s.Recent(typ, host, n) {
		out = append(out, telemetryToMap(typ, e))
	}
	return out
}

// RegisterTelemetryRoutes mounts POST/GET /v1/events/{registry,dns,auth,module} and /v1/events/summary.
func RegisterTelemetryRoutes(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	path := ""
	if store != nil {
		path = store.eventPath + ".telemetry"
	}
	ts, err := NewTelemetryStore(path, telemetryRingMax)
	if err != nil {
		// Never silent: say what is wrong and what we did about it. The corrupt file is moved
		// aside (not deleted) so it can be inspected, and persistence restarts on a fresh file.
		bad := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		if rerr := os.Rename(path, bad); rerr == nil {
			log.Printf("telemetry: persisted ledger unreadable (%v); moved aside to %s and starting empty with persistence on %s", err, bad, path)
			ts, err = NewTelemetryStore(path, telemetryRingMax)
		} else {
			log.Printf("telemetry: persisted ledger unreadable (%v) and could not be moved aside (%v); starting empty with persistence DISABLED", err, rerr)
		}
		if err != nil || ts == nil {
			ts, _ = NewTelemetryStore("", telemetryRingMax)
		}
	}
	defaultTelemetryMu.Lock()
	DefaultTelemetry = ts
	defaultTelemetryMu.Unlock()
	for _, t := range TelemetryTypes {
		typ := t
		mux.HandleFunc("POST /v1/events/"+typ, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, telemetryBodyMax)
			defer r.Body.Close()
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "invalid telemetry event", 400)
				return
			}
			var evs []TelemetryEvent
			dec := json.NewDecoder(strings.NewReader(string(b)))
			dec.DisallowUnknownFields()
			if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
				err = dec.Decode(&evs)
			} else {
				var one TelemetryEvent
				if err = dec.Decode(&one); err == nil {
					evs = []TelemetryEvent{one}
				}
			}
			if err != nil || len(evs) == 0 || len(evs) > telemetryBatchMax {
				http.Error(w, "invalid telemetry event", 400)
				return
			}
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			admin := secureEqual(got, token)
			for i := range evs {
				if evs[i].Validate(typ) != nil {
					http.Error(w, "invalid telemetry event", 400)
					return
				}
				if !admin && (registry == nil || !registry.Verify(evs[i].Host, got)) {
					http.Error(w, "unauthorized", 401)
					return
				}
			}
			if err := ts.Add(typ, evs); err != nil {
				http.Error(w, "storage error", 500)
				return
			}
			// Detection hook: evaluate content rules of this type against the accepted events,
			// within a time budget. Events are already stored; a findings failure is logged, not
			// surfaced as a rejection of the batch.
			nf, skipped, ferr := store.IngestTelemetry(typ, evs, contentTelemetryBudget)
			if ferr != nil {
				log.Printf("telemetry: %s findings persist: %v", typ, ferr)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(evs), "findings": nf, "not_evaluated": skipped})
		})
		mux.HandleFunc("GET /v1/events/"+typ, func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			n := 100
			if v := r.URL.Query().Get("limit"); v != "" {
				x, err := strconv.Atoi(v)
				if err != nil || x < 1 || x > 1000 {
					http.Error(w, "invalid limit", 400)
					return
				}
				n = x
			}
			host := r.URL.Query().Get("host")
			if len(host) > 255 {
				http.Error(w, "invalid host", 400)
				return
			}
			out := []map[string]any{}
			for _, e := range ts.Recent(typ, host, n) {
				out = append(out, telemetryToMap(typ, e))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"type": typ, "events": out})
		})
	}
	mux.HandleFunc("GET /v1/events/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ts.Summary())
	})
}

// IngestTelemetry evaluates content rules for already-accepted telemetry events and stores the
// resulting findings like process/network/file findings. Evaluation runs outside the store lock
// and within budget; it is a no-op on a nil store or when no rules target the type. It returns the
// number of findings stored and the number of events skipped because the budget ran out.
func (s *Store) IngestTelemetry(typ string, evs []TelemetryEvent, budget time.Duration) (int, int, error) {
	if s == nil {
		return 0, 0, nil
	}
	findings, skipped := contentTelemetryBatch(typ, evs, budget)
	findings = append(findings, authBurstFindings(typ, evs)...)
	if len(findings) == 0 {
		return 0, skipped, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range findings {
		if err := s.appendFindingLocked(f); err != nil {
			return i, skipped, err
		}
	}
	return len(findings), skipped, nil
}
