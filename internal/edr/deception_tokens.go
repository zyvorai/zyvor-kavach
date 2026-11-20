package edr

// Canary / honeytoken tripwires. Observation only: a trip raises a Finding and
// is recorded; nothing is blocked, killed or contained.

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	deceptRule         = "deception-canary-tripped"
	deceptCoalesce     = 10 * time.Minute
	deceptMaxCanaries  = 500
	deceptMaxTrips     = 500
	deceptMaxPerCanary = 100
	deceptUALen        = 120
)

func init() {
	// Additive ATT&CK mapping; existing entries are untouched.
	if _, ok := ruleMITRE[deceptRule]; !ok {
		ruleMITRE[deceptRule] = struct{ Tactic, Technique, ID string }{"Credential Access", "Unsecured Credentials", "T1552"}
	}
}

type deceptCanary struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Placement string    `json:"placement,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Created   time.Time `json:"created"`
	// Plantable artifact (all clearly non-functional).
	Value    string    `json:"value,omitempty"`     // credential kind
	Path     string    `json:"path,omitempty"`      // document-beacon
	DNSLabel string    `json:"dns_label,omitempty"` // dns-name
	Trips    int       `json:"trips"`
	LastTrip time.Time `json:"last_trip,omitempty"`
}

type deceptTrip struct {
	ID       string    `json:"id"`
	CanaryID string    `json:"canary_id,omitempty"`
	Time     time.Time `json:"time"`
	Via      string    `json:"via"` // public | agent
	SourceIP string    `json:"source_ip,omitempty"`
	UA       string    `json:"user_agent,omitempty"`
	Host     string    `json:"host,omitempty"`
	Path     string    `json:"path,omitempty"`
	Finding  bool      `json:"finding_created"`
}

type deceptBucket struct {
	tokens float64
	last   time.Time
}

type deceptLimiter struct {
	rate, burst float64
	m           map[string]*deceptBucket
}

func (l *deceptLimiter) allow(key string, now time.Time) bool {
	if len(l.m) > 10000 {
		l.m = map[string]*deceptBucket{}
	}
	b := l.m[key]
	if b == nil {
		b = &deceptBucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type deceptStore struct {
	mu       sync.Mutex
	path     string
	store    *Store
	canaries []deceptCanary
	trips    []deceptTrip
	lastFind map[string]time.Time
	perIP    *deceptLimiter
	global   *deceptLimiter
}

type deceptDisk struct {
	Canaries []deceptCanary `json:"canaries"`
	Trips    []deceptTrip   `json:"trips"`
}

func deceptNewID() string {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func deceptValidID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func deceptClean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

func deceptRandString(alphabet string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// save must be called with mu held.
func (s *deceptStore) save() error {
	b, err := json.Marshal(deceptDisk{Canaries: s.canaries, Trips: s.trips})
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func deceptNewStore(store *Store) *deceptStore {
	s := &deceptStore{
		path: store.path + ".deception.json", store: store,
		lastFind: map[string]time.Time{},
		perIP:    &deceptLimiter{rate: 1, burst: 10, m: map[string]*deceptBucket{}},
		global:   &deceptLimiter{rate: 20, burst: 40, m: map[string]*deceptBucket{}},
	}
	if b, err := os.ReadFile(s.path); err == nil {
		var d deceptDisk
		if json.Unmarshal(b, &d) == nil {
			s.canaries, s.trips = d.Canaries, d.Trips
		}
	}
	for _, c := range s.canaries {
		if !c.LastTrip.IsZero() {
			s.lastFind[c.ID] = c.LastTrip
		}
	}
	return s
}

func (s *deceptStore) find(id string) int {
	for i := range s.canaries {
		if s.canaries[i].ID == id {
			return i
		}
	}
	return -1
}

// record registers a trip for a canary (or unattributed when id==""),
// coalescing Findings to one per canary per 10 minutes.
func (s *deceptStore) record(id string, t deceptTrip, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := -1
	if id != "" {
		if i = s.find(id); i < 0 {
			return
		}
	}
	key := id
	if key == "" {
		key = "host:" + t.Host + t.Path
		if len(key) > 300 {
			key = key[:300]
		}
	}
	t.ID, t.Time, t.CanaryID = deceptNewID()[:16], now.UTC(), id
	name, kind := "unattributed planted item", "unknown"
	if i >= 0 {
		c := &s.canaries[i]
		c.Trips++
		c.LastTrip = t.Time
		name, kind = c.Name, c.Kind
	}
	if last, ok := s.lastFind[key]; !ok || now.Sub(last) >= deceptCoalesce {
		host := t.Host
		if host == "" {
			host = "kavach-server"
		}
		desc := "Canary tripped: " + name + " (" + kind + ")"
		if t.SourceIP != "" {
			desc += " from " + t.SourceIP
		}
		if t.Path != "" {
			desc += " path " + t.Path
		}
		f := Finding{
			ID: "deception-" + deceptNewID()[:12], Time: t.Time, Host: host,
			Rule: deceptRule, Severity: "high", Description: desc,
			Evidence: Event{Time: t.Time, Host: host, Command: "canary trip via " + t.Via},
			Tags:     []string{"deception", "canary"},
		}
		if err := s.store.Append(f); err == nil {
			t.Finding = true
			s.lastFind[key] = now
		}
	}
	// Per-canary cap on stored trip records; the counter keeps counting.
	n := 0
	for _, x := range s.trips {
		if x.CanaryID == id {
			n++
		}
	}
	if n < deceptMaxPerCanary || t.Finding {
		s.trips = append(s.trips, t)
		if len(s.trips) > deceptMaxTrips {
			s.trips = s.trips[len(s.trips)-deceptMaxTrips:]
		}
	}
	_ = s.save()
}

func deceptJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func deceptClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// RegisterDeceptionTokens wires canary management, the public tripwire and trip reporting.
func RegisterDeceptionTokens(mux *http.ServeMux, token string, store *Store) {
	s := deceptNewStore(store)

	mux.HandleFunc("GET /v1/deception/canaries", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		out := append([]deceptCanary{}, s.canaries...)
		s.mu.Unlock()
		deceptJSON(w, 200, map[string]any{"canaries": out})
	})
	mux.HandleFunc("POST /v1/deception/canaries", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
		var in struct{ Kind, Name, Placement, Owner string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		c := deceptCanary{ID: deceptNewID(), Kind: strings.ToLower(strings.TrimSpace(in.Kind)), Created: time.Now().UTC(),
			Name: deceptClean(in.Name, 100), Placement: deceptClean(in.Placement, 300), Owner: deceptClean(in.Owner, 100)}
		if c.Name == "" {
			http.Error(w, "name required", 400)
			return
		}
		switch c.Kind {
		case "credential":
			// Format-alike but clearly marked non-functional.
			c.Value = "# KAVACH CANARY - NON-FUNCTIONAL, DO NOT USE\n" +
				"aws_access_key_id = AKIA" + deceptRandString("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) + "\n" +
				"aws_secret_access_key = " + deceptRandString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 40) + "\n" +
				"password = canary-" + deceptRandString("abcdefghjkmnpqrstuvwxyz23456789", 14) + "-nonfunctional\n"
		case "document-beacon":
			c.Path = "/c/" + c.ID
		case "dns-name":
			c.DNSLabel = "kv" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(c.ID[:20])))[:16]
		default:
			http.Error(w, "kind must be credential, document-beacon or dns-name", 400)
			return
		}
		s.mu.Lock()
		if len(s.canaries) >= deceptMaxCanaries {
			s.mu.Unlock()
			http.Error(w, "canary limit reached", 409)
			return
		}
		s.canaries = append(s.canaries, c)
		err := s.save()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		AppendAudit(token, "deception.canary.create", c.ID)
		deceptJSON(w, 201, c)
	})
	mux.HandleFunc("DELETE /v1/deception/canaries/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.PathValue("id")
		s.mu.Lock()
		i := s.find(id)
		if i < 0 {
			s.mu.Unlock()
			http.Error(w, "not found", 404)
			return
		}
		s.canaries = append(s.canaries[:i], s.canaries[i+1:]...)
		delete(s.lastFind, id)
		_ = s.save()
		s.mu.Unlock()
		AppendAudit(token, "deception.canary.delete", id)
		deceptJSON(w, 200, map[string]any{"deleted": id})
	})

	// Public tripwire: identical response for known and unknown ids; never reflects input.
	trip := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		id := r.PathValue("id")
		ip := deceptClientIP(r)
		now := time.Now()
		if deceptValidID(id) {
			s.mu.Lock()
			ok := s.perIP.allow(ip, now) && s.global.allow("*", now)
			known := ok && s.find(id) >= 0
			s.mu.Unlock()
			if known {
				s.record(id, deceptTrip{Via: "public", SourceIP: ip, UA: deceptClean(r.UserAgent(), deceptUALen)}, now)
			}
		}
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	}
	mux.HandleFunc("GET /c/{id}", trip)
	mux.HandleFunc("POST /c/{id}", trip)

	mux.HandleFunc("POST /v1/deception/trip", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
		var in struct {
			CanaryID string `json:"canary_id"`
			Host     string `json:"host"`
			Path     string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		in.Host, in.Path = deceptClean(in.Host, 200), deceptClean(in.Path, 400)
		if in.Host == "" || in.Path == "" {
			http.Error(w, "host and path required", 400)
			return
		}
		if in.CanaryID != "" {
			s.mu.Lock()
			i := s.find(in.CanaryID)
			s.mu.Unlock()
			if i < 0 {
				http.Error(w, "unknown canary_id", 404)
				return
			}
		}
		s.record(in.CanaryID, deceptTrip{Via: "agent", Host: in.Host, Path: in.Path}, time.Now())
		deceptJSON(w, 202, map[string]any{"recorded": true})
	})

	mux.HandleFunc("GET /v1/deception/trips", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		out := make([]deceptTrip, 0, len(s.trips))
		for i := len(s.trips) - 1; i >= 0; i-- {
			out = append(out, s.trips[i])
		}
		s.mu.Unlock()
		deceptJSON(w, 200, map[string]any{"trips": out})
	})
}
