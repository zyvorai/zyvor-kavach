// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Threat-intel feed ingestion. Feeds are polled and their indicators are
// added to the IOC store used by MatchIOCs. Observation only: indicators are
// always detect_only.

const (
	maxIntelFeeds     = 50
	maxFeedBody       = 1 << 20
	minFeedIntervalM  = 15
	defaultFeedTTLDay = 30
	maxIndicators     = 20000
)

// IntelFeed is a configured threat-intel source.
type IntelFeed struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	Format   string    `json:"format"` // csv | plain | stix-lite-json
	Interval int       `json:"interval"`
	TLP      string    `json:"tlp,omitempty"`
	TTLDays  int       `json:"ttl_days,omitempty"`
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created"`
}

// FeedStatus is the last fetch outcome for one feed.
type FeedStatus struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	LastFetch time.Time `json:"last_fetch,omitempty"`
	Status    string    `json:"status"` // never | ok | not_modified | error
	HTTP      int       `json:"http_status,omitempty"`
	Added     int       `json:"added"`
	Expired   int       `json:"expired"`
	Active    int       `json:"active"`
	Error     string    `json:"error,omitempty"`
}

type feedState struct {
	status  FeedStatus
	etag    string
	expires map[string]time.Time // ioc id -> expiry
}

// IntelFeeds manages feeds and their indicators.
type IntelFeeds struct {
	path string

	mu    sync.Mutex
	feeds []IntelFeed
	state map[string]*feedState

	fetchMu sync.Mutex
	client  *http.Client
	now     func() time.Time
	Tick    time.Duration

	startOnce sync.Once
}

func NewIntelFeeds(store *Store) *IntelFeeds {
	f := &IntelFeeds{
		path:  store.path + ".intel.json",
		state: map[string]*feedState{},
		now:   func() time.Time { return time.Now().UTC() },
		Tick:  30 * time.Second,
		client: &http.Client{
			Timeout:       15 * time.Second,
			Transport:     &http.Transport{DialContext: guardedDial},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if b, err := os.ReadFile(f.path); err == nil {
		_ = json.Unmarshal(b, &f.feeds)
	}
	for _, fd := range f.feeds {
		f.stateLocked(fd)
	}
	return f
}

func (f *IntelFeeds) stateLocked(fd IntelFeed) *feedState {
	s := f.state[fd.ID]
	if s == nil {
		s = &feedState{status: FeedStatus{ID: fd.ID, Name: fd.Name, Status: "never"}, expires: map[string]time.Time{}}
		f.state[fd.ID] = s
	}
	return s
}

func (f *IntelFeeds) saveLocked() error {
	b, err := json.MarshalIndent(f.feeds, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// Start polls due feeds until ctx is done (idempotent).
func (f *IntelFeeds) Start(ctx context.Context) {
	f.startOnce.Do(func() {
		go func() {
			f.poll(ctx)
			t := time.NewTicker(f.Tick)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					f.poll(ctx)
				}
			}
		}()
	})
}

func (f *IntelFeeds) poll(ctx context.Context) {
	f.mu.Lock()
	feeds := append([]IntelFeed(nil), f.feeds...)
	f.mu.Unlock()
	for _, fd := range feeds {
		if ctx.Err() != nil {
			return
		}
		if !fd.Enabled {
			continue
		}
		f.mu.Lock()
		last := f.stateLocked(fd).status.LastFetch
		f.mu.Unlock()
		if last.IsZero() || f.now().Sub(last) >= time.Duration(fd.Interval)*time.Minute {
			f.Fetch(ctx, fd.ID)
		} else {
			f.sweep(fd.ID)
		}
	}
}

func feedIOCPrefix(id string) string { return "feed-" + id + "-" }

// sweep removes expired indicators of a feed.
func (f *IntelFeeds) sweep(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.state[id]
	if s == nil {
		return 0
	}
	n := f.sweepLocked(s)
	s.status.Expired += n
	s.status.Active = len(s.expires)
	return n
}

func (f *IntelFeeds) sweepLocked(s *feedState) int {
	now := f.now()
	dead := map[string]bool{}
	for id, exp := range s.expires {
		if !now.Before(exp) {
			dead[id] = true
			delete(s.expires, id)
		}
	}
	if len(dead) > 0 {
		iocMu.Lock()
		kept := iocs[:0]
		for _, i := range iocs {
			if !dead[i.ID] {
				kept = append(kept, i)
			}
		}
		iocs = kept
		iocMu.Unlock()
	}
	return len(dead)
}

// Fetch performs one fetch of the feed and updates the IOC store.
func (f *IntelFeeds) Fetch(ctx context.Context, id string) (FeedStatus, bool) {
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()
	f.mu.Lock()
	var fd IntelFeed
	found := false
	for _, x := range f.feeds {
		if x.ID == id {
			fd, found = x, true
		}
	}
	if !found {
		f.mu.Unlock()
		return FeedStatus{}, false
	}
	etag := f.stateLocked(fd).etag
	f.mu.Unlock()

	inds, newETag, code, notMod, err := f.download(ctx, fd, etag)

	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.state[id]
	if s == nil {
		return FeedStatus{}, false
	}
	now := f.now()
	s.status.LastFetch, s.status.HTTP = now, code
	s.status.Added, s.status.Error = 0, ""
	exp := now.Add(time.Duration(feedTTL(fd)) * 24 * time.Hour)
	switch {
	case err != nil:
		s.status.Status, s.status.Error = "error", err.Error()
	case notMod:
		s.status.Status = "not_modified"
		for k := range s.expires {
			s.expires[k] = exp
		}
	default:
		s.status.Status = "ok"
		s.etag = newETag
		s.status.Added = f.addIndicatorsLocked(fd, s, inds, exp)
	}
	s.status.Expired = f.sweepLocked(s)
	s.status.Active = len(s.expires)
	return s.status, true
}

func feedTTL(fd IntelFeed) int {
	if fd.TTLDays > 0 {
		return fd.TTLDays
	}
	return defaultFeedTTLDay
}

type indicator struct{ typ, value string }

func (f *IntelFeeds) addIndicatorsLocked(fd IntelFeed, s *feedState, inds []indicator, exp time.Time) int {
	prefix := feedIOCPrefix(fd.ID)
	now := f.now()
	iocMu.Lock()
	defer iocMu.Unlock()
	have := map[string]bool{}
	for _, i := range iocs {
		have[i.Type+"|"+strings.ToLower(i.Value)] = true
	}
	added := 0
	for _, in := range inds {
		h := sha256.Sum256([]byte(in.typ + "|" + in.value))
		id := prefix + hex.EncodeToString(h[:6])
		if _, mine := s.expires[id]; mine {
			s.expires[id] = exp // refresh
			continue
		}
		if have[in.typ+"|"+strings.ToLower(in.value)] {
			continue // analyst-created (or other feed) indicator wins
		}
		iocs = append(iocs, IOC{
			ID: id, Type: in.typ, Value: in.value, Action: "detect_only", Severity: "medium",
			Description: "Threat intel feed " + fd.Name + tlpSuffix(fd.TLP),
			Source:      "feed:" + fd.Name, CreatedAt: now, Enabled: true,
		})
		s.expires[id] = exp
		added++
	}
	return added
}

func tlpSuffix(t string) string {
	if t == "" {
		return ""
	}
	return " (TLP:" + strings.ToUpper(t) + ")"
}

func (f *IntelFeeds) download(ctx context.Context, fd IntelFeed, etag string) (inds []indicator, newETag string, code int, notMod bool, err error) {
	u, err := validateAlertURL(fd.URL)
	if err != nil {
		return nil, "", 0, false, err
	}
	if u.Scheme == "http" {
		ctx = context.WithValue(ctx, loopbackOKKey{}, true)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", 0, false, err
	}
	req.Header.Set("User-Agent", "kavach-intel")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, "", 0, false, err
	}
	defer resp.Body.Close()
	code = resp.StatusCode
	if code == http.StatusNotModified {
		return nil, "", code, true, nil
	}
	if code >= 300 && code < 400 {
		return nil, "", code, false, errors.New("redirects are not followed")
	}
	if code != http.StatusOK {
		return nil, "", code, false, fmt.Errorf("status %d", code)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBody+1))
	if err != nil {
		return nil, "", code, false, err
	}
	if len(body) > maxFeedBody {
		return nil, "", code, false, errors.New("body exceeds 1 MiB limit")
	}
	inds, err = parseFeed(fd.Format, body)
	if err != nil {
		return nil, "", code, false, err
	}
	return inds, resp.Header.Get("ETag"), code, false, nil
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// classify normalises a raw value; hint is an optional declared type.
func classify(raw, hint string) (indicator, bool) {
	v := strings.TrimSpace(strings.Trim(strings.TrimSpace(raw), `"'`))
	if v == "" || len(v) > 2048 {
		return indicator{}, false
	}
	hint = strings.ToLower(hint)
	if strings.Contains(v, "://") && (hint == "" || hint == "url") {
		if u, err := url.Parse(v); err != nil || u.Host == "" {
			return indicator{}, false
		}
		return indicator{"url", v}, true
	}
	lv := strings.ToLower(v)
	if sha256Re.MatchString(lv) && (hint == "" || hint == "sha256") {
		return indicator{"sha256", lv}, true
	}
	if ip := net.ParseIP(v); ip != nil && (hint == "" || hint == "ip" || hint == "ipv4" || hint == "ipv6") {
		if ip.To4() != nil {
			return indicator{"ipv4", ip.String()}, true
		}
		return indicator{"ipv6", ip.String()}, true
	}
	if domainRe.MatchString(lv) && (hint == "" || hint == "domain") {
		return indicator{"domain", lv}, true
	}
	return indicator{}, false
}

func dedupe(in []indicator) []indicator {
	seen := map[string]bool{}
	var out []indicator
	for _, i := range in {
		k := i.typ + "|" + i.value
		if !seen[k] && len(out) < maxIndicators {
			seen[k] = true
			out = append(out, i)
		}
	}
	return out
}

var stixQuoted = regexp.MustCompile(`'((?:[^'\\]|\\.)*)'`)

func parseFeed(format string, body []byte) ([]indicator, error) {
	var out []indicator
	switch format {
	case "plain":
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if i, ok := classify(strings.Fields(line)[0], ""); ok {
				out = append(out, i)
			}
		}
	case "csv":
		r := csv.NewReader(strings.NewReader(string(body)))
		r.Comment, r.FieldsPerRecord, r.LazyQuotes = '#', -1, true
		rows, err := r.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("csv: %v", err)
		}
		for _, row := range rows {
			for _, c := range row {
				if i, ok := classify(c, ""); ok {
					out = append(out, i)
					break
				}
			}
		}
	case "stix-lite-json":
		var items []map[string]any
		if strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
			var bundle struct {
				Objects    []map[string]any `json:"objects"`
				Indicators []map[string]any `json:"indicators"`
			}
			if err := json.Unmarshal(body, &bundle); err != nil {
				return nil, fmt.Errorf("json: %v", err)
			}
			items = append(bundle.Objects, bundle.Indicators...)
		} else if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("json: %v", err)
		}
		for _, it := range items {
			typ, _ := it["type"].(string)
			val, _ := it["value"].(string)
			if val == "" {
				if p, _ := it["pattern"].(string); p != "" {
					if m := stixQuoted.FindStringSubmatch(p); m != nil {
						val = m[1]
						if typ == "indicator" || typ == "" {
							typ = stixPatternType(p)
						}
					}
				}
			}
			if typ == "indicator" {
				typ = ""
			}
			if i, ok := classify(val, typ); ok {
				out = append(out, i)
			}
		}
	default:
		return nil, errors.New("unsupported format")
	}
	return dedupe(out), nil
}

func stixPatternType(p string) string {
	p = strings.ToLower(p)
	switch {
	case strings.Contains(p, "ipv4-addr"), strings.Contains(p, "ipv6-addr"):
		return "ip"
	case strings.Contains(p, "domain-name"):
		return "domain"
	case strings.Contains(p, "sha-256"), strings.Contains(p, "sha256"):
		return "sha256"
	case strings.Contains(p, "url:"):
		return "url"
	}
	return ""
}

func (f *IntelFeeds) statuses() []FeedStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []FeedStatus{}
	for _, fd := range f.feeds {
		s := f.stateLocked(fd)
		s.status.Active = len(s.expires)
		out = append(out, s.status)
	}
	return out
}

// RegisterIntelFeeds wires /v1/intel/feeds and starts the fetcher.
func RegisterIntelFeeds(mux *http.ServeMux, token string, store *Store) *IntelFeeds {
	f := NewIntelFeeds(store)
	f.Start(context.Background())
	registerIntelRoutes(mux, token, f)
	return f
}

func registerIntelRoutes(mux *http.ServeMux, token string, f *IntelFeeds) {
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		f.mu.Lock()
		out := append([]IntelFeed{}, f.feeds...)
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"feeds": out})
	})
	mux.HandleFunc("GET /v1/intel/feeds/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, 200, map[string]any{"status": f.statuses()})
	})
	mux.HandleFunc("POST /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		var raw struct {
			IntelFeed
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		in := raw.IntelFeed
		in.Enabled = raw.Enabled == nil || *raw.Enabled
		in.Name = strings.TrimSpace(in.Name)
		if in.Name == "" || len(in.Name) > 64 || strings.ContainsAny(in.Name, "\r\n\t") {
			http.Error(w, "name required (max 64 chars)", 400)
			return
		}
		in.Format = strings.ToLower(strings.TrimSpace(in.Format))
		switch in.Format {
		case "csv", "plain", "stix-lite-json":
		default:
			http.Error(w, "format must be csv, plain or stix-lite-json", 400)
			return
		}
		if in.Interval == 0 {
			in.Interval = 60
		}
		if in.Interval < minFeedIntervalM || in.Interval > 7*24*60 {
			http.Error(w, "interval must be 15 to 10080 minutes", 400)
			return
		}
		if in.TTLDays < 0 || in.TTLDays > 365 {
			http.Error(w, "ttl_days must be 0 to 365", 400)
			return
		}
		in.TLP = strings.ToLower(strings.TrimSpace(in.TLP))
		switch in.TLP {
		case "", "clear", "white", "green", "amber", "amber+strict", "red":
		default:
			http.Error(w, "invalid tlp", 400)
			return
		}
		if _, err := validateAlertURL(in.URL); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var id [8]byte
		_, _ = rand.Read(id[:])
		in.ID = "fd-" + hex.EncodeToString(id[:])
		in.Created = time.Now().UTC()
		f.mu.Lock()
		if len(f.feeds) >= maxIntelFeeds {
			f.mu.Unlock()
			http.Error(w, "too many feeds", 400)
			return
		}
		for _, x := range f.feeds {
			if strings.EqualFold(x.Name, in.Name) {
				f.mu.Unlock()
				http.Error(w, "feed name already exists", 409)
				return
			}
		}
		f.feeds = append(f.feeds, in)
		f.stateLocked(in)
		err := f.saveLocked()
		f.mu.Unlock()
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		AppendAudit(token, "intel.feed.create", in.Name)
		writeJSON(w, http.StatusCreated, in)
	})
	mux.HandleFunc("DELETE /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.URL.Query().Get("id")
		f.fetchMu.Lock()
		defer f.fetchMu.Unlock()
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, x := range f.feeds {
			if x.ID != id {
				continue
			}
			f.feeds = append(f.feeds[:i:i], f.feeds[i+1:]...)
			delete(f.state, id)
			prefix := feedIOCPrefix(id)
			iocMu.Lock()
			kept := iocs[:0]
			for _, c := range iocs {
				if !strings.HasPrefix(c.ID, prefix) {
					kept = append(kept, c)
				}
			}
			iocs = kept
			iocMu.Unlock()
			if err := f.saveLocked(); err != nil {
				http.Error(w, "storage error", 500)
				return
			}
			AppendAudit(token, "intel.feed.delete", x.Name)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not found", 404)
	})
	mux.HandleFunc("POST /v1/intel/feeds/refresh", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.URL.Query().Get("id")
		f.mu.Lock()
		found, enabled := false, false
		for _, x := range f.feeds {
			if x.ID == id {
				found, enabled = true, x.Enabled
			}
		}
		f.mu.Unlock()
		if !found {
			http.Error(w, "not found", 404)
			return
		}
		if !enabled {
			http.Error(w, "feed disabled", 409)
			return
		}
		st, ok := f.Fetch(r.Context(), id)
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		writeJSON(w, 200, st)
	})
}
