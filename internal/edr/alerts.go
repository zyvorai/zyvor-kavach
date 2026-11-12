// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Alert rules and notifications. Observation only: matching findings are
// reported to a webhook or Slack; nothing is ever blocked or killed.

const (
	maxAlertRules   = 50
	maxDeliveries   = 100
	deliveryTries   = 4
	signatureHeader = "X-Kavach-Signature"
)

// AlertRule routes findings at or above MinSeverity to a destination.
type AlertRule struct {
	ID           string    `json:"id"`
	MinSeverity  string    `json:"min_severity"`
	RuleContains string    `json:"rule_contains,omitempty"`
	HostContains string    `json:"host_contains,omitempty"`
	Type         string    `json:"type"` // webhook | slack
	URL          string    `json:"url"`
	Created      time.Time `json:"created"`
}

// AlertDelivery records the outcome of one notification attempt series.
type AlertDelivery struct {
	Time      time.Time `json:"time"`
	RuleID    string    `json:"rule_id"`
	FindingID string    `json:"finding_id"`
	Type      string    `json:"type"`
	Host      string    `json:"destination_host"`
	Status    string    `json:"status"` // delivered | failed
	Attempts  int       `json:"attempts"`
	Code      int       `json:"http_status,omitempty"`
	Error     string    `json:"error,omitempty"`
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}

func allowPrivateAlerts() bool { return os.Getenv("KAVACH_ALERT_ALLOW_PRIVATE") == "1" }

func isLoopbackHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func blockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast()
}

// validateAlertURL enforces https (http only for loopback) and rejects private
// destinations unless KAVACH_ALERT_ALLOW_PRIVATE=1.
func validateAlertURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("invalid url")
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return nil, errors.New("http allowed only for localhost")
		}
		return u, nil
	default:
		return nil, errors.New("url must be https")
	}
	if allowPrivateAlerts() {
		return u, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip) {
			return nil, errors.New("private or link-local address not allowed")
		}
	} else if isLoopbackHost(host) {
		return nil, errors.New("private or link-local address not allowed")
	}
	return u, nil
}

type loopbackOKKey struct{}

// guardedDial re-checks resolved addresses at connect time (anti DNS-rebinding).
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	loopOK, _ := ctx.Value(loopbackOKKey{}).(bool)
	var d net.Dialer
	d.Timeout = 5 * time.Second
	lastErr := errors.New("no addresses")
	for _, a := range ips {
		if !allowPrivateAlerts() && blockedIP(a.IP) && !(loopOK && a.IP.IsLoopback()) {
			lastErr = errors.New("destination address not allowed")
			continue
		}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Dispatcher watches the store and notifies matching rules.
type Dispatcher struct {
	store *Store
	path  string

	mu         sync.Mutex
	rules      []AlertRule
	deliveries []AlertDelivery
	sent       map[string]struct{}
	seen       map[string]struct{}

	client   *http.Client
	secret   func() string
	Interval time.Duration
	Backoff  time.Duration

	startOnce sync.Once

	// ws, when set, receives hash-chained journal entries for rule changes.
	ws *Workspace
}

// journalRule records an alert-rule change in the analyst journal.
func (d *Dispatcher) journalRule(actor, action, target string) {
	if d.ws == nil {
		return
	}
	d.ws.mu.Lock()
	defer d.ws.mu.Unlock()
	d.ws.appendJournalLocked(actor, action, target)
	_ = d.ws.saveLocked()
}

func NewDispatcher(store *Store) *Dispatcher {
	d := &Dispatcher{
		store: store, path: store.path + ".alerts.json",
		sent: map[string]struct{}{}, seen: map[string]struct{}{},
		Interval: time.Second, Backoff: time.Second,
		secret: func() string { return os.Getenv("KAVACH_WEBHOOK_SECRET") },
		client: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     &http.Transport{DialContext: guardedDial},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if b, err := os.ReadFile(d.path); err == nil {
		_ = json.Unmarshal(b, &d.rules)
	}
	for _, f := range store.List() {
		d.seen[f.ID] = struct{}{}
	}
	return d
}

func (d *Dispatcher) saveLocked() error {
	b, err := json.MarshalIndent(d.rules, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, d.path)
}

// Start runs the poll loop until ctx is done (idempotent).
func (d *Dispatcher) Start(ctx context.Context) {
	d.startOnce.Do(func() {
		go func() {
			t := time.NewTicker(d.Interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					d.scan(ctx)
				}
			}
		}()
	})
}

func (d *Dispatcher) scan(ctx context.Context) {
	var fresh []Finding
	for _, f := range d.store.List() {
		d.mu.Lock()
		_, dup := d.seen[f.ID]
		d.seen[f.ID] = struct{}{}
		d.mu.Unlock()
		if !dup {
			fresh = append(fresh, f)
		}
	}
	for _, f := range fresh {
		d.mu.Lock()
		rules := append([]AlertRule(nil), d.rules...)
		d.mu.Unlock()
		for _, r := range rules {
			if !ruleMatches(r, f) {
				continue
			}
			key := r.ID + "|" + f.ID
			d.mu.Lock()
			_, dup := d.sent[key]
			d.sent[key] = struct{}{}
			d.mu.Unlock()
			if dup {
				continue
			}
			go d.deliver(ctx, r, f)
		}
	}
}

func ruleMatches(r AlertRule, f Finding) bool {
	if severityRank(f.Severity) < severityRank(r.MinSeverity) {
		return false
	}
	if r.RuleContains != "" && !strings.Contains(strings.ToLower(f.Rule), strings.ToLower(r.RuleContains)) {
		return false
	}
	if r.HostContains != "" && !strings.Contains(strings.ToLower(f.Host), strings.ToLower(r.HostContains)) {
		return false
	}
	return true
}

func alertPayload(r AlertRule, f Finding) []byte {
	if r.Type == "slack" {
		b, _ := json.Marshal(map[string]string{"text": fmt.Sprintf("[Kavach %s] %s on %s: %s",
			strings.ToUpper(f.Severity), f.Rule, f.Host, f.Description)})
		return b
	}
	b, _ := json.Marshal(map[string]any{
		"event": "finding",
		"finding": map[string]any{
			"id": f.ID, "time": f.Time, "host": f.Host, "pid": f.PID, "rule": f.Rule,
			"severity": f.Severity, "description": f.Description, "tags": f.Tags,
		},
	})
	return b
}

func (d *Dispatcher) deliver(ctx context.Context, r AlertRule, f Finding) {
	rec := AlertDelivery{Time: time.Now().UTC(), RuleID: r.ID, FindingID: f.ID, Type: r.Type}
	u, err := validateAlertURL(r.URL)
	if err != nil {
		rec.Status, rec.Error = "failed", err.Error()
		d.record(rec)
		return
	}
	rec.Host = u.Host
	body := alertPayload(r, f)
	wait := d.Backoff
	for i := 1; i <= deliveryTries; i++ {
		rec.Attempts = i
		code, err := d.post(ctx, u, r.Type, body)
		rec.Code = code
		if err == nil {
			rec.Status, rec.Error = "delivered", ""
			d.record(rec)
			return
		}
		rec.Error = err.Error()
		if i == deliveryTries {
			break
		}
		select {
		case <-ctx.Done():
			rec.Status = "failed"
			d.record(rec)
			return
		case <-time.After(wait):
		}
		wait *= 2
	}
	rec.Status = "failed"
	d.record(rec)
}

func (d *Dispatcher) post(ctx context.Context, u *url.URL, typ string, body []byte) (int, error) {
	if u.Scheme == "http" {
		ctx = context.WithValue(ctx, loopbackOKKey{}, true)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kavach-alerts")
	if typ == "webhook" {
		if s := d.secret(); s != "" {
			m := hmac.New(sha256.New, []byte(s))
			m.Write(body)
			req.Header.Set(signatureHeader, "sha256="+hex.EncodeToString(m.Sum(nil)))
		}
	}
	resp, err := d.client.Do(req)
	if err != nil {
		// Strip the URL (may embed a secret path) from transport errors.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (d *Dispatcher) record(x AlertDelivery) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deliveries = append(d.deliveries, x)
	if len(d.deliveries) > maxDeliveries {
		d.deliveries = d.deliveries[len(d.deliveries)-maxDeliveries:]
	}
}

// Deliveries returns the most recent results, newest first.
func (d *Dispatcher) Deliveries() []AlertDelivery {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]AlertDelivery, 0, len(d.deliveries))
	for i := len(d.deliveries) - 1; i >= 0; i-- {
		out = append(out, d.deliveries[i])
	}
	return out
}

// RegisterAlerts wires /v1/alerts/rules and /v1/alerts/deliveries and starts the dispatcher.
func RegisterAlerts(mux *http.ServeMux, token string, store *Store) *Dispatcher {
	d := NewDispatcher(store)
	d.Start(context.Background())
	registerAlertRoutes(mux, token, d)
	return d
}

func registerAlertRoutes(mux *http.ServeMux, token string, d *Dispatcher) {
	mux.HandleFunc("GET /v1/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		d.mu.Lock()
		out := append([]AlertRule{}, d.rules...)
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": out})
	})
	mux.HandleFunc("POST /v1/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		var in AlertRule
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		in.MinSeverity = strings.ToLower(strings.TrimSpace(in.MinSeverity))
		if in.MinSeverity == "" {
			in.MinSeverity = "high"
		}
		if severityRank(in.MinSeverity) == 0 {
			http.Error(w, "min_severity must be low, medium, high or critical", 400)
			return
		}
		in.Type = strings.ToLower(strings.TrimSpace(in.Type))
		if in.Type == "" {
			in.Type = "webhook"
		}
		if in.Type != "webhook" && in.Type != "slack" {
			http.Error(w, "type must be webhook or slack", 400)
			return
		}
		if _, err := validateAlertURL(in.URL); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if len(in.RuleContains) > 128 || len(in.HostContains) > 128 {
			http.Error(w, "filter too long", 400)
			return
		}
		var id [8]byte
		_, _ = rand.Read(id[:])
		in.ID = "alr-" + hex.EncodeToString(id[:])
		in.Created = time.Now().UTC()
		d.mu.Lock()
		if len(d.rules) >= maxAlertRules {
			d.mu.Unlock()
			http.Error(w, "too many rules", 400)
			return
		}
		d.rules = append(d.rules, in)
		err := d.saveLocked()
		d.mu.Unlock()
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		d.journalRule(tuneActor(actor), "alert_rule.create", in.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(in)
	})
	mux.HandleFunc("DELETE /v1/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.URL.Query().Get("id")
		d.mu.Lock()
		defer d.mu.Unlock()
		for i, x := range d.rules {
			if x.ID == id {
				d.rules = append(d.rules[:i:i], d.rules[i+1:]...)
				if err := d.saveLocked(); err != nil {
					http.Error(w, "storage error", 500)
					return
				}
				d.journalRule(tuneActor(actor), "alert_rule.delete", id)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "not found", 404)
	})
	mux.HandleFunc("GET /v1/alerts/deliveries", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deliveries": d.Deliveries()})
	})
}
