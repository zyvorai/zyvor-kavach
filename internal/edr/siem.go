// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SIEMConfig controls optional export sinks. Observation-only; no response.
type SIEMConfig struct {
	WebhookURL string
	SyslogAddr string // host:port UDP
	Headers    map[string]string
	Enabled    bool
	Sink       string // webhook|syslog|both|none — from KAVACH_SIEM_SINK
	Format     string // json|ecs|syslog — from KAVACH_SIEM_FORMAT

	allowLoopback bool // test only; never set from the environment
}

type SIEMExporter struct {
	cfg      SIEMConfig
	client   *http.Client
	mu       sync.Mutex
	okCount  atomic.Uint64
	errCount atomic.Uint64
	lastErr  string
	lastOK   time.Time

	attempts int           // webhook attempts per finding (default 3)
	backoff  time.Duration // first retry delay, doubled each time, capped at 5 s
	stop     chan struct{}
	stopOnce sync.Once
}

// Close stops pending webhook retries.
func (s *SIEMExporter) Close() {
	if s != nil {
		s.stopOnce.Do(func() { close(s.stop) })
	}
}

// newSIEMExporter builds an exporter, validating the webhook URL. An unsafe
// webhook is dropped (and reported via status) rather than used.
func newSIEMExporter(cfg SIEMConfig) *SIEMExporter {
	s := &SIEMExporter{cfg: cfg, attempts: 3, backoff: 500 * time.Millisecond, stop: make(chan struct{})}
	allowPriv := siemAllowPrivate()
	if cfg.WebhookURL != "" {
		if _, err := validateSIEMURL(cfg.WebhookURL, allowPriv, cfg.allowLoopback); err != nil {
			s.cfg.WebhookURL = ""
			s.cfg.Enabled = s.cfg.SyslogAddr != ""
			s.noteErr(err)
		}
	}
	s.client = newSIEMHTTPClient(allowPriv, cfg.allowLoopback)
	return s
}

// DefaultSIEM is set by the server process for finding export side-effects.
var DefaultSIEM *SIEMExporter

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func parseHeaderKV(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func NewSIEMExporterFromEnv() *SIEMExporter {
	cfg := SIEMConfig{
		WebhookURL: firstNonEmpty(os.Getenv("KAVACH_SIEM_WEBHOOK"), os.Getenv("KAVACH_SIEM_WEBHOOK_URL")),
		SyslogAddr: firstNonEmpty(os.Getenv("KAVACH_SIEM_SYSLOG"), os.Getenv("KAVACH_SIEM_SYSLOG_ADDR")),
		Headers:    parseHeaderKV(os.Getenv("KAVACH_SIEM_HEADERS")),
		Sink:       strings.ToLower(strings.TrimSpace(firstNonEmpty(os.Getenv("KAVACH_SIEM_SINK"), "both"))),
		Format:     strings.ToLower(strings.TrimSpace(firstNonEmpty(os.Getenv("KAVACH_SIEM_FORMAT"), "ecs"))),
	}
	explicitOff := os.Getenv("KAVACH_SIEM_ENABLED") == "false" || os.Getenv("KAVACH_SIEM_ENABLED") == "0" || cfg.Sink == "none"
	hasSink := cfg.WebhookURL != "" || cfg.SyslogAddr != ""
	switch {
	case explicitOff:
		cfg.Enabled = false
	case os.Getenv("KAVACH_SIEM_ENABLED") == "true" || os.Getenv("KAVACH_SIEM_ENABLED") == "1":
		cfg.Enabled = hasSink
	default:
		cfg.Enabled = hasSink
	}
	// Honor sink selection: webhook-only or syslog-only clears the other.
	switch cfg.Sink {
	case "webhook":
		cfg.SyslogAddr = ""
	case "syslog":
		cfg.WebhookURL = ""
	case "none":
		cfg.WebhookURL, cfg.SyslogAddr = "", ""
		cfg.Enabled = false
	}
	return newSIEMExporter(cfg)
}

// ECSEvent is a minimal Elastic Common Schema flavored document.
type ECSEvent struct {
	Timestamp  time.Time `json:"@timestamp"`
	Message    string    `json:"message"`
	EventKind  string    `json:"event.kind"`
	EventCat   []string  `json:"event.category"`
	Severity   string    `json:"event.severity_label"`
	RuleID     string    `json:"rule.id"`
	HostName   string    `json:"host.name"`
	ProcessPID int       `json:"process.pid,omitempty"`
	Observer   string    `json:"observer.product"`
	Tags       []string  `json:"tags,omitempty"`
	FindingID  string    `json:"kavach.finding_id,omitempty"`
}

func FindingToECS(f Finding) ECSEvent {
	tags := []string{"kavach", "zyvor"}
	tags = append(tags, f.Tags...)
	return ECSEvent{
		Timestamp:  f.Time,
		Message:    f.Description,
		EventKind:  "alert",
		EventCat:   []string{"intrusion_detection"},
		Severity:   f.Severity,
		RuleID:     f.Rule,
		HostName:   f.Host,
		ProcessPID: f.PID,
		Observer:   "kavach",
		Tags:       tags,
		FindingID:  f.ID,
	}
}

func (s *SIEMExporter) noteOK() {
	s.okCount.Add(1)
	s.mu.Lock()
	s.lastOK = time.Now().UTC()
	s.lastErr = ""
	s.mu.Unlock()
}

func (s *SIEMExporter) noteErr(err error) {
	s.errCount.Add(1)
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
	log.Printf("siem: %v", err)
}

func (s *SIEMExporter) ExportFinding(f Finding) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	doc := FindingToECS(f)
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	if s.cfg.WebhookURL != "" {
		go s.postWebhook(b)
	}
	if s.cfg.SyslogAddr != "" {
		go s.sendSyslog(f, b)
	}
}

func (s *SIEMExporter) postWebhook(b []byte) {
	delay := s.backoff
	var err error
	for attempt := 1; attempt <= s.attempts; attempt++ {
		var retry bool
		retry, err = s.postWebhookOnce(b)
		if err == nil {
			s.noteOK()
			return
		}
		if !retry || attempt == s.attempts {
			break
		}
		t := time.NewTimer(delay)
		select {
		case <-s.stop:
			t.Stop()
			s.noteErr(fmt.Errorf("%w (retry cancelled by shutdown)", err))
			return
		case <-t.C:
		}
		if delay *= 2; delay > 5*time.Second {
			delay = 5 * time.Second
		}
	}
	s.noteErr(err)
}

// postWebhookOnce makes one attempt and reports whether a retry may help.
func (s *SIEMExporter) postWebhookOnce(b []byte) (retry bool, err error) {
	req, err := http.NewRequest(http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return !strings.Contains(err.Error(), "destination refused"), err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode >= 500 || resp.StatusCode == 429, fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return false, nil
}

func (s *SIEMExporter) sendSyslog(f Finding, jsonBody []byte) {
	conn, err := net.DialTimeout("udp", s.cfg.SyslogAddr, 2*time.Second)
	if err != nil {
		s.noteErr(err)
		return
	}
	defer conn.Close()
	msg := fmt.Sprintf("<134>1 %s kavach - - - %s", f.Time.UTC().Format(time.RFC3339), string(jsonBody))
	if _, err := conn.Write([]byte(msg)); err != nil {
		s.noteErr(err)
		return
	}
	s.noteOK()
}

func (s *SIEMExporter) Status() map[string]any {
	if s == nil {
		return map[string]any{"enabled": false}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{
		"enabled":     s.cfg.Enabled,
		"sink":        s.cfg.Sink,
		"format":      s.cfg.Format,
		"webhook_set": s.cfg.WebhookURL != "",
		"syslog_set":  s.cfg.SyslogAddr != "",
		"ok_count":    s.okCount.Load(),
		"err_count":   s.errCount.Load(),
		"last_error":  s.lastErr,
	}
	if !s.lastOK.IsZero() {
		out["last_ok"] = s.lastOK.Format(time.RFC3339)
	}
	return out
}

func (s *SIEMExporter) RegisterRoutes(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/siem/status", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !secureEqual(got, token) && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Status())
	})
	mux.HandleFunc("GET /v1/siem/export", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !secureEqual(got, token) && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		if store == nil {
			return
		}
		for _, f := range store.List() {
			b, err := json.Marshal(FindingToECS(f))
			if err != nil {
				continue
			}
			w.Write(b)
			w.Write([]byte("\n"))
		}
	})
}
