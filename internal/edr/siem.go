// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SIEMConfig controls optional export sinks. Observation-only; no response.
type SIEMConfig struct {
	WebhookURL string
	SyslogAddr string // host:port UDP
	Enabled    bool
}

type SIEMExporter struct {
	cfg    SIEMConfig
	client *http.Client
	mu     sync.Mutex
}

// DefaultSIEM is set by the server process for finding export side-effects.
var DefaultSIEM *SIEMExporter

func NewSIEMExporterFromEnv() *SIEMExporter {
	cfg := SIEMConfig{
		WebhookURL: os.Getenv("KAVACH_SIEM_WEBHOOK"),
		SyslogAddr: os.Getenv("KAVACH_SIEM_SYSLOG"),
	}
	cfg.Enabled = cfg.WebhookURL != "" || cfg.SyslogAddr != ""
	return &SIEMExporter{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}
}

// ECSEvent is a minimal Elastic Common Schema flavored document.
type ECSEvent struct {
	Timestamp   time.Time `json:"@timestamp"`
	Message     string    `json:"message"`
	EventKind   string    `json:"event.kind"`
	EventCat    []string  `json:"event.category"`
	Severity    string    `json:"event.severity_label"`
	RuleID      string    `json:"rule.id"`
	HostName    string    `json:"host.name"`
	ProcessPID  int       `json:"process.pid,omitempty"`
	Observer    string    `json:"observer.product"`
	Tags        []string  `json:"tags,omitempty"`
}

func FindingToECS(f Finding) ECSEvent {
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
		Tags:       []string{"kavach", "zyvor"},
	}
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
	req, err := http.NewRequest(http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("siem webhook: %v", err)
		return
	}
	resp.Body.Close()
}

func (s *SIEMExporter) sendSyslog(f Finding, jsonBody []byte) {
	conn, err := net.DialTimeout("udp", s.cfg.SyslogAddr, 2*time.Second)
	if err != nil {
		log.Printf("siem syslog: %v", err)
		return
	}
	defer conn.Close()
	// RFC5424-ish
	msg := fmt.Sprintf("<134>1 %s kavach - - - %s", f.Time.UTC().Format(time.RFC3339), string(jsonBody))
	_, _ = conn.Write([]byte(msg))
}

func (s *SIEMExporter) RegisterRoutes(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/siem/status", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled":     s != nil && s.cfg.Enabled,
			"webhook_set": s != nil && s.cfg.WebhookURL != "",
			"syslog_set":  s != nil && s.cfg.SyslogAddr != "",
		})
	})
	mux.HandleFunc("GET /v1/siem/export", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		// Caller passes findings via store; this endpoint documents ECS shape.
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write([]byte(""))
	})
}
