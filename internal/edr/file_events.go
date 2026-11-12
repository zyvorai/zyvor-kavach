package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileEvent is a metadata-only observation. No file contents are transmitted.
type FileEvent struct {
	ID        string    `json:"id,omitempty"`
	Time      time.Time `json:"time"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Operation string    `json:"operation"`
	Size      int64     `json:"size,omitempty"`
	// Attribution is intentionally optional; the file scanner cannot identify the writer.
	PID int `json:"pid,omitempty"`
}

type FileScanner struct {
	Root, Host string
	mu         sync.Mutex
	baseline   map[string]string
	Limit      int
}

func NewFileScanner(root, host string) *FileScanner {
	return &FileScanner{Root: root, Host: host, Limit: 10000}
}

// Scan records create/change/delete after the first baseline pass. It is a poller,
// not a kernel file sensor, and never reads file content.
func (s *FileScanner) Scan(now time.Time) ([]FileEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := map[string]string{}
	limit := s.Limit
	if limit <= 0 {
		limit = 10000
	}
	err := filepath.WalkDir(s.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(current) >= limit {
			return errors.New("file scan limit exceeded")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		current[path] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.baseline == nil {
		s.baseline = current
		return []FileEvent{}, nil
	}
	out := []FileEvent{}
	for path, nowHash := range current {
		old, ok := s.baseline[path]
		if !ok || old != nowHash {
			op := "modify"
			if !ok {
				op = "create"
			}
			out = append(out, FileEvent{Time: now.UTC(), Host: s.Host, Path: path, Operation: op})
		}
	}
	for path := range s.baseline {
		if _, ok := current[path]; !ok {
			out = append(out, FileEvent{Time: now.UTC(), Host: s.Host, Path: path, Operation: "delete"})
		}
	}
	s.baseline = current
	return out, nil
}
func fileID(e FileEvent) string {
	if e.ID != "" {
		return e.ID
	}
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FileDetections detects a bounded rate of metadata changes. It does not claim
// malware attribution or encryption detection; benign bulk operations may trigger.
type FileDetections struct {
	mu        sync.Mutex
	counts    map[string][]time.Time
	Threshold int
	Window    time.Duration
}

func (d *FileDetections) Observe(e FileEvent) []Finding {
	if e.Time.IsZero() || e.Host == "" || e.Path == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.counts == nil {
		d.counts = make(map[string][]time.Time)
	}
	limit := d.Threshold
	if limit <= 0 {
		limit = 30
	}
	window := d.Window
	if window <= 0 {
		window = 30 * time.Second
	}
	bucket := d.counts[e.Host]
	fresh := bucket[:0]
	for _, t := range bucket {
		if !t.After(e.Time) && e.Time.Sub(t) <= window {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, e.Time)
	d.counts[e.Host] = fresh
	if len(fresh) != limit {
		return nil
	}
	return []Finding{{ID: "mass-file-activity:" + e.Host + ":" + fileID(e), Time: e.Time, Host: e.Host, PID: e.PID, Rule: "mass-file-activity", Severity: "high", Description: fmt.Sprintf("%d file changes in %s; investigate potential ransomware or batch workload (not proof of encryption)", len(fresh), window), Evidence: Event{Host: e.Host, Time: e.Time, PID: e.PID, Command: "[file metadata only]"}}}
}

// RegisterFileRoutes creates a separate host-authenticated ingestion path.
// Access to the admin token is kept for backwards compatible local integration.
func RegisterFileRoutes(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	detector := &FileDetections{}
	mux.HandleFunc("POST /v1/file-events", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		defer r.Body.Close()
		var e FileEvent
		if json.NewDecoder(r.Body).Decode(&e) != nil || e.Host == "" || e.Time.IsZero() || e.Path == "" || e.Operation == "" || len(e.Path) > 4096 || strings.ContainsRune(e.Path, '\x00') {
			http.Error(w, "invalid file event", 400)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !secureEqual(got, token) && (registry == nil || !registry.Verify(e.Host, got)) {
			http.Error(w, "unauthorized", 401)
			return
		}
		findings, err := store.IngestFile(e, detector)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"findings": len(findings)})
	})
}
