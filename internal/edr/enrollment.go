package edr

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// CredentialRegistry persists SHA-256 hashes of randomly generated bearer tokens.
// It is intended for lab enrollment; production deployments should use mTLS identities.
type CredentialRegistry struct {
	mu     sync.Mutex
	path   string
	agents map[string]AgentCredential
}
type AgentCredential struct {
	Host     string    `json:"host"`
	Hash     string    `json:"hash"`
	Created  time.Time `json:"created"`
	Revoked  bool      `json:"revoked"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	Sensor   string    `json:"sensor,omitempty"`
	Queued   int       `json:"queued,omitempty"`
}

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func OpenCredentialRegistry(path string) (*CredentialRegistry, error) {
	r := &CredentialRegistry{path: path, agents: map[string]AgentCredential{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &r.agents); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *CredentialRegistry) save() error {
	b, err := json.MarshalIndent(r.agents, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepathDir(r.path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), r.path)
}
func filepathDir(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return path[:i]
}
func (r *CredentialRegistry) Issue(host string) (string, error) {
	if !hostPattern.MatchString(host) {
		return "", fmt.Errorf("invalid host name")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := "zedr_" + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	r.mu.Lock()
	defer r.mu.Unlock()
	old, exists := r.agents[host]
	r.agents[host] = AgentCredential{Host: host, Hash: hex.EncodeToString(sum[:]), Created: time.Now().UTC()}
	if err := r.save(); err != nil {
		if exists {
			r.agents[host] = old
		} else {
			delete(r.agents, host)
		}
		return "", err
	}
	return token, nil
}
func (r *CredentialRegistry) Revoke(host string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, exists := r.agents[host]
	if !exists {
		return os.ErrNotExist
	}
	v := old
	v.Revoked = true
	r.agents[host] = v
	if err := r.save(); err != nil {
		r.agents[host] = old
		return err
	}
	return nil
}
func (r *CredentialRegistry) Verify(host, token string) bool {
	if len(token) > 256 || len(token) < 32 {
		return false
	}
	r.mu.Lock()
	cred, exists := r.agents[host]
	r.mu.Unlock()
	if !exists || cred.Revoked {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(cred.Hash)
	return err == nil && subtle.ConstantTimeCompare(sum[:], want) == 1
}

// Heartbeat validates the scoped token and records liveness atomically.
func (r *CredentialRegistry) Heartbeat(host, token, sensor string, queued int) error {
	if !hostPattern.MatchString(host) || queued < 0 || queued > 1000000 || len(sensor) > 80 {
		return fmt.Errorf("invalid heartbeat")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.agents[host]
	if !ok || c.Revoked || len(token) < 32 || len(token) > 256 {
		return fmt.Errorf("unauthorized")
	}
	sum := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(c.Hash)
	if err != nil || subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return fmt.Errorf("unauthorized")
	}
	old := c
	c.LastSeen = time.Now().UTC()
	c.Sensor = sensor
	c.Queued = queued
	r.agents[host] = c
	if err := r.save(); err != nil {
		r.agents[host] = old
		return err
	}
	return nil
}

type AgentStatus struct {
	Host     string    `json:"host"`
	State    string    `json:"state"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	Sensor   string    `json:"sensor,omitempty"`
	Queued   int       `json:"queued"`
}

func (r *CredentialRegistry) Status(now time.Time, staleAfter time.Duration) []AgentStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	statuses := make([]AgentStatus, 0, len(r.agents))
	for _, c := range r.agents {
		state := "pending"
		if c.Revoked {
			state = "revoked"
		} else if !c.LastSeen.IsZero() {
			if now.Sub(c.LastSeen) > staleAfter {
				state = "offline"
			} else {
				state = "online"
			}
		}
		statuses = append(statuses, AgentStatus{Host: c.Host, State: state, LastSeen: c.LastSeen, Sensor: c.Sensor, Queued: c.Queued})
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Host < statuses[j].Host })
	return statuses
}

func (r *CredentialRegistry) RegisterRoutes(mux *http.ServeMux, admin string) {
	isAdmin := func(w http.ResponseWriter, req *http.Request) bool {
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(admin)) != 1 {
			http.Error(w, "unauthorized", 401)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /v1/agents/heartbeat", func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, 4096)
		defer req.Body.Close()
		var payload struct {
			Host   string `json:"host"`
			Sensor string `json:"sensor"`
			Queued int    `json:"queued"`
		}
		if json.NewDecoder(req.Body).Decode(&payload) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		bearer := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if err := r.Heartbeat(payload.Host, bearer, payload.Sensor, payload.Queued); err != nil {
			http.Error(w, "unauthorized or invalid heartbeat", 401)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, req *http.Request) {
		if !isAdmin(w, req) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.Status(time.Now(), 90*time.Second))
	})
	mux.HandleFunc("POST /v1/agents/enroll", func(w http.ResponseWriter, req *http.Request) {
		if !isAdmin(w, req) {
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, 4096)
		defer req.Body.Close()
		var payload struct {
			Host string `json:"host"`
		}
		if json.NewDecoder(req.Body).Decode(&payload) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		token, err := r.Issue(payload.Host)
		if err != nil {
			http.Error(w, "invalid host or persistence failure", 400)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"host": payload.Host, "token": token})
	})
	mux.HandleFunc("POST /v1/agents/revoke", func(w http.ResponseWriter, req *http.Request) {
		if !isAdmin(w, req) {
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, 4096)
		defer req.Body.Close()
		var payload struct {
			Host string `json:"host"`
		}
		if json.NewDecoder(req.Body).Decode(&payload) != nil || !hostPattern.MatchString(payload.Host) {
			http.Error(w, "bad host", 400)
			return
		}
		if err := r.Revoke(payload.Host); err != nil {
			http.Error(w, "unknown host", 404)
			return
		}
		w.WriteHeader(204)
	})
}
