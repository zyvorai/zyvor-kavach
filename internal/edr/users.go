// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Simple file-backed multi-user store.
// Activated when the users file exists (default <state>.users.json).
// When empty or missing, behaviour falls back to the single admin token.
// Observation-only.

type User struct {
	Username string    `json:"username"`
	Hash     string    `json:"hash"` // sha256 hex of password
	Role     string    `json:"role"`
	Created  time.Time `json:"created"`
}

type UserStore struct {
	path  string
	mu    sync.Mutex
	users map[string]User
}

func NewUserStore(path string) (*UserStore, error) {
	us := &UserStore{path: path, users: map[string]User{}}
	if path == "" {
		return us, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return us, nil
		}
		return nil, err
	}
	var list []User
	if json.Unmarshal(b, &list) == nil {
		for _, u := range list {
			us.users[strings.ToLower(u.Username)] = u
		}
	}
	return us, nil
}

func (us *UserStore) save() error {
	if us.path == "" {
		return nil
	}
	us.mu.Lock()
	defer us.mu.Unlock()
	list := make([]User, 0, len(us.users))
	for _, u := range us.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := us.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, us.path)
}

func (us *UserStore) Authenticate(username, password string) (User, bool) {
	us.mu.Lock()
	defer us.mu.Unlock()
	u, ok := us.users[strings.ToLower(username)]
	if !ok {
		return User{}, false
	}
	sum := sha256.Sum256([]byte(password))
	if secureEqual(hex.EncodeToString(sum[:]), u.Hash) {
		return u, true
	}
	return User{}, false
}

func (us *UserStore) Add(username, password, role string) error {
	sum := sha256.Sum256([]byte(password))
	us.mu.Lock()
	us.users[strings.ToLower(username)] = User{
		Username: username,
		Hash:     hex.EncodeToString(sum[:]),
		Role:     role,
		Created:  time.Now().UTC(),
	}
	us.mu.Unlock()
	return us.save()
}

var globalUsers *UserStore

func RegisterUsers(mux *http.ServeMux, token string, store *Store) {
	path := os.Getenv("KAVACH_USERS_FILE")
	if path == "" && store != nil {
		path = store.path + ".users.json"
	}
	us, err := NewUserStore(path)
	if err != nil {
		return
	}
	globalUsers = us

	mux.HandleFunc("POST /v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Username == "" || body.Password == "" {
			http.Error(w, "bad request", 400)
			return
		}
		if body.Role == "" {
			body.Role = "analyst"
		}
		if err := us.Add(body.Username, body.Password, body.Role); err != nil {
			http.Error(w, "store error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "created", "username": body.Username})
	})

	mux.HandleFunc("GET /v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		us.mu.Lock()
		list := make([]map[string]any, 0, len(us.users))
		for _, u := range us.users {
			list = append(list, map[string]any{"username": u.Username, "role": u.Role, "created": u.Created})
		}
		us.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})
}
