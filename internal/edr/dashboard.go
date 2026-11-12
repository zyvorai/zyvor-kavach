package edr

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed dashboard.html
var dashboardAssets embed.FS

func sessionSignature(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("kavach-session-v1:" + payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func validSession(r *http.Request, secret string) bool {
	c, err := r.Cookie("zyvor_session")
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if ts > now+60 || ts < now-3600 {
		return false
	}
	expected := sessionSignature(secret, parts[0])
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}
func registerDashboard(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		b, _ := dashboardAssets.ReadFile("dashboard.html")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("POST /v1/session", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var credentials struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&credentials) != nil || subtle.ConstantTimeCompare([]byte(credentials.Token), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		http.SetCookie(w, &http.Cookie{Name: "zyvor_session", Value: ts + "." + sessionSignature(token, ts), Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "zyvor_session", Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		w.WriteHeader(204)
	})
	isAuthorized := func(w http.ResponseWriter, r *http.Request) bool {
		if validSession(r, token) {
			return true
		}
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(auth), []byte(token)) == 1 {
			return true
		}
		http.Error(w, "unauthorized", 401)
		return false
	}
	mux.HandleFunc("GET /v1/summary", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(w, r) {
			return
		}
		findings := store.List()
		severities := map[string]int{}
		hosts := map[string]struct{}{}
		for _, f := range findings {
			severities[f.Severity]++
			hosts[f.Host] = struct{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"findings": len(findings), "hosts": len(hosts), "severities": severities})
	})
	mux.HandleFunc("GET /v1/recent-events", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(w, r) {
			return
		}
		store.mu.Lock()
		events := append([]Event{}, store.recentEvents...)
		net := append([]NetworkEvent{}, store.networkEvents...)
		store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"process": events, "network": net})
	})
}
