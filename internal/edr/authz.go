package edr

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func bearerOrSession(r *http.Request, token string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 || validSession(r, token)
}

func requireAuth(w http.ResponseWriter, r *http.Request, token string) bool {
	if bearerOrSession(r, token) {
		return true
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func requireAdminOrSession(w http.ResponseWriter, r *http.Request, token string) (admin bool, ok bool) {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	admin = subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
	session := validSession(r, token)
	if !admin && !session {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false, false
	}
	return admin, true
}
