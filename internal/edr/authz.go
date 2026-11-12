package edr

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"sync"
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

// Role catalog + optional enforcement via KAVACH_RBAC=1 and X-Kavach-Role / KAVACH_ROLE.
var (
	roleMu sync.Mutex
	rbacRoles = []map[string]any{
		{"id": "role-admin", "name": "Administrator", "permissions": []string{"*"}},
		{"id": "role-analyst", "name": "Analyst", "permissions": []string{"read", "triage", "hunt", "cases", "write", "ingest"}},
		{"id": "role-viewer", "name": "Viewer", "permissions": []string{"read"}},
		{"id": "role-mssp", "name": "MSSP Operator", "permissions": []string{"read", "triage", "tenants", "ingest"}},
	}
)

func RBACRoles() []map[string]any {
	roleMu.Lock()
	defer roleMu.Unlock()
	out := make([]map[string]any, len(rbacRoles))
	copy(out, rbacRoles)
	return out
}

func AppendRBACRole(role map[string]any) {
	roleMu.Lock()
	defer roleMu.Unlock()
	rbacRoles = append(rbacRoles, role)
}

func rbacEnabled() bool {
	v := strings.ToLower(os.Getenv("KAVACH_RBAC"))
	return v == "1" || v == "true" || v == "yes"
}

func requestRole(r *http.Request, token string) string {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 {
		return "admin"
	}
	if h := strings.TrimSpace(r.Header.Get("X-Kavach-Role")); h != "" {
		return strings.ToLower(h)
	}
	if v := strings.TrimSpace(os.Getenv("KAVACH_ROLE")); v != "" {
		return strings.ToLower(v)
	}
	if validSession(r, token) {
		return "analyst"
	}
	return "viewer"
}

func rolePermissions(role string) []string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "admin" || role == "administrator" || role == "role-admin" {
		return []string{"*"}
	}
	for _, r := range RBACRoles() {
		name, _ := r["name"].(string)
		id, _ := r["id"].(string)
		if role == strings.ToLower(name) || role == strings.ToLower(id) || strings.TrimPrefix(strings.ToLower(id), "role-") == role {
			switch perms := r["permissions"].(type) {
			case []string:
				return perms
			case []any:
				out := make([]string, 0, len(perms))
				for _, p := range perms {
					if s, ok := p.(string); ok {
						out = append(out, s)
					}
				}
				return out
			}
		}
	}
	return []string{"read"}
}

func hasPerm(perms []string, need string) bool {
	need = strings.ToLower(need)
	for _, p := range perms {
		p = strings.ToLower(p)
		if p == "*" || p == need {
			return true
		}
	}
	return false
}

// requireRole enforces RBAC only when KAVACH_RBAC is enabled; otherwise always allows.
func requireRole(w http.ResponseWriter, r *http.Request, token string, allowed ...string) bool {
	if !rbacEnabled() {
		return true
	}
	if !bearerOrSession(r, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	perms := rolePermissions(requestRole(r, token))
	for _, a := range allowed {
		if hasPerm(perms, a) {
			return true
		}
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}
