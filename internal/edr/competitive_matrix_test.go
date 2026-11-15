// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCompetitiveMatrixValid(t *testing.T) {
	m, err := LoadCompetitiveMatrix()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Products) != 11 || len(m.Backlog) < 25 {
		t.Fatalf("products=%d backlog=%d", len(m.Products), len(m.Backlog))
	}
}

func TestCompetitiveEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	RegisterCompetitive(mux, "tok")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/world/competitive", nil))
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden {
		t.Fatalf("unauth got %d", rr.Code)
	}
	req := httptest.NewRequest("GET", "/v1/world/competitive", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "last_researched") {
		t.Fatalf("got %d", rr.Code)
	}
}
