package main

import "testing"

func TestAPITokenAdminFallbackLowestPrecedence(t *testing.T) {
	t.Setenv("KAVACH_SKIP_DOTENV", "1")
	t.Setenv("KAVACH_TOKEN", "")
	t.Setenv("ZYVOR_EDR_TOKEN", "")
	t.Setenv("KAVACH_ADMIN_TOKEN", "admin-tok")
	if got := apiToken(); got != "admin-tok" {
		t.Fatalf("fallback: got %q", got)
	}
	t.Setenv("ZYVOR_EDR_TOKEN", "legacy")
	if got := apiToken(); got != "legacy" {
		t.Fatalf("legacy should win: %q", got)
	}
	t.Setenv("KAVACH_TOKEN", "primary")
	if got := apiToken(); got != "primary" {
		t.Fatalf("primary should win: %q", got)
	}
}
