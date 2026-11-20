package edr

import (
	"regexp"
	"strings"
	"testing"
)

func TestHuntPackLibraryQuality(t *testing.T) {
	if len(moreHuntPacks) < 90 {
		t.Fatalf("more packs=%d", len(moreHuntPacks))
	}
	idRe := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	techRe := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	tactics := map[string]bool{"initial-access": true, "execution": true, "persistence": true, "privilege-escalation": true, "defense-evasion": true, "credential-access": true, "discovery": true, "lateral-movement": true, "collection": true, "command-and-control": true, "exfiltration": true, "impact": true}
	seen := map[string]bool{}
	for _, p := range huntPacks {
		if seen[p.ID] {
			t.Errorf("duplicate id %s", p.ID)
		}
		seen[p.ID] = true
		if !idRe.MatchString(p.ID) || p.Name == "" {
			t.Errorf("bad id/name %q", p.ID)
		}
		if !techRe.MatchString(p.Technique) {
			t.Errorf("%s bad technique %q", p.ID, p.Technique)
		}
		if !tactics[p.Tactic] {
			t.Errorf("%s bad tactic %q", p.ID, p.Tactic)
		}
		long := false
		for _, term := range p.Terms {
			if term != strings.ToLower(term) {
				t.Errorf("%s term not lowercase: %q", p.ID, term)
			}
			if len(term) >= 4 {
				long = true
			}
		}
		if !long {
			t.Errorf("%s needs a term >=4 chars", p.ID)
		}
	}
}

func TestMoreHuntPacksBenignBaseline(t *testing.T) {
	benign := []string{"ls -la", "cat /etc/hostname", "bash -c echo hi", "curl https://example.com", "go build ./...", "python3 app.py", "apt update", "systemctl status ssh", "git pull", "docker ps", "git commit -m fix", "make test", "npm test", "vim README.md", "ssh host uptime", "kubectl get pods", "aws --version", "df -h", "ps aux", "top -b -n1", "grep foo main.go", "tar tf a.tar", "sleep 1", "echo hello"}
	for _, p := range moreHuntPacks {
		for _, c := range benign {
			if huntMatchTerms(huntText("/bin/x", c, "", ""), p.Terms) {
				t.Errorf("pack %s hits benign %q", p.ID, c)
			}
		}
	}
}
