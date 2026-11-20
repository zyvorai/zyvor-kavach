package edr

import (
	"regexp"
	"strings"
	"testing"
)

func TestCloudHuntPacksQuality(t *testing.T) {
	if len(cloudHuntPacks) < 30 {
		t.Fatalf("cloud packs=%d", len(cloudHuntPacks))
	}
	idRe := regexp.MustCompile(`^hc(-[a-z0-9]+)+$`)
	techRe := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	tactics := map[string]bool{"initial-access": true, "execution": true, "persistence": true, "privilege-escalation": true, "defense-evasion": true, "credential-access": true, "discovery": true, "lateral-movement": true, "collection": true, "command-and-control": true, "exfiltration": true, "impact": true}
	seen := map[string]bool{}
	for _, p := range huntPacks {
		if seen[p.ID] {
			t.Errorf("duplicate id %s", p.ID)
		}
		seen[p.ID] = true
	}
	benign := []string{"ls -la", "cat /etc/hostname", "bash -c echo hi", "curl https://example.com", "go build ./...", "python3 app.py", "apt update", "systemctl status ssh", "git pull", "docker ps", "git commit -m fix", "make test", "npm test", "vim README.md", "ssh host uptime", "kubectl get pods", "aws --version", "df -h", "ps aux", "kubectl get nodes", "docker build -t app .", "terraform plan", "helm list"}
	for _, p := range cloudHuntPacks {
		if !idRe.MatchString(p.ID) || p.Name == "" || !techRe.MatchString(p.Technique) || !tactics[p.Tactic] {
			t.Errorf("bad pack %+v", p)
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
		for _, c := range benign {
			if huntMatchTerms(huntText("/bin/x", c, "", ""), p.Terms) {
				t.Errorf("pack %s hits benign %q", p.ID, c)
			}
		}
	}
}
