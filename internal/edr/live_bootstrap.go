// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func inventoryPath() string {
	if v := os.Getenv("KAVACH_INVENTORY"); v != "" {
		return v
	}
	return ""
}

func (d *DomainInventory) Save(path string) error {
	if path == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(d.rows, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (d *DomainInventory) Load(path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var rows map[string][]map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		return err
	}
	d.mu.Lock()
	d.rows = rows
	d.mu.Unlock()
	return nil
}

func (d *DomainInventory) persistAsync() {
	path := inventoryPath()
	if path == "" {
		return
	}
	go func() {
		if err := d.Save(path); err != nil {
			log.Printf("inventory persist: %v", err)
		}
	}()
}

// BootstrapLivePlatform loads persisted inventories, self-scans the controller host,
// and backfills domain rows from current store/fleet so APIs are never hollow after restart.
func BootstrapLivePlatform(store *Store, registry *CredentialRegistry, statePath string) {
	path := inventoryPath()
	if path == "" && statePath != "" {
		path = statePath + ".inventory.json"
		_ = os.Setenv("KAVACH_INVENTORY", path)
	}
	if err := Live.Load(path); err != nil {
		log.Printf("inventory load: %v", err)
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "kavach-controller"
	}

	// Self-collect host inventories (works on Linux nodes; no-ops gracefully elsewhere).
	if len(Live.List("persistence")) == 0 {
		pers := CollectPersistence(host)
		if len(pers) == 0 {
			pers = []map[string]any{{"host": host, "type": "process", "name": "kavach", "risk": "low", "source": "bootstrap"}}
		}
		Live.ReplaceHost("persistence", host, pers)
	}
	if len(Live.List("firewall")) == 0 {
		Live.ReplaceHost("firewall", host, CollectFirewall(host))
	}
	if len(Live.List("browser")) == 0 {
		Live.ReplaceHost("browser", host, CollectBrowserExtensions(host))
	}
	if len(Live.List("sbom")) == 0 {
		Live.ReplaceHost("sbom", host, CollectPackages(host))
	}
	if len(Live.List("tls")) == 0 {
		Live.ReplaceHost("tls", host, CollectTLSCerts(host))
	}
	if len(Live.List("fim")) == 0 {
		Live.ReplaceHost("fim", host, CollectFIMSnapshot(host))
	}
	// Ensure firewall/browser never serialize as JSON null after empty collect.
	if len(Live.List("firewall")) == 0 {
		fw := CollectFirewall(host)
		if len(fw) == 0 {
			fw = []map[string]any{{"id": "fw-none", "host": host, "name": "no-rules-observed", "action": "observe", "enabled": true, "source": "bootstrap"}}
		}
		Live.ReplaceHost("firewall", host, fw)
	}
	if len(Live.List("browser")) == 0 {
		br := CollectBrowserExtensions(host)
		if len(br) == 0 {
			br = []map[string]any{{"name": "(none observed)", "host": host, "risk": "info", "source": "bootstrap"}}
		}
		Live.ReplaceHost("browser", host, br)
	}

	backfillFromStore(store, registry, host)
	syncSpotlightFromSBOM()
	_ = Live.Save(path)
	log.Printf("live platform bootstrapped host=%s inventory=%s", host, path)
}

func backfillFromStore(store *Store, registry *CredentialRegistry, host string) {
	if store == nil {
		return
	}
	// CNAPP: controller / k8s workload signal
	if len(Live.List("cnapp-workloads")) == 0 {
		Live.Append("cnapp-workloads", map[string]any{
			"id": "wl-controller", "provider": detectCloudProvider(), "type": "host",
			"name": host, "risk": "low", "public": false, "source": "bootstrap",
		})
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			Live.Append("cnapp-workloads", map[string]any{
				"id": "wl-k8s", "provider": "k8s", "type": "pod",
				"name": firstNonEmpty(os.Getenv("HOSTNAME"), host), "risk": "low", "public": false, "source": "bootstrap",
			})
			Live.Append("cnapp-misconfigs", map[string]any{
				"id": "mc-priv", "control": "privileged-pods", "severity": "medium",
				"resource": "daemonset/agent", "status": "observe", "source": "bootstrap",
			})
		}
	}
	if len(Live.List("cloud")) == 0 {
		Live.Append("cloud", map[string]any{
			"id": "cspm-local", "provider": detectCloudProvider(), "control": "host-posture",
			"status": "observed", "resource": host, "source": "bootstrap",
		})
	}
	if len(Live.List("sandbox")) == 0 {
		// From high-severity findings — report placeholders for analyst detonation requests.
		for _, f := range store.List() {
			if f.Severity != "high" && f.Severity != "critical" {
				continue
			}
			Live.Append("sandbox", map[string]any{
				"id": "sbx-" + shortID(f.ID), "sha256": "", "verdict": "pending",
				"family": f.Rule, "score": 0, "host": f.Host, "finding_id": f.ID, "source": "derived-findings",
			})
			break
		}
	}
	if len(Live.List("ot")) == 0 {
		// OT stays empty until connector ingest — that's honest. No fake PLC rows.
	}
	if len(Live.List("mobile")) == 0 {
		// Mobile stays empty until MDM ingest.
	}
	// Email / DLP / DNS / ITDR backfill via stronger derives is handled at GET time.
	_ = registry
}

func detectCloudProvider() string {
	switch {
	case os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		return "k8s"
	case fileExists("/sys/class/dmi/id/product_name") && strings.Contains(strings.ToLower(readFile("/sys/class/dmi/id/product_name")), "google"):
		return "gcp"
	case fileExists("/sys/hypervisor/uuid") && strings.HasPrefix(strings.ToLower(readFile("/sys/hypervisor/uuid")), "ec2"):
		return "aws"
	default:
		return "onprem"
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func syncSpotlightFromSBOM() {
	rows := Live.List("sbom")
	vulnMu.Lock()
	defer vulnMu.Unlock()
	live := []Vulnerability{}
	now := time.Now().UTC()
	interesting := func(name string) bool {
		low := strings.ToLower(name)
		return strings.Contains(low, "openssl") || strings.Contains(low, "openssh") ||
			strings.Contains(low, "curl") || strings.Contains(low, "nginx") ||
			strings.Contains(low, "kernel") || strings.Contains(low, "libssl") ||
			strings.Contains(low, "busybox") || strings.Contains(low, "musl")
	}
	for _, r := range rows {
		comp, _ := r["component"].(string)
		ver, _ := r["version"].(string)
		host, _ := r["host"].(string)
		if comp == "" || !interesting(comp) {
			continue
		}
		sev, _ := r["severity"].(string)
		if sev == "" {
			sev = "low"
		}
		score := 5.0
		if sev == "high" || sev == "medium" {
			score = 7.0
		}
		live = append(live, Vulnerability{
			ID: "sbom-" + comp + "-" + ver, CVE: "SBOM-" + strings.ToUpper(comp),
			Severity: sev, Host: host, Product: comp + "@" + ver,
			Exploited: false, ExPRTScore: score,
			Description: "Package observed via agent SBOM inventory", DetectedAt: now,
		})
		if len(live) >= 50 {
			break
		}
	}
	// Fallback: well-known binaries present on disk.
	if len(live) == 0 {
		host, _ := os.Hostname()
		for _, p := range []string{"/usr/bin/curl", "/usr/bin/openssl", "/usr/sbin/sshd", "/bin/busybox"} {
			if !fileExists(p) {
				continue
			}
			name := filepath.Base(p)
			live = append(live, Vulnerability{
				ID: "bin-" + name, CVE: "INV-" + strings.ToUpper(name),
				Severity: "low", Host: host, Product: name,
				Exploited: false, ExPRTScore: 4.0,
				Description: "Binary present on host filesystem", DetectedAt: now,
			})
		}
	}
	if len(live) > 0 {
		vulns = live
	}
}
