// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CollectPersistence scans common persistence locations (metadata only).
func CollectPersistence(host string) []map[string]any {
	out := []map[string]any{}
	add := func(typ, name, risk string) {
		out = append(out, map[string]any{"host": host, "type": typ, "name": name, "risk": risk, "source": "agent"})
	}
	// systemd / OpenRC unit names
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/init.d", "/etc/periodic/daily", "/etc/periodic/hourly"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.Contains(dir, "systemd") && !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			typ := "systemd"
			if strings.Contains(dir, "init.d") {
				typ = "openrc"
			} else if strings.Contains(dir, "periodic") {
				typ = "periodic"
			}
			risk := "low"
			n := strings.ToLower(e.Name())
			if strings.Contains(n, "curl") || strings.Contains(n, "nc") || strings.Contains(n, "miner") {
				risk = "high"
			}
			add(typ, e.Name(), risk)
			if len(out) > 200 {
				return out
			}
		}
	}
	// crontabs
	for _, p := range []string{"/etc/crontab"} {
		if b, err := os.ReadFile(p); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				risk := "low"
				low := strings.ToLower(line)
				if strings.Contains(low, "curl") || strings.Contains(low, "wget") || strings.Contains(low, "/dev/tcp") {
					risk = "critical"
				}
				add("cron", truncate(line, 120), risk)
			}
		}
	}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				add("cron.d", e.Name(), "low")
			}
		}
	}
	return out
}

// CollectFirewall inventories host firewall rules (observe-only).
func CollectFirewall(host string) []map[string]any {
	out := []map[string]any{}
	try := func(name string, args ...string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		b, err := cmd.Output()
		if err != nil {
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		n := 0
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "table") {
				continue
			}
			action := "observe"
			low := strings.ToLower(line)
			if strings.Contains(low, "drop") || strings.Contains(low, "reject") {
				action = "block"
			} else if strings.Contains(low, "accept") || strings.Contains(low, "allow") {
				action = "allow"
			}
			out = append(out, map[string]any{
				"id": "fw-" + host + "-" + formatInt(n), "host": host, "name": truncate(line, 80),
				"direction": "mixed", "proto": "any", "action": action, "enabled": true, "source": "agent",
				"raw": truncate(line, 200),
			})
			n++
			if n >= 100 {
				return
			}
		}
	}
	try("nft", "list", "ruleset")
	if len(out) == 0 {
		try("iptables-save")
	}
	if len(out) == 0 {
		try("iptables", "-S")
	}
	// Fallback: listening sockets as observed allow rules (containers often lack iptables).
	if len(out) == 0 {
		if b, err := os.ReadFile("/proc/net/tcp"); err == nil {
			lines := strings.Split(string(b), "\n")
			for i, line := range lines {
				if i == 0 || strings.TrimSpace(line) == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 4 || fields[3] != "0A" { // listen
					continue
				}
				out = append(out, map[string]any{
					"id": "fw-listen-" + formatInt(i), "host": host, "name": "listen:" + fields[1],
					"direction": "in", "proto": "tcp", "action": "allow", "enabled": true, "source": "proc-net",
				})
				if len(out) >= 50 {
					break
				}
			}
		}
	}
	return out
}

// CollectBrowserExtensions scans Chromium-family extension dirs (metadata).
func CollectBrowserExtensions(host string) []map[string]any {
	out := []map[string]any{}
	homes := []string{}
	if h, err := os.UserHomeDir(); err == nil {
		homes = append(homes, h)
	}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}
	seen := map[string]struct{}{}
	for _, home := range homes {
		roots := []string{
			filepath.Join(home, ".config/google-chrome/Default/Extensions"),
			filepath.Join(home, ".config/chromium/Default/Extensions"),
			filepath.Join(home, ".config/microsoft-edge/Default/Extensions"),
			filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions"),
		}
		for _, root := range roots {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				id := e.Name()
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				risk := "low"
				if len(id) < 16 {
					risk = "medium"
				}
				out = append(out, map[string]any{
					"name": id, "host": host, "risk": risk, "source": "agent", "path": filepath.Join(root, id),
				})
			}
		}
	}
	return out
}

// CollectFIMSnapshot records metadata for critical paths (observe-only).
func CollectFIMSnapshot(host string) []map[string]any {
	paths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/hosts",
		"/etc/crontab", "/etc/sudoers",
	}
	out := []map[string]any{}
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		sev := "medium"
		if strings.Contains(p, "shadow") || strings.Contains(p, "sshd") || strings.Contains(p, "sudoers") {
			sev = "high"
		}
		out = append(out, map[string]any{
			"path": p, "host": host, "change": "observed", "severity": sev,
			"mtime": st.ModTime().UTC(), "size": st.Size(), "source": "agent",
		})
	}
	return out
}

// CollectTLSCerts inventories local certificate files (metadata only).
func CollectTLSCerts(host string) []map[string]any {
	out := []map[string]any{}
	roots := []string{"/etc/ssl/certs", "/etc/pki/tls/certs", "/run/tls", "/etc/kavach/tls"}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !(strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".cert")) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			risk := "low"
			if strings.Contains(strings.ToLower(name), "self") || info.Size() < 200 {
				risk = "medium"
			}
			out = append(out, map[string]any{
				"host": host, "path": filepath.Join(root, name), "not_after": "",
				"issuer": "file", "risk": risk, "source": "agent", "size": info.Size(),
			})
			if len(out) >= 100 {
				return out
			}
		}
	}
	return out
}

// CollectPackages returns a lightweight SBOM from package managers.
func CollectPackages(host string) []map[string]any {
	out := []map[string]any{}
	addLine := func(component, version string) {
		sev := "low"
		low := strings.ToLower(component)
		if strings.Contains(low, "openssl") || strings.Contains(low, "curl") || strings.Contains(low, "openssh") {
			sev = "medium"
		}
		out = append(out, map[string]any{
			"component": component, "version": version, "host": host, "severity": sev,
			"cves": []string{}, "source": "agent",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output(); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			parts := strings.Split(sc.Text(), "\t")
			if len(parts) >= 2 {
				addLine(parts[0], parts[1])
			}
			if len(out) >= 300 {
				break
			}
		}
		return out
	}
	if b, err := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n").Output(); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			parts := strings.Split(sc.Text(), "\t")
			if len(parts) >= 2 {
				addLine(parts[0], parts[1])
			}
			if len(out) >= 300 {
				break
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	// Alpine
	if b, err := exec.CommandContext(ctx, "apk", "info", "-v").Output(); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			// name-version-release
			idx := strings.LastIndex(line, "-")
			if idx <= 0 {
				addLine(line, "")
				continue
			}
			rest := line[:idx]
			ver := line[idx+1:]
			idx2 := strings.LastIndex(rest, "-")
			if idx2 > 0 && rest[idx2+1] >= '0' && rest[idx2+1] <= '9' {
				addLine(rest[:idx2], rest[idx2+1:]+"-"+ver)
			} else {
				addLine(rest, ver)
			}
			if len(out) >= 300 {
				break
			}
		}
	}
	return out
}

func formatInt(n int) string {
	return strconv.Itoa(n)
}

func postInventory(ctx context.Context, endpoint, token, domain, host string, items []map[string]any, replace bool, client *http.Client) error {
	if len(items) == 0 {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{
		"domain": domain, "host": host, "replace": replace, "items": items,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("inventory POST %s: HTTP %d", domain, resp.StatusCode)
	}
	return nil
}

// RunHostCollectors pushes persistence/firewall/browser/sbom inventories periodically.
func RunHostCollectors(ctx context.Context, endpoint, token, host string, client *http.Client) {
	run := func() {
		_ = postInventory(ctx, endpoint, token, "persistence", host, CollectPersistence(host), true, client)
		_ = postInventory(ctx, endpoint, token, "firewall", host, CollectFirewall(host), true, client)
		_ = postInventory(ctx, endpoint, token, "browser", host, CollectBrowserExtensions(host), true, client)
		_ = postInventory(ctx, endpoint, token, "sbom", host, CollectPackages(host), true, client)
		_ = postInventory(ctx, endpoint, token, "tls", host, CollectTLSCerts(host), true, client)
		_ = postInventory(ctx, endpoint, token, "fim", host, CollectFIMSnapshot(host), true, client)
	}
	run()
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
