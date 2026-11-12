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
	// systemd unit names
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			risk := "low"
			n := strings.ToLower(e.Name())
			if strings.Contains(n, "curl") || strings.Contains(n, "nc") || strings.Contains(n, "miner") {
				risk = "high"
			}
			add("systemd", e.Name(), risk)
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
