// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// CycloneDX 1.5 JSON emitter for the lockfile analyzer. vmCycloneDX (the host
// inventory exporter) reads the live inventory by host and cannot be called
// with parsed components, so this is a small separate emitter. The shape
// follows the CycloneDX 1.5 schema (bomFormat, specVersion, serialNumber,
// metadata, components with bom-ref/purl/hashes, vulnerabilities with affects).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func lfPurlSeg(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}

// lfPurl builds a Package URL (purl) for a component.
func lfPurl(c lfComp) string {
	var t, ns, n string
	n = c.Name
	switch c.Eco {
	case "npm":
		t = "npm"
		if strings.HasPrefix(n, "@") {
			if i := strings.IndexByte(n, '/'); i > 0 {
				ns, n = n[:i], n[i+1:]
			}
		}
	case "pypi", "cargo", "gem", "nuget", "rpm":
		t = c.Eco
	case "go":
		t = "golang"
		if i := strings.LastIndexByte(n, '/'); i > 0 {
			ns, n = n[:i], n[i+1:]
		}
	case "composer":
		t = "composer"
		if i := strings.IndexByte(n, '/'); i > 0 {
			ns, n = n[:i], n[i+1:]
		}
	case "maven":
		t = "maven"
		if g, a, ok := strings.Cut(n, ":"); ok {
			ns, n = g, a
		}
	case "deb":
		t, ns = "deb", "debian"
	case "apk":
		t, ns = "apk", "alpine"
	default:
		t = "generic"
	}
	var sb strings.Builder
	sb.WriteString("pkg:" + t + "/")
	if ns != "" {
		if c.Eco == "npm" {
			sb.WriteString(lfPurlSeg(ns) + "/")
		} else {
			parts := strings.Split(ns, "/")
			for i, p := range parts {
				parts[i] = lfPurlSeg(p)
			}
			sb.WriteString(strings.Join(parts, "/") + "/")
		}
	}
	sb.WriteString(lfPurlSeg(n))
	if c.Version != "" {
		sb.WriteString("@" + lfPurlSeg(c.Version))
	}
	return sb.String()
}

// lfHash converts a recorded integrity string to a CycloneDX hash, when it
// is one of the formats that maps directly (SRI sha1/256/384/512, or a bare
// hex digest of a known length). Go h1: hashes (base64 of a directory hash)
// and other schemes are not CycloneDX content hashes and are skipped.
func lfHash(s string) (alg, content string, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	if k, v, found := strings.Cut(s, "-"); found {
		var a string
		switch k {
		case "sha1":
			a = "SHA-1"
		case "sha256":
			a = "SHA-256"
		case "sha384":
			a = "SHA-384"
		case "sha512":
			a = "SHA-512"
		}
		if a != "" {
			if raw, err := base64.StdEncoding.DecodeString(v); err == nil {
				return a, hex.EncodeToString(raw), true
			}
			if _, err := hex.DecodeString(v); err == nil {
				return a, strings.ToLower(v), true
			}
		}
	}
	if k, v, found := strings.Cut(s, ":"); found && (k == "sha256" || k == "sha512" || k == "sha1") {
		s = v
	}
	if _, err := hex.DecodeString(s); err == nil {
		switch len(s) {
		case 40:
			return "SHA-1", strings.ToLower(s), true
		case 64:
			return "SHA-256", strings.ToLower(s), true
		case 128:
			return "SHA-512", strings.ToLower(s), true
		}
	}
	return "", "", false
}

func lfSerial(in InspectInput) string {
	h := sha256.Sum256(lfInputBytes(in))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// lfCycloneDX returns the BOM as a map (JSON-serialisable) and whether the
// component list was truncated to lfMaxSBOMComps.
func lfCycloneDX(in InspectInput, comps []lfComp, vulns []lfVuln) (map[string]any, bool) {
	trunc := false
	list := make([]map[string]any, 0, len(comps))
	refOf := map[string]string{}
	used := map[string]bool{}
	for _, c := range comps {
		if len(list) >= lfMaxSBOMComps {
			trunc = true
			break
		}
		ref := lfPurl(c)
		for used[ref] { // purls can collide for unversioned duplicates
			ref += "#" + fmt.Sprint(len(used))
		}
		used[ref] = true
		refOf[strings.ToLower(c.Name)+"@"+c.Version] = ref
		comp := map[string]any{"type": "library", "bom-ref": ref, "name": c.Name, "purl": lfPurl(c)}
		if c.Version != "" {
			comp["version"] = c.Version
		}
		if alg, content, ok := lfHash(c.Integrity); ok {
			comp["hashes"] = []map[string]any{{"alg": alg, "content": content}}
		}
		var props []map[string]any
		if c.Direct != "" {
			props = append(props, map[string]any{"name": "kavach:dependency", "value": c.Direct})
		}
		if c.Version == "" {
			props = append(props, map[string]any{"name": "kavach:pinned", "value": "false"})
		}
		if len(props) > 0 {
			comp["properties"] = props
		}
		list = append(list, comp)
	}
	vs := []map[string]any{}
	for _, v := range vulns {
		ref, ok := refOf[strings.ToLower(v.Package)+"@"+v.Version]
		if !ok {
			continue
		}
		src := map[string]any{"name": "Kavach local advisory data (" + v.Source + ")"}
		if strings.HasPrefix(strings.ToUpper(v.CVE), "CVE-") {
			src = map[string]any{"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(v.CVE)}
		}
		e := map[string]any{"bom-ref": "vuln-" + strings.ToLower(v.CVE) + "-" + ref, "id": v.CVE, "source": src,
			"description": v.Summary, "affects": []map[string]any{{"ref": ref}}}
		if v.CVSS > 0 {
			e["ratings"] = []map[string]any{{"score": v.CVSS, "severity": lfSeverity(v.CVSS), "method": "other"}}
		}
		if v.FixedIn != "" {
			e["recommendation"] = "Advice only: upgrade to " + v.FixedIn + " or later. Kavach does not change anything."
		}
		vs = append(vs, e)
	}
	return map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": lfSerial(in),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools":     map[string]any{"components": []map[string]any{{"type": "application", "name": "kavach", "group": "zyvor"}}},
			"component": map[string]any{"type": "application", "name": truncInspect(lfSafeName(in.Name)), "bom-ref": "submitted-file"},
		},
		"components":      list,
		"vulnerabilities": vs,
	}, trunc
}

func lfSafeName(n string) string {
	if n == "" {
		return "submitted-dependency-file"
	}
	return n
}
