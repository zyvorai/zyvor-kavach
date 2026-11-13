// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// inspectMaxFile mirrors edr.InspectMaxBytes (the server refuses larger input).
const inspectMaxFile = 32 << 20

// inspectMaxText mirrors edr.InspectMaxTextBytes.
const inspectMaxText = 4 << 20

const inspectUsage = `usage: kavachctl inspect <command>
  file PATH [--json]            static analysis of a local file (max 32 MiB; never executed)
  script PATH|- [--json]        analyse script text (- reads stdin)
  cmdline TEXT|- [--json]       analyse a command line (- reads stdin)
  domain NAME [--json]          analyse a domain name
  reports [--limit N] [--json]  recent inspection reports
  analyzers [--json]            registered analyzers per kind`

// inspectDispatch handles `kavachctl inspect ...`.
func inspectDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "inspect" {
		return false, nil
	}
	return true, inspectRun(out, args[1:])
}

func inspectRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", inspectUsage)
	}
	pos, f, b := omParse(args[1:], "limit")
	j := b["json"]
	switch args[0] {
	case "file":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kavachctl inspect file PATH [--json]")
		}
		data, name, err := inspectReadFile(pos[0], inspectMaxFile, "32 MiB")
		if err != nil {
			return err
		}
		raw, err := mlCall("POST", "/v1/inspect/file?name="+url.QueryEscape(name), data, map[string]string{"Content-Type": "application/octet-stream"})
		if err != nil {
			return err
		}
		return inspectPrint(out, raw, j)
	case "script":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kavachctl inspect script PATH|- [--json]")
		}
		var text []byte
		var err error
		name := "stdin"
		if pos[0] == "-" {
			text, err = inspectReadStdin()
		} else {
			text, name, err = inspectReadFile(pos[0], inspectMaxText, "4 MiB")
		}
		if err != nil {
			return err
		}
		return inspectText(out, "script", string(text), name, j)
	case "cmdline":
		text := strings.Join(pos, " ")
		if len(pos) == 1 && pos[0] == "-" {
			t, err := inspectReadStdin()
			if err != nil {
				return err
			}
			text = string(t)
		}
		if strings.TrimSpace(text) == "" {
			return fmt.Errorf("usage: kavachctl inspect cmdline TEXT|- [--json]")
		}
		return inspectText(out, "cmdline", text, "", j)
	case "domain":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kavachctl inspect domain NAME [--json]")
		}
		return inspectText(out, "domain", pos[0], "", j)
	case "reports":
		raw, err := mlCall("GET", omQuery("/v1/inspect/reports", f, "limit"), nil, nil)
		if err != nil {
			return err
		}
		return inspectReports(out, raw, j)
	case "analyzers":
		raw, err := mlCall("GET", "/v1/inspect/analyzers", nil, nil)
		if err != nil {
			return err
		}
		return inspectAnalyzers(out, raw, j)
	}
	return fmt.Errorf("unknown inspect command %q\n%s", args[0], inspectUsage)
}

// inspectReadFile reads exactly the file the user named. A named symlink is resolved once (its
// target is what the user asked for); directories, devices and sockets are refused, and the size
// cap is enforced both from stat and while reading.
func inspectReadFile(path string, max int64, human string) ([]byte, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if !fi.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > max {
		return nil, "", fmt.Errorf("%s is %d bytes; the inspector accepts at most %d bytes (%s)", path, fi.Size(), max, human)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > max {
		return nil, "", fmt.Errorf("%s grew beyond %s while reading; refusing", path, human)
	}
	if len(data) == 0 {
		return nil, "", fmt.Errorf("%s is empty", path)
	}
	return data, filepath.Base(path), nil
}

func inspectReadStdin() ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(omStdin, inspectMaxText+1))
	if err != nil {
		return nil, err
	}
	if len(data) > inspectMaxText {
		return nil, fmt.Errorf("stdin exceeds %d bytes (4 MiB)", inspectMaxText)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("stdin is empty")
	}
	return data, nil
}

func inspectText(out io.Writer, kind, text, name string, asJSON bool) error {
	body, _ := json.Marshal(map[string]string{"text": text, "name": name})
	raw, err := mlCall("POST", "/v1/inspect/"+kind, body, nil)
	if err != nil {
		return err
	}
	return inspectPrint(out, raw, asJSON)
}

type inspectReport struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
	Format   string   `json:"format"`
	Score    int      `json:"score"`
	Level    string   `json:"level"`
	Factors  []string `json:"factors"`
	Findings []struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Technique string `json:"technique"`
		Evidence  string `json:"evidence"`
		Weight    int    `json:"weight"`
		Analyzer  string `json:"analyzer"`
	} `json:"findings"`
	IOCs []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"iocs"`
	Layers []struct {
		Depth   int    `json:"depth"`
		Method  string `json:"method"`
		Bytes   int    `json:"bytes"`
		Preview string `json:"preview"`
	} `json:"layers"`
	KnownIOCs []string `json:"known_iocs"`
	Analyzers []string `json:"analyzers"`
	LimitsHit []string `json:"limits_hit"`
	Errors    []string `json:"errors"`
	Mode      string   `json:"mode"`
	Note      string   `json:"note"`
}

func inspectPrint(out io.Writer, raw []byte, asJSON bool) error {
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var r inspectReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	inspectRender(out, &r)
	return nil
}

func inspectRender(out io.Writer, r *inspectReport) {
	fmt.Fprintf(out, "Verdict: %s   Score: %d/100\n", r.Level, r.Score)
	fmt.Fprintf(out, "Report: %s   Kind: %s   Name: %s\n", r.ID, r.Kind, r.Name)
	fmt.Fprintf(out, "SHA256: %s   Size: %d   Format: %s\n", r.SHA256, r.Size, r.Format)
	if len(r.Factors) > 0 {
		fmt.Fprintln(out, "\nFactors:")
		for _, f := range r.Factors {
			fmt.Fprintf(out, "  - %s\n", f)
		}
	}
	fmt.Fprintf(out, "\nFindings (%d):\n", len(r.Findings))
	if len(r.Findings) > 0 {
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tWEIGHT\tTECHNIQUE\tTITLE\tEVIDENCE\tANALYZER")
		for _, f := range r.Findings {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", f.Severity, f.Weight, f.Technique, f.Title, truncate(f.Evidence, 80), f.Analyzer)
		}
		tw.Flush()
	}
	if len(r.IOCs) > 0 {
		fmt.Fprintf(out, "\nIOCs (%d):\n", len(r.IOCs))
		for _, i := range r.IOCs {
			fmt.Fprintf(out, "  %-8s %s\n", i.Type, i.Value)
		}
	}
	if len(r.KnownIOCs) > 0 {
		fmt.Fprintf(out, "\nMatched known IOCs: %s\n", strings.Join(r.KnownIOCs, ", "))
	}
	if len(r.Layers) > 0 {
		fmt.Fprintf(out, "\nLayers (%d):\n", len(r.Layers))
		for _, l := range r.Layers {
			fmt.Fprintf(out, "  depth %d  %s  %d bytes  %s\n", l.Depth, l.Method, l.Bytes, truncate(l.Preview, 80))
		}
	}
	if len(r.LimitsHit) > 0 {
		fmt.Fprintf(out, "\nLimits hit: %s\n", strings.Join(r.LimitsHit, ", "))
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(out, "Analyzer errors: %s\n", strings.Join(r.Errors, "; "))
	}
	if len(r.Analyzers) > 0 {
		fmt.Fprintf(out, "Analyzers: %s\n", strings.Join(r.Analyzers, ", "))
	}
	if r.Note != "" {
		fmt.Fprintf(out, "\n%s\n", r.Note)
	}
}

func inspectReports(out io.Writer, raw []byte, asJSON bool) error {
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var resp struct {
		Count   int             `json:"count"`
		Reports []inspectReport `json:"reports"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tNAME\tVERDICT\tSCORE\tFINDINGS\tSHA256")
	for _, r := range resp.Reports {
		sha := r.SHA256
		if len(sha) > 16 {
			sha = sha[:16]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", r.ID, r.Kind, r.Name, r.Level, r.Score, len(r.Findings), sha)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d reports\n", resp.Count)
	return nil
}

func inspectAnalyzers(out io.Writer, raw []byte, asJSON bool) error {
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var resp struct {
		Analyzers map[string][]string `json:"analyzers"`
		MaxBytes  int64               `json:"max_bytes"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	for _, k := range []string{"file", "script", "cmdline", "domain"} {
		fmt.Fprintf(out, "%-8s %s\n", k, strings.Join(resp.Analyzers[k], ", "))
	}
	fmt.Fprintf(out, "max file size: %d bytes\n", resp.MaxBytes)
	return nil
}
