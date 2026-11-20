// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

// inspectFileMaxBytes is the hard cap on decoded inspect_file_b64 content.
const inspectFileMaxBytes = 4 << 20

const inspectNote = " Static analysis only: the input is parsed, never executed, and nothing is fetched on its behalf. " +
	"Registered without --allow-mutations because it changes no server state beyond the capped in-memory report ring (reports keep the sha256 and findings, not the input)."

func inspectTextTool(kind, what string) endpointTool {
	return endpointTool{name: "inspect_" + kind, method: "POST", path: "/v1/inspect/" + kind,
		description: "Statically inspect " + what + " and return a report (findings, IOCs, decode layers, score, verdict level)." + inspectNote,
		schema: objSchema(map[string]any{
			"text": strProp("The text to inspect (max 4 MiB)"),
			"name": strProp("Optional label for the report; never used as a path"),
		}, "text"), bodyFields: true}
}

// inspectEndpointTools are the plain endpoint-backed inspector tools.
func inspectEndpointTools() []endpointTool {
	return []endpointTool{
		inspectTextTool("script", "a script (shell, PowerShell, JS, Python, ...) supplied as text"),
		inspectTextTool("cmdline", "a single command line supplied as text"),
		inspectTextTool("domain", "a single domain name supplied as text (lexical and structural scoring only; no DNS lookup)"),
		{name: "inspect_reports", method: "GET", path: "/v1/inspect/reports",
			description: "List recent inspector reports from the capped in-memory ring (no input bytes). Read-only.",
			schema:      objSchema(map[string]any{"limit": strProp("Max reports, default 50")}), queryParams: []string{"limit"}},
		{name: "inspect_analyzers", method: "GET", path: "/v1/inspect/analyzers",
			description: "List registered inspector analyzers and the server's max input size. Read-only.",
			schema:      emptySchema()},
	}
}

func inspectFileB64Tool(c *client) mcpserver.Tool {
	return mcpserver.Tool{
		Name: "inspect_file_b64",
		Description: "Statically inspect file content supplied inline as a base64 string (max 4 MiB decoded; PE, ELF, Mach-O, documents, archives and more) and return a report." +
			" This tool takes content, never a local file path, by design." + inspectNote,
		InputSchema: objSchema(map[string]any{
			"content_b64": strProp("Standard base64 of the file bytes; at most 4 MiB decoded"),
			"name":        strProp("Optional label for the report (e.g. original file name); never used as a path"),
		}, "content_b64"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var args struct {
				Content string `json:"content_b64"`
				Name    string `json:"name"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			if args.Content == "" {
				return "content_b64 is required", true, nil
			}
			if base64.StdEncoding.DecodedLen(len(args.Content)) > inspectFileMaxBytes+3 {
				return fmt.Sprintf("content too large: max %d bytes decoded", inspectFileMaxBytes), true, nil
			}
			data, err := base64.StdEncoding.DecodeString(args.Content)
			if err != nil {
				return "content_b64 is not valid standard base64", true, nil
			}
			if len(data) == 0 || len(data) > inspectFileMaxBytes {
				return fmt.Sprintf("content must be 1..%d bytes decoded", inspectFileMaxBytes), true, nil
			}
			path := "/v1/inspect/file"
			if args.Name != "" {
				path += "?name=" + url.QueryEscape(args.Name)
			}
			out, status, err := c.do(ctx, "POST", path, data, map[string]string{"Content-Type": "application/octet-stream"})
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	}
}

func registerInspectTools(srv *mcpserver.Server, c *client) error {
	for _, t := range inspectEndpointTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return srv.Register(inspectFileB64Tool(c))
}
