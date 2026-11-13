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

// inspectConfigMaxBytes is the hard cap on decoded inspect_config_b64 content.
const inspectConfigMaxBytes = 4 << 20

func inspectConfigB64Tool(c *client) mcpserver.Tool {
	return mcpserver.Tool{
		Name: "inspect_config_b64",
		Description: "Assess a configuration file supplied inline as base64 (max 4 MiB decoded) against Kavach's embedded hardening policies and return pass/fail/unknown results with advisory remediation text." +
			" This tool takes content, never a local file path, by design." +
			" Parse-only: nothing is executed, included, fetched or applied. The compliance percentage covers only the submitted file and only policies for its detected format; it is not an audit of the host (includes, drop-ins and runtime overrides are not seen), and the inspector's malware-style score/level is not meaningful for this kind." +
			inspectNote,
		InputSchema: objSchema(map[string]any{
			"content_b64": strProp("Standard base64 of the configuration file; at most 4 MiB decoded"),
			"name":        strProp("Optional label (e.g. original file name) used as a format hint; never used as a path"),
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
			if base64.StdEncoding.DecodedLen(len(args.Content)) > inspectConfigMaxBytes+3 {
				return fmt.Sprintf("content too large: max %d bytes decoded", inspectConfigMaxBytes), true, nil
			}
			data, err := base64.StdEncoding.DecodeString(args.Content)
			if err != nil {
				return "content_b64 is not valid standard base64", true, nil
			}
			if len(data) == 0 || len(data) > inspectConfigMaxBytes {
				return fmt.Sprintf("content must be 1..%d bytes decoded", inspectConfigMaxBytes), true, nil
			}
			path := "/v1/inspect/config"
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

func registerConfigTools(srv *mcpserver.Server, c *client) error {
	return srv.Register(inspectConfigB64Tool(c))
}

// registerObs2Tools wires every tool of this batch. Read-only tools are always
// registered; mutating ones only when allowMutations is set.
func registerObs2Tools(srv *mcpserver.Server, c *client, allowMutations bool) error {
	for _, f := range []func(*mcpserver.Server, *client) error{
		registerValidateTools, registerVulnPrioTools, registerSeqTools, registerContentCovTools,
		registerSyslogTools, registerConfigTools,
	} {
		if err := f(srv, c); err != nil {
			return err
		}
	}
	for _, f := range []func(*mcpserver.Server, *client, bool) error{
		registerFeedbackTools, registerChainsTools, registerCases2Tools, registerSchedTools, registerSLOReportsTools,
	} {
		if err := f(srv, c, allowMutations); err != nil {
			return err
		}
	}
	return nil
}
