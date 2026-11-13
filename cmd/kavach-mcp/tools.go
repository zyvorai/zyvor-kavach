// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

type endpointTool struct {
	name        string
	method      string
	path        string
	description string
	schema      map[string]any
	pathParams  []string
	queryParams []string
	bodyFields  bool
}

func registerEndpointTool(srv *mcpserver.Server, c *client, t endpointTool) error {
	return srv.Register(mcpserver.Tool{
		Name:        t.name,
		Description: t.description,
		InputSchema: t.schema,
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			args := map[string]any{}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &args); err != nil {
					return fmt.Sprintf("invalid arguments: %v", err), true, nil
				}
			}
			path := t.path
			for _, name := range t.pathParams {
				v, _ := args[name].(string)
				if v == "" && args[name] != nil {
					v = fmt.Sprint(args[name])
				}
				path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(v))
				delete(args, name)
			}
			q := url.Values{}
			for _, name := range t.queryParams {
				if v, ok := args[name]; ok {
					q.Set(name, fmt.Sprint(v))
					delete(args, name)
				}
			}
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var body []byte
			if t.bodyFields && len(args) > 0 {
				b, err := json.Marshal(args)
				if err != nil {
					return fmt.Sprintf("invalid arguments: %v", err), true, nil
				}
				body = b
			}
			out, status, err := c.do(ctx, t.method, path, body, nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func emptySchema() map[string]any { return objSchema(map[string]any{}) }

func httpResultToToolResult(body []byte, status int) (any, bool, error) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		v = string(body)
	}
	if status < 200 || status >= 300 {
		return map[string]any{"status": status, "body": v}, true, nil
	}
	return v, false, nil
}
