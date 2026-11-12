// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type client struct {
	base   string
	token  string
	http   *http.Client
	actor  string
}

func newClient() *client {
	base := strings.TrimRight(firstEnv("KAVACH_URL", "KAVACH_MCP_URL"), "/")
	if base == "" {
		base = "https://127.0.0.1:30899"
	}
	token := firstEnv("KAVACH_TOKEN", "KAVACH_MCP_TOKEN", "ZYVOR_EDR_TOKEN")
	insecure := strings.EqualFold(os.Getenv("KAVACH_MCP_TLS_INSECURE"), "true") ||
		strings.EqualFold(os.Getenv("KAVACH_TLS_INSECURE"), "true")
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // lab/demo controllers use self-signed certs
	}
	return &client{
		base:  base,
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second, Transport: tr},
		actor: firstEnv("KAVACH_MCP_ACTOR", "kavach-mcp"),
	}
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func (c *client) do(ctx context.Context, method, path string, body []byte, headers map[string]string) ([]byte, int, error) {
	if c.token == "" {
		return nil, 0, fmt.Errorf("set KAVACH_TOKEN (or KAVACH_MCP_TOKEN)")
	}
	url := c.base + path
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}
