// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Command kavach-mcp is a Model Context Protocol (MCP) server exposing a
// running Kavach controller's HTTP API as MCP tools over stdio — sister to
// netra-mcp. See docs/mcp-integration.md.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

const version = "0.1.0"

func main() {
	c := newClient()
	allowMutations := strings.EqualFold(strings.TrimSpace(os.Getenv("KAVACH_MCP_ALLOW_MUTATIONS")), "true")
	srv, err := buildServer(c, allowMutations)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kavach-mcp:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "kavach-mcp %s → %s (mutations=%v)\n", version, c.base, allowMutations)
	if err := srv.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "kavach-mcp:", err)
		os.Exit(1)
	}
}

func buildServer(c *client, allowMutations bool) (*mcpserver.Server, error) {
	srv := mcpserver.New("kavach-mcp", version)
	if err := registerReadTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerAnalystReadTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerOpsReadTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerPrompts(srv); err != nil {
		return nil, err
	}
	if err := registerResources(srv, c); err != nil {
		return nil, err
	}
	if err := registerMoreTools(srv, c, allowMutations); err != nil {
		return nil, err
	}
	if err := registerMore2Tools(srv, c, allowMutations); err != nil {
		return nil, err
	}
	if err := registerSIEMTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerContentTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerContentCustomTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerGlobalSearchTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerCertFeedTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerRuleHealthTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerRegulatoryTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerAdversaryTools(srv, c); err != nil {
		return nil, err
	}
	if allowMutations {
		if err := registerMutateTools(srv, c); err != nil {
			return nil, err
		}
		if err := registerOpsMutateTools(srv, c); err != nil {
			return nil, err
		}
	}
	return srv, nil
}
