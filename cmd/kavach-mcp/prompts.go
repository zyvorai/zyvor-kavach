// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"fmt"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

func registerPrompts(srv *mcpserver.Server) error {
	prompts := []mcpserver.Prompt{
		{
			Name:        "kavach_triage",
			Description: "Triage the highest-risk Kavach findings with AI assist.",
			Arguments:   []mcpserver.PromptArg{{Name: "focus", Description: "Optional focus (ransomware, identity, xdr)", Required: false}},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "You are a Kavach SOC analyst. Use kavach_ai_briefing, kavach_ai_cluster, kavach_ai_forecast, and kavach_detections. Focus: {{focus}}. Observation-only — never claim containment was enforced.",
			}},
		},
		{
			Name:        "kavach_hunt",
			Description: "Natural-language hunt workflow.",
			Arguments:   []mcpserver.PromptArg{{Name: "hypothesis", Description: "Hunt hypothesis in English", Required: true}},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Run kavach_ai_nl_hunt with text={{hypothesis}}, then enrich hits with kavach_ai_classify and kavach_ai_attack_path.",
			}},
		},
		{
			Name:        "kavach_incident_report",
			Description: "Draft an incident report for a finding.",
			Arguments:   []mcpserver.PromptArg{{Name: "finding_id", Description: "Finding ID", Required: true}},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Generate a report with kavach_ai_report id={{finding_id}}, plus narrative and remediation. Keep guidance observation-only.",
			}},
		},
		{
			Name:        "kavach_host_risk_briefing",
			Description: "Host risk briefing: riskiest hosts, fleet index and trend.",
			Arguments:   []mcpserver.PromptArg{{Name: "days", Description: "Trend window: 7, 14 or 30", Required: false}},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Use kavach_risk_summary, kavach_risk_hosts and kavach_trends days={{days}} to brief on the riskiest hosts and direction of change. Observation-only — never claim containment was enforced.",
			}},
		},
		{
			Name:        "kavach_shift_handoff",
			Description: "SOC shift handoff summary.",
			Arguments:   []mcpserver.PromptArg{{Name: "hours", Description: "Shift length in hours (default 12)", Required: false}},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Use kavach_shift_report hours={{hours}} and kavach_soc_metrics, then kavach_host_storyline for the top risk hosts, to write a shift handoff: open work, unresolved criticals, riskiest hosts, questions for the next shift. Observation-only — never claim containment was enforced.",
			}},
		},
		{
			Name:        "kavach_compliance_gap_review",
			Description: "Review compliance control gaps for a framework.",
			Arguments:   []mcpserver.PromptArg{{Name: "framework", Description: "cis-v8|nist-csf-2|soc2|iso27001|rbi|cert-in|dpdp", Required: true}},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Use kavach_compliance_controls framework={{framework}} and kavach_compliance_evidence framework={{framework}} format=json to list controls lacking observable evidence and suggest how to close each gap. Results are observation evidence, not certification; for cert-in also check kavach_cert_in_clock (Kavach files no reports).",
			}},
		},
		{
			Name:        "kavach_xdr",
			Description: "Cross-domain Netra×Kavach investigation.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Use kavach_ai_xdr_fusion, kavach_sensor, and kavach_recent_events to explain endpoint+network correlation.",
			}},
		},
	}
	for _, p := range prompts {
		if err := srv.RegisterPrompt(p); err != nil {
			return err
		}
	}
	return nil
}

func registerResources(srv *mcpserver.Server, c *client) error {
	resources := []mcpserver.Resource{
		{
			URI: "kavach://summary", Name: "summary", MimeType: "application/json",
			Description: "Live /v1/summary JSON",
			Read: func(ctx context.Context) (string, error) {
				b, status, err := c.do(ctx, "GET", "/v1/summary", nil, nil)
				if err != nil {
					return "", err
				}
				if status >= 300 {
					return "", fmt.Errorf("summary status %d: %s", status, string(b))
				}
				return string(b), nil
			},
		},
		{
			URI: "kavach://ai/briefing", Name: "ai-briefing", MimeType: "application/json",
			Description: "Live AI daily briefing",
			Read: func(ctx context.Context) (string, error) {
				b, status, err := c.do(ctx, "GET", "/v1/ai/briefing", nil, nil)
				if err != nil {
					return "", err
				}
				if status >= 300 {
					return "", fmt.Errorf("briefing status %d: %s", status, string(b))
				}
				return string(b), nil
			},
		},
		{
			URI: "kavach://ai/capabilities", Name: "ai-capabilities", MimeType: "application/json",
			Description: "AI capability catalog",
			Read: func(ctx context.Context) (string, error) {
				b, status, err := c.do(ctx, "GET", "/v1/ai/capabilities", nil, nil)
				if err != nil {
					return "", err
				}
				if status >= 300 {
					return "", fmt.Errorf("capabilities status %d: %s", status, string(b))
				}
				return string(b), nil
			},
		},
		{
			URI: "kavach://modules", Name: "modules", MimeType: "application/json",
			Description: "Kavach module capability map",
			Read: func(ctx context.Context) (string, error) {
				b, status, err := c.do(ctx, "GET", "/v1/modules", nil, nil)
				if err != nil {
					return "", err
				}
				if status >= 300 {
					return "", fmt.Errorf("modules status %d: %s", status, string(b))
				}
				return string(b), nil
			},
		},
	}
	for _, r := range resources {
		if err := srv.RegisterResource(r); err != nil {
			return err
		}
	}
	return nil
}
