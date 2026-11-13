// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const feedbackNote = " Analyst verdicts label a biased subset of findings, so rates are not fleet-wide precision; rule precision is advisory (review_candidates prompt a human, never an action). Nothing here edits rules, suppressions or hosts."

func feedbackReadTools() []endpointTool {
	return []endpointTool{
		{name: "feedback_list", method: "GET", path: "/v1/feedback",
			description: "Recorded analyst verdicts on findings, newest first." + feedbackNote + " Read-only.",
			schema:      objSchema(map[string]any{"finding_id": strProp("Filter by finding"), "rule": strProp("Filter by rule"), "host": strProp("Filter by host"), "limit": strProp("1-1000, default 100")}),
			queryParams: []string{"finding_id", "rule", "host", "limit"}},
		{name: "feedback_rules", method: "GET", path: "/v1/feedback/rules",
			description: "Per-rule precision from verdicts (Wilson 95% interval, shrunk estimate); rules with too few verdicts are listed separately as not enough data." + feedbackNote + " Read-only.",
			schema:      objSchema(map[string]any{"min_verdicts": strProp("Minimum decided verdicts, 1-1000"), "review_below": strProp("Flag rules whose whole interval is below this (0-1)")}),
			queryParams: []string{"min_verdicts", "review_below"}},
		{name: "feedback_summary", method: "GET", path: "/v1/feedback/summary",
			description: "Verdict counts, verdict coverage of recent findings, time to first verdict and top FP/TP rules." + feedbackNote + " Read-only.",
			schema:      objSchema(map[string]any{"days": strProp("Recent window 1-365, default 7")}), queryParams: []string{"days"}},
		{name: "feedback_verify", method: "GET", path: "/v1/feedback/verify",
			description: "Verify the hash chain of the feedback log (tamper evidence; first_broken_seq=0 means intact). Read-only.",
			schema:      emptySchema()},
		{name: "competitive", method: "GET", path: "/v1/world/competitive",
			description: "Competitive matrix and backlog: static research data shipped with Kavach, not live market data. Read-only.",
			schema:      emptySchema()},
	}
}

func feedbackMutateTools() []endpointTool {
	return []endpointTool{
		{name: "feedback_record", method: "POST", path: "/v1/feedback",
			description: "Record an analyst verdict on a finding (appends one entry to the hash-chained feedback log). Verdicts only inform advisory rule-trust scores; they do not change rules, suppress findings or touch hosts." + mutNote,
			schema:      objSchema(map[string]any{"finding_id": strProp("Finding id (must exist)"), "verdict": strProp("true_positive, false_positive, benign_expected or needs_more_data"), "note": strProp("Optional note")}, "finding_id", "verdict"),
			bodyFields:  true},
	}
}

func registerFeedbackTools(srv *mcpserver.Server, c *client, mut bool) error {
	if err := regEndpoints(srv, c, feedbackReadTools()); err != nil {
		return err
	}
	if mut {
		return regEndpoints(srv, c, feedbackMutateTools())
	}
	return nil
}
