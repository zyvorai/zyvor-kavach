// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const caseWfNote = " Case workflow data lives in Kavach's own case store (templates, checklists, SLA hours); SLA figures are targets for people and are not enforced by Kavach."

func cases2ReadTools() []endpointTool {
	return []endpointTool{
		{name: "case_templates_list", method: "GET", path: "/v1/case-templates",
			description: "List case templates (built-in plus custom) with checklists and per-severity SLA hours." + caseWfNote + " Read-only.",
			schema:      emptySchema()},
		{name: "case_template_get", method: "GET", path: "/v1/case-templates/{id}",
			description: "One case template." + caseWfNote + " Read-only.",
			schema:      objSchema(map[string]any{"id": strProp("Template id")}, "id"), pathParams: []string{"id"}},
		{name: "case_workflow_get", method: "GET", path: "/v1/cases/{id}/workflow",
			description: "Workflow view of one case: applied template, checklist progress and SLA status." + caseWfNote + " Read-only.",
			schema:      objSchema(map[string]any{"id": strProp("Case id")}, "id"), pathParams: []string{"id"}},
	}
}

func cases2MutateTools() []endpointTool {
	id := strProp("Case id")
	return []endpointTool{
		{name: "case_assign", method: "POST", path: "/v1/cases/{id}/assign",
			description: "Set the free-text assignee of a case (empty string clears it). Changes the case record and the workflow journal only." + mutNote,
			schema:      objSchema(map[string]any{"id": id, "assignee": strProp("Assignee, max 80 chars")}, "id", "assignee"), pathParams: []string{"id"}, bodyFields: true},
		{name: "case_apply_template", method: "POST", path: "/v1/cases/{id}/apply-template",
			description: "Apply a case template to a case: sets its checklist and SLA, adds a comment and merges the template's tags into the case. Done steps with identical text are kept." + mutNote,
			schema:      objSchema(map[string]any{"id": id, "template_id": strProp("Template id")}, "id", "template_id"), pathParams: []string{"id"}, bodyFields: true},
		{name: "case_checklist_set", method: "POST", path: "/v1/cases/{id}/checklist/{n}",
			description: "Mark one checklist step of a case done or not done (steps are 1-based; a template must be applied first). Changes the workflow record and journal only." + mutNote,
			schema:      objSchema(map[string]any{"id": id, "n": numProp("1-based checklist step number"), "done": boolProp("true to mark done, false to reopen")}, "id", "n", "done"),
			pathParams:  []string{"id", "n"}, bodyFields: true},
	}
}

func registerCases2Tools(srv *mcpserver.Server, c *client, mut bool) error {
	if err := regEndpoints(srv, c, cases2ReadTools()); err != nil {
		return err
	}
	if mut {
		return regEndpoints(srv, c, cases2MutateTools())
	}
	return nil
}
