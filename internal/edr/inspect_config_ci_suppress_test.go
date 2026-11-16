// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"testing"
)

func TestConfigAssessNoUnrecognizedForCIYAML(t *testing.T) {
	cases := map[string]InspectInput{
		"gha-by-path": {Kind: InspectKindConfig, Name: ".github/workflows/ci.yml", Text: "name: x\non: push\n"},
		"gitlab":      {Kind: InspectKindConfig, Name: ".gitlab-ci.yml", Text: "stages: [build]\nbuild:\n  script: [make]\n"},
	}
	for name, in := range cases {
		rep := RunAnalyzers(context.Background(), in)
		for _, f := range rep.Findings {
			if f.ID == "cfg-unrecognized-format" {
				t.Errorf("%s: unexpected cfg-unrecognized-format", name)
			}
		}
	}
}
