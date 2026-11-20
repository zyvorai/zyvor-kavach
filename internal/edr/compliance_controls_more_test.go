// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import "testing"

func TestCatalogIntegrity(t *testing.T) {
	fws := map[string]bool{}
	for _, f := range evidenceFrameworks {
		fws[f.ID] = true
	}
	known := map[string]bool{sigDetect: true, sigFleet: true, sigAudit: true, sigSBOM: true, sigFIM: true, sigWorkflow: true, sigAlerts: true, sigTelem: true, sigTimely: true}
	seen := map[string]bool{}
	for _, c := range evidenceCatalog {
		if seen[c.ID] {
			t.Errorf("duplicate id %s", c.ID)
		}
		seen[c.ID] = true
		if !fws[c.Framework] {
			t.Errorf("%s: unknown framework %s", c.ID, c.Framework)
		}
		for _, s := range c.Signals {
			if !known[s] {
				t.Errorf("%s: unknown signal %s", c.ID, s)
			}
		}
		if c.Kind != "" && c.Note == "" {
			t.Errorf("%s: manual/n-a control needs a note", c.ID)
		}
		if c.Kind == "" && len(c.Signals) == 0 {
			t.Errorf("%s: evidence control without signals", c.ID)
		}
	}
}

func TestNewFrameworkRollup(t *testing.T) {
	s := evSignals{Counts: map[string]int{}, Level: map[string]int{sigFleet: 2}}
	for _, fw := range []string{"pci-dss-4", "hipaa", "nist-800-53", "iso27001", "soc2", "dpdp", "rbi", "cis-v8"} {
		if len(BuildControlResults(s, fw)) == 0 {
			t.Errorf("no controls for %s", fw)
		}
	}
}
