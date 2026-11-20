package edr

func ctHours(c, h, m, l int) map[string]int {
	return map[string]int{"critical": c, "high": h, "medium": m, "low": l}
}

// Built-in templates. They are read-only; create a custom template to change wording.
var ctDefaults = []CaseTemplate{
	{ID: "tpl-malware-execution", Name: "Malware execution", CaseType: "malware", Severity: "high",
		Checklist: []string{
			"Confirm the flagged program and its full path on the host",
			"Record the parent process chain and the account that ran it",
			"Check whether the same file hash appears on other hosts",
			"Review network connections made by the process",
			"Decide with the host owner whether to isolate or rebuild (performed outside Kavach)",
			"Document the verdict and close the matching findings",
		}, SLAHours: ctHours(4, 8, 24, 72), Tags: []string{"malware", "execution"}, BuiltIn: true},
	{ID: "tpl-suspicious-login", Name: "Suspicious login", CaseType: "identity", Severity: "medium",
		Checklist: []string{
			"Identify the account, source address and login time",
			"Ask the account owner whether the login was expected",
			"Compare against the account's usual hosts and hours",
			"Look for activity after the login (new processes, files, outbound traffic)",
			"Record whether credentials need to be reset by the identity team",
		}, SLAHours: ctHours(2, 6, 24, 72), Tags: []string{"identity", "login"}, BuiltIn: true},
	{ID: "tpl-data-exfiltration", Name: "Data exfiltration", CaseType: "data-loss", Severity: "high",
		Checklist: []string{
			"Identify the destination and how much data went there",
			"List the files or databases read shortly before the transfer",
			"Determine the data classification and who owns it",
			"Check whether other hosts talked to the same destination",
			"Notify the data owner and legal or privacy contact if required",
			"Capture evidence references for the case export",
		}, SLAHours: ctHours(2, 8, 24, 72), Tags: []string{"exfiltration", "data-loss"}, BuiltIn: true},
	{ID: "tpl-ransomware-early-warning", Name: "Ransomware early warning", CaseType: "ransomware", Severity: "critical",
		Checklist: []string{
			"Check for mass file renames, new extensions or ransom notes",
			"Check for backup, shadow-copy or security tool tampering",
			"Identify every host showing the same behaviour",
			"Alert the incident lead immediately and agree containment steps (performed outside Kavach)",
			"Confirm the state of the latest backups",
			"Keep a timeline of observed activity for the post-incident review",
		}, SLAHours: ctHours(1, 2, 8, 24), Tags: []string{"ransomware", "urgent"}, BuiltIn: true},
	{ID: "tpl-cloud-credential-exposure", Name: "Cloud credential exposure", CaseType: "cloud", Severity: "high",
		Checklist: []string{
			"Identify the exposed key, token or secret and the service it belongs to",
			"Find where it was exposed (file, repository, log, command line)",
			"Review cloud audit logs for use of the credential since exposure",
			"Ask the owner to rotate the credential and confirm when done",
			"Search for the same secret in other files and hosts",
		}, SLAHours: ctHours(2, 8, 24, 72), Tags: []string{"cloud", "credentials"}, BuiltIn: true},
	{ID: "tpl-insider-policy-violation", Name: "Insider policy violation", CaseType: "insider", Severity: "medium",
		Checklist: []string{
			"State which policy the activity appears to break",
			"Collect only the evidence needed and note who can see this case",
			"Check for a legitimate business reason with the person's manager",
			"Involve HR or legal before any contact with the person",
			"Record the outcome and any follow-up training or access review",
		}, SLAHours: ctHours(4, 24, 72, 168), Tags: []string{"insider", "policy"}, BuiltIn: true},
}
