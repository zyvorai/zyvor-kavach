// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// ttpTactic is the primary ATT&CK Enterprise tactic of common parent techniques, used only to order
// hints along the kill chain when a detection rule mapping is not available. Techniques that span
// several tactics are listed under the tactic where they are most typically seen.
var ttpTactic = map[string]string{
	"T1001": "Command and Control", "T1003": "Credential Access", "T1005": "Collection", "T1007": "Discovery",
	"T1010": "Discovery", "T1012": "Discovery", "T1014": "Defense Evasion", "T1016": "Discovery",
	"T1018": "Discovery", "T1020": "Exfiltration", "T1021": "Lateral Movement", "T1027": "Defense Evasion",
	"T1029": "Exfiltration", "T1030": "Exfiltration", "T1033": "Discovery", "T1036": "Defense Evasion",
	"T1037": "Persistence", "T1039": "Collection", "T1040": "Credential Access", "T1041": "Exfiltration",
	"T1046": "Discovery", "T1047": "Execution", "T1048": "Exfiltration", "T1049": "Discovery",
	"T1052": "Exfiltration", "T1053": "Persistence", "T1055": "Defense Evasion", "T1056": "Collection",
	"T1057": "Discovery", "T1059": "Execution", "T1068": "Privilege Escalation", "T1069": "Discovery",
	"T1070": "Defense Evasion", "T1071": "Command and Control", "T1074": "Collection", "T1078": "Initial Access",
	"T1082": "Discovery", "T1083": "Discovery", "T1087": "Discovery", "T1090": "Command and Control",
	"T1091": "Initial Access", "T1095": "Command and Control", "T1098": "Persistence", "T1102": "Command and Control",
	"T1105": "Command and Control", "T1106": "Execution", "T1110": "Credential Access", "T1112": "Defense Evasion",
	"T1113": "Collection", "T1114": "Collection", "T1119": "Collection", "T1123": "Collection",
	"T1124": "Discovery", "T1125": "Collection", "T1132": "Command and Control", "T1133": "Initial Access",
	"T1134": "Privilege Escalation", "T1135": "Discovery", "T1136": "Persistence", "T1137": "Persistence",
	"T1140": "Defense Evasion", "T1187": "Credential Access", "T1189": "Initial Access", "T1190": "Initial Access",
	"T1195": "Initial Access", "T1197": "Defense Evasion", "T1199": "Initial Access", "T1203": "Execution",
	"T1204": "Execution", "T1210": "Lateral Movement", "T1211": "Defense Evasion", "T1213": "Collection",
	"T1217": "Discovery", "T1218": "Defense Evasion", "T1219": "Command and Control", "T1220": "Defense Evasion",
	"T1480": "Defense Evasion", "T1482": "Discovery", "T1485": "Impact", "T1486": "Impact",
	"T1489": "Impact", "T1490": "Impact", "T1491": "Impact", "T1496": "Impact",
	"T1505": "Persistence", "T1518": "Discovery", "T1530": "Collection", "T1534": "Lateral Movement",
	"T1539": "Credential Access", "T1542": "Persistence", "T1543": "Persistence", "T1546": "Persistence",
	"T1547": "Persistence", "T1548": "Privilege Escalation", "T1550": "Lateral Movement", "T1552": "Credential Access",
	"T1553": "Defense Evasion", "T1555": "Credential Access", "T1556": "Credential Access", "T1557": "Credential Access",
	"T1558": "Credential Access", "T1559": "Execution", "T1560": "Collection", "T1561": "Impact",
	"T1562": "Defense Evasion", "T1564": "Defense Evasion", "T1566": "Initial Access", "T1567": "Exfiltration",
	"T1568": "Command and Control", "T1569": "Execution", "T1570": "Lateral Movement", "T1571": "Command and Control",
	"T1572": "Command and Control", "T1573": "Command and Control", "T1574": "Persistence", "T1583": "Resource Development",
	"T1584": "Resource Development", "T1585": "Resource Development", "T1586": "Resource Development", "T1587": "Resource Development",
	"T1588": "Resource Development", "T1589": "Reconnaissance", "T1591": "Reconnaissance", "T1593": "Reconnaissance",
	"T1595": "Reconnaissance", "T1598": "Reconnaissance", "T1608": "Resource Development", "T1610": "Execution",
	"T1611": "Privilege Escalation", "T1613": "Discovery", "T1614": "Discovery", "T1621": "Credential Access",
}

var ttpTacticIdx = func() map[string]int {
	m := map[string]int{}
	for i, t := range attackTactics {
		m[t] = i
	}
	return m
}()

// ttpTacticOf returns the tactic of a technique ("" when unknown).
func ttpTacticOf(id string) string { return ttpTactic[ttpParent(id)] }

// ttpTacticRank orders tactics along the kill chain; unknown tactics sort last.
func ttpTacticRank(t string) int {
	if i, ok := ttpTacticIdx[t]; ok {
		return i
	}
	return len(attackTactics)
}
