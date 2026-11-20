package edr

// SSVC decision-tree evaluator (observation only; advice, never action).
//
// Implemented from the published CISA SSVC Guide (November 2022), Table 8
// (Mission Prevalence x Public Well-Being Impact -> Mission and Well-Being)
// and Table 9 (36-row decision table). See docs/research-vuln-priority.md.
//
// CISA's published tree has NO "unknown" value: the guide says to use "the
// most reasonable assumption". Kavach therefore keeps the observed input as
// "unknown", applies a documented default assumption to still reach an
// outcome, and also reports the best/worst outcome over every possible value
// of the unknown inputs, so a caller can see how fragile the outcome is.

const (
	ssvcTreeVersion = "cisa-ssvc-2022-11/table9"

	vpUnknown = "unknown"
)

// Outcomes in ascending urgency.
var ssvcOutcomeNames = []string{"Track", "Track*", "Attend", "Act"}

func ssvcRank(outcome string) int {
	for i, n := range ssvcOutcomeNames {
		if n == outcome {
			return i
		}
	}
	return -1
}

// SSVCInput holds the five decision points; any may be "unknown" (or empty).
type SSVCInput struct {
	Exploitation      string `json:"exploitation"`       // none | poc | active
	Automatable       string `json:"automatable"`        // no | yes
	TechnicalImpact   string `json:"technical_impact"`   // partial | total
	MissionPrevalence string `json:"mission_prevalence"` // minimal | support | essential
	WellBeing         string `json:"public_wellbeing"`   // minimal | material | irreversible
}

// Documented defaults for unknown decision points (CISA: "most reasonable
// assumption"). Chosen as the typical, non-alarming status quo, so that
// absence of evidence never inflates an outcome; the outcome range shows
// the cost of that assumption.
var ssvcDefaults = SSVCInput{
	Exploitation: "none", Automatable: "no", TechnicalImpact: "partial",
	MissionPrevalence: "support", WellBeing: "minimal",
}

var ssvcDomains = map[string][]string{
	"exploitation":       {"none", "poc", "active"},
	"automatable":        {"no", "yes"},
	"technical_impact":   {"partial", "total"},
	"mission_prevalence": {"minimal", "support", "essential"},
	"public_wellbeing":   {"minimal", "material", "irreversible"},
}

// ssvcMissionWB is Table 8.
func ssvcMissionWB(mission, wb string) string {
	t := map[string]map[string]string{
		"minimal":   {"minimal": "low", "material": "medium", "irreversible": "high"},
		"support":   {"minimal": "medium", "material": "medium", "irreversible": "high"},
		"essential": {"minimal": "high", "material": "high", "irreversible": "high"},
	}
	return t[mission][wb]
}

type ssvcRow struct {
	N        int
	Expl     string
	Auto     string
	Tech     string
	MW       string
	Decision string
}

// ssvcTable is Table 9 of the CISA SSVC Guide, row for row.
var ssvcTable = []ssvcRow{
	{1, "none", "no", "partial", "low", "Track"}, {2, "none", "no", "partial", "medium", "Track"}, {3, "none", "no", "partial", "high", "Track"},
	{4, "none", "no", "total", "low", "Track"}, {5, "none", "no", "total", "medium", "Track"}, {6, "none", "no", "total", "high", "Track*"},
	{7, "none", "yes", "partial", "low", "Track"}, {8, "none", "yes", "partial", "medium", "Track"}, {9, "none", "yes", "partial", "high", "Attend"},
	{10, "none", "yes", "total", "low", "Track"}, {11, "none", "yes", "total", "medium", "Track"}, {12, "none", "yes", "total", "high", "Attend"},
	{13, "poc", "no", "partial", "low", "Track"}, {14, "poc", "no", "partial", "medium", "Track"}, {15, "poc", "no", "partial", "high", "Track*"},
	{16, "poc", "no", "total", "low", "Track"}, {17, "poc", "no", "total", "medium", "Track*"}, {18, "poc", "no", "total", "high", "Attend"},
	{19, "poc", "yes", "partial", "low", "Track"}, {20, "poc", "yes", "partial", "medium", "Track"}, {21, "poc", "yes", "partial", "high", "Attend"},
	{22, "poc", "yes", "total", "low", "Track"}, {23, "poc", "yes", "total", "medium", "Track*"}, {24, "poc", "yes", "total", "high", "Attend"},
	{25, "active", "no", "partial", "low", "Track"}, {26, "active", "no", "partial", "medium", "Track"}, {27, "active", "no", "partial", "high", "Attend"},
	{28, "active", "no", "total", "low", "Track"}, {29, "active", "no", "total", "medium", "Attend"}, {30, "active", "no", "total", "high", "Act"},
	{31, "active", "yes", "partial", "low", "Attend"}, {32, "active", "yes", "partial", "medium", "Attend"}, {33, "active", "yes", "partial", "high", "Act"},
	{34, "active", "yes", "total", "low", "Attend"}, {35, "active", "yes", "total", "medium", "Act"}, {36, "active", "yes", "total", "high", "Act"},
}

// ssvcLookup evaluates fully-known inputs. ok=false on an invalid value.
func ssvcLookup(in SSVCInput) (row ssvcRow, ok bool) {
	mw := ssvcMissionWB(in.MissionPrevalence, in.WellBeing)
	for _, r := range ssvcTable {
		if r.Expl == in.Exploitation && r.Auto == in.Automatable && r.Tech == in.TechnicalImpact && r.MW == mw {
			return r, true
		}
	}
	return ssvcRow{}, false
}

func ssvcValid(field, v string) bool {
	for _, x := range ssvcDomains[field] {
		if x == v {
			return true
		}
	}
	return false
}

// SSVCResult is the evaluation of one input set.
type SSVCResult struct {
	Outcome   string    `json:"outcome"`
	Row       int       `json:"table9_row"`
	Effective SSVCInput `json:"effective_inputs"`
	Unknown   []string  `json:"unknown_inputs"`
	BestCase  string    `json:"outcome_if_unknowns_favourable"`
	WorstCase string    `json:"outcome_if_unknowns_adverse"`
	Sensitive bool      `json:"outcome_depends_on_unknowns"`
	MissionWB string    `json:"mission_and_wellbeing"`
}

// ssvcEvaluate applies the tree. Unknown/empty/invalid inputs get the
// documented default and widen the best/worst outcome range.
func ssvcEvaluate(in SSVCInput) SSVCResult {
	names := [5]string{"exploitation", "automatable", "technical_impact", "mission_prevalence", "public_wellbeing"}
	ptrs := [5]*string{&in.Exploitation, &in.Automatable, &in.TechnicalImpact, &in.MissionPrevalence, &in.WellBeing}
	defs := [5]string{ssvcDefaults.Exploitation, ssvcDefaults.Automatable, ssvcDefaults.TechnicalImpact, ssvcDefaults.MissionPrevalence, ssvcDefaults.WellBeing}

	res := SSVCResult{Unknown: []string{}}
	var unk []int
	for i := range names {
		if !ssvcValid(names[i], *ptrs[i]) {
			res.Unknown = append(res.Unknown, names[i])
			unk = append(unk, i)
		}
	}
	// Enumerate every completion of the unknown inputs for the range.
	lo, hi := len(ssvcOutcomeNames), -1
	var rec func(k int, cur [5]string)
	rec = func(k int, cur [5]string) {
		if k == len(unk) {
			r, _ := ssvcLookup(SSVCInput{cur[0], cur[1], cur[2], cur[3], cur[4]})
			o := ssvcRank(r.Decision)
			if o < lo {
				lo = o
			}
			if o > hi {
				hi = o
			}
			return
		}
		for _, v := range ssvcDomains[names[unk[k]]] {
			cur[unk[k]] = v
			rec(k+1, cur)
		}
	}
	rec(0, [5]string{in.Exploitation, in.Automatable, in.TechnicalImpact, in.MissionPrevalence, in.WellBeing})

	for _, i := range unk {
		*ptrs[i] = defs[i]
	}
	row, _ := ssvcLookup(in)
	res.Outcome, res.Row, res.Effective = row.Decision, row.N, in
	res.MissionWB = ssvcMissionWB(in.MissionPrevalence, in.WellBeing)
	res.BestCase, res.WorstCase = ssvcOutcomeNames[lo], ssvcOutcomeNames[hi]
	res.Sensitive = lo != hi
	return res
}
