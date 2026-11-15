// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"sort"
	"time"
)

// Documented prior for shrinkage: Beta(1,1), i.e. Laplace smoothing
// (k+1)/(n+2), prior mean 0.5, worth two pseudo-verdicts. Deliberately weak.
const (
	feedbackPriorA       = 1.0
	feedbackPriorB       = 1.0
	feedbackMinVerdicts  = 5
	feedbackReviewBelow  = 0.25
	feedbackZ95          = 1.959963984540054
	feedbackStatusOK     = "ok"
	feedbackStatusTooFew = "not_enough_verdicts"
)

// wilson95 returns the Wilson score interval for k successes in n trials.
func wilson95(k, n int) (lo, hi float64) {
	if n <= 0 {
		return 0, 1
	}
	z := feedbackZ95
	nf, p := float64(n), float64(k)/float64(n)
	d := 1 + z*z/nf
	c := p + z*z/(2*nf)
	m := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf))
	lo, hi = (c-m)/d, (c+m)/d
	return math.Max(0, lo), math.Min(1, hi)
}

// shrunkPrecision is the posterior mean under the documented Beta prior.
func shrunkPrecision(k, n int) float64 {
	return (float64(k) + feedbackPriorA) / (float64(n) + feedbackPriorA + feedbackPriorB)
}

// FindingLabel is the per-finding consensus of each actor's latest verdict.
type FindingLabel struct {
	FindingID    string            `json:"finding_id"`
	Rule         string            `json:"rule"`
	Host         string            `json:"host"`
	FindingTime  time.Time         `json:"finding_time"`
	FirstVerdict time.Time         `json:"first_verdict_time"`
	Label        string            `json:"label"`    // positive|negative|contested|undecided
	Verdicts     map[string]string `json:"verdicts"` // actor -> latest verdict
}

// consolidate applies "latest per (finding, actor) wins" then a per-finding
// vote so one finding is never counted twice. true_positive is positive;
// false_positive and benign_expected are negative; needs_more_data abstains.
func consolidate(entries []FeedbackEntry) map[string]*FindingLabel {
	out := map[string]*FindingLabel{}
	for _, e := range entries {
		l := out[e.FindingID]
		if l == nil {
			l = &FindingLabel{FindingID: e.FindingID, Rule: e.Rule, Host: e.Host, FindingTime: e.FindingTime,
				FirstVerdict: e.Time, Verdicts: map[string]string{}}
			out[e.FindingID] = l
		}
		if e.Time.Before(l.FirstVerdict) {
			l.FirstVerdict = e.Time
		}
		l.Verdicts[e.Actor] = e.Verdict // entries are in chain order, so later wins
	}
	for _, l := range out {
		pos, neg := 0, 0
		for _, v := range l.Verdicts {
			switch v {
			case VerdictTruePositive:
				pos++
			case VerdictFalsePositive, VerdictBenignExpected:
				neg++
			}
		}
		switch {
		case pos == 0 && neg == 0:
			l.Label = "undecided"
		case pos > neg:
			l.Label = "positive"
		case neg > pos:
			l.Label = "negative"
		default:
			l.Label = "contested"
		}
	}
	return out
}

type RulePrecision struct {
	Rule      string   `json:"rule"`
	Decided   int      `json:"decided_findings"`
	Contested int      `json:"contested_findings"`
	Undecided int      `json:"undecided_findings"`
	Status    string   `json:"status"`
	Positives *int     `json:"true_positives,omitempty"`
	Observed  *float64 `json:"observed_precision,omitempty"`
	WilsonLo  *float64 `json:"wilson95_low,omitempty"`
	WilsonHi  *float64 `json:"wilson95_high,omitempty"`
	Shrunk    *float64 `json:"shrunk_precision,omitempty"`
	Review    bool     `json:"review_candidate"`
	Note      string   `json:"note"`
}

func fptr(v float64) *float64 { return &v }

// rulePrecisions computes per-rule estimates. Below minN decided findings no
// point estimate is reported. Review marks rules whose whole 95% interval lies
// under reviewBelow; it is advisory and nothing acts on it.
func rulePrecisions(labels map[string]*FindingLabel, minN int, reviewBelow float64) []RulePrecision {
	type acc struct{ pos, neg, con, und int }
	by := map[string]*acc{}
	for _, l := range labels {
		a := by[l.Rule]
		if a == nil {
			a = &acc{}
			by[l.Rule] = a
		}
		switch l.Label {
		case "positive":
			a.pos++
		case "negative":
			a.neg++
		case "contested":
			a.con++
		default:
			a.und++
		}
	}
	out := make([]RulePrecision, 0, len(by))
	for rule, a := range by {
		n := a.pos + a.neg
		r := RulePrecision{Rule: rule, Decided: n, Contested: a.con, Undecided: a.und,
			Note: "advisory only; analysts are noisy and nothing is changed automatically"}
		if n < minN {
			r.Status = feedbackStatusTooFew
		} else {
			lo, hi := wilson95(a.pos, n)
			p := a.pos
			r.Status, r.Positives = feedbackStatusOK, &p
			r.Observed, r.WilsonLo, r.WilsonHi = fptr(float64(a.pos)/float64(n)), fptr(lo), fptr(hi)
			r.Shrunk = fptr(shrunkPrecision(a.pos, n))
			r.Review = hi < reviewBelow
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}
