// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Inspector analyzer "obfuscation-stats" for kinds script and cmdline.
//
// It measures transparent statistical features of the text (see
// inspect_obf_features.go), combines them with a logistic model whose
// coefficients are listed in inspect_obf_weights.go (trained by the
// reproducible procedure in inspect_obf_train_test.go on a synthetic corpus),
// and emits modest "obf-*" findings. Like the deobfuscation analyzer, its
// findings can never sum to the contract's 40 "suspicious" threshold on their
// own (obfWeightBudget). It decodes nothing, executes nothing and keeps no
// state. Synthetic calibration overstates real accuracy; see
// docs/research-obfuscation.md.

import (
	"context"
	"fmt"
	"math"
	"strings"
)

const (
	obfWeightBudget = 25  // all obf-* findings together; verdict needs 40
	obfMinChars     = 24  // below this the statistics are meaningless
	obfModelVersion = "1" // bump when features or procedure change
)

func init() {
	RegisterAnalyzer("obfuscation-stats", []string{InspectKindScript, InspectKindCmdline}, analyzeObfStats)
}

// obfModelT is a standardized logistic model: p = sigmoid(Bias + sum W_i*(x_i-Mean_i)/Std_i).
type obfModelT struct {
	Mean, Std, W []float64
	Bias         float64
	Threshold    float64
}

// Prob returns the model probability that f is obfuscated (0.5 when untrained).
func (m obfModelT) Prob(f ObfFeatures) float64 {
	if len(m.W) != len(f.V) {
		return 0.5
	}
	z := m.Bias
	for i, x := range f.V {
		s := m.Std[i]
		if s < 1e-9 {
			s = 1
		}
		z += m.W[i] * (x - m.Mean[i]) / s
	}
	return 1 / (1 + math.Exp(-z))
}

func analyzeObfStats(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	text := in.Text
	if len(strings.TrimSpace(text)) < obfMinChars {
		b.Meta("skipped", "too short for statistics")
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lang := obfDetectLang(in.Name, text)
	f := ObfExtract(text, lang)
	if len(obfTrained.W) != len(f.V) {
		b.Meta("skipped", "model not trained")
		return nil
	}
	p := obfTrained.Prob(f)

	fv := make(map[string]float64, len(f.V))
	for i, n := range obfFeatureNames {
		fv[n] = math.Round(f.V[i]*10000) / 10000
	}
	b.Meta("model_version", obfModelVersion)
	b.Meta("language", lang)
	b.Meta("features", fv)
	b.Meta("probability", math.Round(p*10000)/10000)
	b.Meta("threshold", obfTrained.Threshold)
	b.Meta("flagged", p >= obfTrained.Threshold)
	if p < obfTrained.Threshold {
		return nil
	}

	spent := 0
	add := func(id, title, tech string, w int, ev string) {
		if spent+w > obfWeightBudget {
			w = obfWeightBudget - spent
		}
		if w <= 0 {
			return
		}
		spent += w
		sev := "low"
		if w >= 10 {
			sev = "medium"
		}
		b.Finding(InspectFinding{ID: id, Title: title, Severity: sev, Technique: tech, Evidence: ev, Weight: w})
	}
	span := 1 - obfTrained.Threshold
	if span < 1e-6 {
		span = 1e-6
	}
	w := 6 + int(math.Round(8*(p-obfTrained.Threshold)/span)) // 6..14
	add("obf-statistical", "Text statistics resemble obfuscated "+nz(lang, "script"), "T1027",
		w, fmt.Sprintf("p=%.3f threshold=%.3f lang=%s cos_dist=%.3f entropy=%.2f", p, obfTrained.Threshold, nz(lang, "unknown"), f.Get("cos_dist"), f.Get("entropy")))

	// Specific, documented cut-offs. Each only fires once the model has flagged
	// the text, so an isolated idiom in ordinary code stays silent.
	if f.Get("tick_density") >= 0.8 {
		add("obf-tick-escape", "Backtick escapes inside words", "T1027.010", 3, fmt.Sprintf("tick_density=%.2f per 100 chars", f.Get("tick_density")))
	}
	if f.Get("caret_density") >= 0.8 {
		add("obf-caret-insertion", "Caret insertion inside commands", "T1027.010", 3, fmt.Sprintf("caret_density=%.2f per 100 chars", f.Get("caret_density")))
	}
	if f.Get("quote_split") >= 0.4 {
		add("obf-quote-splitting", "Empty quote pairs splitting words", "T1027.010", 3, fmt.Sprintf("quote_split=%.2f per 100 chars", f.Get("quote_split")))
	}
	if f.Get("case_irregular") >= 0.3 && f.Get("case_flip_rate") >= 0.3 {
		add("obf-random-case", "Random letter case", "T1027", 3, fmt.Sprintf("case_irregular=%.2f flip_rate=%.2f", f.Get("case_irregular"), f.Get("case_flip_rate")))
	}
	if f.Get("pat_charcode") >= math.Log1p(4) {
		add("obf-char-code", "Character-code string assembly", "T1027", 3, fmt.Sprintf("pat_charcode=%.2f", f.Get("pat_charcode")))
	}
	if f.Get("concat_density") >= 0.8 || f.Get("format_density") >= 1.0 || f.Get("pat_join") >= math.Log1p(3) {
		add("obf-string-assembly", "Dense string concatenation, format or join operators", "T1027", 3,
			fmt.Sprintf("concat=%.2f format=%.2f join=%.2f", f.Get("concat_density"), f.Get("format_density"), f.Get("pat_join")))
	}
	if f.Get("blob_ratio") >= 0.25 || f.Get("pat_b64decode") > 0 && f.Get("blob_ratio") >= 0.1 {
		add("obf-encoded-blob", "Large encoded blob", "T1027.013", 4, fmt.Sprintf("blob_ratio=%.2f", f.Get("blob_ratio")))
	}
	if f.Get("var_random_frac") >= 0.5 || f.Get("var_surprisal") >= 4.6 {
		add("obf-random-names", "Machine-generated identifier names", "T1027.002", 3, fmt.Sprintf("var_random_frac=%.2f var_surprisal=%.2f", f.Get("var_random_frac"), f.Get("var_surprisal")))
	}
	if f.Get("pat_envsub") > 0 || f.Get("pat_dollarbrace") >= math.Log1p(2) || f.Get("pat_reverse") > 0 {
		add("obf-substring-tricks", "Environment-substring, ${} or reversal tricks", "T1027", 3,
			fmt.Sprintf("envsub=%.2f dollarbrace=%.2f reverse=%.2f", f.Get("pat_envsub"), f.Get("pat_dollarbrace"), f.Get("pat_reverse")))
	}
	if f.Get("pat_dynexec") > 0 && spent > 0 {
		add("obf-dynamic-exec", "Dynamic execution form in statistically odd text", "T1059", 3, fmt.Sprintf("pat_dynexec=%.2f", f.Get("pat_dynexec")))
	}
	return nil
}

func nz(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
