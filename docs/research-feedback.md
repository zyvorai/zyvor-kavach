# Research notes: analyst feedback loop

Scope: what we read before building `feedback_*.go` (verdicts on findings, per-rule precision with honest uncertainty). Only pages that were actually opened are listed under "Opened"; anything seen only as a search-result snippet is listed separately and was not relied on. Kavach is observation-only: nothing here auto-disables, suppresses or changes a rule.

## Opened (fetched and read)

1. **PACT: Reducing Alert Fatigue in Low-Prevalence SOC Streams with Triggered Active Learning**, arXiv 2605.22324 (https://arxiv.org/html/2605.22324v1). Wraps a frozen alert classifier and asks analysts for labels only when a score-drift trigger fires, mixing near-threshold and highest-score alerts. Labels are applied in batches of at least 32 with a cooldown. On two public benchmarks benign-normalized false positives fell 21 to 43 percent, but recall also dropped (for example about 82 to 72 percent on one set). The authors stress that query-selection biases the labelled sample and that results come from an offline simulator with three seeds. Takeaway for us: labels collected from analysts are a biased subset, so we report coverage and never call a rule's rate "fleet precision". (Only the first 100k characters of the page were read.)
2. **Automated Alert Classification and Triage (AACT)**, arXiv 2505.09843 (https://arxiv.org/html/2505.09843v1). Learns from analysts' normal triage actions (added to an investigation or not) and uses recent per-category action counts as features; low-scoring alerts are auto-closed. Reported a 61 percent alert reduction with about 1.36 percent false negatives in a six-month live run, estimated from sampled auto-closed alerts. They name label noise from analyst mistakes as a direct source of error and propose weighting by analyst experience as future work. Takeaway: record who said what, keep sampling honest, and treat labels as noisy; we also keep the actor on every verdict.
3. **Tuning Detectors** (Red Canary blog, now served at https://www.zscaler.com/blogs/cybersecurity-best-practices/tuning-detectors; the original redcanary.com URL redirects there). Scores each detector by conversion rate (detections over events), analyst time claimed and volume, ranks them weekly, and has analysts sample the worst ones and decide whether to tune, split or leave them. One example raised human-handled conversion from 4 percent to 93 percent. The authors call their weighting "not statistically perfect" and warn that spikes and short-lived noise distort the ranking and that tuning must be checked against history to avoid losing coverage. Takeaway: rank rules to direct human attention, do not automate the change; our review-candidate list follows that shape.
4. **Microsoft Sentinel: Automate threat response with automation rules** (https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules). Documentation only. Describes closing incidents with a reason and comment, and says this helps teams track effectiveness and fine-tune to reduce false positives; it also describes time-limited suppression rules that auto-close known benign incidents. This is the commercial pattern of "classification at close feeds tuning", with suppression as a separate, explicit, human-authored rule. We copy only the first half: record the classification; Kavach does not suppress.
5. **Beta-binomial distribution** (Wikipedia, https://en.wikipedia.org/wiki/Beta-binomial_distribution). States that a Beta(a,b) prior on a success probability gives a Beta(a+k, b+n-k) posterior after k successes in n trials. The page does not discuss shrinkage itself; the posterior-mean formula (a+k)/(a+b+n), a weighted average of the prior mean and the observed rate with weights a+b and n, is standard algebra we applied. Used for the shrunk estimate with Beta(1,1), i.e. Laplace smoothing.

## Seen only as search snippets (not opened, not relied on beyond the statement quoted)

- Brown, Cai and DasGupta, "Interval Estimation for a Binomial Proportion", Statistical Science 2001 (https://projecteuclid.org/euclid.ss/1009213286). Snippet: "we recommend the Wilson interval or the equal-tailed Jeffreys prior interval for small n". The PDF fetch returned empty, so we did not read the paper. We therefore verified Wilson coverage ourselves in tests (below) rather than citing figures.
- Brown, Cai and DasGupta, "Confidence intervals for a binomial proportion and asymptotic expansions", Annals of Statistics 2002. Snippet: Wilson coverage fluctuates around the nominal level; Agresti-Coull is somewhat more conservative.
- Search-result summaries of vendor and practitioner blogs on detection metrics (false positive rate per rule, splitting alert-to-review and review-to-confirm times, feeding dispositions back into rule logic, change control for rule edits). Not opened; they motivated the summary fields (time to first verdict, per-rule volume) only.
- Alahmadi et al., "99% False Positives", USENIX Security 2022, appeared only as a citation in search results.

Not researched: learning to defer and confidence calibration were searched for in passing but no source on them was opened, so nothing here claims to implement them.

## Design decisions

- Verdicts are `true_positive`, `false_positive`, `benign_expected`, `needs_more_data`. For precision, `true_positive` is positive; `false_positive` and `benign_expected` are negative ("the alert was not worth a human"); `needs_more_data` abstains. Each finding counts once: the latest verdict per (finding, actor) wins, then actors vote; ties are "contested" and excluded.
- Actor is only `admin` (bearer token) or `session` (dashboard login), the same identities the analyst journal uses, so "several analysts" collapse to two actors today. A per-analyst identity would need an identity layer that does not exist yet.
- Estimates need at least 5 decided findings; below that the API returns `not_enough_verdicts` and no number. Above it: observed precision, Wilson 95 percent interval, and a posterior mean under Beta(1,1).
- "Review candidate" means the whole Wilson interval is under 0.25 (configurable `review_below`). With 0 true positives that needs at least 12 decided findings. It is a prompt for a person.
- Priority integration: when a rule has enough verdicts, the `rule_trust` factor in `/v1/ml/priority` uses the shrunk precision instead of `1 - noisiness`; otherwise behaviour is unchanged. Priority is a ranking aid only.

## Synthetic evaluation (from `feedback_test.go`, seeded, 20,000 trials per cell)

Labels are drawn independently from a fixed true precision with no analyst error and no drift. Real analysts disagree with each other and with ground truth, label a non-random subset, and rules change over time, so **these numbers overstate real accuracy**. They check that the arithmetic and thresholds behave as intended, not that Kavach's labels are right.

Wilson 95 percent interval coverage (nominal 0.95):

| n | p=0.95 | p=0.50 | p=0.10 |
|---|---|---|---|
| 10 | 0.917 | 0.979 | 0.931 |
| 30 | 0.940 | 0.959 | 0.974 |
| 100 | 0.965 | 0.943 | 0.938 |

Coverage oscillates around 0.95 and dips to about 0.92 at n=10 for extreme precision. The interval is honest on average but not exact.

Mean squared error, raw k/n versus Beta(1,1) shrunk:

| n | p=0.95 raw / shrunk | p=0.50 | p=0.10 | mean of three |
|---|---|---|---|---|
| 5 | 0.0096 / 0.0215 | 0.0503 / 0.0256 | 0.0178 / 0.0220 | 0.0259 / 0.0230 |
| 10 | 0.0047 / 0.0090 | 0.0250 / 0.0174 | 0.0090 / 0.0108 | 0.0129 / 0.0124 |
| 30 | 0.0016 / 0.0022 | 0.0082 / 0.0072 | 0.0031 / 0.0033 | 0.0043 / 0.0043 |

Shrinkage wins clearly only for mid-range rules and is slightly worse for rules near 0 or 1; across the three it wins by about 11 percent at n=5 and 4 percent at n=10 and ties by n=30. So it is a mild stabiliser, not a big accuracy gain. A stronger or fleet-wide empirical prior was not tested.

Review-candidate false flags (flag = Wilson upper bound below 0.25):

| true precision | n | flag rate |
|---|---|---|
| 0.95 | 10, 30 | 0.0000 |
| 0.50 | 20, 40 | 0.0001, 0.0000 |
| 0.10 (truly bad rule) | 10 / 20 / 40 | 0.00 / 0.39 / 0.63 |

Good rules are essentially never flagged. A truly bad rule (10 percent precision) is caught only about 39 percent of the time at 20 verdicts and 63 percent at 40: the flag is deliberately conservative, so a missing flag is not evidence a rule is good.

Tamper tests confirm that editing, reordering, deleting or re-hashing any retained entry breaks the chain at or after the changed entry. The chain detects modification; it cannot stop someone with file access from recomputing the whole chain, and capped history (100,000 entries) drops the oldest entries.
