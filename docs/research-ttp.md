# Research notes: TTP similarity and attack-chain analytics

Scope: `/v1/ttp/similar`, `/v1/ttp/next`, `/v1/ttp/chains` (`internal/edr/ttp_*.go`). Everything here is
observation-only analytics for hunting. Similarity is not attribution.

## Method of this research

Each entry below was opened with WebFetch on the date of the work (2026-11-13). In most cases only the abstract
or landing page was available to me, not the full paper, so what I record is limited to what that page said.
Entries marked **SNIPPET ONLY** were seen only as a web-search result summary and were not opened; treat them
as leads, not as sources. Nothing was taken from memory. Not covered: MITRE Cyber Analytics Repository (CAR)
and Attack2Vec-style embeddings (no matching paper was found or opened).

## Opened

1. Guru, K., Moss, R. J., Kochenderfer, M. J. "On Technique Identification and Threat-Actor Attribution using
   LLMs and Embedding Models", arXiv:2505.11547 (2025). https://arxiv.org/abs/2505.11547 (abstract page only).
   The authors pipe CTI text through GPT-4 and an embedding model to find ATT&CK techniques, build per-actor
   technique profiles and train a model to predict the actor for a new report. They find the generated
   technique sets are noisy and differ from human-made MITRE group data, although the frequency of techniques is
   similar. Even so the trained attribution model beats a baseline. Takeaway for us: technique profiles per actor
   are a recognised basis for a similarity signal, but input noise is large and the result is only "above
   baseline". The abstract gave no metrics, so I record none.

2. Rani, N., Saha, B., Shukla, S. K. "A Comprehensive Survey of Advanced Persistent Threat Attribution:
   Taxonomy, Methods, Challenges and Open Research Problems", arXiv:2409.11415 (2024).
   https://arxiv.org/abs/2409.11415 (abstract page only). A survey of automated attribution: a taxonomy of
   artifacts used for attribution, a classification of datasets, a review and critique of methods, and open
   problems. The abstract says attribution is hard and that the field is moving from manual to ML-based work. It
   does not name specific failure modes such as false flags, so I do not claim them from this source.

3. Turner, M. J., Carenzo, M., Lasky, J., Morris-King, J., Ross, J. "Technique Inference Engine: A Recommender
   Model to Support Cyber Threat Hunting", arXiv:2503.04819 (2025). https://arxiv.org/abs/2503.04819 and
   https://arxiv.org/html/2503.04819v1 (abstract and HTML body, read via a summarising fetch). Builds a dataset of
   6,236 CTI reports with 43,899 technique observations and trains implicit-feedback recommenders (weighted matrix
   factorization, BPR) to suggest techniques likely also present in a campaign. Reported Recall@20 was about 0.40
   for WMF versus 0.34 for a "most frequent techniques" baseline, i.e. a modest gain. The authors stress that
   techniques are chronically under-reported in CTI, that popular techniques (T1059 in 2,069 of 6,236 reports)
   dominate, and that data comes mostly from one repository. Takeaway: our "next technique" output should be a
   hunting hint, and a popularity baseline is hard to beat by much.

4. Rahman, M. R., Williams, L. "Investigating co-occurrences of MITRE ATT&CK Techniques", arXiv:2211.06495
   (2022). https://arxiv.org/abs/2211.06495 (abstract page only). Applies association rule mining and network
   analysis to technique sets of 115 cybercrime groups and 484 malware entries in ATT&CK. Reports that T1059 and
   T1105 pair with a large number of other techniques, that Defense Evasion and Discovery contribute the most
   techniques, and derives detection and mitigation strategies. Treats technique sets as unordered. This
   supports down-weighting T1059 and T1105 as commodity in our model.

5. Al-Shaer, R., Spring, J. M., Christou, E. "Learning the Associations of MITRE ATT&CK Adversarial Techniques",
   arXiv:2005.01654 (IEEE CNS 2020 preprint). https://arxiv.org/abs/2005.01654 (abstract page only). Uses
   hierarchical clustering on ATT&CK APT and software data to find technique associations; the page reports 98
   associations and that about 78% of associated techniques showed significant mutual information. Supports the
   idea that technique co-occurrence carries some predictive signal, with the caveat that it is derived from the
   same public data the profiles come from.

6. MITRE Center for Threat-Informed Defense, "Attack Flow". https://ctid.mitre.org/projects/attack-flow/
   (project page). A language and tooling to describe flows of ATT&CK techniques with actions, conditions and the
   relationships between them, so multi-step behaviour is analysed as a flow rather than isolated events. It
   motivates our `/v1/ttp/chains` view (ordered techniques and tactic progression). Our chain view is much
   simpler: it orders by time and tactic only and does not model conditions or branching.

7. MITRE Center for Threat-Informed Defense, "Top ATT&CK Techniques".
   https://ctid.mitre.org/projects/top-attack-techniques/ (project page). Prioritises techniques by prevalence,
   common choke points and actionability; the page does not say how they are scored. I only borrow the idea that
   prevalence matters, which is mirrored by our document-frequency weighting and the "commodity" label for
   techniques present in 25% or more of profiles.

8. MITRE CTID, "TRAM: Threat Report ATT&CK Mapper" (GitHub README).
   https://github.com/center-for-threat-informed-defense/tram (the ctid.mitre.org/projects/tram page returned
   404). A tool that maps CTI report text to ATT&CK techniques with SciBERT-based models. The README states it
   identifies only up to 50 common techniques out of the box, needs labelled data and GPUs to customise, and is a
   research effort whose effectiveness is still being assessed. Implication: even automated technique labels of
   reports are incomplete, so profiles derived from them will be incomplete too.

9. TrendAI (Trend Micro), "Threat Attribution Framework: How TrendAI Applies Structure Over Speculation".
   https://www.trendaisecurity.com/en-us/resources-insights/research/threat-attribution-framework-how-trendai-applies-structure-over-speculation
   (vendor blog; commercial bias). Argues attribution needs several independent pieces of evidence, that a single
   indicator is not attribution, and that commodity or open-source tools are weak evidence while custom tooling
   and behaviour persisting across campaigns are stronger. It scores evidence with Admiralty-style reliability
   and credibility ratings and refuses to raise confidence while rival explanations remain. This is the main
   basis for our conservative confidence rules and the "similarity is not attribution" caveats.

10. Rid, T., Buchanan, B. "Attributing Cyber Attacks", Journal of Strategic Studies 38(1-2), 2015, 4-37
    (some records list vol. 39). https://ridt.co/attributing-cyber-attacks (author page, summary only; I did not
    read the article). The page presents attribution as more than a purely technical forensic problem and
    introduces the "Q Model" to structure it; the page does not describe the model's parts, and I do not
    describe them either.

## SNIPPET ONLY (not opened; leads)

- Shin et al., "ART" (reclassification of APT groups from ATT&CK matrices using one-hot tactic vectors and
  cosine similarity), as summarised in a search result citing the survey in item 2. Not verified.
- MDPI Electronics 14(23):4597, a graph of APT groups, TTPs and kill-chain stages with Sentence-BERT
  embeddings. https://www.mdpi.com/2079-9292/14/23/4597. Not opened.
- Hussain and Petrova, Future Internet, LLM-extracted TTPs with classical ML classifiers. Not opened.
- Secureworks column in SC Media, "Incident attribution: beware of jumping to conclusions" (false flags;
  ransomware used as cover for espionage; Olympic Destroyer misattribution). Search-result summary only; the
  Olympic Destroyer and ransomware-as-cover claims are therefore unverified here.
- TEISS "Rethinking attribution" and Abnormal AI glossary on attribution. Search results only.

## Design choices that follow

- TF-IDF style weights over parent-level techniques (sub-techniques rolled up), idf = ln((N+1)/(df+1)) + 1,
  computed once at init from the 101 embedded profiles. Score = mean of TF-IDF cosine and weighted Jaccard.
- Minimum 3 distinct parent techniques, otherwise `not_enough_evidence`. Confidence is never above `moderate`
  and needs at least 3 non-commodity techniques, at least 4 overlapping, score at least 0.45 and a 0.05 margin.
- "Next" hints are the techniques missing from the top 5 matching profiles, weighted by their scores, ordered by
  kill-chain tactic. Labelled a hint, not a prediction (items 3 and 4).
- Every response carries `caveats`.

## Evaluation (ttp_test.go, `TestTTPEvaluation`, seed 42)

Important: the profiles are both the training data and the test data. The hold-out query is a subset of the
true profile's own techniques, which are already in the model, so these numbers are optimistic and say nothing
about performance on real intrusions.

Protocol: for every profile with at least 6 distinct parent techniques, 20 trials each; remove a random 30-50%
of the parent techniques, query with the rest (at least 3 kept), find the rank of the true profile among 101.
Ties count against the true profile. 1,960 queries.

| Metric | Result |
|---|---|
| top-1 | 91.2% |
| top-3 | 98.8% |
| top-5 | 99.8% |
| confidence `moderate` | 1,103 of 1,960 queries; top-1 correct in 1,089 (98.7%) |
| confidence `low` | 857 queries; top-1 correct in 698 (81.4%) |

Most frequent top-1 confusions (true profile -> top-ranked profile, count over 1,960 queries): blackbyte -> alphv
(9), wizard-spider -> conti (8), akira -> medusa (7), patchwork -> fin7 (7), lockbit -> hive (6), medusa -> alphv
(6), transparent-tribe -> patchwork (6), gamaredon -> mustang-panda (4), hive -> alphv (4), akira -> alphv (3),
apt1 -> ke3chang (3), apt10 -> apt39 (3). The confusion is mostly inside ransomware families whose public
profiles share the same encrypt-and-exfiltrate technique set (that is exactly the "TTPs are shared" problem), plus
a few espionage pairs. Wizard Spider and Conti are publicly linked, so that confusion is expected.

Negative controls:

- 500 random technique sets (3-8 techniques drawn uniformly from the 139 techniques in the profiles): none got
  `moderate`; 375 of 500 had at most 2 overlapping techniques with their best profile; median top score 0.216,
  95th percentile 0.324.
- Commodity only: {T1059, T1105} and {T1059} return `not_enough_evidence`. {T1059, T1105, T1566} and
  {T1059, T1105, T1204, T1078} return `low` (top scores 0.418 and 0.398, best profile nomadic-octopus, a small
  profile of commodity techniques), so a ranking is shown but flagged low. Scores of that size should not be
  read as meaningful.

## Honest limits

- Train equals test; no external ground truth was used. Real intrusions mix actors' techniques with
  operator-specific behaviour, so real accuracy will be lower and unknown.
- 101 profiles, medium confidence, derived from public reporting that over-represents certain groups and
  under-reports techniques (item 3).
- Observed techniques on a host come from detection-rule mappings, so only techniques Kavach can detect appear;
  one rule maps to one technique. Findings may be benign or caused by testing.
- The technique-to-tactic table in `ttp_tactics.go` uses one primary tactic per technique; many techniques span
  several. Where a rule mapping exists, its tactic is used for observed techniques.
- Time order of findings reflects detection time, not necessarily attacker action order.
- No claim here about attribution: the endpoints rank resemblance to public profiles only.
