# Provenance-graph analysis: research notes and evaluation

Kavach is observation-only. The provenance module (`internal/edr/prov_*.go`) builds a
per-host graph in memory from the retained store on every request, scores and ranks
causally connected "stories", and traces back/forward from a finding. It never persists
state and never acts on a host. Endpoints (all `requireAuth`, all responses carry `method`
and `limitations`): `GET /v1/prov/graph`, `/v1/prov/stories`, `/v1/prov/trace`, `/v1/prov/status`.

## Papers actually opened

Each was fetched as a full text (PDF) and read in the parts relevant to the mechanism
named below. Summaries are in my own words and describe what I borrowed, not a full
review of the paper.

1. S. M. Milajerdi, R. Gjomemo, B. Eshete, R. Sekar, V. N. Venkatakrishnan.
   *HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows.*
   IEEE Symposium on Security and Privacy (S&P) 2019 (arXiv preprint v2, Jan 2019).
   https://arxiv.org/abs/1810.01594
   Low-level audit events are first mapped to a small vocabulary of attacker techniques,
   and the matched techniques are linked by the information flows between the entities
   involved, giving a compact graph of the campaign. Each technique carries a severity,
   and a graph is scored per kill-chain stage, with the stage scores combined
   multiplicatively so the score grows quickly as more distinct stages appear. The paper
   also describes noise reduction learned from benign data, and a "path factor" that
   favours flows an attacker could influence, which they say greatly reduced dependency
   explosion. I used: rule hit -> ATT&CK tactic, severity weights on a CVSS-like scale,
   per-tactic stage maximum, a diversity/order bonus in the story score (my own additive
   form, not their weighted product), and refusing to traverse high-fanout nodes.

2. Q. Wang, W. U. Hassan, D. Li, K. Jee, X. Yu, K. Zou, J. Rhee, Z. Chen, W. Cheng,
   C. Gunter, H. Chen. *You Are What You Do: Hunting Stealthy Malware via Data Provenance
   Analysis* (ProvDetector). NDSS 2020. https://dx.doi.org/10.14722/ndss.2020.24167
   Instead of judging a whole graph, ProvDetector ranks causal paths by how rare they are.
   An edge's regularity combines how many hosts show it and how stable the source and
   destination are over time windows, and a path's regularity is the product along it.
   Taking -log2 turns that into an additive path length, so "the K rarest paths" becomes a
   K-longest-path problem on a graph made single-source and single-sink. Selected paths are
   then embedded and judged by a novelty detector trained on benign data. I used only the
   rarity part: -log2 of a smoothed transition frequency per edge, summed along root-to-leaf
   paths inside a story, top 3 reported. I did not implement the host-fraction/stability
   term or the embedding/novelty model.

3. X. Han, T. Pasquier, A. Bates, J. Mickens, M. Seltzer. *UNICORN: Runtime
   Provenance-Based Detector for Advanced Persistent Threats.* NDSS 2020.
   https://arxiv.org/abs/2001.01525
   Unicorn summarises a streaming provenance graph as a fixed-size histogram of local
   substructures, compresses it to a sketch, and learns clusters of normal sketches. It
   down-weights old and causally unrelated histogram elements so a slow attacker cannot be
   hidden by long uneventful history. Kavach does not build sketches or a learned model. I
   took away the design lesson: aggregate on causal relevance and bound state, which is why
   propagation is directional, hop-limited and decaying, and graphs are capped.

4. Z. Cheng, Q. Lv, J. Liang, Y. Wang, D. Sun, T. Pasquier, X. Han. *KAIROS: Practical
   Intrusion Detection and Investigation using Whole-system Provenance.* IEEE S&P 2024
   (arXiv v3, Sep 2023). https://arxiv.org/abs/2308.05034
   Kairos trains an encoder/decoder over edges of benign provenance and uses reconstruction
   error as a per-edge anomaly signal. Errors are aggregated per time window and windows
   with overlapping suspicious nodes are chained into a queue; an alarm raises the queue,
   and the suspicious subgraph is extracted to reconstruct the attack. Kavach has no
   learned edge model. I used the idea that the unit of output is a time-ordered chain of
   related windows/subgraphs rather than a flat alert list, and that investigation should
   return only the suspicious sub-graph, not the whole host graph.

5. M. N. Hossain, S. M. Milajerdi, J. Wang, B. Eshete, R. Gjomemo, R. Sekar, S. Stoller,
   V. N. Venkatakrishnan. *SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit
   Data.* USENIX Security 2017. https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf
   SLEUTH attaches trust/sensitivity tags to subjects and objects, derived from provenance,
   and uses them to prioritise which parts of a huge audit graph matter. Starting from an
   alarm it runs root-cause (backward) and impact (forward) analysis over the tagged
   dependence graph to recover an attack scenario. This is the model for the trace endpoint
   (`dir=back|fwd|both`, hop and node caps). Kavach does not have tags or file-level
   information flow, so its tracing is plain bounded reachability over process,
   destination and (rare) file edges, and is much weaker than SLEUTH's.

6. A. Alsaheel, Y. Nan, S. Ma, L. Yu, G. Walkup, Z. B. Celik, X. Zhang, D. Xu. *ATLAS: A
   Sequence-based Learning Approach for Attack Investigation.* USENIX Security 2021.
   https://people.cs.umass.edu/~shiqingma/papers/2021/sec21-alsaheel.pdf
   ATLAS turns causal subgraphs around a symptom (alert) node into timestamped sequences
   of abstracted events and learns which sequences look like attack steps, then keeps the
   nodes those sequences implicate to form the attack story. It first simplifies the graph
   to keep sequences short. I took only the framing that a story is an ordered sequence
   anchored at an alert, which is why Kavach orders hits in time and rewards kill-chain
   order. No sequence model was built. (The abstract reports ~91% precision / 97% recall on
   ten real APT engagements; those are the authors' numbers, not ours.)

## SNIPPET ONLY (not opened as full text; nothing here is relied on for design)

- Hassan, Guo, Li, Chen, Jee, Li, Bates. *NoDoze: Combatting Threat Alert Fatigue with
  Automated Provenance Triage.* NDSS 2019. (DOI 10.14722/ndss.2019.23349;
  https://ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage)
  Seen only through a search-result summary: it scores events by historical frequency and
  propagates anomaly scores over the provenance graph to triage alerts. The full PDF fetches
  I tried returned HTML, not the paper. Kavach's alert-triage-by-rarity behaviour is
  inspired by this description only and may differ from the real method.
- BEEP, ProTracer, LogGC, and the anomaly-based priority search of Liu et al.: known to me
  only as one-line mentions in ProvDetector's and HOLMES's related-work sections
  (execution partitioning of event-handling loops, or priority search, to curb dependency
  explosion). I did not open them and give no citation details beyond those names. LDX was
  not accessed at all and is not cited as a source of anything.

## What the dependency-explosion limit means here

Backward/forward tracing over a long-lived process (a shell, `sshd`, `init`) reaches
everything it ever started, so unconstrained tracing links unrelated activity. The papers
above attack this with execution partitioning (instrumenting units of work), tag-based
prioritisation or influence-based path factors. Kavach has no instrumentation or data-flow
labels, so it uses blunt controls: a hop cap, a node cap, no traversal through nodes with
more than 25 edges, and story membership defined by *directed* reachability between hits
(sibling relations through a shared ancestor do not link two hits). The cost is that a real
chain passing through a busy hub process is split.

## Method summary (what the code does)

- Graph: process nodes keyed by (host, pid, process_start, exe); parent edges resolved from
  PPID with an exe-match and time-order heuristic; process->destination edges from
  NetworkEvent.PID; process->file edges only where FileEvent.PID is set. Everything that
  cannot be linked is counted in `missing`, never guessed.
- Scoring: findings attach to processes by pid (and process_start when known); the rule's
  ATT&CK tactic comes from the existing rule/content-rule mapping. Weights low=2, medium=6,
  high=8, critical=10. A hit's weight propagates forward to causal descendants for 3 hops,
  retaining 0.6 per hop, max not sum, so a downstream hit inherits decayed suspicion.
- Stories: hits are joined when one is downstream of the other within 6 hops. Story score =
  (sum over distinct tactics of that tactic's best hit weight) x (1 + 0.5 per extra distinct
  tactic) x (1 + 0.25 per extra step in the longest kill-chain-ordered subsequence of hits by
  time). Ties break on path rarity.
- Rarity: R(edge) = smoothed frequency of the (source exe -> destination label) transition
  among edges of that kind, -log2 R, summed along root-to-leaf paths; counts come from the
  retained store (leave-one-out). A package variable `provLineageSource` lets the behaviour
  model's learned lineage counts be plugged in for spawn edges; it is **not wired** in this
  change (I was told not to edit the model file), so the store fallback is what runs.

## Synthetic evaluation

`TestProvEvaluationSynthetic` (`internal/edr/prov_test.go`) generates N = 300 seeded host
scenarios: an init hub with 40 service children, 8 benign shell sessions with short-lived
tools and some connections, 6 isolated noise findings of random severity (some high or
critical), one "hard negative" benign subtree with 2-3 medium/low findings of different
tactics, and one attack chain of 2-6 stages (random severity per stage; about 1 in 7 attack
findings has an unknown pid and cannot be attached).

Run with seeds 1000..1299:

| metric | value |
| --- | --- |
| top-1 story is the attack chain (majority of its hits are attack hits) | 0.763 (229/300) |
| mean precision of the top-1 story's hits | 0.763 |
| mean recall of attached attack hits in the top-1 story | 0.763 |
| baseline: single highest-severity finding is an attack finding | 0.127 |

Precision equals recall here because stories came out pure: top-1 was either entirely the
attack chain or entirely a benign cluster. Breakdown by how many attack findings attached
to a process, as [top-1 correct, scenarios]: 0 attached: 0/4; 1: 0/23; 2: 20/58; 3: 64/70;
4: 63/63; 5: 62/62; 6: 20/20. So the method is reliable once three or more attack stages are
linked and fails mostly when the evidence is one or two hits, where it is by construction
indistinguishable from the planted hard negative (the single-hit and two-hit cases carry no
multi-stage signal to rank on).

**Caveat: these numbers overstate real accuracy.** The scenarios are generated by the same
author as the scorer, the attack always forms one clean parent-child chain, benign noise is
independent and sparse, tactic labels are always present and correct, the benign
background has no real long-tail behaviour, and N and thresholds were chosen after seeing
early results (the first design linked unrelated sessions through a shared `sshd` and scored
0%; I fixed that by requiring directed reachability, which is a real modelling change, but
it also means the design was iterated against this generator). Real hosts have polling gaps,
pid reuse, missing parents, attacker use of benign tooling and noisy rule hits across many
tactics. Treat the figures as a regression guard and a sanity check that stories beat
flat severity ranking, not as a detection rate.

## Honest limits

- It is not a kernel provenance system: no syscall-level read/write/exec edges, no IPC, no
  injection edges; most file events have no writer so file activity is mostly absent.
- Gaps from polling split chains; a stealthy chain with only one rule hit yields a one-hit
  story, ranked on severity alone.
- Parent resolution is heuristic when pids are reused; ambiguous cases become unresolved
  parents (counted) rather than guesses.
- Scores are ranking aids built on existing rule hits; no new detection capability and no
  learned model. The rarity baseline is the retained store, which may be short or itself
  contaminated.
- Retained store limits (events kept per kind) bound the history; graphs are capped at
  2000 nodes by default (5000 maximum) and truncation is reported.
