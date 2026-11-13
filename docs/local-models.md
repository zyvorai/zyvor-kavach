# Local models

Statistical models that learn from this deployment's own telemetry. No external calls, no LLM, no
cloud. Observation only: they produce scores and neighbours for analysts, never enforcement.

<!-- BEGIN behaviour-models -->
## Behaviour models

Source: `internal/edr/ml_behaviour_*.go`. Every response carries `method: "statistical, learned from
this deployment"`, the sample counts it used, and `status: "not_enough_data"` where a model refuses to
score (cold-start guard). A model below its minimum never returns a score.

### Models

| Model | What it learns | Score | Cold-start minimum |
|-------|----------------|-------|--------------------|
| Process lineage (Markov) | parent basename to child basename transition counts, per host and fleet | surprisal `-log2 P(child\|parent)`, additive smoothing 0.5 over the child vocabulary plus one unseen slot; "novel" at >= 7.0 bits | 200 transitions (fleet), 100 (host) |
| Command-line similarity | char 3-5-gram feature hashing into 2^14 dims, sqrt term weights, cosine | nearest known-bad exemplars (built at `init()` from the positive samples of process-type content rules, with rule id, technique and tactic) and the host's own history | exemplars always ready; host history needs 20 vectors |
| Per-host baselines | EWMA (alpha 0.3) mean and variance per hour-of-week slot (168) of exec count, new-destination count, file-event burst | z-score, anomalous at z >= 3.0; sd floored at max(1, 10% of mean) | 48 closed hours per metric and 4 samples in the slot |

Idle hours between two observed hours are folded as zeros (capped at one week of gap). The
new-destination metric uses a bounded hashed set of destinations per host. `GET /v1/ml/baseline` also
reports the 24 hour first-seen executables and destinations from the prevalence graph.

### How learning happens

`RegisterMLBehaviour` starts one background goroutine that, every 2 seconds, copies only the newly
appended tail of the store's process, network and file event slices (the store lock is held just for
that copy), then updates the models outside the store lock. This needs no change to the ingest path.
The tail cursor is persisted so a restart does not re-learn retained events. Each poll is capped at
50,000 events per type. State is saved atomically at most every 30 seconds.

### Endpoints (all require auth)

- `GET /v1/ml/status` sample counts and ready flags per model.
- `GET /v1/ml/lineage?host=&limit=` ranked transitions by surprisal (fleet when no host).
- `GET /v1/ml/similar?q=<command line>&host=` nearest exemplars (rule id, technique, similarity) and, with `host`, the host-history similarity.
- `GET /v1/ml/baseline?host=` per-metric slot mean/sd, last closed hour z-score, open (partial) hour, first-seen data.
- `POST /v1/ml/reset` (admin or session) discards all learned state; retained events are not re-learned.
- `POST /v1/ml/learn/replay` (admin or session) rebuilds the models from the events retained in the store.

State file: `<store>.mlbehaviour.json`, see `docs/persistence-files.md`.

### Evaluation (synthetic fixtures, enforced by tests)

`go test ./internal/edr -run 'TestML(Lineage|Similarity|Baseline)Evaluation' -v`. The tests fail if the
numbers regress below the gates shown. Numbers are from a seeded run on this repository.

| Model | Fixture | Result at the documented threshold | Test gate |
|-------|---------|------------------------------------|-----------|
| Lineage | 5,000 benign transitions (38 pairs incl. a rare long tail) for training; 5,000 held-out benign draws; 15 injected known-parent/new-child transitions (for example `winword.exe` to `powershell.exe`, `nginx` to `sh`) and 4 never-seen-parent transitions | detection 100% (known parent), **0% (never-seen parent)**; false positive rate 0.42% | detection >= 90%, FPR <= 1% |
| Command similarity | 953 exemplars from 679 process rules; 3,812 operator-style variants (other IPs/ports/hosts, `sudo` prefix and redirect, case); 57 everyday benign command lines; 1,079 near-miss negatives from the content rules that no rule matches | detection 92.3%, correct rule or technique attributed 91.8%; FPR 0% on everyday commands, **26.6% on near-miss negatives** | detection >= 80%, everyday FPR <= 2%, near-miss FPR <= 60% |
| Baselines | 8 weeks of hourly counts with a weekday/night/weekend pattern and noise; 6 weeks training, 2 weeks evaluated; 30 injected bursts (4x plus 30) | detection 100%, FPR 1.96% of clean hours at z >= 3.0 | detection >= 90%, FPR <= 3% |

### Caveats

- Synthetic data overstates real accuracy. The benign corpus is small and regular, the injected
  anomalies are clean, and the variants are mutations of the same exemplars the model was built from.
  Expect more false positives and fewer detections on real fleets; treat the scores as triage hints.
- The lineage model is conditional on the parent: a never-seen parent gets only `log2(vocabulary)`
  bits and is not flagged at 7 bits. The `parent_seen` field is returned so analysts can see this.
- Near-miss commands (for example `aws iam list-users` against `aws iam create-access-key`) look
  similar in n-gram space. The similarity score is a nearest-neighbour hint, not a verdict; it
  complements, and does not replace, the content rules.
- Hourly baselines have only about four samples per slot per month; variance is noisy early on and
  the minimum-history guard is the main protection. The open hour is partial and under-counts.
- Learning includes whatever traffic arrives, including attacker activity; a persistent attacker
  becomes part of the baseline over time. `POST /v1/ml/reset` and replay are provided for that case.
- The existing heuristic AI modules (`ai_platform.go`) are unchanged and independent.
<!-- END behaviour-models -->
