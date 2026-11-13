# Local models: beaconing, draft-rule synthesis, priority fusion

Statistical, local and explainable. No LLM, no network, nothing persisted by these endpoints.
All three require auth. `POST /v1/ml/synthesize` is a POST only because it takes a body; it
changes no state. Observation only. Code: `internal/edr/ml_net*.go`, registered by `RegisterMLNet`.

## GET /v1/ml/beacons

Per `(host, destination)` series of retained `NetworkEvent` timestamps (the store keeps the most
recent `max` network events). Query: `host`, `min_events` (default 8, min 4), `limit` (20),
`min_score`, `exclude_private=1`.

Per series: count, mean, median, coefficient of variation, jitter ratio (MAD/median), burstiness
(Goh-Barabasi B), dominant period (histogram mode refined by the median of its neighbourhood),
autocorrelation at the period lag, a 12-bin interval histogram over [0, 3 x median], the score and
its factors. Fewer than `min_events` events: counted under `not_enough_data`, never scored.

Score (0-100) = `100 * clamp01((0.50*regularity + 0.35*concentration + 0.15*periodicity) * (1 - max(0,B)) * confidence)`

| factor | definition |
|---|---|
| regularity | `clamp01((1 - rcv)/0.8)`, `rcv = 1.4826*MAD/median` (robust CV). Fixed period -> 1, +-50% jitter ~0.79, Poisson ~0 |
| concentration | `clamp01((f-0.35)/0.65)`, f = share of intervals in [0.5, 1.5] x median (Poisson ~0.35) |
| periodicity | autocorrelation of the event-count series (slot = period/4) at the period lag |
| burstiness penalty | human-like bursty traffic has B>0 and is penalised linearly |
| confidence | `min(1, n/20)` |

Levels: `suspect` >= 60, `high` >= 80.

Benign periodic destinations are skipped (`excluded_benign_periodic`): loopback always; built-in
list of NTP, OS update, OCSP, CDN and connectivity-check names plus `:123`; optional
`exclude_private=1` for RFC1918/link-local. Edit the list by creating
`<store path>.beacon_allowlist.json` (JSON array; entries are host suffixes, exact hosts or `:port`).
The file is read on each request and never written.

## POST /v1/ml/synthesize

Body: exactly one of `{"finding_id": "..."}`, `{"command": "..."}`, `{"event": {LabEvent}}`.
Supports process, file and network events.

1. Tokenise the source (executable basename, parent, command tokens and bigrams, path pieces,
   destination host/port).
2. Count how many benign events each candidate substring matches. The benign set is
   `testdata/benign_corpus.json` (embedded, 1611 events), the negative samples of every embedded
   content pack and the custom-content benign baseline (3167 events total).
3. Greedy conjunction: anchor on the executable name (process), then repeatedly add the candidate
   that removes the most remaining benign matches (ties: flags/paths over plain tokens, instance
   IP literals last, longer pattern), up to 4 conditions, prune unneeded ones, minimum 2.
4. If no 2-4 condition conjunction reaches zero benign matches the call returns 422 with the
   benign events that still match (the source is too generic to synthesize safely).
5. Build the `ContentRule`: id `synth-<hash>`, severity capped at `medium` (`low` when the
   source finding is low/unknown), tags `synthesized`, `needs-review`, batch `synthesized`,
   ATT&CK fields borrowed from the source finding's rule when known. Positive samples: the source and
   a host variant. Negative samples: nearest benign events plus the source with one condition
   broken (kept only if the compiled rule rejects them).
6. Validate with `validateCustomRule`, the function behind `POST /v1/content/custom` (schema,
   id collisions, own samples, benign baseline).

Response: `rule`, `validation` (verdict), `conditions` (each with its benign hit count),
`benign_check` (events checked, per-source counts, nearest benign events), `saved:false`,
`enabled:false`, `recommended_initial_lifecycle: "testing"` and next steps. The analyst saves with
`POST /v1/content/custom` and then `PUT /v1/rules/lifecycle/{id}` `{"state":"testing"}`.

## GET /v1/ml/priority?finding_id=|host=

Explainable fusion; advisory, never overrides `/v1/ai/score`. Without parameters it ranks the
retained findings (`limit`, default 50).

| factor | weight | value |
|---|---|---|
| severity | 0.30 | low .2, medium .5, high .8, critical 1 |
| rarity | 0.20 | `MLRarityProvider(host, exe, parent)` (0..1) |
| beaconing | 0.20 | beacon score/100 for the finding's `(host, destination)` |
| asset_criticality | 0.15 | `(criticality-1)/4` from `/v1/posture/assets` |
| rule_trust | 0.15 | `1 - noisy_score/100` from rule health (`BuildRuleHealth`) |

Score = weighted mean of the factors that are present, x100; absent factors are listed under
`omitted` and the remaining weights renormalised (`coverage` shows the weight actually used).
Levels: low <35, medium 35-55, high 55-75, critical >=75.

`var MLRarityProvider func(host, exe, parent string) (float64, bool)` is the only coupling to the
lineage/similarity model; with no provider (or `ok=false`) the rarity factor is omitted.

## Evaluation (synthetic, seeded; fails on regression)

`go test ./internal/edr -run TestBeaconEvaluation -v`, 300 series per class, 20-100 events each,
threshold 60:

| class | flagged | mean score |
|---|---|---|
| fixed period (+-0.3 s noise) | 300/300 (100%) | 96.7 |
| 10% jitter | 300/300 (100%) | 95.8 |
| 25% jitter | 300/300 (100%) | 89.6 |
| 50% jitter | 295/300 (98.3%) | 74.4 |
| human bursty (sessions + lognormal pauses) | 0/300 (0% FP) | 22.2 |
| Poisson (random) | 0/300 (0% FP) | 5.5 |

`go test ./internal/edr -run TestSynthesize -v`: 28 varied source events (process, file,
network; Linux, macOS, Windows). All 28 produce rules that pass `validateCustomRule`, match the
source and match 0 of the 3167 benign events under every event kind; unrelated sources do not
cross-match (at most 2 allowed). Generic benign input is refused (422).

## Honest limits

- Fixtures are synthetic; real fleets have clock skew, proxies, retries and dropped check-ins that
  these classes do not model. Expect to tune the allowlist and thresholds on real data.
- A beacon with long sleeps (hours) needs many retained events; the store keeps only the last
  `max` network events, so slow beacons may stay `not_enough_data`.
- Periodic legitimate software (telemetry agents, monitoring pings, mail polling) not on the
  allowlist will score high. Human-like or heavily randomised (>50% jitter, adaptive) C2 evades it.
- Synthesized rules are only guaranteed against the benign sets above. Zero benign hits is a weak
  proof of low false positives; conditions can be instance-specific (a file name, a one-off IP).
  They are drafts: review, then run in `testing` lifecycle.
- Priority weights are hand-set, not learned. Rarity is only as good as the provider.
