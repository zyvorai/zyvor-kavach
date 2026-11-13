# Testing

```
go test -race ./...                 # CI job: race detector, reduced statistical corpora
go test ./...                       # full counts, no race detector
go test -race -shuffle=on -count=3 ./internal/edr
```

Both runs are required: the race run proves goroutine safety, the non-race run proves the full
statistical and size-bound coverage. Run them both before releasing.

## Race-only reductions

`race_on_test.go` / `race_off_test.go` export `const raceEnabled`; `scaleN(full, reduced)` picks
the count. The race detector slows the CPU-bound loops below by 8 to 10x and adds no value there:
they are single goroutine, deterministic computations. The race run keeps every code path; it
only samples the corpora. The non-race run keeps the full counts.

| Test | Under `-race` | Full run | Why it is safe |
|---|---|---|---|
| `TestContentPrefilterEquivalence` | 100 generated rules (500), 300 random events (1500), every 5th shipped sample event (all) | all | The test asserts prefilter on/off equivalence per rule and event; sampling still covers every rule against varied events, the complete corpus runs in the non-race job. |
| `TestContentPrefilterSpeedup` | 300 regexes (1000) | 1000 | Ratio check (>= 5x) is unchanged. |
| `TestMLSimilarityEvaluation` | every 5th positive sample (all) | all | Thresholds (detection >= 0.80, FPR limits) are unchanged and still asserted. |
| `TestSimilarityEvaluation` | 10 base blobs (24), 25 unrelated blobs (60) | all | Per-class 90 percent thresholds and zero false matches still asserted. |
| `TestObfEvaluation` | 60 samples per language (150) | 150 | Thresholds unchanged. |
| `TestObfBudgetOverCorpus` | 10 per language (40) | 40 | Budget check per sample unchanged. |
| `TestFileStringsAnalyzerASCIIAndUTF16` | 2 MiB strings blob (24 MiB) | 24 MiB | At 24 MiB the 5 s analyzer budget is exceeded under race on a loaded machine. The input-size bound is exercised in the non-race run. |
| `TestDeobBombCapped`, PDF bomb in `TestFilePDF`, `TestFileZipBombRatio`, `TestByteHugeInputIsBounded` | 8 to 24 MiB bombs (40 to 64 MiB, 32 MiB) | full | Still many times over the cap (deob cap is 1 MiB), so the cap logic runs. |

Skipped under race:

* `TestObfTrain`: retrains the logistic model and compares it to the committed weights. It is a
  sequential, goroutine-free reproducibility check (about 90 s under race). Runs in the non-race job.
* `TestSimilarityWorstCaseSizeRuntime` (already skipped before this change): wall-clock bound
  on a 32 MiB input.

## Shared fixtures

`loadTestRegistry` builds the embedded content registry once per test binary (`sync.Once`); it
is read-only for tests. Tests needing a mutable registry call `buildContentRegistry` themselves.

## Package-level state audit

No test calls `t.Parallel()`: the package has too much shared global state to make it safe
without a larger refactor, and the reductions above already meet the time budget. Globals, and
how each is handled:

| Global | Handling |
|---|---|
| `mlRarityProvider` (was exported `MLRarityProvider`) | atomic pointer; `RegisterMLBehaviour` clears it (owner-checked) on `Store.Close`. Test overrides use `setMLRarityProvider(fn)()`. |
| `feedbackRuleTrust` (was exported `FeedbackRuleTrust`) | atomic pointer; cleared on `Store.Close`. |
| `excSvc`, `schedSvc`, `ruleSvc` | atomic pointers; cleared (compare-and-swap) on `Store.Close`. |
| `Live` (domain inventory) | persist path is a field (no longer `os.Setenv("KAVACH_INVENTORY")`, which leaked the first test's TempDir into every later test); persist goroutines are tracked and waited on in `detach` at `Store.Close`. |
| `certFeedStore`, `certFeedDefs`, `cfInsecure`, `cfExtra` | saved and restored by test cleanups. |
| `ctNow`, `contentTelemetryBudget`, `ebpfAvailable`, `mlExemplars`, analyzer registry (`withAnalyzers`) | mutated only by single tests with cleanups; not parallel-safe, so no test is parallel. |
| `vmFeeds`, `vpEPSS`, `certFeeds` background refreshers | start only when their feature env is set; never started by tests. |

## TempDir cleanup races

Causes found and fixed:

* `Register*` functions (`RegisterFleetSLO`, `RegisterHuntPacks`, `RegisterMLBehaviour`,
  `RegisterReportSched`, `RegisterScheduledDetections`, `RegisterAlerts`, `RegisterIntelFeeds`,
  `RegisterTuningDigest`) started goroutines that wrote next to the store file and could never be
  stopped. They now attach to the store (`Store.OnClose` / `Store.goBG`); `Store.Close` stops and
  waits for them. The daemon never closes the store, so production behaviour is unchanged.
* `BootstrapLivePlatform` set a process-wide env var to the first store's path, so inventory
  persistence in later tests re-created (`MkdirAll`) a deleted TempDir.
* Tests create stores with `testStore(t, ...)`, which registers `Store.Close` as a cleanup that
  runs before TempDir removal.

## Not touched

* Wall-clock polling loops in `syslog_test.go`, `alerts_test.go`, `report_sched_test.go`,
  `observability_test.go`: they poll a condition with a deadline; the few fixed sleeps assert
  absence of an event.
* Production `time.Sleep` refresh loops in `vuln_feeds.go`, `vuln_prio_epss.go`, `cert_feeds.go`
  (env gated, not started in tests).
