# Testing

```
go test -race -timeout 30m ./...    # CI job: race detector, reduced statistical corpora (the edr package needs more than Go's default 10m)
go test ./...                       # full counts, no race detector
go test -race -shuffle=on -count=3 ./internal/edr
```

Both runs are required: the race run proves goroutine safety, the non-race run proves the full
statistical and size-bound coverage. Run them both before releasing.

**The `-timeout 30m` is required for the race run.** The `internal/edr` package alone exceeds Go's default
10 minute test timeout under the race detector; without the flag the run is killed with
`panic: test timed out after 10m0s`. CI uses the same flag (`.github/workflows/ci.yml`, job `go`), and
`go-full` runs `go test ./...` without `-race`. `scripts/smoke.sh` is a much smaller local check (tests, vet, build
of the binaries and a narrow race subset); it is not a substitute for the two full runs.

## Fast loops while editing docs or CLI surface

```bash
go test ./internal/edr/ -run 'Docs|OpenAPI'   # docs index, console menu coverage, OpenAPI route coverage
go test ./cmd/...                             # kavachctl, kavach-mcp and netra-bridge, including surface parity
go vet ./...
```

| Test | What it enforces |
|---|---|
| `TestDocsIndexListsEveryDoc` | Every `.md` and `.yaml` under `docs/` is linked from `docs/index.md` or `docs/README.md` (as `(relative/path)`). A new doc must be added to the index |
| `TestDocsConsoleListsMenuPages` | Every console Browse-menu page label appears in `docs/console.md` |
| `TestOpenAPICoversRegisteredRoutes` | Every route registered in `internal/edr` is documented in `docs/openapi.yaml` or on an allowlist with a reason; stale allowlist entries fail |
| `TestEveryGETRouteHasCLICommandOrExemption` (`cmd/kavachctl`) | Every `GET` route has a `kavachctl` command or an entry in `parityExempt`; stale exemptions fail |
| `TestSurfaceToolsReadOnly`, `TestSurfaceToolsRequests` (`cmd/kavach-mcp`) | The parity MCP tools are read-only GETs with no body. There is no automatic MCP route parity test, so new read-only routes are added by hand |
| Help and completion tests (`cmd/kavachctl`) | Every catalog command appears in `--help` and in the completion word list |
| `TestDashboardEveryPageResolves` and siblings | The console page ids, loader guards, g-keys and inline script parse; text token contrast |
| `security_routes_test.go` and siblings | Route walk without credentials, body caps, panics on malformed bodies, header set ([security-review.md](security-review.md)) |

## Fuzz targets

Nine targets live in `internal/edr/security_fuzz_test.go` (inspect text and file bytes, event ingest, telemetry
validate, hunt query parser, lab rule parser, byte-pack parser, syslog parser, Sigma converter). Each ran for 12 seconds
in the security review with no crashers; that is a smoke test, not long-duration fuzzing.

```bash
go test ./internal/edr -run '^$' -fuzz FuzzParseSyslog -fuzztime 30s
```

## Regenerating golden and trained artifacts

| Variable | Effect |
|---|---|
| `KAVACH_UPDATE_GOLDEN=1` | `go test ./internal/edr -run TestSIEMGoldenFormats` rewrites the SIEM export golden files; review the diff before committing |
| `KAVACH_OBF_WRITE=1` | `TestObfTrain` rewrites the committed obfuscation model weights (`inspect_obf_weights.go`) |
| `KAVACH_OBF_REPORT=/path/report.md` | `TestObfEvaluation` writes an evaluation report |

## Honest limits of the test suite

* Detection and similarity corpora are **synthetic**; thresholds prove the code behaves as designed on those corpora,
  not that it catches real attacks ([research-validation-lab.md](research-validation-lab.md)).
* The SIEM mappings, syslog parsers, eBPF programs and Helm/Setura Gateway flows have unit or template-level tests only; no
  live SIEM, device, kernel or cluster is exercised by `go test` ([siem-export.md](siem-export.md),
  [syslog-listener.md](syslog-listener.md), [ebpf.md](ebpf.md)).
* Wall-clock bounds (analyzer budgets) can flake on a heavily loaded machine; the race reductions below exist for that
  reason. Re-run a single failing test with `-run` and `-count=1` before assuming a regression.
* A failing test in a package you did not touch usually means an upstream change in shared registries; run
  `go test -race -shuffle=on -count=3 ./internal/edr` to expose order-dependence.

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
| `TestSimilarityAnalyzerIsWindowed` | 12 MiB input (32 MiB) | 32 MiB | Still beyond the 8 MiB digest window, so windowing and the limit report are exercised; the 5 s analyzer budget was exceeded under race. |
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
| `mlRarityProvider` (was exported `MLRarityProvider`) | atomic pointer; `RegisterMLBehaviour` registers an owner-checked clear as a lifecycle stopper. Test overrides use `setMLRarityProvider(fn)()`. |
| `feedbackRuleTrust` (was exported `FeedbackRuleTrust`) | atomic pointer; owner-checked clear registered as a lifecycle stopper. |
| `excSvc`, `schedSvc`, `ruleSvc` | atomic pointers; cleared (compare-and-swap) by lifecycle stoppers. |
| `Live` (domain inventory) | persist path is a field (no longer `os.Setenv("KAVACH_INVENTORY")`, which leaked the first test's TempDir into every later test); persist goroutines are tracked by `lc.bg`, the path is cleared by a lifecycle stopper. |
| `certFeedStore`, `certFeedDefs`, `cfInsecure`, `cfExtra` | saved and restored by test cleanups. |
| `ctNow`, `contentTelemetryBudget`, `ebpfAvailable`, `mlExemplars`, analyzer registry (`withAnalyzers`) | mutated only by single tests with cleanups; not parallel-safe, so no test is parallel. |
| `vmFeeds`, `vpEPSS`, `certFeeds` background refreshers | start only when their feature env is set; never started by tests. |

## TempDir cleanup races

Causes found and fixed:

* `Register*` workers could not be stopped and wrote next to the store file. They now register
  with the lifecycle registry (`lifecycle.go`: `RegisterStopper`, `LifecycleContext`, `lcGo`),
  which is also the production shutdown path (SIGTERM calls `StopAll`).
* `BootstrapLivePlatform` set a process-wide env var to the first store's path, so inventory
  persistence in later tests re-created (`MkdirAll`) a deleted TempDir.
* Tests create stores with `testStore(t, ...)`, which registers `StopAllForTest` as a cleanup that
  runs before TempDir removal. The registry is process-global; tests are sequential so this is correct.

## Not touched

* Wall-clock polling loops in `syslog_test.go`, `alerts_test.go`, `report_sched_test.go`,
  `observability_test.go`: they poll a condition with a deadline; the few fixed sleeps assert
  absence of an event.
* Production `time.Sleep` refresh loops in `vuln_feeds.go`, `vuln_prio_epss.go`, `cert_feeds.go`
  (env gated, not started in tests).
