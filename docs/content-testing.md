# Content testing: detection as code

Kavach ships many built-in detections (49 `web-*` content rules, 6 `web-an-*`, 6 `auth-an-*`, 14 `idp-an-*`, 11 `rwlog-an-*`, 3 tripwire rules and the content packs). Tests written by the same author as the rule show consistency, not coverage or a false-positive rate. This harness makes the examples explicit, runs them through the real detection paths and gives you tools to bring your own logs.

Everything here is observation only and offline. The commands run inside the `kavachctl` process: no server, no token, no network. Nothing is fetched, contacted, blocked or stored, and the tripwire registry is swapped for the duration of a case and restored.

| Command | What it does |
|---|---|
| `kavachctl content test FILE... [--pack PACK.json] [--json]` | Run `kavach-content-tests/1` files. Exit 1 on any failing case. |
| `kavachctl content selftest [--rules] [--pack PACK.json] [--json]` | Every rule must fire on its own positive example and stay quiet on its own negative one. Exit 1 otherwise. |
| `kavachctl content fp-report --benign PATH... [--builtin] [--kind K] [--threshold N] [--fail-on-noisy] [--json]` | Replay clean logs and report per-rule hits and rates. |
| `kavachctl content tested-coverage [--json]` | ATT&CK techniques covered by rules that pass their own positive example. |

## Test file format: `kavach-content-tests/1`

JSON lines. Blank lines and lines starting with `#` or `//` are ignored. The first content line is the header, every later line is one case.

```
{"schema":"kavach-content-tests/1","name":"my web tests"}
{"case":"sqli probe fires","kind":"web","format":"combined","lines":["203.0.113.7 - - [15/Jan/2026:10:00:00 +0000] \"GET /a?id=1%20union%20select%201,2 HTTP/1.1\" 200 5 \"-\" \"curl/8\""],"expect":["web-sqli-union-select"],"forbid":["web-an-ua-rotation"]}
```

Case fields:

| Field | Meaning |
|---|---|
| `case` | Name, 1 to 160 characters. |
| `kind` | The detection path: `web` (access logs: `web-*` content rules and `web-an-*` analytics), `auth` (`auth-an-*`, plus tripwires), `idp` (`idp-an-*`), `ransom` (`rwlog-an-*`), `tripwire` (declared decoys over any log), `event` (content-pack rules over events), `zslog` (exported Zscaler NSS and LSS logs, `zs-an-*`: records or lines, optional `format` of auto, json, csv or tsv), `zspolicy` (exported Zscaler policy review, `zspol-*`: one JSON object in `records`), `zdx` (probe-metric experience score, `zdx-an-*`: records or CSV lines), `netcfg` (network-device configuration review, `netcfg-*`: config text in `lines`, optional `format` of auto, pan-xml, fortigate, asa, iptables or nft). |
| `format` | Web only: `auto` (default), `combined`, `json`, `logfmt`. |
| `host` | Optional host label. |
| `lines` | Raw log lines (web, tripwire) or JSON lines. |
| `records` | JSON objects (auth, idp, ransom, tripwire). |
| `events` | Content-rule events for kind `event`: the same object as a rule `tests.positive` entry, with `kind` set to `process`, `network`, `file`, `registry`, `dns`, `auth` or `module`. |
| `gen` | Synthetic generator, see below. |
| `input` | A file next to the test file, instead of the inline fields. Exclusive with them. Relative path inside the test file's directory only: no absolute path, no `..`, no symlink out. |
| `tripwires` | Decoys for this case: `{"kind":"account\|ip\|value\|hostname\|path","match":"...","label":"..."}` (auth, idp, ransom, tripwire kinds). |
| `dormant_days` | idp only, 7 to 730. |
| `expect` | Rule ids that MUST fire. |
| `forbid` | Rule ids that MUST NOT fire. |
| `exact` | Nothing outside `expect` may fire. |
| `rule` and `polarity` | Shorthand used by the built-in examples: `positive` expects the rule, `negative` forbids it. |

Strict by design: unknown fields, unknown rule ids and cases that assert nothing are errors, so a typo cannot make a test pass. A malformed case line becomes one failing case; the rest of the file still runs. A missing or wrong header (`schema` other than `kavach-content-tests/1`) rejects the file.

### The generator

`gen` builds large inputs without large files: `{"count":N,"start":"RFC3339","step_ms":M,"template":T}`. `T` is a JSON string (a raw line) or a JSON object (a record). In string values, `{i}` is the index, `{i%K}` the index modulo K, `{i/K}` the index divided by K, `{t}` an RFC 3339 time and `{clf}` a common-log time; time is `start + i*step_ms` (default start 2026-01-15T10:00:00Z, step 1000). Example, 60 failures against 25 accounts from 12 addresses:

```
{"case":"stuffing","kind":"auth","gen":[{"count":60,"template":{"time":"{t}","user":"u{i%25}","ip":"198.51.100.{i%12}","outcome":"failure"}}],"expect":["auth-an-credential-stuffing"]}
```

### Output

Per case `PASS` or `FAIL` with `file:line`, then a diff:

```
FAIL  my.jsonl:2  sqli probe fires
      - my.jsonl:2 expected rule web-sqli-union-select did not fire
      + my.jsonl:2 forbidden rule web-an-ua-rotation fired 1x
```

For per-event rules (`web-*` content rules and `event` cases) the diff adds `(input line N)`; windowed analytics have no single line, so no line is given. `--json` prints the whole report (`schema`, `files`, `cases`, `passed`, `failed`, and per case `fired` rule counts with `input_lines`, `diff`, `error`) and the exit code is still 1 on failure, so CI can use both.

`--pack PACK.json` adds a content pack (same schema as `internal/edr/content/*.json`, every rule needs positive and negative samples) so you can test your own rules. A pack with an invalid rule is rejected.

### Limits

Test file 4 MiB; 2000 cases per file; 50000 records or lines per case; 8 MiB per case input; at most 8 `gen` blocks; 64 rule ids per list; a 20 second budget for event cases. Anything over a limit is a failing case or a rejected file, never a crash; inputs are analysed by the same bounded parsers the server uses.

## Selftest and the CI gate

`content selftest` runs the examples for every registered rule:

- `web-*` content rules: each of the rule's own `tests.positive` and `tests.negative` events is rendered back into the raw access-log line a server would have written and run through the real parser, normaliser and rules (so the examples also exercise the log parser).
- Built-in analytic rules (`web-an-`, `auth-an-`, `idp-an-`, `rwlog-an-`, `tripwire-`): examples live in `internal/edr/content_examples/*.jsonl`, in the format above with `rule` and `polarity`. One positive and one near-miss negative per rule.
- Other content-pack rules: their embedded samples are checked with the matcher.

A rule is `ok` only with at least one positive and one negative example, every positive firing the rule and every negative leaving it silent. Other statuses: `no-examples`, `no-positive-example`, `no-negative-example`, `positive-not-firing`, `negative-fires`.

`TestEveryRuleHasPassingExamples` in `internal/edr` runs this on every `go test`, and checks that every rule registered under a built-in analytic prefix is in the inventory, so a new rule cannot ship without both examples. To add a rule: register it, then add its positive and negative cases to the matching file in `content_examples/` (or the sample events in its pack). Examples must be original text you wrote.

## False-positive report

`content fp-report --benign PATH...` replays logs you believe are clean. PATH is a file or a directory (`.log`, `.txt`, `.json`, `.jsonl`, `.ndjson`; regular files only, no symlinks followed). The kind is taken from the file name (`web`, `access`, `nginx`, `okta`, `entra`, `idp`, `auth`, `login`, `ransom`, `backup`, `event`...), else from the first record's keys; use `--kind` to force it. `--builtin` adds a small synthetic benign corpus built into the binary (about 3000 web lines, 600 auth, 300 idp, 800 file and 6 backup records). The repo's own event corpus works too: `--benign internal/edr/testdata/benign_corpus.json`.

Per rule you get hits, files hit, hits per 1000 records of the rule's kind, and up to 3 redacted samples (the data-governance redaction rules for secrets, e-mail, IP addresses and long hex, plus redaction of secret-looking query values). A rule is flagged noisy when its rate reaches `--threshold` (default 1.0 hits per 1000 records); `--fail-on-noisy` turns that into a non-zero exit.

This measures the supplied corpus only. A rule with no hits can still be noisy in your environment, a hit is a false positive only if the corpus really is clean, and analytic rules count findings (capped per rule per file), not records. Limits: 1000 files, 32 MiB per file (the rest is skipped and reported as truncated), 256 MiB total, a 5 minute budget.

## ATT&CK coverage by tested rule

`content tested-coverage` groups every rule by technique and counts a technique as covered only when at least one mapped rule passes its own positive and negative examples. It lists, per technique, the tested and the untested rules. It measures example coverage of the shipped rules, not coverage of real attacker behaviour.

## Boundaries

Offline and observation only. No test or report calls a cloud, identity, threat-intelligence or other API, scans a host or fetches a link. Test inputs are read from the files you name. Examples and the synthetic corpus are original and use documentation address ranges (RFC 5737) and example domains.
