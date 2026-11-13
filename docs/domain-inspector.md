# Domain inspector

Analyzer `domain` (kind `domain`, `POST /v1/inspect/domain`) plus a reusable
scorer, `edr.ScoreDomain(name) DomainScore`. Offline only: no DNS lookup, no
connection, nothing executed. Heuristic, not a verdict engine.

Code: `internal/edr/inspect_domain*.go`, embedded data in
`internal/edr/domaindata/`, corpus in `internal/edr/testdata/domain_*.txt`
(regenerate with `go run internal/edr/testdata/gen_domain_corpus.go internal/edr/testdata`).

## What it does

1. **Parsing.** Lowercase, strip trailing dot, tolerate a pasted URL or `host:port`,
   split labels, validate (length 63/253, empty labels, hyphen edges, illegal
   characters, bad UTF-8), decode `xn--` labels with a built-in RFC 3492 decoder
   (no new dependency). Invalid input produces a `dom-invalid` finding, never a
   panic. Numeric hosts (IPv4/IPv6, decimal, `0x...`) produce `dom-ip-host`.
   Public suffix handling uses a small **partial** embedded list of multi-label
   suffixes (`co.uk`, `com.au`, `github.io`, ...); anything not listed falls back
   to the last label, so registrable-domain extraction is wrong for unlisted
   multi-part suffixes.
2. **DGA-likeness score (0-100)** on the registrable label, as a sum of capped,
   visible points (all listed in `Factors`): tri-gram/bi-gram log-likelihood
   against a model built at `init()` from the embedded word lists (~3,900 base words (more after light inflection); English, ten other languages in ASCII form, and
   brand-neutral tech tokens, all written for this repo), dictionary coverage by
   dynamic-programming segmentation, Shannon entropy, length, digit ratio,
   longest consonant run, vowel ratio, and a dictionary-concatenation shape
   bonus. Labels under 6 characters and non-ASCII labels are not scored.
   Decision threshold: **40** (`DomainDGAThreshold`).
3. **Other checks** (ids prefixed `dom-`, weights 3-35): `dom-mixed-script`
   (Latin with Cyrillic/Greek in one label, also via punycode), `dom-punycode`,
   `dom-deep-subdomain`, `dom-encoded-subdomain` (hex or base32 shaped long
   labels), `dom-suspicious-tld` (weak, embedded list), `dom-typosquat` (edit
   distance 1, or 2 for names of 9+ chars, against 105 embedded brand names; a
   swap counts as 1), `dom-brand-embedded`, `dom-brand-subdomain`,
   `dom-dga-likeness`, `dom-dga-borderline`.
   No finding weighs more than 35, below the contract's "suspicious" level (40),
   so a verdict needs at least two independent signals (tested).

## Evaluation

Fixture corpus, labelled in the files:

* `domain_dga.txt`: 410 **synthetic** names from generators written for this repo:
  random letters (110), short random letters of 6-8 chars (70), dictionary
  concatenation of 2-4 words (70), hex (60), base32 (60), letters+digits (40).
  These are not real malware domains.
* `domain_benign.txt`: 330 names: ~100 real-looking well-known domains, ~100
  deliberately awkward cases (CDN hash hosts, EC2/googlevideo/akamai hosts,
  very long legitimate subdomains, Polish consonant clusters, unusual short
  brands, long keyword concatenations, IDN names) and ~120 generated from a
  held-out word list that is not in the model vocabulary.

Result at threshold 40 (`TestDomainEvaluation`, run `go test -run TestDomainEvaluation -v ./internal/edr`):

| TP | FN | FP | TN | precision | recall | F1 |
|----|----|----|----|-----------|--------|-----|
| 323 | 87 | 8 | 322 | 0.976 | 0.788 | 0.872 |

Per family recall: random letters 105/110, short random 58/70, hex 60/60,
base32 60/60, letters+digits 40/40, **dictionary concatenation 0/70**.

The test fails if recall < 0.75 or precision < 0.95 (the documented floors).

### False positives (8, reported as found)

* `d111111abcdef8.cloudfront.net`, `d3k9f2m8x7q1w5.cloudfront.net`,
  `dq4l2s9x8h1g3z.cloudfront.net`: CDN hash hostnames are indistinguishable from
  random labels by character statistics. `cloudfront.net` is in the suffix list,
  so the hash is treated as the registrable label. Expect many of these in real
  traffic.
* `rzeszow.pl`, `szczecin.pl`, `krzyzanowski.pl`, `bydgoszcz.pl`: legitimate
  Polish names with consonant clusters. The model is English-centred with
  ASCII-folded romance/germanic words.
* `airbnb.com`: a legitimate brand coinage with no vowels in the middle.

Note that only the registrable label is DGA-scored. Benign cases whose odd part
is a subdomain (`zxcvbnm.example.com`, long marketing subdomains, `mail-ej1-f68.google.com`)
are therefore not FPs of the scorer; they are only subject to the tunnelling-shape
rules, where long hex/base32 subdomains (CDN-style) do trigger `dom-encoded-subdomain`
at weight 14. A hash-labelled host such as `a1b2c3d4e5f6a7b8.azurefd.net` is
treated as registrable only when its suffix is listed, which `azurefd.net` is not.

### Honest limits

* **Synthetic data overstates real-world accuracy.** The DGA samples come from
  simple generators that this scorer's features were tuned against (the
  thresholds and calibration constants were chosen while looking at this same
  corpus, so there is no clean holdout). Real DGAs, real registrations and real
  traffic are messier. Treat 0.976/0.788 as an upper bound for this feature
  set, not as expected field performance. Real-world benign sets contain far
  more non-English names, brand coinages and CDN/cloud hosts than this one, so
  real precision will be lower.
* **Dictionary-concatenation DGAs are essentially not detected** (0/70). They
  look like benign keyword domains by every feature here. They surface only as
  `dom-dga-borderline` at best, usually not at all. Detecting them needs
  external intelligence (word-list fingerprints, registration age, passive DNS),
  which this offline analyzer deliberately lacks.
* Short random names (6-8 chars) are the weakest random case (58/70).
* Typosquat and brand checks use a ~110 name list and edit distance; they miss
  most squats and may flag unrelated short names. TLD reputation is a weak signal.
* The public suffix list is partial. IDN labels in non-Latin scripts are parsed
  and checked for mixed scripts but not DGA-scored.
* The score says "looks machine-generated", not "malicious". Legitimate
  systems (CDNs, cloud hosts, tracking and mail-delivery hosts) generate such names.
