# Similarity hashing for the artifact inspector: research and evaluation

Scope: static similarity digests for files submitted to the inspector
(`internal/edr/inspect_sim_*.go`). Observation only: bytes are parsed, never
executed, and only digests (not bytes) are kept in the in-memory index.

## Kavach-native, not compatible

The digests are implemented from the published algorithm descriptions. No
source code from ssdeep (GPL), TLSH or any other implementation was read or
copied. Constants, rolling function, chunk hash, bucket function, header
layout and scoring are Kavach's own. Therefore:

- `kavach-ctph1:...` is NOT an ssdeep digest and its 0-100 score is not an
  ssdeep score.
- `kavach-lsh1:...` is NOT a TLSH digest and its distance is not a TLSH score.
- Compatibility with the reference tools was NOT claimed, because no test
  vectors from the papers were available to prove it.
- The `imphash`-style value follows the public convention (below) but is not
  claimed value-identical to other tools in every corner case (ordinal-only
  imports, malformed tables).

## Sources

### Opened and read (open-access full text obtained)

1. J. Oliver, C. Cheng, Y. Chen. "TLSH - A Locality Sensitive Hash." 4th
   Cybercrime and Trustworthy Computing Workshop, Sydney, Nov 2013.
   https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf
   (read in full via text extraction). The paper builds a fixed-length digest by
   sliding a 5-byte window, hashing byte triplets from it into 128 buckets,
   splitting the counts at quartiles and keeping 2 bits per bucket, with a
   short header of a checksum, a log-scaled length and two quartile ratios.
   It argues for a distance score (0 means identical, no upper cap) instead of
   a 0-100 similarity, because the 0-100 scales of ssdeep and sdhash leave no
   usable threshold between "almost nothing" and "nothing". Its evaluation on
   a malware corpus reports very low false-positive rates for ssdeep and
   sdhash but low detection rates, and an ROC area of about 0.98 for TLSH
   versus about 0.69 (sdhash) and 0.66 (ssdeep); mutation experiments on a
   novel text show ssdeep scores collapsing to 0 after a few edits while
   TLSH distances stay in the "similar" range. These are the authors' numbers
   on their data; we did not reproduce them.

2. F. Breitinger, H. Baier. "Performance Issues About Context-Triggered
   Piecewise Hashing." ICDF2C 2011 (Springer LNICST 88, 2012).
   https://opus.bibliothek.uni-augsburg.de/opus4/files/117618/117618.pdf
   (read the algorithm description and the improvement sections; did not study
   every experiment). It restates Kornblum's CTPH precisely: a rolling hash
   over a 7-byte window, a block-size modulus (b = 3 * 2^k) that makes a byte a
   trigger point, each chunk between triggers reduced to one Base64 character,
   a signature of 32-64 characters, and a block size chosen so about 64 chunks
   result. Signatures are only comparable when their block sizes are equal or
   differ by a factor of two, so two signatures are stored. It also notes
   that the 64-character cap lets an adversary insert crafted trigger
   sequences, and proposes counting triggers for several block sizes in one
   pass, which Kavach's digest follows.

3. F. Breitinger, H. Baier. "Similarity Preserving Hashing: Eligible
   Properties and a New Algorithm MRSH-v2." ICDF2C 2012 (Springer 2013).
   https://opus.bibliothek.uni-augsburg.de/opus4/files/117617/117617.pdf
   (read the abstract, introduction and the Bloom-filter background; did not
   work through the evaluation). It proposes uniform terminology and desirable
   properties for similarity-preserving hashes, and MRSH-v2, a Bloom-filter
   digest with a regular mode and a fragment-detection mode. It motivates
   the idea of comparing digests through set overlap of features rather than
   position-by-position.

4. V. Roussev, G. Richard III, L. Marziale. "Multi-resolution similarity
   hashing." DFRWS 2007, Digital Investigation 4S.
   https://cct.lsu.edu/~golden/Papers/dfrws2007.pdf
   (read the abstract and introduction only). It proposes hashing raw data
   once at several granularities so that similarity of targets of very
   different sizes can be queried without re-reading the data, with digests
   a small fraction of the input size. Kavach does not implement the
   multi-resolution scheme.

5. V. Roussev. "Data Fingerprinting with Similarity Digests." Advances in
   Digital Forensics VI, IFIP AICT 337, 2010, pp. 207-226.
   https://link.springer.com/content/pdf/10.1007/978-3-642-15506-2_15.pdf
   (only the first two pages were retrievable: abstract and introduction).
   It selects fingerprint features by statistical rarity rather than by random
   rolling-hash selection, so the digest is built from features least likely
   to occur by chance, and flags inputs that carry too few distinctive features
   for a reliable comparison. Its scores are 0-100. Kavach does not implement
   sdhash; the idea of flagging "too little structure to compare" is reflected
   in our minimum-size rule only loosely.

### SNIPPET ONLY (search-result summaries; full text not opened)

- J. Kornblum. "Identifying almost identical files using context triggered
  piecewise hashing." DFRWS 2006, Digital Investigation 3S, pp. 91-97.
  https://dfrws.org/presentation/identifying-almost-identical-files-using-context-triggered-piecewise-hashing/
  The direct PDF host refused the connection. The CTPH design in Kavach is
  taken from the restatement in source 2, not from this paper itself.
- Mandiant, "Tracking Malware with Import Hashing" (Jan 2014).
  https://cloud.google.com/blog/topics/threat-intelligence/tracking-malware-import-hashing
  Seen only in search summaries: it hashes a PE's import table to link samples
  from the same toolset, and import order matters. The convention in
  `peImpHash` (lowercase `dll.function`, extension stripped, comma-joined,
  MD5) is the widely documented practice and was not checked against this page.
- Trend Micro, telfhash (ELF symbol hash used for Linux IoT malware
  clustering, in VirusTotal since 2020).
  https://www.trendmicro.com/en_us/research/20/d/grouping-linux-iot-malware-samples-with-trend-micro-elf-hash.html
  Summaries say it hashes the imported functions of an ELF and feeds them to
  TLSH. Kavach's ELF value is only inspired by this: an exact hash of the sorted
  undefined dynamic-symbol set, not a similarity digest.
- Breitinger, Baier, Beckingham. Security and implementation analysis of
  sdhash (opus.bibliothek.uni-augsburg.de/opus4/files/117822/117822.pdf).
  Summary only: an active adversary can push sdhash scores low while
  preserving perceptual content.
- "ssdeeper: Evaluating and improving ssdeep" (DFRWS 2022). The fetch returned
  an HTML page, not the paper. Summary only: newer schemes beat ssdeep on
  precision and recall, yet ssdeep remains widely deployed.
- Mach-O: no paper was consulted. The dylib/symbol hash is Kavach's own
  analogue of imphash. The "NIST digest studies" requested in the brief were
  not found or opened.

## What was built

| Value | Meta key / field | Construction |
|---|---|---|
| `kavach-ctph1` | `similarity.digests.ctph` | 7-byte polynomial rolling hash, trigger when the mixed hash mod b = b-1, FNV-style chunk hash to one Base64 char, <= 64 chars, two block sizes (b, 2b). Two linear passes. Compare: runs squashed, requires a shared 7-char run, score = 100 - 100*Levenshtein/maxlen. Needs >= 512 bytes. |
| `kavach-lsh1` | `...lsh` | 5-byte window, six triplet shapes, 128 buckets, quartile 2-bit quantisation, header of 1/8-octave length and two quartile ratios. Distance = sum of bucket diffs + capped length diff + ratio diffs, integer in 0..478. One linear pass. Needs >= 256 bytes. |
| imphash | `...imphash` | PE, from `debug/pe`: import-table order, lowercase `dll.func`, `.dll/.ocx/.sys` stripped, MD5 of the comma-joined list. MD5 is an identifier here only. |
| ELF symbol hash | `...elf_symhash` | SHA-256/128 of sorted unique undefined dynamic symbols. |
| Mach-O hash | `...macho_hash` | SHA-256/128 of sorted dylib base names + imported symbols (first slice of a fat file). |
| Entropy vector | `...entropy_vec`, `..._hash` | One hex digit per section (<= 64), Shannon entropy in half-bit steps (read cap 8 MiB per section). |

API: `ComputeDigests(data []byte) SimDigests`, `CTPHCompare`, `LSHDistance`,
`GET /v1/inspect/similar?sha256=|digest=&limit=`.

The `similarity` analyzer (kind `file`) emits `sim-near-duplicate`,
`sim-imphash-match` or `sim-symhash-match`, weights 4-14 (info or low), only
against an earlier, different sha256, never for first-seen content, and
uses a 1024-entry digest index plus the report ring. A match says "looks like
something submitted before", not that either file is malicious.

Documented thresholds: CTPH score >= 55, LSH distance <= 24. They were set
after the evaluation below (the first LSH threshold of 40 gave 10% false
matches on random binaries and was tightened).

## Evaluation (synthetic; run `go test ./internal/edr -run SimilarityEval -v`)

Corpus: 24 base blobs (24-224 KiB, a mix of random runs, repeated records and
low-entropy fill), 3 variants each per class (n=72/class), and 60 unrelated
blobs per negative set (1770 pairs).

| Variant class | CTPH detect (mean score) | LSH detect (mean dist) |
|---|---|---|
| 3 insertions <= 200 B | 100% (94) | 100% (1) |
| 3 deletions <= 200 B | 100% (94) | 100% (1) |
| 5 inserts + 5 deletes | 99% (82) | 100% (1) |
| swap two 2 KiB blocks | 100% (91) | 100% (0) |
| 4 KiB zero padding at end | 100% (98) | 100% (1) |
| 1 KiB prepended | 100% (98) | 100% (3) |
| 0.1% point edits | 15% (25) | 100% (1) |
| 8 x 1/32 of file rewritten (~25%) | 71% (57) | 65% (23) |

False matches on unrelated pairs (threshold CTPH 55, LSH 24):

| Negative set | CTPH | LSH |
|---|---|---|
| random binary-like blobs | 0 / 1770 | 0 / 1770 (smallest unrelated distance 26, mean 59) |
| text from one shared vocabulary | 0 / 1770 | 419 / 1770 (23.7%) |

Other checks: related-vs-unrelated CTPH scores separate cleanly (related
minimum 95, unrelated maximum 0 in 20 pairs); XOR with two different
keystreams (a stand-in for per-sample packing/encryption) linked 0/20 by
either digest; imphash matched 12/12 same-import PE fixtures and gave 12
distinct values for 12 random import sets; a 32 MiB input digests in about
1.6 s of the 5 s analyzer budget on a loaded laptop.

Comparison. CTPH is conservative: no false matches here and strong on
indel/shuffle/padding, but a signature of ~64 chunks means edits spread
across the file (the 0.1% case touches every chunk) break it. LSH tolerates
dispersed point edits (it measures statistics) but is the weaker discriminator:
it reached the unrelated-pair range on same-vocabulary text, and with only
26 vs 24 between the nearest unrelated binary pair and the threshold the
margin is thin. Using either signal ("either") detected 90% of the heavy
rewrite class. This agrees qualitatively with the TLSH paper's argument for
distance scales over 0-100 scores, but it does not validate their numbers.

## Honest limits

- Synthetic data overstates real accuracy. Real malware families share
  libraries, compilers and packers, producing both more true links and many more
  false ones (statistical profiles of compiled code resemble each other).
- Packed, encrypted or per-sample-obfuscated payloads defeat both digests
  (0/20 above); the import and symbol hashes also fail when imports are
  resolved dynamically, and many different programs share a small import set.
- Both digests are manipulable by an adversary who knows the algorithm (the
  trigger-injection attack on 64-character signatures applies to kavach-ctph
  too; no counter-measure beyond squashing runs is implemented).
- Inputs under 512 B (CTPH) or 256 B (LSH) get no digest.
- A similarity finding never proves maliciousness; weights are modest, and
  the verdict still comes from the other analyzers.
- Thresholds were tuned on the same synthetic generator that is used to report
  the numbers; treat them as starting points to re-tune on real submissions.
- The index is in memory only (1024 digests, lost on restart); the report ring
  holds 200 reports.
