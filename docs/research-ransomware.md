# Ransomware behaviour detector: research notes and evaluation

Code: `internal/edr/ransom_detect_core.go`, `ransom_detect_http.go` (one registration line in `edr.go`).
Endpoints: `GET /v1/ransom/hosts`, `GET /v1/ransom/host?host=`, `GET /v1/ransom/status` (all authenticated, report-only).

## Papers actually opened (full text read, via PDF)

1. Scaife, Carter, Traynor, Butler. "CryptoLock (and Drop It): Stopping Ransomware Attacks on User Data." IEEE ICDCS 2016.
   https://www.cise.ufl.edu/~butler/pubs/icdcs16.pdf
   The system (CryptoDrop) scores each process from three primary content indicators (file-type change, similarity-hash
   mismatch against the prior version, write entropy) and two secondary ones (mass deletion, file-type funnelling). It
   requires the union of the primary indicators for fast action, reasoning that a benign program rarely trips all three,
   plus a separate non-union threshold fallback. The paper reports 492 samples across 14 families detected, median 10 of
   5,099 files lost, and notes Class C ransomware (write new file, delete original) can avoid the union and is caught by
   deletion/funnelling. I used: the primary/secondary split, the union rule, deletion and funnelling as secondary
   signals, and the honest caveat that it needs content, which Kavach lacks.

2. Kharraz, Arshad, Mulliner, Robertson, Kirda. "UNVEIL: A Large-Scale, Automated Approach to Detecting Ransomware."
   USENIX Security 2016. https://khoury.northeastern.edu/home/mkharraz/publications/unveil-USENIX.pdf
   Describes three I/O strategies observed in families: overwrite the file in place with ciphertext; read, encrypt and
   delete the original; read, write an encrypted copy and securely delete the original. It detects via decoy user files,
   write-entropy and I/O pattern analysis in a sandbox. Reported results are in the abstract (96.3% detection at zero
   false positives on its corpus; sandbox, not production). I used the three strategies as the shape of my synthetic
   families (in-place, delete-original, encrypted copy).

3. Kharraz, Kirda. "Redemption: Real-Time Protection Against Ransomware at End-Hosts." RAID 2017.
   https://khoury.northeastern.edu/home/mkharraz/publications/raid2017redemption.pdf
   Computes a per-process malice score from content features (entropy ratio of reads vs writes, whole-file overwrite,
   deletion) and behaviour features (directory traversal, converting many file types to one type, access frequency,
   i.e. short gaps between writes to different files). The abstract reports 100% true positives at 0.8% false positives
   with about 2.6% overhead (their testbed). I used the behavioural features that survive without content: file-type
   funnelling, delete operations, directory breadth, and inter-write timing (as a burstiness measure).

4. Pont, Arief, Hernandez-Castro. "Why Current Statistical Approaches to Ransomware Detection Fail." (University of
   Kent). https://www.cs.kent.ac.uk/people/staff/ba284/Papers/ISC2020.pdf
   (The PDF text did not state the venue line in the part I read; cited by title/authors, venue not verified.)
   Tests randomness thresholds (Shannon entropy, chi-square, mean, Monte-Carlo pi, serial correlation) from prior tools on
   84,327 files of images, compressed and encrypted data. It reports false-positive rates often above 50% and
   sometimes above 90%, and false negatives of 5-20%. I used it to justify NOT building entropy into a design that
   cannot see content, and to state that even with content, entropy alone is weak and must be combined with behaviour.

5. Venturini, Freda, Miotto, Conti, Giaretta. "Differential Area Analysis for Ransomware: Attacks, Countermeasures, and
   Limitations." arXiv:2303.17351v2. https://arxiv.org/html/2303.17351v2
   (Read via the fetch tool's summary of the HTML page, not a PDF I parsed myself.) Shows header-entropy detection
   (DAA, 256-byte header) dropping from 98.24% to 64.34% accuracy when ransomware writes low-entropy padding or
   repeated bytes, and notes legitimate encryption/compression can false-alarm, suggesting I/O-rate monitoring as a
   complement. I used it as evidence that content entropy is evadable and that I/O-rate context matters.

## SNIPPET ONLY (not opened; do not rely on for details)

- Continella et al. "ShieldFS: A Self-healing, Ransomware-aware Filesystem." ACSAC 2016. Only search snippets seen
  (multi-tier filesystem-activity models, 11 families, 688 samples per summaries). Its 403-blocked PDF was not read.
  Listed as an influence only; no design detail is attributed to it.
- Practitioner and vendor pages on entropy evasion (intermittent encryption, low-entropy schemes): snippet claims only,
  one is vendor marketing; used nowhere as a number.

## Design (what Kavach can and cannot do)

Kavach sees `Path, Operation, Size, Time, optional PID`. No contents, so no entropy, no file-type change, no similarity.
Those are CryptoDrop's three primaries; they are therefore replaced by metadata analogues:

| Kind | Indicator | Trigger (default) |
|---|---|---|
| primary | extension_churn: files acquiring one common suffix (appended to a previously seen name, `name.docx.X`, or a known ransom extension; benign suffixes like .gz/.bak/.tmp excluded) | >= 20 files / 60 s |
| primary | ransom_note_dirs: ransom-note-named file in distinct dirs | >= 3 dirs |
| primary | backup_shadow_destruction: delete/rename inside shadow-copy/backup paths | >= 3 |
| primary | mass_inplace_rewrite: previously seen files modified across dirs with near-constant size | >= 100 files, >= 5 dirs, >= 60% uniform size |
| secondary | type_funnelling, delete_heavy, high_rate, directory_breadth, machine_pacing (burstiness B <= 0) | see `/v1/ransom/status` |

Score = sum of points (primary up to 35/30/30/40, secondary 4-10 each; 50% of max at trigger, 100% at 3x), capped at 100.
Alert = score >= 50 AND (>= 2 primaries OR 1 primary + >= 2 secondaries). Watch = score >= 30. Every response lists
all factors with value, trigger, points. Sliding windows: 60 s length, 30 s stride. Rename events carry one path
(assumed to be the new name).

Optional entropy field: not added. `FileEvent` lives in `file_events.go`, which this task may not edit, so entropy
is documented as a recommended agent-side change (per-event content entropy and magic-type for a bounded prefix, ideally
with the header-based approach of the papers above); the detector would then gain CryptoDrop's primaries.

## Evaluation (synthetic; overstates real accuracy)

Traces: 6 ransomware behaviours x 40 seeds (rename-with-extension, in-place overwrite without note, in-place with notes,
delete-original after encrypted copy, shadow-copy wipe then encrypt, fast NAS-style extension rename); 10 benign
behaviours x 40 seeds (backup copy, compiler build, package install, git checkout, log rotation, photo import, archive
extraction, IDE indexing, backup snapshot prune of 8 files, batch photo rename). Tests `TestRansomDetectionRate`
(>= 95% overall and >= 90% per scenario) and `TestRansomFalsePositiveRate` (<= 2%) fail on regression.

- Detection: 240/240 (100%) at the default threshold.
- False positives: 0/400 (0%).
- Thresholds were first set from the literature's qualitative indicators, then adjusted once (alert 60 -> 50, in-place
  rewrite weight 25 -> 40) because in-place overwrite without notes could not alert. This is tuning on the same
  generators, so the 100% / 0% figures are partly circular.

Known failures (measured or by construction):
- slow_and_low (about 1 file per 80 s over hours): 0/40 alerts by design; the 60 s window never sees enough files.
  Asserted in `TestRansomKnownEvasions`.
- random_names_common_ext (new random names plus delete of original): 0/40 alerts; no appended suffix, no notes.
- Hard benign look-alikes (`ransom_detect_hard_test.go`, informational): lossless image re-pack in place (400 files)
  alerts 40/40, and a mass snapshot prune of 400 files alerts 40/40. These are indistinguishable from the ransomware
  shape using metadata only.
- Ransomware that appends an allowlisted suffix (.zip, .bak) evades extension_churn; a renamed-to-ransom-extension
  that is not in the list is only caught when appended to a previously seen name or a document-like inner extension.
- Attribution: nothing identifies the writing process; PID is not used.

Real-world caveat: the corpora were written by us from published descriptions and our assumptions about tools; real
benign fleets (databases, sync clients, antivirus, VM images, build farms) will produce false positives not seen here,
and real families vary. Treat the numbers as regression guards, not as accuracy claims.
