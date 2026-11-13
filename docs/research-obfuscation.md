# Statistical script and command-line obfuscation scoring

This note records the literature that informed the `obfuscation-stats`
inspector analyzer (`internal/edr/inspect_obf_*.go`), what was actually read,
how the model works, and how it was evaluated. Everything is observation-only:
the analyzer measures text, never decodes or executes it.

## 1. Sources actually opened

Each entry below was opened and read (full text or the sections named). Notes
are in my own words. Numbers are quoted only where the opened text states them.

1. **Bohannon, D. and Holmes, L. "Revoke-Obfuscation: PowerShell Obfuscation
   Detection Using Science" (white paper, Black Hat USA 2017).**
   https://services.google.com/fh/files/misc/powershell-obfuscation-detection-using-science.pdf
   (PDF text extracted and read.) The paper argues that obfuscated PowerShell
   "looks nothing like regular code", so detection should look for the
   obfuscation itself rather than for payload signatures. A first approach used
   per-letter character frequency compared by cosine similarity to an average
   built from PoshCode; on their labelled corpus (about 408,000 scripts, with
   5,674 known-clean and 5,590 known-obfuscated labelled files, the obfuscated
   ones largely produced by Invoke-Obfuscation, ISE Steroids and
   Invoke-CradleCrafter) that gave 89% precision but only 37% recall, and the
   authors note it is trivially defeated by padding with text that restores the
   average frequencies. The final classifier is a logistic regression trained
   by gradient descent (80/20 train/validation split) over 4,098 features taken
   from the PowerShell tokenizer and AST (AST-type distributions, operator
   distributions, per-type character frequency, entropy, length statistics,
   whitespace density, casing and so on); they report 96% accuracy and 95% F1,
   about ten times better at finding obfuscated content than character
   frequency alone with half the false positives. They also list the string
   techniques seen in tools (concatenation, `-join`, `-f` format operator,
   reversal, `-split`/`-replace`, backtick escapes, aliases such as `iex`,
   `Get-Command` wildcards).
2. **Chai, H., Ying, L., Duan, H., Zha, D. "Invoke-Deobfuscation: AST-Based and
   Semantics-Preserving Deobfuscation for PowerShell Scripts" (IEEE/IFIP DSN
   2022).** https://snowroll.github.io/papers/Invoke_Deobfuscation_DSN_2022.pdf
   (PDF text extracted; abstract, introduction and the evaluation setup read,
   not every section.) It identifies obfuscated pieces from tokens and
   recoverable AST nodes, traces variables, and rewrites pieces in place. The
   evaluation dataset is 39,713 wild scripts, compared against PSDecode,
   PowerDrive, PowerDecode and a tool by Li et al. The paper also defines an
   obfuscation score: techniques are grouped into three levels (L1 to L3), each
   technique type present scores once by its level, and the sum is the script's
   score; they report their tool lowers that score by 46% on average. This is
   the model for our per-technique (not per-occurrence) thinking, and it
   confirms that token-level obfuscation (ticks, case) is something
   regex-based deobfuscators miss.
3. **Fass, A., Krawczyk, R. P., Backes, M., Stock, B. "JaSt: Fully Syntactic
   Detection of Malicious (Obfuscated) JavaScript" (DIMVA 2018).**
   https://notify.cispa.uni-saarland.de/papers/fass2018jast.pdf (PDF text
   extracted; abstract and introduction read.) Parses JavaScript to an AST,
   turns it into a sequence of syntactic units, and uses frequencies of unit
   n-grams as features for a random forest. The central claim is that malicious
   samples share syntactic similarities at an abstract level, which survives
   many obfuscation transformations; the abstract states almost 99.5% accuracy
   and a 0.54% false-negative rate. Lesson for us: frequency-of-pattern features
   are cheap and effective, but they need a parser, which we deliberately avoid
   (we use regex token patterns).
4. **Fass, A., Backes, M., Stock, B. "JStap: A Static Pre-Filter for Malicious
   JavaScript Detection" (ACSAC 2019).**
   https://notify.cispa.uni-saarland.de/papers/fass2019jstap.pdf (PDF text
   extracted; abstract and introduction read.) Extends the lexical/AST line with
   control and data flow, ten modules each with its own random forest,
   evaluated on over 270,000 samples; unanimous voting of modules classifies
   93% of the data at 99.73% accuracy and the rest goes to a second layer. The
   introduction also stresses that static detectors mis-classify and are best
   used as a pre-filter, which is how we position the obfuscation score (a
   modest signal, never a verdict).
5. **Outrata, V., Polak, M. A., Kopp, M. (Cisco). "Command-line Obfuscation
   Detection using Small Language Models" (arXiv 2408.02637, 2024).**
   https://arxiv.org/abs/2408.02637 (PDF text extracted; abstract, prior art,
   preprocessing and training sections skimmed.) Trains a small transformer
   from scratch on process execution logs to flag obfuscated Windows command
   lines, normalising volatile values (GUIDs, IPs) before tokenization and
   using a custom tokenizer. The data are large-scale real telemetry, with a
   small labelled fine-tuning set where benign examples dominate (a stated
   imbalance of about ten benign commands per obfuscated one). It is the
   closest published relative of our command-line half; its main argument is
   that signature enumeration does not scale to the variability of
   command-line obfuscation.
6. **Bohannon, D. "Invoke-DOSfuscation: Techniques FOR %F IN (-style) DO
   (S-level CMD Obfuscation)" (HITB Amsterdam 2018 slides, companion to the
   Black Hat Asia 2018 white paper).**
   https://conference.hitb.org/hitbsecconf2018ams/materials/D1T2%20-%20Daniel%20Bohannon%20-%20Invoke-DOSfuscation.pdf
   (slide text extracted; the technique and detection overview read, not every
   slide.) Catalogs cmd.exe obfuscation: random case, extra whitespace, commas
   and semicolons as delimiters, caret escapes (including doubled carets inside
   arguments), unpaired double quotes, environment-variable substring
   encoding (`%var:~n,m%`) and FOR-loop based payload assembly, with the point
   that these mainly defeat static detection. The slides point to
   signature-less approaches such as Revoke-Obfuscation as the defence and to
   command-line and parent/child process visibility. The wording of the
   examples (`,;,%coMSPec:^^^^\^^^^=...`) drove our caret, quote and
   random-case features.
7. **Bohannon, D. "DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and
   Detection Techniques" (Mandiant blog, 22 March 2018) and "Revoke-Obfuscation"
   blog.**
   https://cloud.google.com/blog/topics/threat-intelligence/dosfuscation-exploring-obfuscation-and-detection-techniques
   and
   https://cloud.google.com/blog/topics/threat-intelligence/revoke-obfuscation-powershell
   (both fetched via the web fetch tool, which returned only high-level
   summaries.) The DOSfuscation post is an abstract: nine months of research,
   environment-variable substring encoding, and four payload obfuscation
   approaches, with the detail left to the white paper, which I did not
   obtain. The Revoke-Obfuscation post mainly points to the white paper and
   mentions the ~408,000-script corpus with ~7,000 manually labelled scripts.

## 2. Seen only as search snippets (NOT opened, do not rely on them)

SNIPPET ONLY:

- Curtsinger, Livshits, Zorn, Seifert, "ZOZZLE: Fast and Precise In-Browser
  JavaScript Malware Detection" (USENIX Security 2011): search summaries say
  it uses Bayesian classification over AST-context features; I did not open it
  (the PDF fetch returned an HTML page, not the paper), so no numbers are
  quoted here.
- Skolka et al., "Anything to Hide? Studying Minified and Obfuscated Code in
  the Web" (WWW 2019): only seen as a reference entry inside the JStap paper,
  where it is cited for the prevalence of minified or obfuscated first-party
  scripts. Relevant to the minified-JS false-positive risk; not read.
- Mandiant, "Obfuscated Command Line Detection Using Machine Learning" blog;
  CrowdStrike, "BERT Embeddings ... Detecting Malware from Command Lines";
  "SENTINEL: A Multi-Pathway Architecture for Detecting Living-Off-the-Land APT
  Attacks on Windows Command Lines" (arXiv 2609.14593); the LOLAL active
  learning paper: search-result descriptions only.
- Black Hat / DerbyCon / DEF CON listings of the Revoke-Obfuscation talk and
  the Invoke-Obfuscation tool pages: listing text only.

## 3. What we took from the literature

| Idea | Source | Where in the analyzer |
|---|---|---|
| Character-frequency distance from "ordinary" scripts (cosine) | Revoke-Obfuscation | `cos_dist`, `class_dist`, one reference distribution per language built from `testdata/obf/reference/*.txt` |
| Entropy and per-token length statistics | Revoke-Obfuscation | `entropy`, `tok_len_*` |
| Random variable names (MSF stager observation) | Revoke-Obfuscation | `var_surprisal` (own bigram model), `var_random_frac` |
| Backtick, case, concatenation, `-f`, `-join`, reversal, `iex` forms | Revoke-Obfuscation, Invoke-Deobfuscation | `tick_density`, `case_*`, `concat_density`, `format_density`, `pat_join`, `pat_reverse`, `pat_dynexec` |
| Caret, quote, comma/semicolon, `%v:~n,m%` | DOSfuscation | `caret_density`, `quote_split`, `pat_envsub` |
| Logistic regression by gradient descent with a held-out split | Revoke-Obfuscation | `inspect_obf_train_test.go` |
| Pattern frequency features, static pre-filter positioning | JaSt, JStap | regex token patterns (no AST), modest weights |
| Large benign skew in real telemetry | Cisco SLM paper | caveats in section 6 |

The bigram model is our own: letter-pair statistics from the identifiers and
words in the embedded reference scripts plus a short list of common programming
words (`obfCommonWords`). We did not reuse `ScoreDomain`, which is tuned for
DNS labels.

## 4. The analyzer

* Registered as `obfuscation-stats` for kinds `script` and `cmdline`
  (new file only; the contract, `edr.go` and other analyzers are untouched).
* Language: file extension in `Name` if present, otherwise marker counting
  (powershell, cmd, bash, javascript, python, vba); unknown falls back to the
  closest reference distribution.
* 26 features (`obfFeatureNames` in `inspect_obf_features.go`), emitted in
  `Meta["obfuscation-stats.features"]` together with language, probability,
  threshold and a `flagged` boolean.
* Score: standardized logistic model, coefficients committed in
  `inspect_obf_weights.go` (generated, and a test fails if a fresh training run
  does not reproduce them).
* Findings (all `obf-*`): `obf-statistical` (weight 6 to 14 by margin over the
  threshold), plus `obf-tick-escape`, `obf-caret-insertion`,
  `obf-quote-splitting`, `obf-random-case`, `obf-char-code`,
  `obf-string-assembly`, `obf-encoded-blob`, `obf-random-names`,
  `obf-substring-tricks`, `obf-dynamic-exec` at weight 3 or 4. Specific
  findings only fire after the statistical flag. The total is capped at 25, so
  the analyzer alone can never reach the contract's 40 "suspicious" threshold
  (tested over 480 generated samples; the observed maximum was exactly 25).
  Note the contract sums the top ten findings across analyzers, so the
  deobfuscation analyzer's own cap of 35 plus this one can together exceed 40;
  that is by design (two independent signals agreeing) but worth knowing.
* Inputs shorter than 24 characters are skipped; text beyond 256 KiB is
  ignored; nothing is executed or decoded.

## 5. Training and evaluation procedure

Everything is reproducible: `go test ./internal/edr -run TestObfTrain`.

1. Generators (`inspect_obf_gen_test.go`, `inspect_obf_hard_test.go`) are
   written for this repo, seeded, and independent of the published tools.
   Benign samples: build scripts, admin one-liners, installers, config tools,
   multi-part scripts and long pipelines, plus a "hard benign" class (encoded
   config blobs, `curl | sh` installers, minified JS, ANSI escape sequences,
   format-heavy logging, caret line continuations, `Chr(13) & Chr(10)`).
   Obfuscated samples apply one to three of: random case, tick insertion, caret
   insertion, empty-quote splitting, string splitting, format operator,
   char-code assembly, hex escapes, reversal, `${IFS}`, cmd env-substring,
   base64 encoding, and variable renaming; sources are 55% download-cradle and
   similar payloads and 45% benign templates (as Revoke-Obfuscation did).
2. Training set: seed 20240601, 150 benign + 150 obfuscated per language across
   PowerShell, cmd, bash, JavaScript, Python and VBA (1,800 samples). Features
   are computed with the analyzer's own language auto-detection.
3. Logistic regression: standardized features, zero init, batch gradient
   descent, learning rate 0.5, L2 1e-3, 3,000 iterations. Threshold: the value
   in 0.30..0.95 (step 0.01) maximizing training F1 subject to a training
   false-positive rate of at most 1%. Result: threshold 0.71.
4. Evaluation set: seed 777001, same generators, 900 benign + 900 obfuscated,
   never used in training. A separate hand-written set of 20 tricky benign cases
   is held out entirely (not produced by the generators, although the
   "hard benign" generator classes were designed around the same kinds of
   cases, so it is not independent either).

## 6. Results (evaluation seed 777001, threshold 0.71)

Overall: precision 0.993, recall 0.841, F1 0.911 (TP 757, FP 5, FN 143, TN 895).
Language auto-detection agreed with the generator's label on 85.4% of samples
(the rest were analysed against the closest reference distribution).

| Language | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| powershell | 1.000 | 0.787 | 0.881 | 118 | 0 | 32 | 150 |
| cmd | 1.000 | 0.860 | 0.925 | 129 | 0 | 21 | 150 |
| bash | 0.993 | 0.913 | 0.951 | 137 | 1 | 13 | 149 |
| javascript | 1.000 | 0.820 | 0.901 | 123 | 0 | 27 | 150 |
| python | 0.965 | 0.733 | 0.833 | 110 | 4 | 40 | 146 |
| vba | 1.000 | 0.933 | 0.966 | 140 | 0 | 10 | 150 |

Per technique (recall; there is no per-technique precision because benign
samples carry no technique label). "Alone" means the sample used only that
technique.

| Technique | Recall (any sample containing it) | n | Recall (alone) | n alone |
|---|---|---|---|---|
| caret | 0.894 | 47 | 0.625 | 8 |
| charcode | 0.746 | 193 | 0.591 | 44 |
| encoding | 0.960 | 277 | 0.926 | 54 |
| envsub | 0.952 | 42 | 0.818 | 11 |
| format | 0.568 | 37 | 0.250 | 12 |
| hexesc | 0.802 | 131 | 0.667 | 30 |
| ifs | 0.980 | 51 | 1.000 | 14 |
| quote | 0.978 | 89 | 0.947 | 19 |
| randcase | 0.986 | 138 | 0.967 | 30 |
| rename | 0.895 | 256 | 0.672 | 58 |
| reverse | 0.781 | 169 | 0.636 | 33 |
| split | 0.827 | 168 | 0.775 | 40 |
| tick | 0.950 | 20 | 1.000 | 2 |

Weak spots, plainly: the format operator on short literals (25% alone), a lone
rename of a few variables (67%), char-code or hex escapes of a few short
strings (59 to 67%), and Python (recall 0.73) where obfuscated snippets are
short and look like ordinary code. These are exactly the cases where the
literature also reports that character statistics alone are weak (Revoke-
Obfuscation measured 37% recall for pure character-frequency before moving to
AST features).

Tricky benign cases (hand-written, 20): minified jQuery-style and canvas JS, a
600-byte base64 certificate in PowerShell, a base64 key in a heredoc, a hex
checksum, rustup, Homebrew and nvm installers, the Chocolatey one-liner, a
benign `-EncodedCommand`, ANSI colour escapes in Python, legitimate
`String.fromCharCode`, `-f`-heavy logging, VBA `Chr(13) & Chr(10)`, a
caret-continued robocopy, a regex-heavy JS file, a long `docker run` with a URL
and credentials, a JWT in `curl`, Python `struct`/bytes literals, a splatted
PowerShell pipeline.

False positives listed honestly: 2 of 20.

* `encodedcommand-benign`: a harmless `powershell -EncodedCommand <b64>` is
  flagged (p about 1.00). From the text alone it is indistinguishable from the
  encoding obfuscation class, so this is an inherent limitation; the finding is
  still a fair "this is encoded" observation.
* `ansi-colors-py`: `\x1b[31m` escapes in print statements are flagged
  (p 0.87). The same pattern also accounts for the synthetic false positives
  (4 Python, 1 bash printf).

All other tricky cases (including minified JS, the long base64 config and the
`curl | sh` installers) passed, but note the generators' hard-benign class
contains similar material, so this is closer to a regression check than to an
independent measurement. Before adding the hard-benign class to training, the
same 20 cases gave 14 false positives (base64 blobs, installers, format
strings, regexes) and the first synthetic F1 was an inflated 0.959; the hard
negatives cost about 5 points of recall at the 1% false-positive budget. That
gap is a more honest picture of the difficulty than the headline numbers.

Failing floors enforced in `TestObfEvaluation`: overall F1 at least 0.88,
precision at least 0.95, recall at least 0.78, per-language F1 at least 0.78,
tricky-benign false positives at most 20%.

## 7. Limits and caveats

* **Synthetic data overstates real accuracy.** The calibration and the
  evaluation use the same generators (different seeds), written by the same
  author as the features. The features were designed with those obfuscators in
  mind; real obfuscation (Invoke-Obfuscation, packers, JavaScript obfuscators,
  hand-made droppers) is more varied, and real benign code is far more varied
  than the 5 to 14 templates per language used here.
* **Class balance.** Evaluation is 50/50. Real telemetry is overwhelmingly
  benign (the Cisco paper trains with about ten benign per obfuscated sample
  and still evaluates on very large benign volumes). At 1% false-positive rate
  and a tiny prior, real-world precision would be far lower than 0.99; that is
  why the findings are weighted low and capped at 25.
* **Evasion.** Character statistics can be padded: the Revoke-Obfuscation
  authors point out that adding comments, strings or names restores the average
  frequencies. This analyzer has the same weakness; it detects obfuscation that
  makes no effort to look ordinary. It is a triage signal, not a detector.
* **No AST.** The literature's best results (Revoke-Obfuscation's 96%, JaSt,
  JStap) rely on parsers. We use regex token patterns and cannot see structure,
  data flow, or semantics.
* **Language detection** is a marker heuristic (85% agreement on synthetic
  text); short inputs often fall back to "unknown".
* **Legitimate encoded content** (certificates, `-EncodedCommand` from
  management tools, minified or bundled JS, ANSI escape output) can be
  flagged; the finding text says "resembles", not "is malicious".
* The reference distributions come from about 30 short hand-written scripts
  (5 or 6 per language), so they are crude.
