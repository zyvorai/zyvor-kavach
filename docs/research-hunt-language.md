# Research notes: a sequence-capable hunting language (kavach-seq)

Only sources whose content was actually fetched and read during this work are listed
under "Sources opened". Notes are paraphrased. Short verbatim code or query snippets are
kept in a separate section so the paraphrase and the quotation are never mixed.
Tools: the web fetcher returned page text for HTML pages; the two PDFs were downloaded and
converted to text locally before reading. Anything that could not be read is listed at
the end as "not used".

## Sources opened

1. Elastic, "EQL syntax reference" (Elasticsearch reference, current).
   https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
   An EQL query is an event category plus a condition. Comparison operators distinguish
   `==` (case-sensitive, no wildcards) from `:` (case-insensitive, wildcards and lists
   allowed); `like`, `regex` and `in` have case-insensitive `~` variants. A `sequence`
   lists ordered steps in brackets, `by` joins steps on shared values, `with maxspan`
   bounds the window starting at the first event, and `until` expires a pending sequence
   when an expiration event arrives. The page states that sequences do not enumerate
   every possible match: each step is a state holding at most one pending sequence per
   join-key group, and a newer arrival overwrites an older pending one, so results can
   differ from a naive brute-force reading. This informed our choice to define precise,
   documented semantics instead of inheriting this overwrite behaviour.

2. Elastic, "EQL search" overview (Elasticsearch reference, current).
   https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html
   Describes EQL as a language for event-based time series data, SQL-like in feel, built
   for threat hunting. Its distinguishing feature is matching ordered series of related
   events across categories and time spans, with `maxspan`, `by` and missing-event `!`
   as the main sequence controls. Used for orientation and the category-then-`where`
   shape of a single-event query.

3. SigmaHQ, "Sigma correlations" specification page.
   https://sigmahq.io/docs/meta/correlations.html
   Correlation rules sit in a `correlation` block and refer to base rules by name or id.
   Types include `event_count`, `value_count`, `temporal` (all referenced rules fire
   within a timespan, any order) and `temporal_ordered` (same, but in listed order); the
   page warns that ordered correlation is rarely supported by backends. Grouping uses
   `group-by` and the window is `timespan`, with unit case mattering (`m` minutes vs `M`
   months). Takeaway: Sigma separates "count/threshold" correlation from "ordered
   temporal" correlation, and ordering support is the weak spot, which motivated giving
   kavach-seq first-class ordered sequences with a real evaluator.

4. Microsoft Learn, "join operator" (Kusto Query Language).
   https://learn.microsoft.com/en-us/kusto/query/join-operator
   KQL correlates by joining two tabular expressions on named columns with a selectable
   join flavour (default `innerunique`, plus inner, outer, semi and anti variants). There
   is no built-in ordered-sequence operator on this page: temporal ordering must be
   built by joining and then filtering on timestamp comparisons. Takeaway: KQL-style
   hunting is relational (join + filter), so a pipeline of joins is verbose for "A then B
   then C"; kavach-seq makes the ordered step list the primitive and keeps the join key
   (`by`) as a clause.

5. Splunk, "transaction" search command (Splunk Enterprise SPL search reference 9.4).
   https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.4/search-commands/transaction
   `transaction` groups events by shared field values and bounds them with `maxspan`
   (first-to-last) and `maxpause` (gap between consecutive events). `startswith` and
   `endswith` take filter expressions that open and close a transaction, which is the
   closest SPL analogue to EQL `until`. The page notes the command expects events in
   newest-first order and that a preceding command that reorders them needs an explicit
   `sort`. Takeaway: ordering is an explicit, easily broken precondition in SPL, so
   kavach-seq sorts internally and deterministically before matching.

6. osquery docs, "Creating tables" (osquery 4.7.0 documentation).
   https://osquery.readthedocs.io/en/4.7.0/development/creating-tables/
   osquery exposes operating-system state as SQL virtual tables defined by a spec file and
   a row generator. WHERE constraints are passed down to the generator so a table can skip
   expensive work (the `processes` table checks a `pid` constraint before costly lookups),
   and some tables require a predicate. Event-based tables are a separate category backed
   by event subscribers. Takeaway: a point-in-time relational model fits state queries,
   not ordered behaviour, and field availability is a property of each table, which we
   mirror with a per-category field catalogue that lists unavailable fields explicitly.

7. Velociraptor docs, "VQL" introduction.
   https://docs.velociraptor.app/docs/vql/
   The page is only an introduction. It presents VQL as central to Velociraptor so that
   responders can write a query, package it as an artifact and hunt across a fleet without
   waiting for a software release, and artifacts can be shared. The syntax pages
   (plugins, functions, lazy evaluation) were NOT in the page that was fetched, so no
   claim about VQL grammar is made here. Takeaway used: shareable, named query artifacts
   are valuable, which is why kavach-seq ships an embedded catalogue of example queries
   (`GET /v1/hunt/seq/examples`).

8. Gyllstrom, Agrawal, Diao, Immerman, "On Supporting Kleene Closure over Event Streams"
   (SASE+), ICDE 2008, UMass Amherst. PDF read locally after text extraction.
   https://people.cs.umass.edu/~yanlei/publications/sase-icde08.pdf
   Introduces SASE+, a compact complex-event language, and defines event selection
   strategies. Strict contiguity requires selected events to be adjacent in the input
   (the regular-expression-on-a-string case). Partition contiguity requires adjacency
   within a partition formed by an equivalence attribute. Skip-till-next-match removes
   the adjacency requirement: irrelevant events are skipped until the next relevant event
   is read. Skip-till-any-match additionally allows non-deterministic branching so one
   event can both extend and not extend a partial match, yielding all combinations. The
   paper also describes termination criteria (time window, "minimal effort") and an
   expressiveness analysis tying the strict/partition, next-match and any-match
   subsets to progressively larger complexity classes. We adopt partition-by-key plus
   skip-till-next-match and say so in the docs.

9. Zhang, Diao, Immerman, "On Complexity and Optimization of Expensive Queries in
   Complex Event Processing", SIGMOD 2014, UMass Amherst. PDF read locally.
   https://people.cs.umass.edu/~immerman/pub/sigmod2014-cep.pdf
   Analyzes which language features make CEP pattern queries expensive and names the main
   bottlenecks: Kleene closure evaluated under skip-till-any-match, and confidence
   computation for imprecise timestamps. It orders selection strategies from strict or
   partition contiguity, through skip-till-next-match, to skip-till-any-match as the most
   flexible and costly. This supports our decision to implement only the deterministic,
   polynomial next-match strategy and to omit Kleene closure and any-match enumeration.

## Snippet-only entries (quoted examples, not full analysis)

These are short example queries copied from the pages above, kept here verbatim.

- Elastic EQL syntax page, single-event form:
  `process where process.name == "svchost.exe"`
- Elastic EQL syntax page, sequence form:
  ```
  sequence with maxspan=15m
    [ file where file.extension == "exe" ]
    [ process where true ]
  ```
- Elastic EQL overview page:
  ```
  sequence with maxspan=1h
    [ process where process.name == "regsvr32.exe" ]
    [ file where stringContains(file.name, "scrobj.dll") ]
  ```
- Splunk transaction page (9.4): `... | transaction host cookie maxspan=30s maxpause=5s`
- osquery creating-tables page (C++ fragment):
  `if (!context.constraints["pid"].matches<int>(pid)) { continue; }`
- Sigma correlations page, an `event_count` rule fragment: `type: event_count`,
  `group-by: [SourceIP]`, `timespan: 10m`, `condition: {gte: 20}` (the fetcher labelled
  the full example "adapted for illustration", so treat it as paraphrase, not a verbatim
  copy of the specification).

## Not used

- Search results mentioning osquery.io/schema, Kolide and Red Hat osquery articles, and
  a third-party Rust SASE+ implementation (varpulis-sase) were seen only as search
  snippets and were not opened, so nothing is taken from them.
- The Splunk 7.0.2 transaction page returned HTTP 403; the 9.4 page (source 5) was used.
- The VQL fetch response included a sample query labelled by the fetcher as general
  VQL style and not from the page; it is deliberately not reproduced.

## Design decisions that follow

- Own grammar and name (`kavach-seq`), EQL-inspired surface: `cat where cond`,
  `sequence by ... with maxspan=... [..] [..] until [..]`.
- Deterministic semantics, fully documented in the doc comment of `runSeq`  (internal/edr/hunt_eql_eval.go): partition by join key, skip-till-next-match, ordered by time then
  event id, non-overlapping matches, `until` aborts, inclusive `maxspan`.
  Chosen over EQL's overwrite-pending-state behaviour so a brute-force reading of the
  stated rules gives the same answer; a test enforces exactly that on random inputs.
- No Kleene closure, no any-match enumeration, no negation `!`, no pipes (cost and
  complexity per source 9; scope).
- Regex is RE2 only (Go `regexp`, linear time) with a 256-byte pattern cap.
- Per-category field catalogue including explicitly absent fields (source 6 idea).
