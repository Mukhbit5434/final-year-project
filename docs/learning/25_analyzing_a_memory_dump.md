# 25 — Analyzing a Memory Dump: Extraction Through Severity

The memory pipeline's version of file 24 — same overall shape (a
background thread picks up a `RUNNING` job, extraction happens in a
separate process, then prediction/explanation/tagging/severity happen back
in the main process) but a genuinely different internal *order*, worth
paying close attention to: the memory pipeline deliberately gathers its
own direct observations and computes severity **before** it ever decides
whether to bother asking the model to explain itself — the concrete,
step-by-step expression of hard rule 22 ("memory reports lead with
observations, never the model's score").

## Visual flow

```
jobs.run(app, job_id)                                            [jobs.py]
  -> job.status = RUNNING; commit                                  sequential
  -> jobs._memory(app, job, path)                                  sequential
       |
       |  -- BACKGROUND HAND-OFF: extraction runs in a SEPARATE PROCESS --
       |
       -> pool().submit(extract_memory, ...)      <-- hands off, does not block yet
       -> _await(job, future, progress_file)      <-- blocks HERE, polling once/second
            |                                          (full mechanism: file 27)
            |
            |  [inside the separate worker process:]
            |  extract_memory()                                    [jobs.py]
            |    -> memory.extract()                                [extractors/memory.py]
            |         -> build_context()            (architecture gate)   sequential
            |         -> run_plugin() x9            (one plugin after another,
            |                                        NOT in parallel)      sequential
            |         -> dedupe_services()                                sequential
            |         -> from_pslist(), from_dlllist(), ... x9            sequential
            |         -> assemble()                 (builds the 55-vector) sequential
            |         -> evidence()                 (builds locator lists) sequential
            |
       <- (once the worker process finishes, _await() returns the result)
       |
       -> model.predict(vec)                                       [inference/memory.py]
       -> model.ood(vec)                                            [inference/memory.py]
       -> model.dominant_ood(vec)                                    [inference/memory.py]
       -> meanings.observed(vec, names)                               [forensics/meanings.py]
       -> baseline.compare(observed)                                   [forensics/baseline.py]
       -> mitre.match(everything observed, "memory")                    [forensics/mitre.py]
       -> mitre.match(only elevated, "memory")                           [forensics/mitre.py]
       -> severity.for_memory(elevated, standout, prob, reliable, ...)    [forensics/severity.py]
       -> baseline.volumetric_context(vec, names, elevated)                [forensics/baseline.py]
       -> Result(...) / db.session.add()
       -> meanings.describe()  (per observed feature, always)               [forensics/meanings.py]
       -> baseline.phrase()    (per observed feature, always)                [forensics/baseline.py]
       -> IF malicious AND reliable:
            explain.memory_findings(vec)   (ONLY case LIME runs at all)       [explain.py]
       -> jobs._findings(result, described, matched)                          [jobs.py]
  <- back in jobs.run(): job.status = COMPLETED; commit
```

## 1. Trigger

Identical in kind to file 24's: a Flask-Executor background thread
reaching `jobs.run(app, job_id)`, this time finding `job.artifact ==
"memory"`.

## 2. The full sequence, step by step

**Step 1 — `jobs.run(app, job_id)`, `app/jobs.py`.** Exactly the same
entry point as file 24 — this one function branches to `_memory()` instead
of `_disk()` based purely on `job.artifact`.

**Step 2 — `_memory(app, job, path)`, `app/jobs.py`.** Computes a
progress-file path, then hands extraction off.

**Step 3 — `pool().submit(extract_memory, str(path), names, str
(progress_file))`.** Same process-pool hand-off mechanism as file 24 — the
reason here is slightly different but related: Volatility 3's plugin
execution is CPU-bound Python that would otherwise hold the GIL and
freeze the whole web server for several minutes (§7).

**Step 4 — `_await(job, future, progress_file)`.** Identical mechanism to
file 24's step 4 — covered fully in file 27.

**Step 3, continued (inside the separate process) — `extract_memory(path,
feature_names, progress_file)`, `app/jobs.py`.** Calls `memory.extract
(path, feature_names, progress=stage)`.

**Step 5 — `memory.extract(...)`, `app/extractors/memory.py`.** The real
work. In exact order: `build_context(dump, catalog)` first — this single
call is the architecture gate (§10): it resolves just enough of a
`PsList` plugin to determine the memory layer's class, and if it isn't
64-bit x64, raises an error right here, **before any of the nine real
plugins run at all**. Then, one at a time, **strictly sequentially, never
in parallel** — `run_plugin()` for every entry in `PLUGINS` (`pslist`,
`dlllist`, `handles`, `ldrmodules`, `malfind`, `psxview`, `modules`,
`svcscan`, `callbacks`), each one's wall-clock time individually recorded.
Then `dedupe_services()` fixes Volatility 3's own duplicate-emission bug
on the raw `svcscan` rows (§10). Then all nine `from_*()` functions run,
each turning one plugin's rows into a small `{feature: value}` dictionary
— `from_pslist`, `from_dlllist`, `from_handles`, `from_ldrmodules`,
`from_malfind`, `from_psxview`, `from_modules`, `from_svcscan`,
`from_callbacks`. Then `assemble(parts, feature_names, ...)` merges all
nine dictionaries by name and lays the final 55-value vector out in
exactly `feature_list.json`'s order — the one place ordering is ever
imposed (§10, §8). Then `evidence(collected)` separately builds the
capped, sorted per-process locator lists from the same already-collected
plugin rows, at essentially no extra cost.

**Step 6 (back in the main process, inside `_await()`) — the future
resolves**, returning the full result dictionary (the 55-value vector, the
gap list, per-plugin timings, the evidence structure, and more) back to
`_memory()`.

**Step 7 — `model.predict(vec)`, `app/inference/memory.py`.** Runs the
full 55-value vector through the loaded XGBoost model, using
`inplace_predict` specifically (never the more common `DMatrix` path — §8
explains exactly why this model in particular needs that). Output: a
probability and a boolean verdict.

**Step 8 — `model.ood(vec)`, `app/inference/memory.py`.** Checks all 55
values against the training data's per-column min/max. Output: a count,
and the list of which specific features are out of range.

**Step 9 — `model.dominant_ood(vec)`, `app/inference/memory.py`.**
Narrows that same check to just the four features the model leans on
most heavily. Output: which of those four (if any) are out of range.
`reliable = not dominant` — this one boolean, computed here, at this exact
point, is what governs whether the model's own opinion is trusted for
*everything* that follows in this chain, including, several steps down,
whether LIME even runs at all.

**Step 10 — five fields written directly onto the `Job` row**:
`extraction_gaps`, `ood_count`, `ood_fields`, `plugin_seconds`,
`evidence` — all copied straight from `memory.extract()`'s own return
value from step 5/6, with no further processing.

**Step 11 — `meanings.observed(vec, names)`, `app/forensics/meanings.py`.**
Plain language: picks out every one of the eleven `BEHAVIOURAL` features
that has a genuinely nonzero value in this specific capture. Why here,
this early, deliberately *before* the model's own opinion has been
consulted for anything except its bare probability: this is the concrete
implementation of "memory reports lead with observations" — these values
are Volatility's own direct measurements and don't depend on what the
model predicted at all. Output: a `{feature: value}` dictionary.

**Step 12 — `baseline.compare(observed)`, `app/forensics/baseline.py`.**
Checks each observed value against `ceiling(feature)` — the highest value
ever seen across the seven clean reference captures, times a small margin
(§11). Output: a `{feature: True/False}` dictionary of which ones are
genuinely elevated, not merely present.

**Step 13 — `mitre.match(list(observed), "memory")`, `app/forensics/
mitre.py`.** The **first** of two calls to this exact function in this
one chain. Runs over *every* observed feature, elevated or not — this is
what produces `matched`, used purely to **label** findings so an analyst
can see what each measurement maps to. *Called from elsewhere?* Yes — this
same function is called once (not twice) inside file 24's disk chain too.
See file 29.

**Step 14 — `mitre.match([f for f, hi in elevated.items() if hi],
"memory")`, `app/forensics/mitre.py`.** The **second** call to the same
function, over a deliberately narrower input — only the features step 12
marked as genuinely elevated. Produces `standout`. Why two calls rather
than one: §11 and §7 both cover this in depth — matching on mere presence
alone once scored a perfectly clean reference capture as Critical, so only
this narrower, elevated-only result is allowed to influence severity next.

**Step 15 — `severity.for_memory(elevated, standout, prob, reliable,
baselined=baseline.loaded())`, `app/forensics/severity.py`.** Plain
language: computes the Low/Medium/High/Critical bucket. Notice the
argument order itself: `elevated` and `standout` (the evidence) come
*first*; `prob` (the model's score) comes third, and only ever contributes
as a small, capped adjustment, never as the primary driver (§11's full
walkthrough of this function's internal logic). Output: a severity level
and a plain-English reason string naming exactly which categories and how
many indicators drove it.

**Step 16 — `baseline.volumetric_context(vec, names, elevated)`, `app/
forensics/baseline.py`.** Computed *after* severity, deliberately, and its
result is never passed back into anything severity-related — it produces
configuration-context data (service counts, process counts) that's
reported separately and is structurally incapable of affecting the
severity already computed in step 15 (§11's architectural-separation
explanation).

**Step 17 — `Result(...)`, then `db.session.add(result)`.** One single
row (unlike disk's one-per-file loop — memory analyzes one whole dump, not
many separate files, §4) carrying the probability, threshold, verdict,
and the severity/reason just computed.

**Step 18 — building the findings list, first pass: always runs, for
every observed feature.** For each feature in `observed`, sorted
highest-value-first: `meanings.describe(feature)`, `app/forensics/
meanings.py` (resolves the plain-English label/explanation), then
`baseline.phrase(feature, value)`, `app/forensics/baseline.py` (appends
the exact clean-baseline comparison sentence onto that explanation). This
whole pass runs **unconditionally** — regardless of what the model
predicted, this is evidence Volatility genuinely measured.

**Step 19 — the one and only condition under which `explain.
memory_findings(vec)` (`app/explain.py`) is ever called: `if malicious and
reliable:`.** Both halves of this condition matter independently: `malicious`
(the model actually flagged this dump) and `reliable` (computed all the way
back in step 9 — the four dominant features are themselves in range). If
either is false, LIME never runs for this job at all, and this
functionality's findings are built entirely from step 18's direct
observations. When it *does* run: exactly the same `_top()`/`meanings.
describe()` mechanism file 24 already covered for disk, just against the
memory explainer and the memory feature names — and only features not
already covered by step 18's direct observations get added, avoiding
duplicate findings for the same measurement.

**Step 20 — `jobs._findings(result, described, matched)`, `app/jobs.py`.**
The exact same shared helper file 24's disk chain calls too (see file 29)
— attaches whichever MITRE tag (from `matched`, step 13's broad match, not
`standout`) claimed each described feature, and creates one `Finding` row
per item.

**Step 21 (back in `jobs.run()`) — `job.status = COMPLETED`, then the
`finally` block finishes exactly as file 24's did.**

## 3. Sequential versus background/parallel

The same three-level structure as file 24 applies at the outer level
(this whole functionality already runs on a background thread; extraction
specifically is handed off to a separate process and waited on) — **with
one real difference worth calling out explicitly**: inside `memory.
extract()`, the nine plugins run **strictly one after another, never in
parallel**, unlike disk's PE-vectorization step, which genuinely does
parallelise across a small worker pool. There is no equivalent "second
pool inside the first worker" for memory extraction at all — every one of
the nine plugins' wall-clock times, recorded individually into
`plugin_seconds`, are measuring nine genuinely sequential steps, not nine
things that happened at once. Everything from step 7 onward (prediction
through building findings) is also strictly sequential, on the single
worker thread that's been waiting on `_await()`.

## 4. Where this functionality starts and ends

**Starts:** the moment the background thread begins executing `jobs.run
(app, job_id)` and finds `job.artifact == "memory"`.
**Ends:** identically to file 24 — the moment `job.status` becomes
`COMPLETED` (or `FAILED`, file 28) and the final commit in `jobs.run()`'s
`finally` block completes.

## 5. Check your understanding

**Q1. `mitre.match()` is called twice in this one chain, with two
different inputs. Name what each call's input actually is, and which one
feeds into `severity.for_memory()`.**

A: The first call runs over `list(observed)` — every behavioural feature
that measured as nonzero at all, regardless of whether it's unusual for
this machine — producing `matched`, used only to label findings. The
second call runs over only the features `baseline.compare()` marked as
genuinely elevated against the clean baseline, producing `standout` — and
it's specifically `standout`, the narrower result, that gets passed into
`severity.for_memory()`, never the broader `matched`.

**Q2. Trace exactly which three things all have to be true at the same
time for `explain.memory_findings()` to run at all in this chain, and name
the two functions, called earlier in the same sequence, that determined
two of those three things.**

A: `malicious` must be true (determined by `model.predict(vec)`, step 7)
and `reliable` must be true (`reliable = not dominant`, where `dominant`
comes from `model.dominant_ood(vec)`, step 9) — both checked together in
the single `if malicious and reliable:` condition at step 19. (The third
implicit condition is simply that this step is reached at all, i.e.
nothing earlier in the chain raised an exception.)

**Q3. Compare this chain to file 24's disk chain: in file 24, the model's
prediction (`model.predict()`) happens, and immediately afterward the
result row is created before anything else runs. In this memory chain,
several steps (observing features, comparing to baseline, matching MITRE
tags twice, computing severity) all happen *between* `model.predict()`
and the `Result(...)` row being created. Why does memory's chain have all
that in between, when disk's doesn't?**

A: Because memory severity is deliberately evidence-led rather than
verdict-led (§11) — the `Result` row needs its `severity` and
`severity_note` fields filled in at the moment it's created, and computing
those requires the observed-feature data, the baseline comparison, and the
narrower MITRE match to already exist *before* `severity.for_memory(...)`
can be called. Disk's severity, by contrast, is verdict-led and can be
computed directly from the probability plus a much shorter tag-matching
step, so far less has to happen between predicting and creating the
result row.
