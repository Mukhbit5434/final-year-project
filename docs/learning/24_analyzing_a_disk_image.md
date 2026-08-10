# 24 — Analyzing a Disk Image: Extraction Through Severity

This is the first of two "big" functionality files — the complete real
chain the code runs for a disk job, from the moment a background thread
picks it up to the moment every file inside the image has a stored
verdict. This single file deliberately covers extraction, prediction,
explanation, tagging, *and* severity together, because in the real code
they run as one continuous, tightly-linked sequence inside one function —
see file 20's overview for why splitting that real sequence across four
separate files would have made it harder, not easier, to see the actual
order things happen in.

## Visual flow

```
jobs.run(app, job_id)                                          [jobs.py]
  -> job.status = RUNNING; commit                                sequential
  -> jobs._disk(app, job, path)                                  sequential
       |
       |  -- BACKGROUND HAND-OFF: extraction runs in a SEPARATE PROCESS --
       |
       -> pool().submit(extract_disk, ...)     <-- hands off, does not block yet
       -> _await(job, future, progress_file)   <-- blocks HERE, polling once/second
            |                                       (see file 27 for the full
            |                                        progress-reporting mechanism)
            |
            |  [inside the separate worker process, running independently:]
            |  extract_disk()                                    [jobs.py]
            |    -> disk.scan()                                  [extractors/disk.py]
            |         -> open_image()                              sequential
            |         -> filesystems()                             sequential
            |         -> walk()  (one big loop, finds every PE)     sequential
            |         -> ProcessPoolExecutor(_init_worker)  <-- ANOTHER, SEPARATE
            |              -> _vectorize() per file            pool, INSIDE this
            |                                                  already-separate worker
            |
       <- (once the worker process finishes, _await() returns the result)
       |
       -> model.names()                                          [inference/disk.py]
       -> FOR EACH FILE FOUND (one full sequential pass, file by file):
            -> model.subset(vec_2381)                             [inference/disk.py]
            -> model.predict(vec_150)                              [inference/disk.py]
            -> Result(...)  / db.session.add()
            -> IF NOT flagged: severity.for_disk(prob, [], threshold)  -- STOP, next file
            -> IF flagged:
                 -> explain.disk_findings(vec)                     [explain.py]
                      -> LIME explain_instance()
                      -> meanings.describe()  (per candidate feature)  [forensics/meanings.py]
                 -> mitre.match(features, "disk", values)           [forensics/mitre.py]
                 -> severity.for_disk(prob, matched, threshold)     [forensics/severity.py]
                 -> jobs._findings(result, described, matched)      [jobs.py]
                      -> Finding() per item / db.session.add()
       -> job.files_scanned / files_flagged / skipped = ...
  <- back in jobs.run(): job.status = COMPLETED; commit
```

## 1. Trigger

Not a person clicking anything — the trigger is **a Flask-Executor
background thread reaching the point where it calls `jobs.run(app,
job_id)`**, which itself was scheduled by `job_queue.start()` at the very
end of file 23's upload functionality. By the time this functionality's
first real step runs, the analyst's browser has usually already received
its own response and moved on — this functionality runs completely
independently of any specific request.

## 2. The full sequence, step by step

**Step 1 — `jobs.run(app, job_id)`, `app/jobs.py`.** Sets `job.status =
RUNNING`, records `job.started_at`, commits — this single commit is what
makes the "in progress" state visible to a browser polling `job_status()`
(file 27). Reads `job.artifact`, sees `"disk"`, and calls `_disk(app, job,
path)`. *(This same function, `jobs.run()`, is also the entry point for
the memory pipeline — file 25 — which is exactly why "disk" vs. "memory"
is decided by one simple `if` right here rather than two entirely separate
top-level functions.)*

**Step 2 — `_disk(app, job, path)`, `app/jobs.py`.** The real entry point
for everything specific to disk analysis. Computes a progress-file path
(`_progress_file`, file 27), then immediately does the background
hand-off described next.

**Step 3 — `pool().submit(extract_disk, str(path), max_files, max_bytes,
str(progress_file))`, `app/jobs.py`.** Plain language: hands the actual
extraction work off to a completely separate operating-system **process**
(not a thread — file 07/§7 covers exactly why this specific work needs a
real process: `lief`, called deep inside this chain, is native code
parsing potentially hostile input, and a crash there must not be able to
take the whole web server down with it). This call itself returns
*immediately* with a "future" (a placeholder for a result that isn't ready
yet) — it does not wait.

**Step 4 — `_await(job, future, progress_file)`, `app/jobs.py`.** This is
where the current thread actually *does* wait — but not with a plain,
blind wait. It repeatedly calls `future.result(timeout=1.0)`, and every
time that one-second wait expires without the worker being done, it reads
whatever the worker has most recently written to the progress file and
copies it onto the `Job` row. File 27 is dedicated entirely to this exact
mechanism; it's mentioned here only to mark where, in this functionality's
sequence, that separate concern is actually happening — concurrently,
"underneath" this same `_await()` call, for the whole rest of Part 3 below.

**Step 3, continued (inside the separate process) — `extract_disk(path,
max_files, max_bytes, progress_file)`, `app/jobs.py`.** This is the actual
function object that was handed to the process pool in step 3 — it runs
on a completely different process than everything above and below it in
this list, with no shared memory at all with the main web server. It calls
`disk.scan(path, max_files=..., max_bytes=..., workers=2, progress=...)`.

**Step 5 — `disk.scan(...)`, `app/extractors/disk.py`.** The real
filesystem work begins here. In order: `open_image(path)` (opens the raw
or E01 image); `filesystems(img)` (finds every mountable partition);
then, for each filesystem found, it consumes `walk(fs, ...)` — a generator
(§9) that yields, one at a time, either "examined" markers, "skip"
records with a reason, or a genuine PE file's record plus its raw bytes.
`scan()` itself enforces the file-count cap and content-hash
deduplication on every PE record `walk()` yields (§9's own detailed
walkthrough of `scan()` covers this loop in full — it is not repeated
here, since this file's job is the *overall* sequence, not re-explaining
each extractor function individually a second time).

**Step 6 — vectorization, `disk.scan(...)`'s own second half.** Once the
*entire* filesystem walk is finished (not interleaved with it — a
genuinely separate phase), `scan()` opens a **second, different**
`ProcessPoolExecutor` — yes, a pool of processes *inside* a function that
is itself already running inside a separate process from the main web
server — sized by the `workers` parameter, and submits every found PE
file's raw bytes to `_vectorize()`, running inside `_init_worker()`'s
already-built `ember` extractor (§9). Each file's result (or timeout, or
parse failure, individually) comes back and is attached to that file's own
record. `scan()` returns one dictionary: every successfully vectorized
file, every skip with its reason, and summary counts.

**Step 7 (back in `extract_disk()`) — vector conversion.** Every found
file's NumPy vector is converted to a plain Python list
(`rec["vec"].tolist()`) before this whole function returns — necessary
because the result has to survive being pickled back across the process
boundary to the main web server process (§7 covers exactly why this
conversion specifically happens here).

**Step 8 (back in the main process, inside `_await()`) — the future
finally resolves**, and `_await()` returns the full result dictionary back
up to `_disk()`.

**Step 9 (back in `_disk()`) — `model.names()`, `app/inference/disk.py`.**
Plain language: returns the list of the 150 real feature names, in the
model's own expected order — needed a few steps down, to attach real names
to values before calling `mitre.match()`.

**Step 10 — the per-file loop begins.** `_disk()` now iterates over every
single file `disk.scan()` found, running the following steps for **each
one individually**, in order, one file completely finishing before the
next one starts (a genuinely sequential loop, not parallel — extraction
was the parallel part; scoring is not):

**Step 10a — `model.subset(rec["vec"])`, `app/inference/disk.py`.** Plain
language: reduces this one file's full 2,381-value EMBER vector down to
exactly the 150 values the model actually expects, using the index list
computed once at startup (file 21, file 08). Input: the 2,381-length raw
vector. Output: a 150-length vector.

**Step 10b — `model.predict(vec_150)`, `app/inference/disk.py`.** Plain
language: runs the 150-value vector through the loaded LightGBM model.
Output: a probability, and a boolean of whether it's at or above the real
operating threshold (never a hardcoded `0.5` — file 08). *Called from
elsewhere?* The disk model's `predict()` is also the function
`scripts/scan_image.py` and `scripts/predict_vector.py` call directly when
run standalone — see file 29.

**Step 10c — `Result(...)`, `app/models.py`, then `db.session.add(result)`.**
A new database row is created for this one file, carrying every locator
field (path, both hashes, size, MACB timestamps) straight from the
extractor's own record, plus this prediction's probability and threshold.

**Step 10d — the branch that decides whether the rest of this loop
iteration even runs.** If `not malicious`: `severity.for_disk(prob, [],
threshold)` is called immediately, with an **empty** findings list, and the
loop moves straight to the next file — LIME is never invoked for a file
that wasn't flagged (§7 explains directly why: it would be pure wasted
runtime, since nobody will ever read an explanation for a clean verdict).

**Step 10e (only for a flagged file) — `explain.disk_findings(vec)`,
`app/explain.py`.** Plain language: asks the pre-built disk LIME explainer
(built once, back in file 21's startup sequence) to explain this specific
prediction. Inside it: `explainer.explain_instance(vec, _proba(disk),
num_features=15, labels=(1,))` runs LIME itself; `_top(explanation, names,
8)` then walks LIME's `as_map()[1]` results (never `as_list()` — §11
explains why in full) and, for each positively-weighted feature, calls
`meanings.describe(feature_name)`, `app/forensics/meanings.py`, to turn
the raw feature name into a plain-English label and explanation. Output: a
list of up to 8 described findings, each carrying its feature name,
weight, and plain-English text.

**Step 10f — `mitre.match([d["feature"] for d in described], "disk",
values)`, `app/forensics/mitre.py`.** Plain language: checks every one of
this file's described findings against the small, human-authored table of
MITRE ATT&CK indicator tags. `values` (a `{name: value}` dictionary built
just before this call) lets the one value-aware disk tag (the
unsigned-binary check, §11) verify a feature's *real* value rather than
just its name being present. Output: every matching tag, not just one
(§11 explains why "every," not "best").

**Step 10g — `severity.for_disk(prob, matched, threshold)`, `app/
forensics/severity.py`.** Plain language: turns the probability and the
matched tags into a Low/Medium/High/Critical bucket plus a plain,
human-readable reason string, using disk's verdict-led additive scoring
(§11). *Called from elsewhere?* Yes — step 10d above calls this exact same
function too, just with an empty findings list, for every unflagged file.

**Step 10h — `jobs._findings(result, described, matched)`, `app/jobs.py`.**
Plain language: creates one `Finding` database row per described item,
attaching whichever MITRE tag (if any) claimed that specific feature (§7's
detailed walkthrough of this small helper's `owner` dictionary). *Called
from elsewhere?* Yes — file 25's memory pipeline calls this exact same
function too, at the very end of its own chain. See file 29.

**Step 11 (after the loop over every file has finished) —
`job.files_scanned = out["examined"]`, `job.files_flagged = flagged`,
`job.skipped = out["skipped"]`.** Three summary fields, written once,
directly onto the `Job` row itself (distinct from the many per-file
`Result` rows already created inside the loop).

**Step 12 (back in `jobs.run()`) — `job.status = COMPLETED`, then the
`finally` block records `finished_at`, clears the live-progress fields,
and commits one final time.** This is where file 24 genuinely ends —
covered in full, alongside what happens if any step above had raised an
exception instead, in file 28.

## 3. Sequential versus background/parallel

Three genuinely different levels of "background" appear in this one
functionality, worth telling apart precisely:

1. **The whole of `_disk()`'s extraction-through-scoring work is itself
   already running on a background thread**, relative to the web server's
   own ability to keep answering other, unrelated requests — this hand-off
   happened back in file 23.
2. **Within that, extraction specifically (`disk.scan()`) is handed off
   again**, to a genuinely separate operating-system *process* — and the
   supervisor (`_disk()`'s own thread) genuinely waits for it, via
   `_await()`, rather than doing anything else in the meantime.
3. **Within extraction itself, vectorizing the many found PE files runs in
   parallel**, across a small pool of worker processes (`workers=2` by
   default) — this is the one genuinely parallel (not just backgrounded)
   step in this whole functionality: multiple files' bytes really are
   being turned into vectors at the same moment, on different processes.

Everything else — the filesystem walk itself, and the entire per-file
scoring loop (steps 10a–10h, run once per file) — is strictly sequential,
one file completely finishing its whole prediction-through-severity
sequence before the next file's begins.

## 4. Where this functionality starts and ends

**Starts:** the moment the background thread scheduled back in file 23
actually begins executing `jobs.run(app, job_id)` and finds `job.artifact
== "disk"`.
**Ends:** the moment `job.status` is set to `COMPLETED` (or, covered fully
in file 28, `FAILED`) and the final commit in `jobs.run()`'s `finally`
block completes. Everything from here on — an analyst actually *viewing*
these now-finished results — belongs to file 26, not this one.

## 5. Check your understanding

**Q1. `disk.scan()` uses two separate `ProcessPoolExecutor` pools, at two
different points in this one functionality's sequence. What is each one
actually for, and are they the same pool reused twice or genuinely two
different pools?**

A: They're two genuinely different pools. The first hand-off —
`pool().submit(extract_disk, ...)` inside `_disk()` — sends the *entire*
extraction job to one worker process, specifically so a crash while
parsing hostile input can't take down the main web server. The second,
separate pool is created *inside* `disk.scan()` itself (already running
inside that first worker process) purely to vectorize multiple found PE
files in parallel, sized by the `workers` argument — a completely
independent pool with a completely different purpose (parallelising many
small, independent tasks, rather than isolating one risky operation).

**Q2. For a disk image containing 200 files, of which 6 are flagged as
malicious, how many times does `explain.disk_findings()` actually get
called during this whole functionality — and why not 200 times?**

A: Exactly 6 times — once per flagged file, never for the other 194. The
per-file loop (step 10) checks `if not malicious:` immediately after
predicting, and for every file that check is true, the loop calls
`severity.for_disk(...)` with an empty findings list and moves straight to
the next file, skipping `explain.disk_findings()` (and `mitre.match()`,
and `_findings()`) entirely — deliberately, to avoid the real, non-trivial
cost of running LIME on results nobody will ever read an explanation for.

**Q3. `severity.for_disk()` is called at two different points inside the
per-file loop (step 10d and step 10g), not just once. What's different
about the two calls, and why does the function need to be called twice
rather than once at the end of the loop for each file?**

A: The two calls happen on two mutually exclusive paths for the same file
— never both for the same file. Step 10d's call (`severity.for_disk(prob,
[], threshold)`) runs only when the file *wasn't* flagged, passing an
empty list because there are no MITRE matches to consider at all. Step
10g's call (`severity.for_disk(prob, matched, threshold)`) runs only when
the file *was* flagged, after `mitre.match()` has actually produced real
matched tags to feed in. Both calls exist because every single `Result`
row needs a severity value set regardless of whether it was flagged, but
only a flagged file has real tag data worth passing in — calling it once
at the very end for every file would mean either running the whole
explain/tag pipeline for clean files too (wasteful) or restructuring the
loop awkwardly to defer the severity call past the branch, for no real
benefit.
