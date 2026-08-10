# 99 — Glue It Together: One Memory Capture, Start to Finish

This is the payoff file. Every prior file explained one layer in isolation;
this one traces a single, real request through every one of those layers,
in the exact order the code actually executes, from the moment an analyst
clicks "Upload and queue" to the moment they view a finished report. Every
step names the specific file and function responsible, and the section of
this curriculum that covers it in depth — read this as confirmation that
everything really does connect, not as a first introduction to any of it.

The scenario: an analyst, already signed in, uploads `malicious_1.raw` — a
real memory capture of the reference machine, taken while
`scripts/sim_injector.py` and `scripts/sim_spawnkill.py` (§15) were both
running — selecting "Detect automatically."

## Part 1 — Before this request even happens: the server is already running

Some time earlier, someone ran `python run.py` (§5). Inside its
`if __name__ == "__main__":` guard, `create_app()` (`app/__init__.py`, §5)
ran once: it read `Config` (§3) and copied every setting onto the live
Flask app; it attached SQLAlchemy, Flask-Migrate, CSRF protection,
Flask-Executor, and the rate limiter (§1, §5); because `LOAD_MODELS` was
`True`, it called `inference.init(...)` (§8), which loaded both the
XGBoost memory model and the LightGBM disk model, ran every one of their
startup sanity checks (feature counts, thresholds not equal to `0.5`, the
non-monotonic subset-index assertion for disk, the bimodal reference-
distribution check for both), and would have refused to boot at all had
any of them failed; it called `explain.init(...)` (§11), building both
LIME explainers against their reference samples; it called
`baseline.load(...)` (§11), reading the seven-capture clean-machine
baseline JSON into memory; it registered the `auth` and `main` blueprints
(§6, §7, §13); and it called `jobs.recover_orphans(app)` (§7), which found
no stale `RUNNING` jobs this time and did nothing. `app.run(host=
"127.0.0.1", port=5000, threaded=True)` then started listening for real
HTTP requests. None of what follows would work correctly if any single one
of those startup steps had been skipped.

## Part 2 — The upload request

The analyst's browser sends a `POST /upload` request, carrying the file
bytes and the form's CSRF token. Three decorators on
`routes.py:upload()` (§7) run in order: the rate limiter checks this
analyst hasn't exceeded `UPLOAD_RATE_LIMIT` (§1, §3); `@login_required`
(§6) confirms `current_user.is_authenticated`, reading the signed session
cookie Flask-Login set when this analyst originally logged in.

Inside the route body (§7): `form.validate_on_submit()` confirms the CSRF
token is valid and a file was genuinely attached. `artifacts.ext_of(...)`
reads the extension — `.raw` — and confirms it's in `ALLOWED_EXT` (§3).
`artifacts.store(...)` (§7) streams the file to disk 4 MB at a time,
hashing incrementally with SHA-256 as it goes, and writes it under a fresh
random UUID name into `uploads/` — never the client's own filename, and
never fully loaded into memory at once.

`form.artifact.data` reads `"auto"` (the analyst left detection on
automatic), so `artifacts.sniff(path)` (§7) runs: it reads the first 1024
bytes, checks for a crash-dump header, an EWF magic, a GPT header, an MBR
signature — finds **none** of them, because a raw memory dump genuinely
carries no identifying header at all — and honestly returns `(None, "no
disk signature and no crash-dump header...")`.

A new `Job` row (§4) is created: `filename="malicious_1.raw"`,
`stored_name` the random UUID name, the real `sha256` and `size_bytes`,
`artifact=None`, `status="NEEDS_TYPE"`. It's flushed (to get a real `id`),
audited (`log("upload", ...)`, §6), and committed. Because `detected` is
`None`, the route flashes "Could not identify this artifact from its
contents" and redirects to `confirm_type(job.id)` — **no background job
has been dispatched yet.**

## Part 3 — Resolving the ambiguous type

`confirm_type()` (§7) loads the job via `_owned(job_id)` (§7's
authorization pattern — 404, not 403, for a job that isn't this analyst's
own), confirms its status is genuinely `NEEDS_TYPE`, and shows
`confirm_type.html` (§13), which explains directly, in plain language, why
detection was inconclusive — the same honest framing already embedded in
`artifacts.sniff()` itself.

The analyst selects "Memory dump" and submits. `job.artifact = "memory"`,
`job.detected_as = "confirmed by analyst after inconclusive detection"`,
`job.status = "PENDING"` — this exact row is updated, not a new one
created. **Only now** does `job_queue.start(app._get_current_object(), job.
id)` (§7) actually run: `DISPATCH_JOBS` is `True` in the real `Config`
(§3), so `executor.submit(run, app, job.id)` hands the whole job off to a
Flask-Executor thread and returns immediately. The browser is redirected
to `job_detail.html` (§13), which — because the job isn't `done` yet —
shows the live progress card and starts polling `job_status()` (§7, §13)
every 3 seconds via `fetch()`.

## Part 4 — Inside the background thread: `jobs.run()`

On its assigned thread, `jobs.run(app, job_id)` (§7) begins:
`with app.app_context():` establishes the context this thread needs to use
`db.session`/`current_app` correctly at all. The job is re-fetched fresh
from the database by ID. `job.status = "RUNNING"`, `job.started_at =
utcnow()`, committed **immediately** — this single commit is what the very
next poll from the browser will see, flipping the page from "queued" to
showing a live stage.

`job.artifact == MEMORY`, so `_memory(app, job, path)` (§7) runs, wrapped
in the outer function's `try`/`except`/`finally` — any exception raised
anywhere in the next several steps will be caught, logged, and turned into
a clean `FAILED` status with a readable error, rather than crashing the
thread silently or leaving the job stuck.

## Part 5 — Extraction, across a process boundary

`_memory()` computes a progress-file path (`_progress_file`, §7), then
calls `pool().submit(extract_memory, str(path), names, str(pf))` (§7) —
this is the hand-off to the **separate process pool** (§7's core
architectural explanation: Volatility 3 is CPU-bound Python that would
otherwise hold the GIL and freeze the whole web server for the several
minutes this takes). `_await(job, future, pf)` (§7) then blocks on
`future.result(timeout=1.0)` in a loop — every second it doesn't finish,
it reads whatever `extract_memory`'s own `_reporter` (§7) has most
recently, atomically written to the progress JSON file, and if it changed,
copies `stage`/`progress_pct` onto the `Job` row and commits — this is
precisely what the browser's poll requests have been picking up since Part
3, showing "Building the kernel layer," then "Running windows.pslist (1 of
9)" through "Running windows.callbacks (9 of 9)," then "Assembling the
feature vector."

Inside the worker process, `extract_memory()` (§7) calls
`memory.extract(path, names, progress=stage)` (§10) — the real work:
`build_context(dump, catalog)` (§10) constructs just enough of a `PsList`
plugin to resolve the memory layer, checks `isinstance(layer, Intel32e)` —
this capture genuinely is x64, so extraction is allowed to proceed (had it
not been, an `ExtractionError` would have propagated all the way back up
through `_await` → `_memory` → `run()`'s `except` block, and the job would
have failed cleanly with a message naming the x64-only scope). All nine
plugins in `PLUGINS` (§10) then run in turn via `run_plugin()`, each
timed individually into `timings`.

Because `sim_injector.py` was holding 30 RWX regions open at capture time,
`windows.malware.malfind.Malfind` finds real hits — the injector's own
process plus a handful of legitimately RWX-allocating system processes
(Defender, PowerShell). Because `sim_spawnkill.py` was holding ~100
terminated processes' handles open, `windows.malware.psxview.PsXView`
finds real discrepancies — not primarily in `not_in_pslist`, as an early,
since-corrected theory predicted, but in `not_in_ethread_pool` and
`not_in_csrss_handles` (§10's full account of "silent bug #8" — the terminated
processes stay linked in `pslist` itself, but lose their thread objects and
CSRSS session entries regardless).

`svcscan`'s raw rows are deduplicated by `Order` (§10, fixing Volatility
3's own duplicate-emission bug). All nine `from_*()` functions (§10) turn
their plugin's rows into named `{feature: value}` dictionaries —
`from_malfind` computing real, elevated `ninjections`/`commitCharge`/
`uniqueInjections`; `from_psxview` computing real, elevated
`not_in_ethread_pool`/`not_in_csrss_handles`. `torn_rows()` checks for any
structurally impossible process records this live capture might have
produced. `assemble(parts, feature_names, ...)` (§10) merges every
dictionary by name and only *then* lays the final 55-value vector out in
`feature_list.json`'s exact order — the single line where ordering is
ever imposed at all, closing the entire "feature-naming trap" loop §8
opened this whole curriculum's technical narrative with. `evidence()`
(§10) builds the capped, sorted per-process locator lists — the injected
regions naming `python.exe` and its real virtual addresses, the hidden
processes naming the terminated `conhost.exe` instances and their real
exit timestamps.

The whole result dictionary — `vec`, `gaps`, `plugin_rows`, `bits`,
`plugin_seconds`, `evidence`, `torn_process_rows`, the svcscan duplicate
ratio — travels back across the process boundary by pickling (§10's
extended discussion of why every evidence field is forced through `_int`/
`_hex`/`_text` first, to avoid the exact `BrokenProcessPool` crash this
project once hit for real). `_await()`'s next `future.result()` call
finally returns normally — extraction is done.

## Part 6 — Prediction

Back in `_memory()` (§7), `model.predict(vec)` (§8) reshapes the 55-value
vector, calls `_booster.inplace_predict(mat, iteration_range=(0, 173))` —
deliberately `inplace_predict`, not the more common `DMatrix` path, because
this model carries real internal feature names that `DMatrix`-based
prediction would otherwise validate and reject a plain positional array
over (§8) — and returns a real probability, genuinely elevated above the
0.0077–0.0081 range every clean reference capture scores, because this
capture really is different: it's roughly 0.474, against the threshold of
0.2336726188659668.

`model.ood(vec)` (§8) checks all 55 values against the training data's
per-column min/max (`reference_data/memory_sample.npy`) — a large fraction
read outside range, unsurprising for any real capture given the training
data's single-VM origin (§8, §2's dataset-saturation story). `model.
dominant_ood(vec)` (§8) checks specifically whether the four features the
model leans on most (`svcscan.nservices`, `handles.nmutant`, `svcscan.
shared_process_services`, `svcscan.kernel_drivers`) are themselves out of
range — on a real capture, they are, so `reliable = False`. This single
boolean is about to determine how much of what follows even gets to use
the model's own opinion at all.

## Part 7 — Forensics: evidence, tags, and severity

`meanings.observed(vec, names)` (§11) picks out every `BEHAVIOURAL`
feature with a genuinely nonzero value — `malfind.ninjections`,
`malfind.commitCharge`, `malfind.uniqueInjections`, `psxview.not_in_
ethread_pool`, `psxview.not_in_csrss_handles`, and others — entirely
independent of what the model predicted. `baseline.compare(observed)`
(§11) checks each one against `ceiling(feature)` — the highest value ever
seen across the seven clean reference captures, times 1.2 — and this is
where the real, measured elevation gets confirmed: `malfind.ninjections`
at roughly 46 clears its ceiling of 10.8 several times over; `psxview.
not_in_ethread_pool` clears its ceiling by over 20×.

`mitre.match(list(observed), "memory")` (§11) is called once, over
*everything* observed, producing `matched` — labelling every finding
regardless of whether it's elevated. A second, narrower call,
`mitre.match([f for f, hi in elevated.items() if hi], "memory")`, produces
`standout` — only the genuinely elevated subset — and this is the call
that actually feeds `severity.for_memory(elevated, standout, prob,
reliable, baselined=True)` (§7, §11). Two distinct high-risk technique
categories match: **Process Injection (T1055)**, from the malfind features,
and **Rootkit / Hidden Artifacts (T1014)**, from the psxview features. With
`risky == 2`, `level` starts at 2 (High); with several indicators elevated
at once, it bumps to 3 (Critical); and because `reliable` is `False`, the
model's own probability is explicitly **withheld** from the score entirely
— the returned reason string says so in plain words, rather than silently
ignoring it. The result: **Critical**, driven entirely by the evidence, with
the model's real (elevated, but untrusted) probability recorded for
reference only.

`baseline.volumetric_context(vec, names, elevated)` (§11) separately
checks whether configuration counts (like `pslist.nproc`, elevated here too
— the ~100 spawned-and-killed processes really did raise the live process
count) are also elevated, producing a note worded to say this is
"consistent with additional software" rather than a finding — and,
architecturally, this data is never even passed to `severity.for_memory()`
at all, so it could not affect the Critical verdict even if it were far
more dramatic.

One `Result` row (§4) is created: `probability≈0.474`, `threshold=
0.2336726188659668`, `malicious=True`, `severity="Critical"`, carrying the
full reason string. Findings are built (§7's `jobs.py:_memory()`): every
genuinely observed behavioural feature first, each with `meanings.describe
(...)`'s (§11) plain-English explanation plus `baseline.phrase(...)`'s
(§11) exact comparison sentence appended — this is hard rule 22 made
concrete, evidence listed before the model is ever consulted at all. Only
because `malicious and reliable` would need to *both* be true does LIME
get consulted next — but `reliable` is `False` here, so **LIME never runs
for this result at all**, saving real runtime on an explanation nobody
should trust anyway. `_findings(result, described, matched)` (§7) writes
one `Finding` row per description, each carrying whichever MITRE tag (if
any) claimed that specific feature.

## Part 8 — Finishing the job

Back in `jobs.run()`'s outer function (§7), nothing raised an exception, so
`job.status = "COMPLETED"`. The `finally` block always runs regardless:
`job.finished_at = utcnow()`, `stage`/`progress_pct` cleared back to
`None`, one final commit, `db.session.remove()`, and the now-unneeded
progress file deleted. The next time the browser's poll (still running
every 3 seconds since Part 3) receives a response with `"done": true`
(§13's `job_status()`), its JavaScript calls `location.reload()`.

## Part 9 — Viewing the result

The full page reload hits `job_detail()` (§7, §13) again, this time with
real results present. It sorts results by severity-then-probability
(§4's `Result.rank` idiom, reused here), builds the severity counter for
the doughnut chart, and — critically — calls `report.evidence_rows(job)`
and `report.limitations(job)` (§12) **directly**, passing their output
straight into the template. `job_detail.html` (§13) renders: the severity
hero shows **Critical**, in the red `sev-Critical` colour defined once in
`app.css` (§13); because `job.artifact == 'memory'`, the findings count and
the "Model verdict is secondary" note appear (§13, quoting hard rule 22
directly in a template comment), with the real 0.474 probability shown
only inside that clearly-demoted note box, never as the headline number.
The findings table lists every observed indicator with its plain-English
meaning and MITRE tag. The evidence section (§10's `evidence()`, §12's
`evidence_rows()`) shows `python.exe`'s real injected-region addresses and
the terminated `conhost.exe` processes' real exit timestamps — an analyst
could go pivot directly on either. `{% include "_limitations.html" %}`
(§13) loops over the exact same `limitations(job)` list, showing the
extraction gaps, the out-of-distribution count, the SMOTE/saturation
caveat, and the reference-environment scope statement (§12).

## Part 10 — The PDF

The analyst clicks "PDF report." `routes.py:report()` (§7, §12) re-fetches
the job (ownership-checked again via `_owned`), calls `renderer.render
(job)` (§12) — building an entirely fresh PDF from the same stored
database rows, nothing cached anywhere — audits the download
(`log("report_download", ...)`, §6), and streams the resulting bytes back
with an `inline` `Content-Disposition` header so the browser can display it
directly. Inside `render()` (§12): chain of custody prints the real
SHA-256 and the honest retention statement; the executive summary states,
in its very first sentence, that this report leads with observations, not
a model score, and names the two matched technique categories; verdict
detail shows the real 0.474 probability, but only in section 3, after the
executive summary already led with evidence, with the explicit "secondary
triage signal" sentence printed directly into the PDF itself; findings and
per-process evidence sections repeat, byte-for-byte in wording, the exact
same `evidence_rows()`/content the web page already showed; and the
mandatory "Scope and limitations" section — checked by `REQUIRED_ALWAYS`
and `REQUIRED_MEMORY` (§12), and, independently, by `verify_pipeline.py`
(§14) against real rendered PDFs exactly like this one — carries every one
of the five required substrings, because nothing about this pipeline ever
gives it a reason not to.

## What this trace actually proves

Every one of the fourteen files before this one covered a piece in
isolation, with its own worked examples and its own "check your
understanding" questions. This trace is the demonstration that those
pieces are not just individually correct but **genuinely wired together**:
the same `Job` row created in Part 2 is the one whose `stage` field Part 5
updates from inside a different process entirely; the same `severity.
for_memory()` inputs computed in Part 7 are what both the web page in Part
9 and the PDF in Part 10 render, word for word, from the exact same
function calls; the same feature-ordering discipline established in §8 and
implemented in §10 is what makes Part 6's prediction meaningful at all
rather than silently wrong. If you can now point to the exact file and
function responsible for any single step in this trace, and explain *why*
it's built the way it is rather than some simpler alternative, you have
genuinely learned this codebase — not summarised it.
