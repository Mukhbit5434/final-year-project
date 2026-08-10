# 20 — Functionalities Overview: The Map of Every Call Chain

The earlier curriculum (files 00–15, 99) explained this codebase **file by
file** — what each file contains, in isolation. This second curriculum
explains it **action by action** — for one specific thing the system does,
which functions call which other functions, in what order, and why. The
confusion this exists to fix: a function like `mitre.match()` is defined
once, in one file, but it gets *called* from two genuinely different
places for two genuinely different reasons — and reading `mitre.py` in
isolation (as file 11 did) can't show you that. This curriculum can.

## Two plain-language terms used constantly from here on

- **Entry point** — the very first function that runs when a functionality
  begins. Nothing calls it *for* this purpose; something outside the
  system (a browser request, a background worker picking up its next
  task, the server starting) triggers it directly.
- **Call chain** — the ordered list of every function that runs, one after
  another (or, sometimes, in the background alongside each other — files
  21–28 mark this distinction explicitly every time it matters), starting
  from the entry point and ending when the functionality is done.

## How I found this list

Every functionality below was found by reading the actual route functions
in `app/routes.py` and `app/auth.py`, the actual background-job functions
in `app/jobs.py`, and the actual startup function in `app/__init__.py` —
the same source files files 05–07 already documented in depth. This is not
a list reconstructed from memory of what a typical Flask app "usually"
does.

## A scoping decision, made explicit up front

Your request listed "uploading a disk image" and "uploading a memory
dump" as two separate items. Reading `routes.py:upload()`, they are
**the same route, the same function, the same code path** — there is no
branch in the code between "this is a disk upload" and "this is a memory
upload" until *after* the file is already saved and its type is already
known. Splitting that one shared route into two separate functionality
files would mean writing nearly the same file twice and inventing a
divergence point that doesn't really exist yet at upload time. So file 23
covers uploading **both** kinds of artifact as one functionality, and
shows you exactly where and how it genuinely does branch (at type
detection, and again once a background job actually starts).

Similarly, "making a prediction," "generating LIME explanations,"
"matching MITRE tags," and "calculating severity" are four functions that,
in the real code, are called **one immediately after another, inside one
tight, unbroken sequence**, once per pipeline (`jobs.py:_disk()` and
`jobs.py:_memory()`). Splitting that one real, continuous chain across
four separate files would force you to keep flipping between files to see
what genuinely happens as one uninterrupted sequence — which fights
directly against the whole point of this curriculum. So files 24 and 25
each walk their pipeline's **entire** extraction-through-severity chain in
one file, with every one of those four steps still given its own full,
individually-detailed treatment inside that file — nothing you asked to
see in detail is skipped, only regrouped to match how the code actually
runs.

## The eight functionalities, in full

| # | File | Functionality | Entry point | One-line call chain |
|---|---|---|---|---|
| 21 | `21_starting_the_application.md` | The server boots up, loads both trained models, both LIME explainers, and the clean-machine baseline, and cleans up any job left stuck from a previous crash. | `create_app()` in `app/__init__.py` | `create_app() → inference.init() → [memory.load(), disk.load(), _check_versions()] → explain.init() → baseline.load() → jobs.recover_orphans()` |
| 22 | `22_registering_signing_in_and_out.md` | An analyst creates an account, signs in, or signs out. | `register()` / `login()` / `logout()` in `app/auth.py` | `register() → User() → user.set_password() → db.session.commit()` **/** `login() → _by_name() → user.check_password() → login_user()` **/** `logout() → logout_user()` |
| 23 | `23_uploading_an_artifact.md` | An analyst uploads a raw disk image or memory dump; the system saves it, hashes it, guesses its type, and either queues analysis immediately or asks the analyst to confirm an ambiguous type. | `upload()` in `app/routes.py` | `upload() → artifacts.store() → artifacts.sniff() → Job() → job_queue.start()` (or, if type is ambiguous, `→ confirm_type() → job_queue.start()`) |
| 24 | `24_analyzing_a_disk_image.md` | A queued disk-image job runs: the filesystem is walked, every executable is vectorised, and every file gets a prediction, an explanation (if flagged), a MITRE tag match, and a severity score. | `jobs.run()` → `jobs._disk()` in `app/jobs.py` | `_disk() → extract_disk() [worker process] → disk.scan() → (per file) model.subset() → model.predict() → explain.disk_findings() → mitre.match() → severity.for_disk()` |
| 25 | `25_analyzing_a_memory_dump.md` | A queued memory-dump job runs: nine Volatility 3 plugins produce 55 features, the model predicts, the extractor's own direct observations are gathered and compared to a clean baseline, MITRE tags are matched twice, and severity is scored from the evidence first. | `jobs.run()` → `jobs._memory()` in `app/jobs.py` | `_memory() → extract_memory() [worker process] → memory.extract() → model.predict() → model.ood() → meanings.observed() → baseline.compare() → mitre.match() ×2 → severity.for_memory() → explain.memory_findings()` (conditionally) |
| 26 | `26_viewing_results_web_page_and_pdf.md` | An analyst opens a finished job's page in the browser, or downloads its PDF report — both built from the exact same underlying data and the exact same two shared functions. | `job_detail()` in `app/routes.py`, and `report()` in `app/routes.py` | `job_detail() → report.evidence_rows() → report.limitations() → render_template()` **/** `report() → report.render() → [_summary(), _kv(), limitations(), evidence_rows()] → doc.build()` |
| 27 | `27_checking_job_progress.md` | While a job is still running, the browser repeatedly asks the server how far along it is, and the server answers using data a completely separate worker process wrote to a small file on disk. | `job_status()` in `app/routes.py` (asked repeatedly by the browser's own JavaScript) | `[worker process] extract_disk()/extract_memory() → _reporter()'s report() → (writes a file)` … `[supervisor thread] _await() → (reads the same file) → db.session.commit()` … `[browser] fetch(job_status()) → updates the page` |
| 28 | `28_handling_job_failure_and_recovery.md` | A job breaks partway through and is marked `FAILED` with a readable reason instead of hanging forever — either live, while it's running, or after the fact, if the whole server crashed and left a job stuck. | `jobs.run()`'s own `except`/`finally` blocks (live failure); `jobs.recover_orphans()` (crash recovery, called from `create_app()` — see file 21) | `run() → [_disk() or _memory() raises] → except Exception → job.status = FAILED` **/** `create_app() → recover_orphans() → (finds stale RUNNING jobs) → job.status = FAILED` |
| 29 | `29_shared_functions_map.md` | *(not a functionality — the index of every function reused across two or more of the eight above)* | — | — |

## Functionalities that exist but don't get their own detail file

These are real, distinct things the system does, found in the same files
above — but each one is a single database query followed by handing the
result straight to a template, with no branching and no interesting call
chain to trace. Giving each one the full five-part treatment would mostly
repeat file 13's already-thorough coverage of the same templates. Listed
here for completeness, as you asked for a complete list:

- **Viewing the public landing page** — `index()` in `routes.py`, which
  simply checks whether someone is signed in and shows either
  `landing.html` or redirects to the dashboard.
- **Viewing the dashboard** — `dashboard()` in `routes.py`: one set of
  database queries, tallied in Python, handed to `dashboard.html`.
- **Viewing the full jobs list** — `jobs()` in `routes.py`: one query,
  one small dictionary of "worst severity per job," handed to `jobs.html`.
- **Exporting results as CSV or JSON** — `export()` in `routes.py`: one
  query for a job's results, formatted into rows either with Python's
  built-in `csv` module or `json.dumps`, and sent back as a file download.
  Genuinely simple — it doesn't call into `report.py`, `forensics/`, or
  `inference/` at all; the analysis it displays has already happened by
  the time an export is requested.

## Total count

**Eight functionalities get a full detailed file (21–28).** One further
file (29) is not a functionality at all — it's the cross-reference index
your original request specifically asked for, resolving the "same function
called from multiple places" confusion directly. Four more simple,
single-query functionalities are named above for completeness but not
given their own file, for the reason stated. **Ten new files in total**
will exist in `docs/learning/` once this set is complete, including this
overview.
