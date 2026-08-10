# 14 — Tests: `tests/` and `scripts/verify_pipeline.py`

This file covers every test file's purpose — what class of bug it exists to
catch — plus a full, detailed walkthrough of `verify_pipeline.py`, which
STATUS.md records as the single check that caught **every one of the seven
silent bugs** this project's own unit tests never could. That contrast is
the real subject of this file: two genuinely different kinds of
"correctness," and why a serious project needs both.

## `tests/conftest.py` — the shared setup every other test file builds on

```python
@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
        limiter.reset()
        yield app
        _db.session.remove()
        _db.drop_all()

@pytest.fixture
def db(app):
    return _db

@pytest.fixture
def analyst(db):
    u = User(username="farooq", email="farooq@example.test")
    u.set_password("correct horse battery staple")
    db.session.add(u)
    db.session.commit()
    return u

@pytest.fixture
def client(app, tmp_path):
    app.config["UPLOAD_DIR"] = tmp_path / "uploads"
    return app.test_client()

@pytest.fixture
def signed_in(client, analyst):
    client.post("/login", data={"username": "farooq",
                                "password": "correct horse battery staple"})
    return analyst
```

A **fixture**, in pytest terms, is a small function that sets something up
for a test to use and, optionally, tears it down afterward — any test
function that names a fixture as one of its own arguments automatically
receives whatever that fixture produces. `app` is the foundational one:
it calls `create_app(TestConfig)` (file 05, file 03) fresh for every single
test, creates all the database tables (`_db.create_all()`, using the
schema currently described by `models.py`, not by replaying the real
migration chain — appropriate for a throwaway in-memory test database),
resets the rate limiter's counters (since it's shared, module-level state
that would otherwise leak between tests, file 01), and — the `yield`
keyword — hands control to the actual test, then, once the test finishes,
cleans everything up again (`drop_all()`).

`db`, `analyst`, `client`, and `signed_in` each build on the one before it
— a real, pre-created user account with a known password; a Flask test
client (Flask's own built-in tool for making fake HTTP requests directly
against the app in-process, no real network involved) pointed at a
temporary upload directory unique to this one test run; and a client that's
already POSTed a real login request, ready for tests that need to act as an
already-authenticated analyst. This chain of small, composable fixtures is
what lets most individual test functions stay short — they simply name
whichever fixtures they need (`def test_x(client, signed_in, db, analyst):`)
and the setup work has already happened before the test body even starts.

## What each test file actually guards against

Rather than walking every individual test line by line (this project has
well over 200 tests), this section groups them by what real class of
mistake each file exists to catch — which is the more useful way to
understand a test suite's actual value.

**`tests/test_auth.py`** — guards the login/register/logout flow covered in
file 06: correct credentials succeed, wrong ones fail with the *same*
message regardless of which half was wrong (guarding against the user-
enumeration fix ever regressing), disabled accounts are refused, usernames
match case-insensitively, the open-redirect protection on `?next=` actually
rejects external URLs, and logout genuinely requires a POST request.

**`tests/test_models.py`** — guards the database schema itself (file 04):
passwords are never stored in plain text, usernames are genuinely unique,
a disk job with many files and findings round-trips correctly through the
ORM, every flagged disk result carries a path and a SHA-256 (hard rule 16,
enforced structurally here, not just by convention), deleting a job
genuinely cascades to delete its results and findings, and a `Finding`'s
`mitre_url` property expands sub-technique IDs correctly.

**`tests/test_upload.py`** — guards `artifacts.py` and the `upload()` route
(file 07): every one of `sniff()`'s magic-byte checks (MBR, GPT, crash
dump) is individually verified, a signature-less raw file genuinely lands
in `NEEDS_TYPE` rather than being guessed at, an analyst's explicit type
choice skips detection, the stored SHA-256 genuinely matches the uploaded
bytes, the stored filename is the application's own random name (never the
client's), disallowed extensions are refused, uploads are audited, and —
directly testing a real security property — uploaded artifacts are
confirmed unreachable at any guessable URL.

**`tests/test_jobs.py`** — guards the background job engine (file 07): the
disk pipeline persists one `Result` per file with correct locators, the
memory pipeline persists exactly one `Result` and correctly records the
out-of-distribution count, status transitions happen in the right order
with a correctly-computed duration, a failing extractor marks the job
`FAILED` rather than leaving it hung, a job with no artifact type fails
cleanly rather than crashing unpredictably, orphaned `RUNNING` jobs are
correctly recovered at boot, the status endpoint returns only the small
counts it's supposed to, and — importantly — that dispatching is genuinely
disabled under `TestConfig` (file 03's `DISPATCH_JOBS` setting).

**`tests/test_inference.py`** — guards both loaded models (file 08): the
feature counts and thresholds are exactly what's expected, the disk subset
indices are genuinely not sorted, `subset()` picks the right positions and
rejects a wrong-width vector, both reference samples produce the expected
bimodal probability split, and — the single most powerful test in this
file — **scrambled memory and disk columns are correctly rejected at
load**, tested not just once but across many random seeds
(`test_scrambled_memory_columns_are_rejected_at_load(mem_ref, seed)`),
directly exercising the `_check_reference()` distribution guard from file
08. It also confirms the known, honestly-documented limitation of that
guard directly: `test_the_distribution_check_does_not_catch_small_
transpositions` proves the check's real limits rather than overselling it.

**`tests/test_disk_extractor.py`** — narrowly and precisely tests
`looks_like_pe()` (file 09): a real PE is accepted, a file starting with
`"MZ"` but lacking the real PE signature is rejected (this is the direct
regression test for silent bug #1), a text file merely named `.exe` is
rejected, and various malformed `e_lfanew` values (pointing past the end of
the file, pointing back inside the header) are all correctly rejected.

**`tests/test_memory_extractor.py`** — the largest test file for the most
intricate extractor, covering nearly every `from_*()` function from file
10 individually: the vector's 55 values are produced in exactly the JSON's
order (not insertion order — a direct test of the "dictionary first,
ordered list last" discipline), a missing or an unexpected field fails
loudly rather than defaulting silently, `nprocs64bit` genuinely counts
WOW64 processes despite its name, `avg_handlers` genuinely uses the
handles plugin's count rather than pslist's empty column, handle types are
counted correctly and `nport` is always zero, `malfind.protection` sums the
Volatility 2 index correctly and an unrecognised protection flag is
disclosed rather than guessed at, `psxview` correctly maps only the four
available sources and the three unavailable ones are honestly zero (never
invented), service types match by exact string (never substring), duplicate
service records are correctly collapsed by their `Order` field, the feature
count is locked at exactly 55 (a direct test of hard rule 23 — the three
dropped Apihooks features are never emitted), and the gap list correctly
separates missing fields from inferred ones and is never empty.

**`tests/test_memory_torn_rows.py`** — narrowly tests the torn-row handling
from file 10: a structurally impossible row is correctly detected, it does
not poison the thread-count average, it still correctly counts toward
`nproc`, a torn PPID doesn't inflate the distinct-parent-count, and torn
rows are honestly disclosed as an extraction gap.

**`tests/test_evidence.py`** — guards `extractors/memory.py:evidence()`
(file 10): injected regions carry process, address, and size correctly;
only modules/processes genuinely missing from a list are reported (not
every module/process); totals count *everything found*, not just what
survived the display cap; malformed or empty input rows don't crash the
function; and — the direct regression test for silent bug #7 — evidence
data holds only Python builtins and genuinely survives a real pickle
round-trip, the exact operation that failed and took down the whole worker
pool the first time this bug was found.

**`tests/test_forensics.py`** — the broadest single test file, covering
`meanings.py`, `mitre.py`, and `severity.py` together (file 11): every
selected disk feature resolves to *some* description; the three genuinely-
exact disk feature groups (general, data-directory, section) are correctly
distinguished from the hashed ones; hash groups never claim a specific API
name (a direct test of hard rule 15); the three permanently banned MITRE
technique IDs are confirmed absent from the whole table; every matching tag
is emitted, not just one; the removed "Persistence - Services" tag is
confirmed to genuinely no longer exist; Process Hollowing genuinely needs
both of its required signals; the unsigned-binary tag stays low-confidence
and genuinely never fires on a signed binary; a value-aware tag stays
silent when no values are supplied at all; and both severity functions are
tested directly, including the specific regression test for the "clean
capture scored Critical" bug
(`test_a_clean_capture_matching_its_own_baseline_is_not_critical`) and a
direct test that the model's score can contribute to memory severity but
never solely drive it.

**`tests/test_baseline_ceiling.py`** — narrowly tests the observed-max ×
`MARGIN` logic from file 11, including a direct regression test that a
fresh-boot capture's legitimately high `not_in_pslist` value does not flag
itself against its own baseline, and — genuinely useful — tests that
reproduce the actual injection and spawn-kill demo scenarios against the
live, committed baseline numbers, confirming exactly which techniques a
realistic simulated capture would and wouldn't be expected to trigger.

**`tests/test_volumetric.py`** — narrowly tests the volumetric-context
wording from file 11, including a direct structural test
(`test_no_memory_tag_maps_to_a_volumetric_feature`) confirming the
architectural separation between configuration counts and severity
actually holds, and `test_volumetric_features_cannot_reach_severity`,
confirming it directly rather than just trusting the earlier structural
check.

**`tests/test_report.py`** — guards `report.py` (file 12): a disk report
renders as real PDF bytes, all sections are present, the mandatory
limitation strings genuinely survive into the rendered PDF for both
pipelines, a flagged file's path and hash genuinely reach the rendered
output, the limitations section still appears (with "None recorded.")
even when nothing was skipped, a memory report genuinely doesn't headline
the probability (checking the exact ordering of text within the rendered
PDF), the extraction-gap split is preserved, disk reports don't claim
memory-only caveats, the OOD count genuinely appears in every memory
report, the report route enforces ownership, report downloads are
audited, and CSV/JSON export both carry correct data.

**`tests/test_views.py`** — the remaining web routes not covered above
(file 13): the landing page is public and states the disk model's headline
metric, an authenticated visitor is redirected straight to the dashboard,
dashboard totals only count completed jobs, the dashboard is private, the
jobs list correctly shows the worst severity per job, the upload page
genuinely no longer carries the runtime/scope advisory text (a direct,
deliberate test of a UI decision, not a bug fix — see this project's
recorded UI-copy history), a running job's live stage/progress genuinely
reaches the page, and — narrowly — the exact cross-process progress-file
mechanism from file 07 (`_reporter`/`_await`) is tested directly, including
that it's a safe no-op when no progress file path was given at all.

**`tests/test_concurrency.py`** — specifically tests that multiple
simultaneous uploads and jobs don't corrupt each other's state, against a
genuinely **file-backed** SQLite database rather than the default
in-memory one — the file's own comment explains why this distinction
matters: an in-memory SQLite database hands every thread the exact same
underlying connection, which would mask the very race conditions this test
exists to catch (`StaleDataError` being the actual failure mode a shared
in-memory connection produces), so this is a case where the normally-
preferred faster/simpler test setup would actually be the *wrong* choice.

**`tests/test_malmem_holdout.py`** — tests `scripts/malmem_holdout.py`'s
reproducible-split logic (file 15) against a small, synthetic, hand-built
CSV, so the test suite doesn't need the real 19 MB dataset file to run at
all. It specifically tests that the refusal gate actually *works* by
feeding it deliberately wrong parameters (wrong split counts, wrong dedup
totals, wrong class balance, group leakage between train and test) and
confirming each one is caught and refused — a genuinely important kind of
test: not just "does the correct case work," but "does the safety check
actually catch a wrong case," proven with real, deliberately-broken inputs
rather than assumed.

## `scripts/verify_pipeline.py` — the check that found what unit tests couldn't

Everything above tests one *piece* of the system at a time, using small,
synthetic, hand-built inputs — a fake `Job` row, a toy CSV, a handful of
manufactured plugin rows. That's genuinely valuable, and it catches a huge
range of logic errors quickly and cheaply. But it cannot catch a category
of bug that only shows up when **real** Volatility output, or a **real**
PE file, or a **real** multi-gigabyte dump actually flows through the
system end to end — because a hand-built test fixture, by construction,
never contains the specific messiness real evidence contains.

STATUS.md is direct about this: **all seven of the silent bugs this
project found (file 09 and file 10 already covered several of them in
detail — the missing PE signature check, the inverted `nprocs64bit`
naming, the torn-row averaging bug, the renderer-object pickling crash,
and others) were found by running real artifacts through the real
pipeline, not by any unit test.** This is exactly the job
`verify_pipeline.py` exists to do, and it's worth understanding precisely
how it's built to do that job well.

```python
SAMPLES = [
    ("disk", ROOT / "sample" / "disk" / "2020JimmyWilson.E01"),
    ("memory", ROOT / "sample" / "memory" / "win10_memory.raw"),
]

EXPECTED = {
    "2020JimmyWilson.E01": "3,817 files examined, 13 results, 0 flagged, 60 skipped",
    "win10_memory.raw": "67 processes (ground truth 67), 21 of 55 out of distribution",
}
```

The docstring at the top of the real file states a deliberate design
choice directly: this script is **not** "whatever happens to be sitting in
`sample/`" — it names two *specific*, real artifacts, and records exactly
what they produced the last time this script was genuinely run and
verified by a human. This matters because a result that silently *drifts*
from a previously-verified number is far more informative than a script
that just checks "did it run without crashing" — a number quietly
changing from what it used to be is exactly the kind of signal that would
have caught several of this project's real bugs the moment they were
introduced, if this script had been run right afterward.

```python
    class VerifyConfig(Config):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{(ROOT / 'instance' / 'verify.db').as_posix()}"
        WTF_CSRF_ENABLED = False

    (ROOT / "instance").mkdir(exist_ok=True)
    app = create_app(VerifyConfig)
```

A third configuration class, distinct from both `Config` and `TestConfig`
(file 03) — the comment states its purpose plainly: "uses instance/
verify.db so it never disturbs the development database." This is a
genuinely real, practical concern: running this script shouldn't ever be
able to corrupt or clutter the actual database an analyst might be using
for real work, so it gets its own, completely separate, disposable SQLite
file.

```python
        for artifact, src in SAMPLES:
            if not src.exists():
                print(f"\n-- skipping {src.name}: not present")
                continue

            stored = f"verify_{src.name}"
            dest = app.config["UPLOAD_DIR"] / stored
            if not dest.exists():
                shutil.copy2(src, dest)

            job = db.session.query(Job).filter_by(stored_name=stored).first()
            if job is None:
                job = Job(user_id=user.id, filename=src.name, stored_name=stored,
                          sha256="0" * 64, size_bytes=dest.stat().st_size,
                          artifact=artifact, status=PENDING)
                db.session.add(job)
            else:
                job.status, job.error = PENDING, None
                for r in list(job.results):
                    db.session.delete(r)
            db.session.commit()

            jobs.run(app, job.id)
```

This is the crucial part: `jobs.run(app, job.id)` calls the **exact same
function** covered in full detail in file 07 — the real production job
engine, with its real process-pool dispatch, its real extraction calls,
its real inference, its real forensics and severity scoring. This isn't a
simulation or a reimplementation of what the job pipeline does; it *is*
the job pipeline, run against real artifact bytes copied from `sample/`.
If a job with this exact `stored_name` was already run before, its old
results are cleanly deleted first (`db.session.delete(r)` for each old
`Result` — recall from file 04 that deleting a result cascades to delete
its findings too) so re-running the script produces a fresh, honest result
rather than silently accumulating duplicate rows.

```python
            print(f"    status  : {job.status}"
                  + (f" ({job.duration:.0f}s)" if job.duration else ""))
            if job.error:
                failures.append(f"{src.name}: {job.error}")
                print(f"    error   : {job.error}")
                continue
            print(f"    results : {len(job.results)}   "
                  f"findings: {sum(len(r.findings) for r in job.results)}")
            ...
            if job.plugin_seconds:
                slow = sorted(job.plugin_seconds.items(), key=lambda kv: -kv[1])
                print("    timings : " + "  ".join(f"{k}={v}s" for k, v in slow[:5]))
```

After the real job finishes, the script prints — but crucially doesn't yet
*judge* — a whole set of real numbers: status, duration, result and
finding counts, scan counts, out-of-distribution count, and the five
slowest plugins by wall-clock time (drawing directly on the
`plugin_seconds` data file 10's `extract()` records, specifically kept
because total runtime has been observed to vary unexplained between runs —
having this printed on every verification run is exactly what would
eventually let someone spot a genuine pattern in that variance).

```python
            pdf = report.render(job)
            required = report.REQUIRED_ALWAYS + (
                report.REQUIRED_MEMORY if artifact == "memory" else report.REQUIRED_DISK)
            body = report.render(job, compress=False)
            for text in required:
                if text.encode("latin-1", "replace") not in body:
                    failures.append(f"{src.name}: report is missing {text!r}")
```

This is where `report.py`'s `REQUIRED_*` lists (file 12) actually get
checked against a **real, rendered PDF** built from **real extraction
output** — not the hand-built synthetic `Job` rows `tests/test_report.py`
uses. `text.encode("latin-1", "replace")` converts the expected Python
string into raw bytes the same way ReportLab's own internal PDF stream
encoding works, and checks for that exact byte sequence inside the
uncompressed PDF body — the same raw-byte-level check discussed in file
12's explanation of why `SCOPE_STATEMENT`'s required fragments deliberately
avoid parentheses.

```python
    with app.test_client() as c:
        c.post("/login", data={"username": "verify", "password": "verify-only-not-a-login"})
        for job_id in job_ids:
            for suffix in ("", "/status", "/export.csv", "/export.json", "/report.pdf"):
                r = c.get(f"/jobs/{job_id}{suffix}")
                ...

        for stored in stored_names:
            for path in (f"/static/{stored}", f"/uploads/{stored}"):
                if c.get(path).status_code not in (404, 308):
                    failures.append(f"{path} is reachable over HTTP")
```

Beyond checking the pipeline and the report, this script also drives every
route these two real jobs' pages expose (job detail, status, both export
formats, the PDF), through a genuine, real Flask test client — confirming
each one returns HTTP 200 and reporting the exact byte size of every
response, which makes an unexpectedly-sized response (a page that
suddenly rendered far shorter than usual, for instance) visible at a
glance even without a specific assertion catching it. And, directly
testing a real security property (matching what `tests/test_upload.py`
already checks with synthetic data, but here against the real stored
files): every uploaded artifact's stored filename is confirmed genuinely
unreachable at either a `/static/` or `/uploads/` URL.

```python
    if not args.keep:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            try:
                (ROOT / "instance" / f"verify.db{suffix}").unlink(missing_ok=True)
            except OSError as e:
                print(f"could not remove verify.db{suffix}: {e}")

    print("\n" + ("FAILURES:" if failures else "all checks passed"))
    for f in failures:
        print("  -", f)
    return 1 if failures else 0
```

By default (unless run with `--keep`), the script cleans up its own
throwaway database afterward — the comment notes a small, real
Windows-specific wrinkle handled here: Windows won't let you delete a
SQLite file while a connection to it is still open, so the pooled database
connections are explicitly released (`db.session.remove()`,
`db.engine.dispose()`) *before* attempting to delete the files, and the
comment is explicit that this cleanup step never affects the script's exit
code — "a leftover scratch database is untidy, not a verification
failure." The very last lines are the whole script's actual verdict: every
`failures.append(...)` call anywhere above accumulates into one list, and
the script prints either "all checks passed" or a full, itemised list of
exactly what went wrong, exiting with status code `1` (conventionally,
"something failed") if the list is non-empty, `0` otherwise — which is
what lets this script be dropped straight into an automated pipeline just
as easily as being run by hand and read by a person.

## Check your understanding

**Q1. Why does `tests/test_concurrency.py` specifically avoid using the
usual in-memory SQLite database (`"sqlite://"`) that most other tests rely
on?**

A: An in-memory SQLite database hands every connection from the same
process the exact same underlying connection object, which would silently
mask the very race conditions a concurrency test is trying to catch —
multiple simultaneous operations wouldn't genuinely be contending for
access the way they would against a real, shared file. Using a genuinely
file-backed database instead means multiple threads/connections actually
have to coordinate access the way a real deployment would, so a real
concurrency bug (like the `StaleDataError` this test file's own comment
names) has a chance to actually manifest and be caught.

**Q2. What specific, real property does
`test_evidence.py:test_evidence_holds_only_builtins_and_survives_pickling`
verify, and why is it a *direct regression test* for a specific past bug
rather than a general-purpose sanity check?**

A: It confirms that the evidence data structure built in
`extractors/memory.py:evidence()` (file 10) contains only genuine Python
builtin types, and that it genuinely survives a real pickle round-trip
(the same serialization step needed to cross the process boundary back
from a worker to the supervisor). This is a direct regression test for
silent bug #7 specifically — the real, previously-observed failure where
Volatility's own renderer objects (`BitField`, `UnreadableValue`) could
pickle going *into* a worker process's result but fail coming back *out*,
crashing the entire process pool with a misleading `BrokenProcessPool`
error nowhere near the real cause.

**Q3. `verify_pipeline.py` names two specific, fixed artifacts and records
what they produced the last time it was run, rather than simply scanning
whatever files happen to be present in `sample/`. Why is that a deliberate
design choice, not an oversight?**

A: Because a result that quietly *drifts* from a previously recorded,
verified value is a far stronger and more actionable signal than a script
that only checks "did this run without an outright crash." Pinning two
specific artifacts with recorded expected numbers means any unexpected
change in behaviour — even one that still technically "works" and produces
no error — becomes visible as a mismatch the next time someone runs and
reads this script's output, which is exactly the property that would have
caught several of this project's real historical bugs the moment they were
introduced.

**Q4. In what specific, load-bearing way does `verify_pipeline.py` differ
from `tests/test_jobs.py` and `tests/test_report.py`, even though all
three ultimately exercise the same underlying `jobs.run()` and
`report.render()` functions?**

A: The unit tests build small, synthetic, hand-constructed inputs — a fake
`Job` row with manufactured feature values, or Python-level mocked
extraction output — specifically so they run fast and don't depend on
having real, multi-gigabyte evidence files available. `verify_pipeline.py`
instead runs those same real functions against **genuine** artifact bytes,
through the real filesystem-walking, real Volatility 3 plugin execution,
and real `ember`/`lief` PE parsing — the actual messy, unpredictable
real-world data path that a hand-built test fixture, by its very
construction, can never fully replicate. That's precisely why it's the
check that found every one of this project's silent bugs, and the unit
tests, despite testing genuinely correct and useful things, never could.

**Q5. Why does `verify_pipeline.py` explicitly release the database's
pooled connections (`db.session.remove()`, `db.engine.dispose()`) before
trying to delete its own scratch `verify.db` file, and why doesn't a
failure during that cleanup step affect the script's overall pass/fail
result?**

A: On Windows specifically, the operating system won't allow a file to be
deleted while any process still holds an open handle to it — and SQLite
connections held in a connection pool count as open handles. Explicitly
releasing them first is what makes the subsequent delete actually succeed.
Cleanup failing anyway (wrapped in its own `try`/`except`, only printing a
message) doesn't affect the exit code, because a leftover scratch database
file is merely untidy — it doesn't mean anything about whether the actual
pipeline, report, or routes being verified worked correctly, which is the
only thing this script's pass/fail result is meant to represent.
