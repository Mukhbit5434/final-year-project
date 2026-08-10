# 07 — The Heart of the System: Upload and Background Jobs

This is the single most important file in this curriculum. Everything before
it (config, database, startup, auth) is scaffolding; everything after it
(inference, extraction, forensics, reporting) is *work that this file
orchestrates*. Take your time here.

## The problem this whole file exists to solve

Analysing a raw artifact takes **minutes, not seconds** — a memory dump
typically 3.5–7 minutes, sometimes far more (CLAUDE.md hard rule 10). A
standard web request/response cycle is built around the assumption that a
server answers quickly. If the code handling an upload tried to run the
*entire* extraction and analysis pipeline directly, right there in the same
function that's responding to the browser's HTTP request, the browser tab
would sit spinning for several minutes with no feedback, the single web
worker handling that request would be completely unavailable to serve
*any other* request (including, absurdly, the analyst's own attempt to check
on a different job) for the whole duration, and if the browser or the
network connection dropped even once during those minutes, the entire
analysis could be lost.

The fix is a **background job**: the upload request does the fast part
(save the file, record it in the database) and immediately responds — "got
it, here's where to watch progress" — while the slow part (extraction,
prediction, scoring) runs independently, in the background, checked on by
the browser *polling* (asking again every few seconds) rather than waiting
on one single request.

## `app/artifacts.py` — receiving and identifying the file

### `store()` — streaming, hashing, and never trusting the client's filename

```python
CHUNK = 4 * 1024 * 1024

def store(stream, dest_dir, suffix):
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    name = f"{uuid.uuid4().hex}{suffix}"
    path = dest_dir / name

    sha = hashlib.sha256()
    size = 0
    with open(path, "wb") as out:
        while True:
            buf = stream.read(CHUNK)
            if not buf:
                break
            sha.update(buf)
            size += len(buf)
            out.write(buf)

    return name, sha.hexdigest(), size
```

The comment above this function in the real source states the two
constraints it's built around directly: multi-GB images must never be read
fully into memory, and a second pass just to hash the file afterward would
double the disk I/O for no reason. `CHUNK = 4 * 1024 * 1024` is 4
megabytes. The `while True: ... buf = stream.read(CHUNK)` loop reads the
incoming upload 4 MB at a time rather than all at once — `stream.read(CHUNK)`
returns an empty value once there's nothing left, which is what the
`if not buf: break` check catches to end the loop. Each chunk is fed into
`sha.update(buf)` — SHA-256 hashing is designed to work incrementally like
this, producing the exact same final hash as if you'd hashed the whole file
in one go — and written straight to disk with `out.write(buf)`, so at no
point does the whole file exist anywhere except on disk (never all at once
in RAM).

`name = f"{uuid.uuid4().hex}{suffix}"` generates the file's name **on
disk**, and the comment is explicit about why: "our own name, never the
client's — this is what keeps a crafted filename from escaping the upload
directory." A UUID (Universally Unique Identifier) is a randomly generated
128-bit value, formatted here as a plain hex string, essentially guaranteed
never to collide with another one. If the stored filename were instead
built from whatever the uploading browser claimed the file was called, a
malicious or malformed filename (containing `../` sequences, for instance)
could in principle be used to try to write the file somewhere outside the
intended upload folder — a classic **path traversal** vulnerability. By
never using the client-supplied name for anything except display (it's
stored separately, in `Job.filename`, purely as a label), that entire class
of attack is closed off structurally, not just filtered.

### `sniff()` — guessing disk vs. memory from raw bytes

```python
EWF = b"EVF\x09\x0d\x0a\xff\x00"
EWF2 = b"EVF2\x0d\x0a\x81\x00"
CRASHDUMPS = (b"PAGEDUMP", b"PAGEDU64", b"PAGEDUMP64")


def sniff(path):
    with open(path, "rb") as f:
        head = f.read(1024)
        f.seek(510)
        mbr = f.read(2)
        f.seek(512)
        gpt = f.read(8)

    for magic in CRASHDUMPS:
        if head.startswith(magic):
            return MEMORY, f"Windows crash dump header {magic.decode()}"

    if head.startswith(EWF) or head.startswith(EWF2):
        return DISK, "EWF/E01 evidence container"
    if gpt == b"EFI PART":
        return DISK, "GPT protective header at offset 512"
    if mbr == b"\x55\xaa":
        return DISK, "MBR boot signature 0x55AA at offset 510"

    return None, "no disk signature and no crash-dump header; raw memory images carry neither"
```

This function reads a handful of specific byte ranges from the very start
of the file and checks them against known **magic bytes** — fixed sequences
that specific file formats are guaranteed to begin with. `b"..."` in Python
is a **bytes literal** — raw binary data, as opposed to a text string;
`\x09` etc. are individual bytes written in hexadecimal because they're not
printable characters. `f.seek(offset)` moves the file's read position to an
exact byte offset before the next `f.read(...)` — MBR's boot signature is
defined to live at exactly byte offset 510, and a GPT protective header's
`"EFI PART"` marker at exactly byte offset 512, both fixed, standardised
locations.

The function checks, in order: is this a Windows crash dump (identified by
one of three possible header strings — `.dmp` files specifically can be
told apart this way); is this an EWF/E01 evidence container (its own
distinct binary magic bytes); does it carry a GPT (GUID Partition Table)
protective header; does it carry a classic MBR (Master Boot Record) boot
signature. If **none** of those match, the function returns `(None, "...")`
— and the comment/reasoning here is one of the most important pieces of
forensic honesty in this entire codebase, directly reflecting CLAUDE.md's
"positive identification only" rule: **the absence of a disk signature is
not evidence of a memory dump.** A raw memory dump (`.raw`, `.mem`,
`.vmem`) simply has no reliable magic bytes of its own at all — there is no
positive test this function *can* run to confirm "this is definitely
memory." So rather than guessing (and risking a wrong guess that silently
sends a real disk image through the memory pipeline or vice versa), an
inconclusive result is reported honestly as inconclusive, and the analyst
is asked directly (this is exactly what produces a job's `NEEDS_TYPE`
status, from file 04).

## `app/routes.py` — the `upload()` route, in full

```python
@bp.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit(lambda: current_app.config["UPLOAD_RATE_LIMIT"], methods=["POST"])
def upload():
    form = UploadForm()
    if not form.validate_on_submit():
        return render_template("upload.html", form=form)
```

Three decorators stack on this one function, applied bottom-to-top when the
route actually runs: the rate limiter checks first (file 01, file 03), then
`login_required` (file 06), then Flask's own routing dispatches to the
function body. If the form wasn't validly submitted (e.g. a `GET` request
just loading the page, or a `POST` missing a required field), the upload
page is shown (again) with whatever validation errors WTForms attached to
the form object.

```python
    fs = form.artifact_file.data
    ext = artifacts.ext_of(fs.filename)
    if ext not in current_app.config["ALLOWED_EXT"]:
        allowed = ", ".join(sorted(current_app.config["ALLOWED_EXT"]))
        flash(f"{ext or 'That file type'} is not accepted. Allowed: {allowed}", "danger")
        log("upload_rejected", detail=f"extension {ext!r}")
        db.session.commit()
        return redirect(url_for("main.upload"))
```

`form.artifact_file.data` is the uploaded file object itself (Flask-WTF's
`FileField`, file 01). `artifacts.ext_of(fs.filename)` (a tiny helper in
`artifacts.py` using `Path(...).suffix.lower()`) pulls out the extension in
lowercase. If it's not in the configured allowlist (file 03's
`ALLOWED_EXT`), the whole thing is rejected immediately — before any bytes
are even read off the network stream — with a specific audited reason.
Note this check happens *before* `store()` is ever called, so a disallowed
file is never even written to disk.

```python
    name, sha, size = artifacts.store(fs.stream, current_app.config["UPLOAD_DIR"], ext)
    path = current_app.config["UPLOAD_DIR"] / name

    chosen = form.artifact.data
    if chosen == "auto":
        detected, why = artifacts.sniff(path)
    else:
        detected, why = chosen, "selected by analyst at upload"
```

Now the file is actually streamed to disk and hashed (the `store()`
function covered above). `form.artifact.data` reads the radio-button choice
from `UploadForm` (file 06's `forms.py` covers the login/register forms;
`UploadForm` itself lives in the same file and offers `"auto"`, `"disk"`,
or `"memory"`) — if the analyst explicitly picked a type rather than
leaving it on "Detect automatically," that choice is trusted directly and
recorded as such, skipping `sniff()` entirely.

```python
    job = Job(user_id=current_user.id,
              filename=fs.filename or name,
              stored_name=name, sha256=sha, size_bytes=size,
              artifact=detected, detected_as=why,
              status=PENDING if detected else NEEDS_TYPE)
    db.session.add(job)
    db.session.flush()
    log("upload", job=job, detail=f"{size} bytes, sha256={sha}, type={detected or 'undetermined'}")
    db.session.commit()

    if not detected:
        flash("Could not identify this artifact from its contents. Please tell us what it is.",
              "warning")
        return redirect(url_for("main.confirm_type", job_id=job.id))

    job_queue.start(current_app._get_current_object(), job.id)
    flash(f"Uploaded and queued as a {detected} artifact. Analysis takes minutes, "
          "not seconds.", "success")
    return redirect(url_for("main.job_detail", job_id=job.id))
```

A new `Job` row is created and immediately committed — this is the exact
moment a job first exists in the system, with `status` set to `PENDING` if
detection succeeded, or `NEEDS_TYPE` (file 04) if it didn't. `db.session.
flush()` before the audit log call is the same pattern from file 06's
`register()` — get a real `id` assigned before referencing it.

If detection was inconclusive, the flow stops here entirely — the browser
is redirected to `confirm_type()`, and **no background job is dispatched
yet**. Only when a type is known (either from `sniff()` or from an explicit
analyst choice) does `job_queue.start(...)` actually run — this is the one
line that hands the job off to the background system covered in the rest of
this file. `current_app._get_current_object()` is a small but necessary
piece of Flask plumbing: `current_app` (file 01) is normally a *proxy*
object that only works correctly inside an active request; the background
thread that will eventually run this job is a genuinely different execution
context, so the code needs the *real*, underlying Flask app object handed
to it explicitly, which is exactly what this call extracts.

Note the response is **immediate** — the browser is redirected to the job
detail page right away, long before extraction has even started, let alone
finished. This is the concrete mechanism that solves the "browser can't sit
waiting for seven minutes" problem described at the top of this file.

### `confirm_type()` — resolving an inconclusive detection

```python
@bp.route("/jobs/<int:job_id>/type", methods=["GET", "POST"])
@login_required
def confirm_type(job_id):
    job = _owned(job_id)
    if job.status != NEEDS_TYPE:
        return redirect(url_for("main.job_detail", job_id=job.id))

    form = ConfirmTypeForm()
    if form.validate_on_submit():
        job.artifact = form.artifact.data
        job.detected_as = "confirmed by analyst after inconclusive detection"
        job.status = PENDING
        log("artifact_type_set", job=job, detail=job.artifact)
        db.session.commit()
        job_queue.start(current_app._get_current_object(), job.id)
        flash(f"Queued as a {job.artifact} artifact.", "success")
        return redirect(url_for("main.job_detail", job_id=job.id))

    return render_template("confirm_type.html", form=form, job=job)
```

`_owned(job_id)` (defined at the bottom of `routes.py`) both fetches the job
*and* enforces authorization in one call — see below. If somehow revisited
after the type was already resolved (`job.status != NEEDS_TYPE`), it just
redirects straight to the job's page rather than showing a form that no
longer makes sense. Once the analyst picks a type and submits, the job's
`artifact` and `status` fields are updated directly on the already-existing
row (not a new one), and *then* — for the first time — `job_queue.start(...)`
is called, exactly mirroring the end of `upload()` above.

### `_owned()` — the whole authorization model in five lines

```python
def _owned(job_id):
    job = db.session.get(Job, job_id)
    if job is None or job.user_id != current_user.id:
        abort(404)
    return job
```

Every route that operates on a specific job (`job_detail`, `report`,
`export`, `job_status`, `confirm_type`) calls this first. The comment
explains a deliberate, precise security choice: this returns a plain
**404 Not Found**, not a 403 Forbidden, for a job that exists but belongs to
someone else — because a 403 response would itself leak information (it
confirms "yes, a job with this ID exists, you're just not allowed to see
it"), whereas a 404 gives an outside observer no way to distinguish "this
job doesn't exist" from "this job exists and isn't yours." This is the
project's entire authorization model in one small function: every single
job-scoped route funnels through it, so there's exactly one place this rule
is enforced, rather than it being repeated (and potentially inconsistently
repeated) in every route individually.

## `app/jobs.py` — the background engine, function by function

### Two different kinds of "background," and why both exist

```python
_pool = None

def pool():
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(max_workers=1)
    return _pool
```

This is genuinely the most important architectural idea in the whole
project, and it's worth being precise about it. There are **two separate**
background mechanisms at work, doing two different jobs:

1. **Flask-Executor's thread pool** (file 01, file 03's `EXECUTOR_*`
   settings) is the **supervisor**. `job_queue.start()` (below) hands a
   whole job's *coordination* work — track status, wait for extraction,
   persist results — to one of these threads, freeing up the web server's
   request-handling immediately.
2. **This project's own `ProcessPoolExecutor`**, created lazily by the
   `pool()` function above, is where the actual **extraction** work runs —
   walking a filesystem, running Volatility 3 plugins, parsing a PE file
   with `lief`. This is a genuinely separate operating-system *process*, not
   just a thread.

Why both, rather than just doing everything in the thread pool? Two
distinct, real reasons, both stated directly in the comment on `pool()`
itself and matching CLAUDE.md's hard rule 20:

- **`lief` parses hostile input in native (C++) code.** A malformed or
  deliberately crafted PE file can, in principle, crash the interpreter
  outright (a segfault) while `lief` is parsing it. If that parsing
  happened inside the same process as the web server, that crash would take
  down the *entire* Flask application — every other analyst's session,
  every other in-progress job, gone. Running it in a separate process means
  a crash there costs exactly one job, and the rest of the system is
  completely unaffected.
- **Volatility 3 is CPU-bound Python.** Recall the GIL from file 00's
  glossary: only one thread can execute Python bytecode at a time within a
  single process. If extraction ran on a Flask-Executor *thread*, it would
  hold the GIL for the entire multi-minute duration, and every other
  thread in that same process — including the ones serving completely
  unrelated web requests — would be effectively frozen. A separate
  *process* has its own independent Python interpreter and its own GIL, so
  it genuinely runs in parallel with the web server, not just seemingly so.

`pool()` creates the process pool **lazily** — only the first time it's
actually needed, not the moment this file is imported — specifically so
that importing `jobs.py` from a test file or a small CLI script doesn't
silently spawn worker processes nobody asked for. `max_workers=1` means
only one extraction runs at a time; this project deliberately keeps
extraction serialized rather than parallel, given how CPU- and memory-
intensive a single job already is.

### `_reporter()` and `_await()` — talking across the process boundary

This is the cleverest, most carefully-reasoned piece of code in the whole
project, and it solves a real, non-obvious problem: **the worker process
that's running extraction has no application context and no database
session at all** (it isn't running inside Flask, it's just running one
plain Python function), and the supervisor thread that's waiting for it has
nothing to actively do except wait. So how does a live "5 of 9 plugins
done, 45%" progress figure get from inside the worker to the web page an
analyst is watching?

```python
def _reporter(progress_file):
    path = Path(progress_file) if progress_file else None

    def report(stage, pct=None):
        if path is None:
            return
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"stage": stage, "pct": pct}))
        tmp.replace(path)

    return report
```

`_reporter(progress_file)` is a small **factory function** — it doesn't do
the reporting itself, it *returns* a new function (`report`) that, when
later called with a stage name and percentage, writes that information out
as JSON text to a specific file on disk. The `.tmp` file, then
`tmp.replace(path)` two-step is a deliberate atomicity trick: writing
directly to the real progress file risks the supervisor reading it at the
exact instant it's half-written (a **race condition**), producing corrupt
JSON. Writing to a differently-named temporary file first, then
**atomically renaming** it over the real file (an operation the operating
system guarantees either fully happens or doesn't happen at all — never a
half-completed rename) means whoever reads `progress_file` always sees
either the old complete value or the new complete value, never a
half-written mess.

```python
def _await(job, future, progress_file):
    last = None
    while True:
        try:
            return future.result(timeout=1.0)
        except TimeoutError:
            try:
                cur = json.loads(progress_file.read_text())
            except (OSError, ValueError):
                continue
            if cur != last:
                last = cur
                job.stage = cur["stage"]
                job.progress_pct = cur["pct"]
                db.session.commit()
```

This runs on the supervisor side, inside the same thread that dispatched
the extraction work to the process pool. `future` is what
`ProcessPoolExecutor.submit(...)` immediately returns — a placeholder
object representing "the result of this background work, whenever it's
ready." `future.result(timeout=1.0)` normally means "block here until the
work is done, then give me the return value" — but with a `timeout`
argument, it instead raises `TimeoutError` if the work *hasn't* finished
within that many seconds, rather than blocking forever.

The comment in the real source states the elegant idea directly: this
one-second timeout **doubles as the poll interval**. Every time the work
isn't done yet, the `except TimeoutError:` branch runs, reads whatever the
worker has most recently written to the progress file (guarding against the
file not existing yet, or being mid-write despite the atomic-rename trick,
with `except (OSError, ValueError): continue` — just try again next second),
and if the content actually changed since last time (`if cur != last:`),
copies it onto the real `Job` row and commits — which is what makes it
visible to the web page the next time it polls (`routes.py:job_status()`,
covered in the templates discussion in file 13). Then the loop goes right
back to `future.result(timeout=1.0)` again. This continues, once per
second, until extraction genuinely finishes, at which point
`future.result(...)` returns normally (no `TimeoutError` this time) and the
function returns that real result immediately. **There is no separate
sleep loop and no second thread anywhere in this mechanism** — the
`timeout` parameter on a single, already-necessary blocking call is doing
double duty as both "wait for the result" and "check back periodically,"
which is exactly the elegant part worth remembering.

### `extract_disk()` and `extract_memory()` — what actually runs inside the worker process

```python
def extract_disk(path, max_files, max_bytes, progress_file=None):
    from .extractors import disk

    report = _reporter(progress_file)
    report("Walking the filesystem")
    out = disk.scan(path, max_files=max_files, max_bytes=max_bytes, workers=2,
                    progress=lambda n, p: report(f"Vectorising executable {n}"))
    report("Scoring executables")
    for rec in out["files"]:
        rec["vec"] = rec["vec"].tolist()
    return out
```

This is the actual function object handed to `pool().submit(...)` — it runs
**inside** the separate process, which is why it imports `.extractors.disk`
locally rather than at the top of the file (importing it fresh inside the
worker, rather than relying on whatever was already imported in the parent
process before the fork/spawn happened, is safer and clearer given how
Windows starts new processes — file 05 covered the related
`__main__`-re-import subtlety). It calls the disk extractor's `scan()`
function (file 09 covers this fully), passing its own `_reporter` instance
as a progress callback so the analyst sees "Vectorising executable 47" tick
upward in real time.

The last two lines matter more than they look: `rec["vec"].tolist()`
converts each file's feature vector from a NumPy array into a plain Python
list before the function returns. The reason is right there in the
comment: everything this worker function returns has to travel back across
the process boundary via **pickling** (Python's built-in serialization
mechanism, file 00's glossary — turning a Python object into bytes that can
be reconstructed in a different process). Plain Python lists survive that
round-trip more predictably across different library versions than raw
NumPy arrays do, and since this isn't a performance-critical hot path, the
small conversion cost is a worthwhile trade for robustness.

```python
def extract_memory(path, feature_names, progress_file=None):
    from .extractors import memory

    report = _reporter(progress_file)
    report("Building the kernel layer", 2)
    total = len(memory.PLUGINS)
    seen = [0]

    def stage(key, plugin):
        seen[0] += 1
        report(f"Running {plugin} ({seen[0]} of {total})",
               int(5 + 90 * (seen[0] - 1) / total))

    out = memory.extract(path, feature_names, progress=stage)
    report("Assembling the feature vector", 97)
    return out
```

Same overall shape for the memory pipeline. `seen = [0]` is a small,
slightly unusual-looking Python idiom: `stage(...)` is a *nested* function
that needs to remember and update a running count across multiple calls,
but Python's basic rule is that a nested function can *read* a variable
from its enclosing function but can't *reassign* it directly without
special syntax (`nonlocal`). Wrapping the counter in a one-element list
sidesteps that entirely — `seen[0] += 1` mutates the list's contents rather
than reassigning the name `seen` itself, which is allowed. The percentage
math (`5 + 90 * (seen[0] - 1) / total`) spreads progress across the 5%–95%
range as each of the nine plugins completes, leaving a little headroom at
each end for the "building the kernel layer" and "assembling the vector"
steps that bookend the real plugin work.

### `_progress_file()`, `start()`, and `run()` — dispatch and the full status lifecycle

```python
def _progress_file(app, job_id):
    d = Path(app.instance_path) / "progress"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{job_id}.json"


def start(app, job_id):
    if not app.config.get("DISPATCH_JOBS", True):
        return
    from . import executor
    executor.submit(run, app, job_id)
```

`_progress_file` computes the same path both `_reporter` (writing, from the
worker) and `_await` (reading, from the supervisor) need to agree on — one
small JSON file per job ID, inside `instance/progress/`.

`start()` is the function `routes.py` calls after creating a job. Notice
the `DISPATCH_JOBS` check right at the top — file 03 already introduced
this setting and *why* `TestConfig` sets it to `False` (a test upload
carries a few hundred fake bytes, and actually dispatching it would spawn a
real process pool and hand Volatility a file that isn't a real memory
dump); here is exactly where that setting takes effect. When dispatch *is*
enabled, `executor.submit(run, app, job_id)` — the Flask-Executor thread
pool from file 01 — hands the entire `run()` function (below), with these
exact arguments, off to a background thread and returns immediately. This
is the literal moment control returns to `routes.py`'s `upload()`, letting
it redirect the browser right away.

```python
def run(app, job_id):
    with app.app_context():
        job = db.session.get(Job, job_id)
        if job is None:
            return
        try:
            job.status = RUNNING
            job.started_at = utcnow()
            db.session.commit()

            path = app.config["UPLOAD_DIR"] / job.stored_name
            if job.artifact == DISK:
                _disk(app, job, path)
            elif job.artifact == MEMORY:
                _memory(app, job, path)
            else:
                raise ValueError(f"job {job.id} has no artifact type")

            job.status = COMPLETED
        except Exception as e:
            log.exception("job %s failed", job_id)
            job.status = FAILED
            job.error = f"{type(e).__name__}: {e}"[:2000]
        finally:
            job.finished_at = utcnow()
            job.stage = None
            job.progress_pct = None
            db.session.commit()
            db.session.remove()
            _progress_file(app, job_id).unlink(missing_ok=True)
```

This is the complete `PENDING → RUNNING → COMPLETED`/`FAILED` lifecycle in
one function, and it's worth reading slowly, because it's exactly the kind
of code where getting the ordering and error handling right matters a
great deal.

`with app.app_context():` — the comment above `run()` in the real source
explains precisely why this is necessary: "Flask-Executor hands the task a
bare thread with no application context." Code like `db.session` or
`current_app.config` only works correctly when Flask has set up certain
per-request (or, here, explicitly per-task) bookkeeping first; a background
thread doesn't get that automatically the way an actual web request does,
so this line manually establishes it for the duration of this whole
function.

The job is fetched fresh from the database (not passed in as an object,
only its `id` — because objects loaded in one context shouldn't be assumed
still valid or attached correctly in another). If it's somehow already
gone, the function just returns quietly. Otherwise: mark it `RUNNING`,
record `started_at`, and commit *immediately* — this is what makes the
job's in-progress state visible to the web page the very next time it
polls, even before any actual extraction work has started.

The `try`/`except`/`finally` structure is the heart of making failures
*visible* rather than silent. If `_disk(...)` or `_memory(...)` (below)
raises **any** exception at all — a crashed extractor, a model that
refuses a malformed vector, anything — `except Exception as e:` catches it,
logs the full traceback (`log.exception(...)`, which is Python's standard
way to log an error along with exactly where it happened) for developers to
debug later, and — critically — sets `job.status = FAILED` with a readable
`job.error` message, rather than letting the job simply vanish or hang
forever in the `RUNNING` state. `f"{type(e).__name__}: {e}"[:2000]` builds
a message like `"ValueError: expected 55 features, got 40"` and truncates
it to 2000 characters as a defensive cap against an unexpectedly enormous
error message.

The `finally:` block runs **no matter what** — whether the job succeeded or
failed. It always records `finished_at`, always clears `stage`/
`progress_pct` back to empty (so a page that already loaded doesn't show a
stale "Running windows.malfind" message forever after the job has actually
finished), always commits, always calls `db.session.remove()` (which
releases this thread's database session cleanly — important in a
multi-threaded server so sessions don't leak or get reused incorrectly
across different jobs), and always deletes the now-unneeded progress file
(`missing_ok=True` means don't complain if it's somehow already gone).

### `_disk()` and `_memory()` — turning raw extraction output into stored results

These two functions are where extraction (files 09–10), inference (file
08), and forensics (file 11) all genuinely come together for the first
time. A full walkthrough of *what* each called function does belongs in
those later files; here, the focus is the **orchestration** — the order
things happen in, and why.

```python
def _findings(result, described, matched):
    owner = {}
    for m in matched:
        for feature in m["features"]:
            owner.setdefault(feature, m)

    for item in described:
        m = owner.get(item["feature"])
        db.session.add(Finding(
            result=result, feature=item["feature"], weight=item.get("weight"),
            rank=item.get("rank"), meaning=item["why"],
            tag=m["tag"] if m else None,
            mitre_id=m["mitre_id"] if m else None,
            mitre_name=m["mitre_name"] if m else None,
            confidence=m["confidence"] if m else None))
```

A small shared helper both `_disk()` and `_memory()` call at the end.
`matched` is a list of MITRE tag matches (file 11), each one naming which
raw feature names it "claims." The `owner` dictionary is built first so
that, for each described finding, a quick lookup (`owner.get(item["feature"])`)
tells you which tag (if any) claimed that specific feature —
`setdefault(feature, m)` means "record this tag as the owner of this
feature, but only if nothing has claimed it yet," so the first matching
tag wins if more than one somehow could apply to the same feature. Then one
`Finding` database row (file 04) gets created per described item, carrying
either the matched tag's MITRE details or `None` for all of them if nothing
matched — a finding can legitimately exist with a plain-English explanation
but no MITRE attribution at all.

```python
def _disk(app, job, path):
    from . import explain
    from .forensics import mitre, severity
    from .inference import disk as model

    cfg = app.config
    pf = _progress_file(app, job.id)
    out = _await(job, pool().submit(extract_disk, str(path), cfg["MAX_PE_FILES"],
                                    cfg["MAX_PE_BYTES"], str(pf)), pf)

    names = model.names()
    flagged = 0
    for rec in out["files"]:
        vec = model.subset(rec["vec"])
        prob, malicious = model.predict(vec)
        flagged += malicious
```

`pool().submit(extract_disk, ...)` hands the worker function off to the
process pool (this is the actual hand-off across the process boundary),
and `_await(...)` immediately starts polling for its progress and its final
result, exactly as described above. Once extraction genuinely finishes,
`out["files"]` is the list of every PE file found, each carrying its raw
2,381-value EMBER vector. For **every single file**, in a loop: reduce it to
the 150 selected features (`model.subset`, file 08), get a probability and
a boolean verdict (`model.predict`, file 08), and count how many were
flagged.

```python
        result = Result(
            job=job, probability=prob, threshold=model.threshold(),
            malicious=bool(malicious),
            path=rec["path"], partition=rec["partition"], inode=rec["inode"],
            file_sha256=rec["file_sha256"], file_md5=rec["file_md5"],
            file_size=rec["file_size"], allocated=rec["allocated"],
            data_offset=rec["data_offset"], mtime=rec["mtime"],
            atime=rec["atime"], ctime=rec["ctime"], btime=rec["btime"])
        db.session.add(result)

        if not malicious:
            result.severity, result.severity_note = severity.for_disk(
                prob, [], model.threshold())
            continue

        described = explain.disk_findings(vec)
        values = dict(zip(names, (float(x) for x in vec)))
        matched = mitre.match([d["feature"] for d in described], "disk", values)
        result.severity, result.severity_note = severity.for_disk(
            prob, matched, model.threshold())
        _findings(result, described, matched)
```

One `Result` row is created per file, carrying every locator field from
file 04's schema straight from the extractor's output. Then a genuinely
important optimisation and design choice: **if the file wasn't flagged as
malicious, LIME is never run for it at all** — `severity.for_disk(prob, [],
...)` is called with an empty findings list, and the loop moves straight to
the next file via `continue`. The comment elsewhere in this codebase
explains this directly: "explaining a benign verdict wastes the expensive
part of LIME." Running LIME (file 11) on every single one of potentially
hundreds of clean files in a disk image, when nobody is ever going to read
an explanation for a clean verdict, would make every disk job dramatically
slower for zero benefit. Only for the files that actually crossed the
threshold does the full explain → tag-match → build-findings sequence run.

```python
    job.files_scanned = out["examined"]
    job.files_flagged = flagged
    job.skipped = out["skipped"]
```

Finally, three summary fields get written onto the `Job` row itself
(distinct from the per-file `Result` rows) — the total files examined, how
many were flagged, and the full list of files that were skipped and why
(file 09 covers exactly what gets skipped and why that list matters).

```python
def _memory(app, job, path):
    from . import explain
    from .forensics import baseline, meanings, mitre, severity
    from .inference import memory as model

    names = model.names()
    pf = _progress_file(app, job.id)
    out = _await(job, pool().submit(extract_memory, str(path), names, str(pf)), pf)
    vec = out["vec"]

    prob, malicious = model.predict(vec)
    count, fields = model.ood(vec)
    dominant = model.dominant_ood(vec)
    reliable = not dominant

    job.extraction_gaps = out["gaps"]
    job.ood_count = count
    job.ood_fields = fields
    job.plugin_seconds = out.get("plugin_seconds")
    job.evidence = out.get("evidence")
```

The memory pipeline produces exactly **one** feature vector for the whole
dump (unlike disk's one-per-file loop). Beyond the probability and boolean
verdict, this immediately also computes the out-of-distribution check
(`model.ood`) and specifically whether the four features the model leans on
most heavily are themselves out of range (`model.dominant_ood` — file 08
covers exactly what "dominant" means and why it matters so much for this
particular model). `reliable = not dominant` is the single boolean that
everything downstream about *how much to trust the model's own score* hinges
on. A batch of summary fields get written straight onto the job row.

```python
    observed = meanings.observed(vec, names)
    elevated = baseline.compare(observed)

    matched = mitre.match(list(observed), "memory")
    standout = mitre.match([f for f, is_high in elevated.items() if is_high], "memory")
    sev, note = severity.for_memory(elevated, standout, prob, reliable,
                                    baselined=baseline.loaded())
```

This is the single most important design decision in the whole memory
pipeline, and file 11 covers the full reasoning behind it — but the
orchestration itself lives right here, so it's worth pointing out precisely.
`mitre.match(...)` is called **twice**, over two deliberately different
sets of features: once over *everything observed* (`matched`), and once over
only the subset that's actually *elevated against the clean baseline*
(`standout`). `matched` is what gets attached to the individual `Finding`
rows, so the analyst can see what every measurement maps to, regardless of
whether it's unusual for this machine. `standout` — the narrower one — is
what actually gets passed into `severity.for_memory(...)` to compute the
Low/Medium/High/Critical score. The comment elsewhere in this codebase
records exactly why this split exists: matching on mere *presence* alone
once scored a perfectly clean reference capture as Critical, because every
healthy Windows machine legitimately has some malfind hits, some loader-list
mismatches, some psxview discrepancies — only when those measurements are
substantially higher than what a clean baseline of *this same machine*
shows should they be allowed to drive severity upward.

```python
    volumetric, volumetric_note = baseline.volumetric_context(vec, names, elevated)
    job.volumetric = {"raised": volumetric, "note": volumetric_note}

    result = Result(job=job, probability=prob, threshold=model.threshold(),
                    malicious=bool(malicious), severity=sev, severity_note=note)
    db.session.add(result)

    described = []
    for feature, value in sorted(observed.items(), key=lambda kv: -kv[1]):
        d = meanings.describe(feature)
        if d is None:
            continue
        d["why"] = f"{d['why']} {baseline.phrase(feature, value)}."
        d["rank"] = len(described) + 1
        described.append(d)

    if malicious and reliable:
        seen = {d["feature"] for d in described}
        for d in explain.memory_findings(vec):
            if d["feature"] not in seen:
                d["rank"] = len(described) + 1
                described.append(d)

    _findings(result, described, matched)
```

Configuration-context data (file 11 explains what "volumetric" means and
why it's structurally incapable of affecting severity) gets computed and
stored separately on the job. The single `Result` row is created with the
severity that was just computed.

The findings themselves are built in a specific, deliberate order: **first**,
every genuinely-observed indicator (`meanings.observed`, file 11) is turned
into a plain-English description, sorted highest-value first, **regardless
of whether the model flagged anything at all** — these are Volatility's own
direct measurements of the dump and hold whatever the model says (this is
the concrete implementation of hard rule 22, "memory reports lead with
observed findings, never the probability"). **Only afterward**, and **only**
if the model both flagged this dump as malicious *and* its score is
considered reliable (`malicious and reliable`), does LIME get run at all
(`explain.memory_findings`, file 11) — and even then, only features not
already covered by the direct observations get added, via the `seen` set
check, to avoid duplicate findings for the same feature. This mirrors the
disk pipeline's "don't run LIME on a benign result" cost-saving logic, but
adds a second, memory-specific condition on top: don't trust — or even
bother running — the model's explanation when the model's own score has
already been judged unreliable for this particular capture.

### `recover_orphans()` — cleaning up after a crash

```python
def recover_orphans(app):
    with app.app_context():
        stale = db.session.query(Job).filter_by(status=RUNNING).all()
        for job in stale:
            job.status = FAILED
            job.error = "interrupted: the server stopped while this job was running"
            job.finished_at = utcnow()
            job.stage = None
            job.progress_pct = None
            _progress_file(app, job.id).unlink(missing_ok=True)
        if stale:
            log.warning("marked %d interrupted job(s) as failed", len(stale))
            db.session.commit()
        return len(stale)
```

Introduced already in file 05 as one of the steps `create_app()` runs at
startup (gated behind `RECOVER_ORPHANS`). Here's exactly what it does and
why it's needed: if the whole server process is killed or crashes while a
job is genuinely `RUNNING` (a power loss, a deployment restart, anything),
that job's row is left permanently stuck showing `RUNNING` in the
database — nothing is ever going to come along and finish it, because
whatever thread was managing it no longer exists. Without this function,
that job would sit forever showing "in progress" on the dashboard, which
is actively misleading. Instead, every job found in that stuck state at the
next startup is honestly marked `FAILED`, with a specific, readable
explanation (`"interrupted: the server stopped while this job was
running"`) rather than a generic error — and its now-meaningless progress
file is cleaned up too.

## Check your understanding

**Q1. Why does this project use *two* separate background mechanisms (a
thread pool for job supervision, a process pool for extraction) instead of
just running extraction directly on a Flask-Executor thread?**

A: Two independent reasons. First, `lief` parses potentially hostile input
in native code, and a crash there (a segfault) would take down the entire
process it runs in — running it in a separate process means that failure
costs one job, not the whole web server. Second, Volatility 3's extraction
work is CPU-bound Python, which would hold the GIL for the entire multi-
minute duration if run on a thread, freezing every other thread — including
ones serving unrelated web requests — in the same process. A separate
process has its own interpreter and GIL, so it genuinely runs in parallel.

**Q2. How does live progress ("Running windows.malfind, 5 of 9") actually
get from inside the worker process onto the web page an analyst is
watching, given that the worker has no database session and no application
context at all?**

A: Through a small JSON file on disk, written atomically by the worker
(`_reporter`, writing to a temp file and then renaming it over the real
file so a reader never sees a half-written state) and read by the
supervisor thread (`_await`), which is polling it once per second — the
same second it's already blocked on `future.result(timeout=1.0)` for.
Whenever the read content changes, the supervisor copies it onto the real
`Job` row and commits, which is what the web page's own periodic poll (file
13) then picks up.

**Q3. In `_disk()`, why is LIME never run for a file whose probability
didn't cross the threshold?**

A: Because nobody is going to read an explanation for a verdict that isn't
malicious — LIME is comparatively expensive to run, and running it for
every single clean file in a disk image that might contain hundreds of
executables would make every job dramatically slower for zero analytical
benefit. `severity.for_disk(prob, [], threshold)` is called instead, with
an empty findings list, and the loop moves straight to the next file.

**Q4. `mitre.match(...)` is called twice inside `_memory()`, over two
different sets of features (`matched` and `standout`). What's the
difference between them, and why does that split exist?**

A: `matched` runs over every feature genuinely observed in the capture,
regardless of whether it's unusual for this particular machine — it's used
to label the `Finding` rows an analyst sees, so every measurement has a
plain explanation attached. `standout` runs only over the narrower subset
that is elevated *against the clean-machine baseline*, and it's the only
one of the two that feeds into `severity.for_memory(...)`. The split exists
because matching on mere presence alone once scored a perfectly clean
reference capture as Critical — every healthy Windows machine legitimately
shows some malfind hits, loader-list mismatches, and psxview discrepancies,
and only substantially elevated values should be allowed to drive severity.

**Q5. If the whole server crashes while three jobs are `RUNNING`, what
happens to those three jobs the next time the server starts, and why does
that matter for an analyst using the dashboard?**

A: `recover_orphans()` runs automatically as part of `create_app()`, finds
every job still marked `RUNNING` (which can only mean the process that was
supposed to finish it no longer exists), and marks each one `FAILED` with
an honest, specific error message explaining that the server was
interrupted. Without this, those jobs would sit forever showing "in
progress" on the dashboard and jobs list, actively misleading an analyst
into thinking something is still happening when nothing ever will be again.

**Q6. Trace the exact sequence of database writes to a `Job` row from the
moment `upload()` first creates it to the moment a memory analysis
completes successfully. How many separate commits happen, and what changes
at each one?**

A: (1) `upload()` creates the row with `status=PENDING` (or `NEEDS_TYPE`)
and commits. (2) `jobs.run()` sets `status=RUNNING` and `started_at`, and
commits — this is what makes the "in progress" state visible before any
extraction work has even begun. (3) While extraction runs, `_await()`
commits again, possibly many times, each time the progress file's content
changes (`stage`/`progress_pct` updated). (4) Once `_memory()` finishes
successfully, `jobs.run()` sets `status=COMPLETED`, and in its `finally`
block sets `finished_at`, clears `stage`/`progress_pct` back to empty, and
commits one final time. So: at minimum two commits (start, finish) if
progress never happened to be polled in between, but realistically several
more, one per observed progress change, given a job typically running for
minutes.
