# 23 — Uploading an Artifact (Disk Image or Memory Dump)

## Visual flow

```
upload()                                            [routes.py]   entry point
  -> form.validate_on_submit()                                     sequential
  -> artifacts.ext_of()                              [artifacts.py] sequential
  -> artifacts.store()                                [artifacts.py] sequential (streams to disk)
       (hashes while writing; never loads whole file into memory)
  -> IF analyst chose "auto":
        artifacts.sniff()                             [artifacts.py] sequential
     ELSE:
        (trust the analyst's explicit choice directly)
  -> Job()                                             [models.py]   sequential
  -> db.session.flush() / log() / db.session.commit()                sequential

  -- BRANCH A: type was determined (disk, memory, or analyst's choice) --
  -> job_queue.start()                                 [jobs.py]
       -> executor.submit(run, app, job.id)             <-- HANDS OFF, DOES NOT WAIT
            (jobs.run() begins on a separate background thread --
             see files 24/25 for everything that happens after this point)
  -> return "queued" response to the browser IMMEDIATELY,
     without waiting for jobs.run() to do anything at all

  -- BRANCH B: type could not be determined at all --
  -> redirect to confirm_type()                        [routes.py]
       -> (analyst picks disk or memory, submits a form)
       -> job.artifact = ...; job.status = PENDING
       -> job_queue.start()  (same hand-off as Branch A, just later)
```

The single most important thing to notice in this diagram: `job_queue.
start()` **does not wait** for the analysis to actually happen. It hands
the job off and the function returns immediately — this is a **background
hand-off**, not a sequential step, and it's the one place in this entire
functionality where that distinction matters. Everything else drawn above
it happens strictly one step after another, on the same thread that's
handling the browser's request.

## 1. Trigger

An analyst, signed in, fills in the upload form and clicks "Upload and
queue" — a `POST /upload` request, carrying the raw file bytes and the
analyst's choice of "Detect automatically," "Disk image," or "Memory
dump."

## 2. The full sequence, step by step

**Step 1 — `upload()`, `app/routes.py`.** The entry point. Three
decorators run first, in order, before the function body even starts: the
rate limiter (checking this analyst hasn't uploaded too many artifacts too
recently, §3, §7), then `@login_required` (§6, §22). Plain language for
the function itself: receives the uploaded file, decides what kind of
artifact it is, creates a database record for it, and either starts
analysis immediately or asks the analyst to clarify.

**Step 2 — `form.validate_on_submit()`, backed by `UploadForm` in
`app/forms.py`.** Confirms a file was genuinely attached and the CSRF
token is valid. If this fails, the upload form is simply shown again — the
chain stops here.

**Step 3 — `artifacts.ext_of(fs.filename)`, `app/artifacts.py`.** Plain
language: pulls the lowercase file extension off whatever name the
browser reported for the uploaded file. Input: the client-reported
filename (untrusted — see step 4's note). Output: an extension string
like `.raw`. Checked immediately against `ALLOWED_EXT` (§3); a
disallowed extension stops the whole chain right here, before a single
byte of the file is even read into `store()`.

**Step 4 — `artifacts.store(fs.stream, upload_dir, ext)`, `app/
artifacts.py`.** Plain language: streams the file to disk 4 MB at a time,
computing its SHA-256 hash incrementally as it goes, and saves it under a
**freshly generated random name**, never the client's own filename — §7
covers exactly why using the client's own name would be a security risk
(path traversal). Input: the raw upload stream and the destination folder.
Output: a three-part result — the new random stored filename, the real
SHA-256 hash, and the file's size in bytes — none of which existed before
this step ran.

**Step 5 — type detection.** If the analyst left the choice on
"Detect automatically": `artifacts.sniff(path)`, `app/artifacts.py`. Plain
language: reads specific fixed byte ranges near the start of the
just-saved file and checks them against known disk-image and crash-dump
signatures. Why here, and not before storing the file: `sniff()` needs to
read real bytes off disk, which only exist once `store()` (step 4) has
finished writing them. Input: the path to the just-stored file. Output: a
tuple — either `("disk", "some specific reason")`, `("memory", "some
specific reason")`, or `(None, "no disk signature and no crash-dump
header...")`. If the analyst instead explicitly chose "Disk image" or
"Memory dump" at upload time, this whole step is skipped entirely, and
that explicit choice is trusted directly instead.

**Step 6 — `Job(...)`, `app/models.py` (§4).** Plain language: constructs
a new database row representing this upload — recording the original
client filename (for display only), the real stored filename, the real
hash and size, and whatever type detection just produced (or `None`, if
detection was inconclusive). `status` is set to `PENDING` if a type is
known, or `NEEDS_TYPE` if it isn't.

**Step 7 — `db.session.flush()`, then `log("upload", job=job, ...)`
(`app/audit.py`, §6), then `db.session.commit()`.** The same
flush-then-audit-then-commit pattern already seen in file 22's
registration chain — the flush gets the new job a real ID before the
audit entry references it.

**Step 8 — the branch.** If `detected` came back `None` (step 5's
inconclusive result), the function flashes a message and `redirect(url_for
("main.confirm_type", job_id=job.id))` — **this whole functionality's
first attempt ends here, with no background job started at all.** Otherwise
(a type was determined, either by `sniff()` or by the analyst's explicit
choice):

**Step 9 — `job_queue.start(app._get_current_object(), job.id)`, `app/
jobs.py` (§7).** Plain language: hands this job's ID off to the background
job system. Why `app._get_current_object()` specifically, rather than
just `current_app`: the background thread this is about to run on is a
genuinely different execution context than the current request, and needs
the *real* underlying Flask app object explicitly, not the request-bound
proxy (§7 covers this). Input: the real app object, and the new job's ID.
Output: nothing meaningful returned — and critically, **this call itself
does not wait for the job to actually run**. Inside `start()`: if
`DISPATCH_JOBS` is enabled (true in real use, false under the test suite,
§3), `executor.submit(run, app, job_id)` hands the entire `jobs.run(...)`
function off to a Flask-Executor background thread and returns
*immediately* — this is the exact hand-off point where "uploading" ends
and "analyzing" (files 24, 25) begins, on a genuinely different thread,
running independently of everything that happens next in this function.

**Step 10 — `flash(...)` and `redirect(url_for("main.job_detail", job_id=
job.id))`.** The browser is sent to the job's detail page immediately —
**well before** the background job has done any real work at all. The job
detail page itself (file 26) will show a live "in progress" view, polling
for updates (file 27), precisely because analysis genuinely hasn't
finished — often hasn't even *started* — by the time this response reaches
the browser.

### The `confirm_type()` branch, when detection was inconclusive

**Step 1 — `confirm_type(job_id)`, `app/routes.py`.** Entry point for this
branch specifically — reached only via the redirect in step 8 above, or by
an analyst navigating back to that URL directly. Calls `_owned(job_id)`
first (§7's authorization pattern — confirms this job exists and belongs
to the signed-in analyst).

**Step 2 — the analyst submits `ConfirmTypeForm`, choosing "Disk image" or
"Memory dump."** `form.validate_on_submit()` confirms the choice was made.

**Step 3 — the *same* already-existing `Job` row from the original upload
is updated directly** (`job.artifact = form.artifact.data`, `job.
detected_as = "confirmed by analyst..."`, `job.status = PENDING`) — **no
new job row is created here.** This matters: from this point on, it's
exactly the same job the analyst originally uploaded, just now carrying a
type it didn't have a moment ago.

**Step 4 — `log("artifact_type_set", ...)`, then `db.session.commit()`.**

**Step 5 — `job_queue.start(...)`.** The exact same function call as step
9 above, just reached via a different path and later in time — this is
the concrete answer to "where do the two upload paths (immediate type
detection vs. asking the analyst) actually converge back into one." Both
paths end at this identical call.

## 3. Sequential versus background/parallel

Steps 1 through 8 (and, in the ambiguous-type branch, every step of
`confirm_type()`) are entirely **sequential** — the browser's request is
genuinely waiting on the server for all of that to finish, including the
full multi-gigabyte file transfer in step 4. The **one and only**
background hand-off in this whole functionality is `executor.submit(run,
app, job_id)` inside `job_queue.start()` (step 9) — from that exact
instant onward, the actual analysis work (files 24, 25) proceeds
completely independently, on a separate thread, and this functionality's
own response to the browser is sent without waiting for any of it.

## 4. Where this functionality starts and ends

**Starts:** the moment a `POST /upload` request (carrying real file bytes)
arrives at the server.
**Ends:** the moment `job_queue.start(...)` has been called and the
redirect response has been sent to the browser — which, for a job whose
type was known immediately, is a single request/response cycle; for a job
whose type was ambiguous, spans two separate requests (`/upload`, then
later `/jobs/<id>/type`), with the job sitting in the `NEEDS_TYPE` state in
between, doing nothing at all, waiting on the analyst. Either way, this
functionality's job is done the instant a background job has genuinely
been started — everything that happens to the artifact from that point on
belongs to file 24 or file 25, not this one.

## 5. Check your understanding

**Q1. `artifacts.sniff()` is only called under one specific condition.
What is that condition, and what happens instead when it isn't met?**

A: It's only called when the analyst left the artifact-type choice on
"Detect automatically." If the analyst explicitly selected "Disk image" or
"Memory dump" at upload time, `sniff()` is skipped entirely, and that
explicit choice is used directly as the job's `artifact` value instead —
the code trusts an explicit human choice over needing to guess from the
file's bytes.

**Q2. Why does `store()` run *before* `sniff()`, rather than the other way
around?**

A: `sniff()` works by reading specific byte ranges directly from the
file's actual saved content on disk. Until `store()` has finished
streaming and writing the full upload to a real file, there's no saved
file on disk yet for `sniff()` to read anything from at all — the
dependency only goes one direction.

**Q3. When exactly does `upload()`'s response actually get sent back to
the analyst's browser — before or after the disk/memory analysis has
finished? What single function call is responsible for making that true?**

A: Before — in fact, usually well before analysis has even meaningfully
started, let alone finished. `job_queue.start()`'s internal call to
`executor.submit(run, app, job_id)` hands the entire analysis process off
to a background thread and returns immediately, without waiting for
`jobs.run(...)` to do anything at all. `upload()`'s own final steps
(flashing a message, redirecting to the job detail page) then run
right away, while the actual analysis is only just beginning, independently,
on a separate thread.
