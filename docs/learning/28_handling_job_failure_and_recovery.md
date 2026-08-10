# 28 — What Happens When a Job Fails

This functionality actually has **two separate triggers**, covered
together here because they solve the same underlying problem — a job that
can no longer make progress must never be left silently claiming it's
still `RUNNING` — from two different moments in time: while the job is
genuinely still executing, and after the fact, if the whole server itself
went down before the job could finish.

## Visual flow

```
LIVE FAILURE (job is genuinely still running)          CRASH RECOVERY (server restarts later)
---------------------------------------------          ---------------------------------------
jobs.run(app, job_id)                    [jobs.py]      create_app()                [__init__.py]
  -> job.status = RUNNING; commit          sequential     -> ... (file 21's full sequence) ...
  -> try:                                                 -> jobs.recover_orphans(app)  [jobs.py]
       _disk(app, job, path)                                   -> query: every Job where
         or                                                        status == RUNNING
       _memory(app, job, path)                                 -> FOR EACH stale job found:
       (-- something inside here raises --)                         job.status = FAILED
  -> except Exception as e:                                         job.error = "interrupted: ..."
       job.status = FAILED                                          delete its progress file
       job.error = "<type>: <message>"                         -> db.session.commit()
  -> finally:
       job.finished_at = ...
       job.stage = None; job.progress_pct = None
       db.session.commit()
       db.session.remove()
       delete the progress file

  Both entirely sequential -- no background work in either
  path. The difference is WHEN each one runs, not how.
```

## 1. Trigger

**Live failure:** something inside `_disk(app, job, path)` or `_memory
(app, job, path)` (files 24, 25) raises a genuine Python exception while
the job is actively running — a corrupted image, an unreadable dump, an
extractor bug, a model refusing a malformed input, anything at all.

**Crash recovery:** the whole server process itself was stopped or crashed
(a power loss, a manual restart, a deployment) while at least one job's
status was still `RUNNING` in the database, and the server is now starting
back up.

## 2. The full sequence, step by step

### Live failure

**Step 1 — `jobs.run(app, job_id)`, `app/jobs.py`.** The same entry point
files 24 and 25 already covered — this file focuses specifically on its
`try`/`except`/`finally` structure, which wraps *everything* those two
files' whole chains do.

**Step 2 — `job.status = RUNNING`; commit.** Already covered in files
24/25 — mentioned again here because it's the state a job is left in if
nothing below ever runs to change it, which is exactly the dangerous
condition this whole functionality exists to prevent.

**Step 3 — `try: ... _disk(app, job, path) ... or ... _memory(app, job,
path) ...`.** Everything from files 24 or 25's entire chain runs inside
this one `try` block. Any exception raised *anywhere* inside that entire
chain — inside extraction, inside `model.predict()`, inside `mitre.
match()`, inside `severity.for_memory()`, anywhere at all — is caught by
the single `except` clause below, not by anything closer to where it
happened. Why one wide `try` around the whole chain, rather than many
small ones scattered through files 24/25: a failure anywhere in this
whole sequence means the same thing either way — this job cannot produce
a trustworthy result and must be marked `FAILED` — so one catch-all at the
top level correctly and simply covers every possible failure point without
needing to anticipate each one individually.

**Step 4 — `except Exception as e:`.** Plain language: catches the
exception. `log.exception("job %s failed", job_id)` writes the *full*
technical traceback to the application's own log file — for a developer
to debug later, never shown to the analyst directly. `job.status = FAILED`
and `job.error = f"{type(e).__name__}: {e}"[:2000]` build a short,
readable summary (e.g. `"ValueError: expected 55 features, got 40"`),
truncated defensively to 2000 characters, and store it directly on the job
row — this is what an analyst actually sees on the job's page.

**Step 5 — `finally:` — runs unconditionally, whether the `try` block
succeeded or the `except` block just ran.** `job.finished_at = utcnow()`;
`job.stage = None` and `job.progress_pct = None` (so a page that's already
loaded doesn't keep showing a stale "Running windows.handles" message
forever, §27); `db.session.commit()` — this is the single commit that
actually makes the `FAILED` status (or, on success, `COMPLETED`) visible
to a browser's next poll; `db.session.remove()` releases this thread's
database session cleanly; and `_progress_file(app, job_id).unlink
(missing_ok=True)` deletes the now-meaningless progress file (§27's
functionality genuinely ends here, one way or another, for this job).

### Crash recovery

**Step 1 — `create_app()`, `app/__init__.py` (file 21's full sequence).**
`recover_orphans()` is called from deep inside this sequence — not a
separate trigger of its own, but a specific step within starting the
application. Included as its own numbered sequence here because its
*purpose* — cleaning up a stuck job — is the same purpose as live failure
handling above, just reached from a genuinely different starting point.

**Step 2 — `jobs.recover_orphans(app)`, `app/jobs.py`.** Plain language:
queries the database for every single job whose `status` is still
`RUNNING`. Why this query is meaningful at all, at startup specifically:
the *only* way a job's status can still legitimately be `RUNNING` at the
exact moment the server is starting back up is if whatever was supposed
to finish it (a specific background thread, in a specific now-gone process)
no longer exists — a `RUNNING` job found here is, by definition, orphaned.
Input: the app object (needed for `app.app_context()` and to compute each
stale job's progress-file path). Output: the count of jobs it found and
fixed.

**Step 3 — for each stale job found: `job.status = FAILED`; `job.error =
"interrupted: the server stopped while this job was running"`; `job.
finished_at = utcnow()`; `job.stage = None`; `job.progress_pct = None`;
its progress file is deleted.** Notice this is genuinely the same *shape*
of cleanup as the live-failure path's `finally` block above — the same
fields get reset to the same "cleanly finished, nothing left dangling"
state — just reached by a different route, and with a distinctly-worded
error message that honestly describes *this specific* situation (a server
interruption) rather than reusing live failure's generic exception-message
format.

**Step 4 — `if stale: log.warning(...); db.session.commit()`.** All the
fixes for every orphaned job found are committed together, in one
transaction, only if at least one was actually found (an empty result
skips the commit entirely, since there's nothing to save).

## 3. Sequential versus background/parallel

Both paths are entirely sequential, with no background work of their own.
The live-failure path runs on whatever background thread was already
executing the job (the one set up back in file 23's upload hand-off) —
it's "in the background" only in the sense that files 24/25's whole chain
already was; the actual `try`/`except`/`finally` logic itself doesn't add
any further parallelism. The crash-recovery path runs as one more
sequential step inside `create_app()`'s already entirely-sequential
startup sequence (file 21).

## 4. Where this functionality starts and ends

**Live failure starts** the instant an exception is raised anywhere
inside files 24 or 25's chain and **ends** the instant the `finally`
block's final commit completes — at which point the job is durably marked
`FAILED`, with a readable reason, and nothing further ever happens to it
automatically (an analyst would need to re-upload the artifact to try
again — there's no "retry" functionality anywhere in this codebase).

**Crash recovery starts** the instant `create_app()` reaches its call to
`recover_orphans()` and **ends** the instant that function returns, back
into the middle of file 21's own sequence — after which startup simply
continues with its remaining steps (error handler registration, and so
on) exactly as file 21 describes.

## 5. Check your understanding

**Q1. Why does `jobs.run()` wrap the *entire* call to `_disk()`/`_memory()`
in one single `try` block, rather than putting smaller `try`/`except`
blocks around individual risky steps inside files 24 and 25's own chains?**

A: Because no matter *where* inside that whole chain something goes
wrong — extraction, prediction, explanation, tagging, severity scoring —
the correct response is identical every time: mark this job `FAILED` with
a readable reason and stop. One wide `try` around the entire chain
correctly captures every possible failure point with a single, simple
rule, rather than needing many scattered `except` blocks that would each
have to independently remember to do the same cleanup.

**Q2. A job is stuck showing `RUNNING` on the dashboard because the whole
server crashed five minutes into a memory extraction. What specific
function notices this, when does it run, and what does it change about
that stuck job?**

A: `jobs.recover_orphans(app)`, called from inside `create_app()` (file
21) the next time the server starts up — not while the server is down, and
not automatically the instant it crashes, only at the very next boot. It
finds every job still marked `RUNNING`, and for each one, sets its status
to `FAILED`, gives it a specific, honest error message explaining the
server was interrupted, clears its now-meaningless progress fields, and
removes its orphaned progress file.

**Q3. Compare the `job.error` text produced by a live in-progress failure
versus a crash-recovered orphan. Are they generated by the same piece of
code, and why might an analyst want to be able to tell the two situations
apart just by reading the error message?**

A: No — they're two different, deliberately distinct messages. A live
failure's message is built dynamically from the real Python exception that
occurred (`f"{type(e).__name__}: {e}"`, e.g. `"ValueError: expected 55
features, got 40"`), naming the actual technical cause. A crash-recovered
job's message is a fixed, hand-written string,
`"interrupted: the server stopped while this job was running"`, which
deliberately says nothing about the job's own content at all, because
nothing about the job's own content was actually the problem — the server
itself stopped. An analyst reading the message can immediately tell
whether a specific artifact caused a real analysis failure worth
investigating, or whether the job simply never got the chance to run to
completion for reasons that have nothing to do with the artifact itself.
