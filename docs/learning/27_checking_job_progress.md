# 27 — Checking Job Progress While a Job Runs

This functionality is genuinely different in shape from every other file
in this curriculum: it involves **three separate things running at
once** — a worker process, a supervisor thread, and a browser — none of
which ever call each other's functions directly. They communicate
entirely through two indirect channels: a small file on disk, and the
database. This file traces all three "threads of activity" and shows
exactly how they line up in time.

## Visual flow

```
[WORKER PROCESS -- running extract_disk() or extract_memory()]     [SUPERVISOR THREAD          [BROWSER]
                                                                      -- inside _await()]
_reporter(progress_file) returns report()
report("Walking the filesystem")
  -> writes progress.tmp, renames over progress.json  ---------->  future.result(timeout=1.0)
                                                                      times out (1 sec passed)
                                                                      reads progress.json
                                                                      job.stage = "..."; commit -----> (next poll picks this up)
report("Vectorising executable 1")
  -> writes progress.tmp, renames over progress.json  ---------->  future.result(timeout=1.0)
                                                                      times out again
                                                                      reads progress.json (changed!)
                                                                      job.stage = "..."; commit
        ... this repeats, once per second, for the whole            ... this repeats in lock-step
        duration of extraction ...                                  with the left column ...
                                                                                                       fetch(job_status())
                                                                                                       every 3 seconds
                                                                                                       -> updates page text
                                                                                                          and progress bar
extract finishes, returns its real result       -------------->   future.result(timeout=1.0)
                                                                      succeeds this time, returns
                                                                      the real result -- loop ends
```

The left and middle columns are **two genuinely separate operating-system
processes**, with no shared memory at all — the only thing connecting
them is the small JSON file each one touches independently. The right
column (the browser) is separate again, connected to the middle column
only through ordinary HTTP requests, on its own independent 3-second
timer.

## 1. Trigger

This functionality begins the instant a job's `status` becomes `RUNNING`
(the very first real step of file 24's or file 25's chain) and the
analyst's browser is sitting on that job's detail page. There are, in
effect, two separate triggers running the whole time this functionality is
active: the worker process calling `report(...)` every time it starts a
new stage, and the browser's own JavaScript timer firing every 3 seconds
— neither one waits for or directly triggers the other.

## 2. The full sequence, step by step

**Step 1 — `_reporter(progress_file)`, `app/jobs.py`.** Plain language:
not itself a progress report — a small **factory function** that, given a
file path, returns a *new* function (`report`) which, whenever it's
called later, writes the given stage text and percentage to that exact
file. Why it exists as a factory rather than a plain function taking the
path every time: `extract_disk()` and `extract_memory()` (files 24, 25)
each call this once, at the very start, and then call the small returned
`report(...)` function many times afterward without needing to keep
re-specifying the file path.

**Step 2 (inside the worker process, called repeatedly throughout files
24/25's extraction steps) — `report(stage, pct)`, the function `_reporter`
returned.** Plain language: writes `{"stage": ..., "pct": ...}` as JSON —
but not directly to the real progress file. It first writes to a
differently-named `.tmp` file, then calls `tmp.replace(path)` to
atomically rename it over the real file. Why this two-step dance,
specifically: without it, the supervisor thread (step 4, below) could, in
principle, read the progress file at the exact moment it's only half
written, getting corrupt, unparseable JSON. An atomic rename means a
reader always sees either the complete old content or the complete new
content, never something in between. *Called from elsewhere?* This
specific returned closure isn't reused outside files 24/25, but the
factory function `_reporter` itself is called by both `extract_disk()`
and `extract_memory()` — see file 29.

**Step 3 — `_await(job, future, progress_file)`, `app/jobs.py`.** This is
where the supervisor thread (the thread that submitted the extraction work
back in file 24/25's step 3–4) actually spends nearly all of its time
during a real job. Plain language: repeatedly calls `future.result
(timeout=1.0)` — normally a call that blocks until a background result is
ready, but with a `timeout` argument, it instead raises `TimeoutError`
after that many seconds if the result isn't ready yet, rather than
blocking indefinitely.

**Step 4 — every time that one-second wait expires without the worker
being finished** (`except TimeoutError:`), `_await()` reads whatever is
currently in the progress file (`json.loads(progress_file.read_text())`),
wrapped in its own error handling (`except (OSError, ValueError):
continue`) for the rare moment it's read between the worker's temp-file
write and its rename. If the content genuinely changed since the last
time this loop checked (`if cur != last:`), it copies the new `stage` and
`pct` values directly onto the real `Job` database row and commits. Why
only on a genuine change, not every single second regardless: avoids
writing an identical, unchanged value to the database dozens of times in a
row for no reason. Then the loop goes straight back to waiting on
`future.result(timeout=1.0)` again — **this one call is doing two jobs at
once**: waiting for the real result, and doubling as the once-per-second
poll interval, with no separate sleep loop and no second thread needed at
all (§7's own framing of this as one of the more elegant pieces of this
whole codebase).

**Step 5 — meanwhile, independently, the browser's own JavaScript** (in
`job_detail.html`'s `{% block scripts %}`, §13) runs `setInterval(async ()
=> { ... }, 3000)` — a timer completely unrelated to, and unsynchronised
with, the worker/supervisor's one-second cycle above. Every 3 seconds, it
calls `fetch(url)`, where `url` is `{{ url_for('main.job_status', job_id=
job.id) }}`.

**Step 6 — `job_status(job_id)`, `app/routes.py`.** The actual server-side
entry point the browser's fetch reaches. Plain language: calls `_owned
(job_id)` (§7, same shared helper as file 26), then returns a small plain
dictionary — Flask automatically turns this into a JSON HTTP response.
Reads *only* already-committed database fields (`job.status`, `job.stage`,
`job.progress_pct`, `job.error`, and a few counts) — this route does not
talk to the progress file at all; it only ever sees whatever `_await()`
already copied onto the `Job` row in step 4. Output: a small JSON object.

**Step 7 (back in the browser) — the fetch's JSON response is read, and
the page's own DOM is updated directly**: `text.textContent = j.stage`,
`bar.style.width = j.progress_pct + "%"`. If `j.done` is `true`, the
JavaScript instead calls `location.reload()` — a full page reload, which
lands back on `job_detail()` (file 26), now showing genuinely finished
results instead of a progress bar.

**Step 8 — this whole cycle (steps 2–7) repeats** for as long as
extraction continues — dozens or hundreds of times for a real, multi-
minute memory extraction — until the worker process's function finally
returns its real result, `future.result(timeout=1.0)` succeeds instead of
timing out, and `_await()` returns that result back up to `_disk()`/
`_memory()` (files 24, 25), which is the moment this progress-checking
functionality effectively stops mattering — the very next thing that
happens is `jobs.run()` setting the job's final status (file 24/25's last
steps, and file 28 for the failure path).

## 3. Sequential versus background/parallel

This entire functionality **is** the background/parallel case — it's the
one file in this curriculum where genuinely three independent things are
happening "at once," on their own separate schedules, for the whole
duration of a real job:

- The **worker process** writes progress whenever it starts a new
  extraction stage (an irregular interval — however long each Volatility
  plugin or PE file takes).
- The **supervisor thread** checks that progress file once every second,
  on its own fixed clock, regardless of how often the worker actually
  wrote anything new.
- The **browser** asks the server for a status update once every three
  seconds, on its own separate fixed clock, regardless of both of the
  above.

None of these three ever call into one another's functions directly — the
worker and the supervisor share nothing but a file on disk; the supervisor
and the browser share nothing but an ordinary HTTP request/response and
the database in between.

## 4. Where this functionality starts and ends

**Starts:** the instant a job's status becomes `RUNNING` and its progress
file is first created (file 24/25's very first steps).
**Ends:** the instant the job's status becomes `COMPLETED` or `FAILED` —
at that exact point, `jobs.run()`'s own `finally` block (§7, file 28)
deletes the progress file entirely (`_progress_file(app, job_id).unlink
(missing_ok=True)`), and the browser's next poll (or the `"done": true`
flag in the very next `job_status()` response) triggers the final
`location.reload()` that ends the polling loop on the browser's side too.

## 5. Check your understanding

**Q1. If the worker process crashed at the exact moment it was halfway
through writing its progress file, what would the supervisor thread
actually read the next time it checked, and why doesn't that crash
corrupt what the supervisor sees?**

A: The supervisor would read whatever the **complete, previous** progress
value was — never a half-written, corrupted one. This is because the
worker never writes directly to the real progress file; it always writes
to a separate `.tmp` file first and only makes the new content visible via
an atomic rename over the real file at the very end. A reader can only
ever see the file in one of two complete states (the old content, or the
new content) — there is no in-between state to accidentally read.

**Q2. `_await()`'s call to `future.result(timeout=1.0)` is described as
"doing two jobs at once." What are those two jobs, and why does that
avoid needing a separate sleep loop or a second thread?**

A: It's simultaneously waiting for the real extraction result to become
available, *and* acting as the once-per-second interval at which the
supervisor checks the progress file — because `TimeoutError` is raised
exactly once every second the result isn't ready yet, giving the code a
natural, built-in "check back in one second" rhythm for free, without
needing a separate `time.sleep(1)` loop running alongside it, and without
needing a second thread dedicated purely to polling.

**Q3. The browser's polling interval (3 seconds) and the supervisor's
polling interval (1 second) are different numbers, and neither is
triggered by the other. Trace, in order, everything that has to happen
between the worker writing one new progress update and the browser
actually displaying it.**

A: (1) The worker calls `report(...)`, which atomically writes the new
stage/percentage to the progress file. (2) At some point within the next
second, the supervisor's `_await()` loop times out, reads the changed
file, and copies the new values onto the `Job` database row, committing
them. (3) At some point within the next three seconds, the browser's own
timer fires, calls `fetch()` against `job_status()`, which reads those
now-committed database values and returns them as JSON. (4) The browser's
JavaScript then updates the page's text and progress bar from that
response. Nothing here is instantaneous or directly triggered — each step
waits on its own independent timer, so the true worst-case delay between a
real change and it appearing on screen is roughly the sum of both
intervals, about 4 seconds.
