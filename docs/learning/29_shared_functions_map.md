# 29 — Shared Functions Map

This file exists to answer one question directly: **"I keep seeing the
same function name pop up while reading different parts of this
project — is it really the same function, and if so, why does it get
called from more than one place instead of each place having its own
copy?"** Every entry below was found by re-checking, across files 21–28,
every function that genuinely appears in more than one of those eight
call chains.

## Scoping decision, stated up front

This table covers functions **this project itself defines** — not calls
into Flask, SQLAlchemy, or any other library (`db.session.commit()`,
`render_template()`, and similar calls appear dozens of times across
every functionality file, but including them here would make this table
enormous and useless, since *every* Flask project calls those constantly;
they're not evidence of *this codebase's own* design choices the way the
functions below are).

## The main table: functions called from more than one functionality

| Function | File | What it does, in one sentence | Called from | Why sharing it makes sense |
|---|---|---|---|---|
| `log(action, ...)` | `app/audit.py` | Writes one row to the `audit_log` table describing a security-relevant event. | **22** (register, three points inside login, logout) · **23** (upload, confirm_type) · **26** (report download) — also by `export()`, a simpler route not given its own file (§20) | Every one of these events needs the identical set of fields recorded the identical way (who, what, when, from where). Writing this logic out separately in six-plus different places would mean six-plus chances for one of them to record it slightly differently — forgetting the IP address in one, forgetting to handle an anonymous user in another — and an audit trail with inconsistent gaps like that would be far less trustworthy. |
| `_owned(job_id)` | `app/routes.py` | Fetches a job and confirms it belongs to the signed-in analyst, or returns a 404 if not. | **23** (`confirm_type`) · **26** (`job_detail`, `report`) · **27** (`job_status`) — also by `export()` | This is the *entire* authorization rule for "can this analyst see this job" in the whole application. If every route that needed this check wrote its own version, a mistake in just one of them (say, forgetting the check entirely, or accidentally returning 403 instead of 404 and leaking which job IDs exist) would create a real security hole in exactly one route while the others stayed safe — a single shared function means the rule is enforced identically everywhere or not at all, and fixing a bug in it fixes it everywhere at once. |
| `jobs._findings(result, described, matched)` | `app/jobs.py` | Creates one `Finding` database row per described item, attaching whichever MITRE tag claimed that feature. | **24** (disk, once per flagged file) · **25** (memory, once per job) | Both pipelines end up with the same two ingredients at the end of their chain — a list of plain-English findings, and a list of matched MITRE tags — and need the identical logic to combine them into database rows. Disk and memory findings *look* different to an analyst, but the mechanical last step of "attach the right tag to the right finding and save it" is genuinely identical work either way. |
| `mitre.match(features, pipeline, values=None)` | `app/forensics/mitre.py` | Checks a set of feature names against the indicator-tag table and returns every match. | **24** (disk, once) · **25** (memory, twice — see the note in file 25 about `matched` vs. `standout`) | The matching *logic* — does this feature name, or feature group, appear in the table, are any required companion features also present, does an optional value-check pass — is identical regardless of which pipeline is asking. The `pipeline` argument is what keeps disk and memory tags from ever crossing into each other's results, without needing two separately-written, easily-diverging copies of the same matching logic. |
| `meanings.describe(feature)` | `app/forensics/meanings.py` | Turns one raw feature name into a plain-English label and explanation. | **24** (indirectly — every disk finding passes through this on its way out of `explain._top()`) · **25** (directly, for every observed feature, *and* indirectly through `explain._top()` for any LIME-sourced finding) | Every single finding shown anywhere in this whole application — no matter whether it came from a direct Volatility measurement or from a LIME explanation, no matter which pipeline — has to go through exactly this one translation step before an analyst ever sees it. One shared resolver is what guarantees a feature named `malfind.ninjections` always gets described the same way, everywhere it appears, rather than risking two different hand-written explanations existing in two different places. |
| `explain._top(explanation, names, limit)` | `app/explain.py` | Turns a raw LIME result into a clean list of findings, using `as_map()` and skipping non-positive weights (§11). | **24** (called from inside `disk_findings()`) · **25** (called from inside `memory_findings()`) | This is the one place the "never use `as_list()`, always resolve through `as_map()`" rule (§11) is actually implemented. If both pipelines' public functions (`disk_findings()`, `memory_findings()`) each reimplemented this resolution logic separately, that rule would have to be gotten right twice — and a future bug fix or safety improvement made to only one of the two copies would leave the other silently un-fixed. |
| `pool()` | `app/jobs.py` | Returns the shared, lazily-created extraction process pool, creating it on first use. | **24** (`_disk`) · **25** (`_memory`) | Both pipelines need the exact same kind of isolation (extraction in a separate process, §7), and there is deliberately only **one** such pool for the whole application, not two — running disk and memory extraction through two separate pools would let them compete for resources independently and defeat the deliberate `max_workers=1` decision to keep extraction serialized. |
| `_reporter(progress_file)` | `app/jobs.py` | Returns a small function that atomically writes stage/progress text to a file. | **24** (`extract_disk`) · **25** (`extract_memory`) — and central to the whole mechanism in **27** | Both extraction paths need to report progress back across the exact same kind of process boundary, using the exact same atomic-write safety trick (§27). Writing two separate progress-reporting mechanisms — one per pipeline — would double the chance of one of them getting the atomicity subtlety wrong. |
| `_await(job, future, progress_file)` | `app/jobs.py` | Blocks on an extraction result while copying live progress onto the job row once a second. | **24** (`_disk`) · **25** (`_memory`) — and central to **27** | Same reasoning as `pool()` and `_reporter()` above — both pipelines wait for their background work the identical way, and the clever "one timeout doing two jobs at once" trick (§27) only has to be written, and be correct, in one place. |
| `_progress_file(app, job_id)` | `app/jobs.py` | Computes the one, consistent path to a given job's progress file. | **24**, **25** (used when starting extraction) · **28** (used in `jobs.run()`'s `finally` block to delete it, and inside `recover_orphans()` to clean up an orphaned one) | The writer (`_reporter`, inside a worker), the reader (`_await`, in the supervisor), the cleanup-on-success-or-failure code, and the cleanup-on-crash-recovery code all have to agree on the *exact same* file path for a given job, every time, or they'd simply never find each other's file. One function computing that path is what guarantees they always agree. |
| `report.evidence_rows(job)` | `app/report.py` | Turns a job's stored evidence data into ready-to-render table sections. | **26** (both the web-page path and the PDF path — see below) | See the combined note with `limitations()` immediately below. |
| `report.limitations(job)` | `app/report.py` | Builds the full, structured "Scope and limitations" content for a job. | **26** (both the web-page path and the PDF path) | Both call sites happen to live inside the same functionality file (26), because viewing the page and downloading the PDF were grouped together precisely *because* they share this content — but they are two genuinely independent triggers (a page load, and a separate PDF download request, possibly minutes or days apart) reusing the identical function. This is the literal mechanism that makes it structurally impossible for the web page and the PDF to ever disclose different limitations for the same job (§12, §26) — there's only one place this content is ever computed, so there's nothing for the two to disagree about. |

## Functions reused *within* a single functionality — the same lesson, a smaller scale

The confusion in your original question doesn't only happen *across*
functionality files — it happens within one, too. A few worth noticing,
already covered where they occur:

- **`severity.for_disk()`** is called **twice** inside file 24's own
  per-file loop — once for every unflagged file (with an empty findings
  list) and once for every flagged file (with real matched tags). Same
  function, two different moments in the same loop, for two different
  files.
- **`mitre.match()`** is called **twice** inside file 25's single chain —
  once over everything observed, once over only the elevated subset — a
  single functionality reusing one function with two different inputs to
  produce two genuinely different results (§25).
- **`_kv(...)`** (a small table-building helper in `report.py`) is called
  roughly a dozen times throughout `report.render()` alone — for chain of
  custody, for verdict detail, and once per flagged file's locator block —
  purely because "build a two-column key/value table" is a formatting need
  that recurs many times within the one act of building a PDF.

## Functions that *look* shared but genuinely aren't — a deliberate trap to watch for

These pairs have matching or near-matching names and do analogous jobs,
which can make them look like one shared function when reading quickly —
but they are **two separate function definitions**, living in two
separate places, each used by exactly one pipeline:

- **`inference/disk.py:predict()`** and **`inference/memory.py:predict()`**
  — two different functions, in two different files, each wrapping a
  different underlying model library (LightGBM versus XGBoost, §8). File
  24 only ever calls the disk one; file 25 only ever calls the memory one.
  They were **deliberately never merged** into one shared function — §8
  explains this directly: "XGBoost and LightGBM disagree on how to load,
  how to predict and what a feature name is, and papering over that is
  how the two get swapped."
- **`explain.py:disk_findings()`** and **`explain.py:memory_findings()`**
  — two separate public functions (though, as the main table above shows,
  they *do* both call the one genuinely shared `_top()` underneath).
- **`severity.py:for_disk()`** and **`severity.py:for_memory()`** — two
  functions with deliberately *different scoring logic* (§11 calls this
  out explicitly: verdict-led versus evidence-led), not two copies of the
  same logic.
- **`jobs.py:extract_disk()`**/**`jobs.py:_disk()`** and
  **`jobs.py:extract_memory()`**/**`jobs.py:_memory()`** — four separate
  functions, one pair per pipeline, each pair handling that one pipeline's
  own extraction and scoring shape.

Recognising this pattern matters exactly as much as recognising real
sharing: seeing two similarly-named functions and *assuming* they're the
same one being called twice is exactly the kind of misreading this whole
second curriculum was written to prevent.

## What "reusable" actually means, in plain terms

A function is **reusable** when it's written once, in one place, and
different parts of a program call that one copy instead of each part
containing its own separately-written version of the same logic. Think of
it like a single, shared house key made for a lock, versus every family
member cutting their own separate key by eye — the shared key is
guaranteed to open the same lock the same way every time; separately-cut
keys might all *mostly* work, until one of them doesn't, in a way that's
hard to predict in advance.

**Why this is considered good practice, concretely, using this project's
own real examples:**

- **One place to fix a bug.** If `_owned()`'s ownership check had a flaw,
  fixing it once fixes it for every one of the five-plus routes that call
  it. If each route had its own separately-written copy of that check, the
  same flaw could easily be fixed in four of them and missed in the fifth
  — and that fifth one would quietly stay a security hole.
- **One place to change behaviour.** When this project's limitations
  wording needed to change (an earlier, real decision recorded in the
  first curriculum's file 12), it only had to change inside
  `report.limitations()` — both the PDF and the web page picked up the
  new wording automatically, because both call that one function, rather
  than needing the same edit made correctly in two separate places.
- **Less code, and less code that can silently drift apart.** Two
  independently-written implementations of "wait for a background result
  while polling a progress file" would very likely start out identical and
  then slowly diverge over time as one gets a bug fix or a tweak the other
  doesn't — `_await()` being the one and only version used by both
  pipelines makes that kind of silent drift structurally impossible.

**How to recognise, while reading code, whether you're looking at a
shared function or a one-off:**

1. **Check where it's defined.** A function defined inside a specific
   route function, or as a small nested `def` only used immediately below
   it (like `jobs.py`'s `stage()` function inside `extract_memory()`), is
   almost always a one-off, written for exactly one purpose in exactly one
   place.
2. **Search for its name across the rest of the codebase.** This is the
   single most reliable check, and it's exactly the process that built
   this file — every function in the table above was confirmed shared by
   finding it called from more than one of the eight functionality chains,
   not by guessing from its name or its location.
3. **Read its parameters.** A genuinely shared function's inputs tend to
   be *general* — `mitre.match(features, pipeline, values=None)` takes a
   `pipeline` argument specifically *because* it's meant to serve two
   different callers with two different needs. A one-off function's
   parameters tend to be very specific to the one situation it was written
   for.
4. **Watch for a name that describes an action, not a specific scenario.**
   `_owned()`, `log()`, `_await()` describe a general action reusable in
   many contexts. `_disk()`/`_memory()` describe a specific scenario each
   — and, true to that naming, each is called from exactly one place (file
   24 or file 25's own trigger inside `jobs.run()`).

If you take one thing from this whole file: seeing a function name appear
more than once while reading through files 21–28 is not a sign you
misread something or that the same code was pasted in twice — it's a
deliberate, load-bearing design choice, and the table above is the
complete, verified list of every place it happens.
