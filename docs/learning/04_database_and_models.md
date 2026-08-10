# 04 — The Database: `app/db.py`, `app/models.py`, and `migrations/`

## What a database is, in the simplest possible terms

Think of a database as a **structured filing cabinet**, not a spreadsheet.
A spreadsheet is one big flat grid — great for a single list of things, bad
the moment those things relate to each other in more than one way. This
project needs to remember: which user uploaded which job, which job
produced which results, which result triggered which findings, and a
running log of every security-relevant action anyone took. Those are four
different *kinds* of thing, each with its own set of properties, connected
to each other by explicit links (a result *belongs to* a specific job; a
finding *belongs to* a specific result). A filing cabinet with labelled
drawers — one drawer per kind of thing, with index cards inside each drawer
that reference cards in other drawers by their ID number — is a much closer
mental model than "one big spreadsheet," and that's exactly what a
**relational database** (which is what this project uses) is: a collection
of **tables** (the drawers), each holding **rows** (the index cards), where
rows in one table can point at rows in another via a shared ID.

This project uses **SQLite** in development (a whole database stored as one
ordinary file on disk, `instance/app.db`, needing no separate server
process — see file 03) and is designed to also work against **PostgreSQL**
(a "real" database server) in a production deployment, without changing a
single line of application code, because of the next concept.

## What an ORM is, and why not just write SQL by hand

**SQL** (Structured Query Language) is the standard language for talking
directly to a relational database — `SELECT * FROM jobs WHERE user_id = 3`
is a SQL query. You absolutely *could* write every database interaction in
this project as hand-built SQL strings. Two serious problems with doing
that everywhere:

1. **Security.** Building a SQL string by directly inserting values a user
   typed (like a username) is exactly how SQL-injection vulnerabilities
   happen — a malicious value can be crafted to change the *meaning* of the
   query rather than just supplying data to it. It's avoidable with care,
   but it's a sharp edge you'd have to get right in every single place you
   touch the database.
2. **Repetition and portability.** Describing "a job has many results" in
   SQL means writing `JOIN` clauses by hand every time you want that data,
   and SQLite and PostgreSQL don't speak identical SQL dialects, so code
   written for one wouldn't automatically work against the other.

An **ORM** (Object-Relational Mapper — see the glossary in file 00) solves
both: you describe each table once, as a Python class, and the ORM
generates safe, correctly-escaped SQL underneath every time you write
ordinary Python code like `db.session.add(job)` or `job.results`. This
project's ORM is **SQLAlchemy**, wired into Flask by **Flask-SQLAlchemy**
(file 01 covers both as libraries).

## `app/db.py` — creating the shared database object

```python
import sqlite3

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()
```

`db = SQLAlchemy()` creates the extension object *before* any Flask app
exists — the same create-then-attach pattern file 01 introduced for every
Flask extension in this project. Every other file that needs the database
imports this exact same `db` object (`from .db import db`), so there is
only ever one database connection manager for the whole app, no matter how
many files reference it.

```python
@event.listens_for(Engine, "connect")
def _sqlite_pragmas(conn, _rec):
    if isinstance(conn, sqlite3.Connection):
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
```

This is the one piece of genuinely non-obvious code in this small file, and
the comment above it in the real source explains exactly why it exists:
extraction jobs run for 15–45 minutes, during which the background worker
holds the database open. SQLite's *default* mode has a single writer block
every reader for however long that writer holds the database — which, with
a 45-minute job in progress, would make the web server itself start
throwing "database is locked" errors on completely unrelated requests.

- `@event.listens_for(Engine, "connect")` is a **decorator** (see glossary,
  file 00) from SQLAlchemy itself: it registers the function right below it
  to run automatically every single time a brand-new low-level database
  connection is opened — not once at startup, but on every connection,
  because SQLite settings like this are per-connection, not saved
  permanently in the database file.
- `isinstance(conn, sqlite3.Connection)` checks that the connection is
  really a SQLite one (this same event fires for any database engine
  SQLAlchemy might be managing) — these three settings are SQLite-specific
  and would be meaningless, or an error, against PostgreSQL.
- `PRAGMA journal_mode=WAL` switches SQLite into **Write-Ahead Logging**
  mode, where writes go to a separate log file first and readers can keep
  reading the main database file undisturbed — this is what actually fixes
  the "long-running job blocks everything else" problem described above.
- `PRAGMA busy_timeout=30000` tells SQLite, when a brief lock conflict *does*
  still occur, to automatically retry for up to 30,000 milliseconds (30
  seconds) before giving up and raising an error, rather than failing
  instantly the first time two operations happen to overlap by a fraction of
  a second.
- `PRAGMA foreign_keys=ON` — SQLite, unusually, does not enforce foreign-key
  constraints (the "a result must point at a real job" kind of rule) unless
  explicitly told to for every connection. Without this line, deleting a job
  wouldn't automatically clean up its results and findings the way the
  model relationships expect (see `ondelete="CASCADE"` below).

## `app/models.py` — every table, and what it represents

### The constants at the top

```python
NEEDS_TYPE, PENDING, RUNNING, COMPLETED, FAILED = (
    "NEEDS_TYPE", "PENDING", "RUNNING", "COMPLETED", "FAILED")
DISK, MEMORY = "disk", "memory"

LOW, MEDIUM, HIGH, CRITICAL = "Low", "Medium", "High", "Critical"
SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1}
```

These aren't database concepts at all — they're plain Python string
constants, defined once here and imported everywhere else that needs to
compare a job's status or a result's severity (`if job.status == RUNNING:`
instead of the error-prone `if job.status == "RUNNING":` sprinkled
everywhere, where a typo like `"Running"` would silently never match).
`SEVERITY_ORDER` is a **dictionary** mapping each severity name to a number,
which is what lets other code sort or compare severities meaningfully
(`Critical` outranks `Low`) even though the underlying stored value is just
text.

`NEEDS_TYPE` deserves its own note, because the comment directly above it in
the real file explains something that could otherwise look like a bug: it's
the status a job lands in when the system genuinely cannot tell from a
`.raw` file's contents whether it's a disk image or a memory dump — and
that's a *normal*, expected outcome, not an error, because a raw memory
dump carries no identifying header at all (file 06's upload-detection logic
covers this fully).

### `User` — one row per analyst account

```python
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255))
    pw_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    jobs = db.relationship("Job", back_populates="user")

    def set_password(self, pw):
        self.pw_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.pw_hash, pw)
```

Represents one signed-up analyst. `class User(UserMixin, db.Model)` inherits
from **two** classes at once — `db.Model` is what makes it a real database
table, and `UserMixin` (from Flask-Login, file 01) supplies the handful of
methods/properties Flask-Login expects every user object to have
(`is_authenticated`, `get_id()`, etc.) without writing them by hand.

Column by column:
- `id` — the **primary key**: a unique whole number automatically assigned
  to every row, which is how every other table refers back to a specific
  user.
- `username` — `unique=True` means the database itself refuses to ever
  store two rows with the same username; `nullable=False` means this
  column can never be left empty; `index=True` builds a fast lookup
  structure on this column, because looking up a user by username (at
  login) is a very common operation and would otherwise require scanning
  every single row.
- `email` — no `nullable=False`, so it's genuinely optional (`forms.py`
  agrees — see file 06).
- `pw_hash` — the **hashed** password (file 01's Werkzeug section), never
  the plain password itself. There is no column anywhere in this schema
  that stores a plain-text password, by design.
- `is_active` — `default=True` means new rows automatically get `True`
  unless told otherwise; lets an administrator disable an account without
  deleting it.
- `created_at` — `default=utcnow` (a plain Python function defined just
  above, returning the current UTC time) is called automatically the
  moment a row is created, so nobody has to remember to set it manually.

`jobs = db.relationship("Job", back_populates="user")` is not a real
database column at all — it's a piece of SQLAlchemy convenience that lets
you write `some_user.jobs` in Python and get back the list of every `Job`
row whose `user_id` points at this user, computed on demand. `back_populates`
tells SQLAlchemy that `Job` has a matching `user` relationship pointing the
other way (see below), so the two stay in sync automatically.

`set_password`/`check_password` are ordinary Python **methods** (functions
defined inside a class, automatically given access to that specific
object's own data via `self`) that wrap the two Werkzeug functions from
file 01 — nowhere else in the codebase calls `generate_password_hash`
directly, which keeps the hashing logic in exactly one place.

### `Job` — one row per uploaded artifact and its analysis

This is the largest, busiest table in the project, and its columns map
directly onto the full lifecycle a job goes through (file 07 walks that
lifecycle in depth; here the focus is what each column *stores* and *why it
exists at all*).

```python
class Job(db.Model):
    __tablename__ = "jobs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    filename = db.Column(db.String(512), nullable=False)
    stored_name = db.Column(db.String(128), unique=True, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    size_bytes = db.Column(db.BigInteger, nullable=False)
    artifact = db.Column(db.String(8))
    detected_as = db.Column(db.String(32))
```

- `user_id` — a **foreign key** (`db.ForeignKey("users.id")`): this column's
  value must always match a real row's `id` in the `users` table. This is
  the actual database-level link the `db.relationship` calls above build
  their convenience on top of.
- `filename` — the name the analyst's browser reported for the uploaded
  file. Purely descriptive; **never** used to decide where the file is
  stored on disk (see `stored_name` next) or what type of artifact it is
  (that's `artifacts.sniff()`, covered in file 06) — a hostile or careless
  filename must never be trusted for anything security- or logic-relevant.
- `stored_name` — the actual filename on disk inside `uploads/`, generated
  by the application itself (a random UUID, see file 06), `unique=True` so
  two uploads can never collide.
- `sha256` — the SHA-256 hash (file 01's hashlib usage) of the uploaded
  bytes, computed once during upload and never recomputed — this is the
  forensic fingerprint printed in every report's chain-of-custody section.
- `size_bytes` — `db.BigInteger` rather than the plain `db.Integer` used
  elsewhere, because a multi-gigabyte memory dump's size in bytes can
  exceed what a regular 32-bit integer column can hold.
- `artifact` — `"disk"` or `"memory"`, or genuinely `None`/empty while a
  job sits in the `NEEDS_TYPE` state. The comment in the real file is
  explicit: this column is nullable *specifically and only* to represent
  that inconclusive-detection state, not as a general "might be unset"
  escape hatch.
- `detected_as` — a short human-readable explanation of *how* the type was
  decided (e.g. `"MBR boot signature 0x55AA at offset 510"` or `"confirmed
  by analyst after inconclusive detection"`) — shown in the chain-of-custody
  section so the decision is auditable, not just the conclusion.

```python
    status = db.Column(db.String(16), default=PENDING, nullable=False, index=True)
    error = db.Column(db.Text)

    stage = db.Column(db.String(80))
    progress_pct = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
```

- `status` — one of the five constants from the top of the file, `indexed`
  because "show me all jobs still running" or "find jobs stuck RUNNING
  after a crash" (file 07's orphan recovery) are real, frequent queries.
- `error` — `db.Text` rather than a length-limited `db.String`, because a
  Python exception's full message could in principle be long; only
  populated when `status == FAILED`.
- `stage` / `progress_pct` — live progress text and a percentage, updated
  *while* a job is `RUNNING` (e.g. `"Running windows.malfind (5 of 9)"`,
  `45`). The comment above them in the real file explains the mechanism
  precisely: extraction reports this from *inside* a separate worker
  process, and the supervisor copies it here so the web page has something
  concrete to show for the several minutes a real artifact takes — file 07
  covers the actual cross-process mechanism in full. `progress_pct` being
  `None` specifically means "working, but the total amount of work isn't
  known yet" (e.g. the disk pipeline doesn't know how many PE files it will
  find until the filesystem walk finishes).
- `created_at` / `started_at` / `finished_at` — three separate timestamps
  rather than one, because "when was this uploaded," "when did processing
  actually begin," and "when did it finish" are three genuinely different
  moments, and the gap between the first two is meaningful (a job can sit
  queued if the worker pool is busy).

```python
    files_scanned = db.Column(db.Integer)
    files_flagged = db.Column(db.Integer)
    skipped = db.Column(db.JSON)
```

Disk-pipeline-specific counters and a **JSON column** — a column that
stores an arbitrary structured value (here, a Python list of small
dictionaries like `{"path": ..., "reason": ...}`) serialized as JSON text
inside the database, rather than needing its own separate table. The
comment explains exactly why `skipped` exists as a list rather than just a
count: an analyst has to be able to tell "scanned and clean" apart from
"never examined," and a bare number can't distinguish those two very
different situations.

```python
    extraction_gaps = db.Column(db.JSON)
    ood_count = db.Column(db.Integer)
    ood_fields = db.Column(db.JSON)
    plugin_seconds = db.Column(db.JSON)
    evidence = db.Column(db.JSON)
    volumetric = db.Column(db.JSON)
```

Six more JSON columns, all **memory-pipeline-only** (the comment says so
directly), each one added by its own dedicated migration as the project's
needs grew (see the migrations table below) — a concrete illustration of
why migrations exist at all:
- `extraction_gaps` — which of the 55 features were missing or had an
  inferred (not certain) derivation, and why (file 10).
- `ood_count` / `ood_fields` — how many of the 55 features, and which
  ones, fall outside the range the model was trained on (file 08, hard
  rule 17).
- `plugin_seconds` — how long each of the nine Volatility 3 plugins took,
  kept specifically because total runtime has been observed to vary
  roughly 2× between runs on identical input, and this is the data that
  might eventually explain why.
- `evidence` — the actual per-process locators (PIDs, addresses, module
  paths) behind the indicators, so a memory report is investigable rather
  than just a set of bare counts (file 10, file 11).
- `volumetric` — configuration counts (like "how many services are
  registered") reported as context, structurally separate from anything
  that can affect severity (file 11).

```python
    user = db.relationship("User", back_populates="jobs")
    results = db.relationship("Result", back_populates="job",
                              cascade="all, delete-orphan", passive_deletes=True)

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def done(self):
        return self.status in (COMPLETED, FAILED)
```

`results` is the reverse of `User.jobs` — `some_job.results` gives every
`Result` row belonging to this job. `cascade="all, delete-orphan"` tells
SQLAlchemy: if this job is deleted, delete all of its results too, rather
than leaving orphaned rows pointing at a job that no longer exists.
`passive_deletes=True` tells SQLAlchemy to let the *database itself* handle
that cascading delete (via the `ondelete="CASCADE"` set on `Result.job_id`,
below) rather than SQLAlchemy loading every result into memory first just
to delete them one by one — faster and simpler for a case this
straightforward.

`@property` is a Python decorator that lets you write `job.duration` (no
parentheses, as if it were a plain stored value) even though it's actually
computed fresh every time from two other columns. `duration` returns `None`
rather than crashing or returning `0` when either timestamp is missing —
an important, deliberate choice: a `None` result is treated everywhere
downstream as "not known," never as "took zero seconds," which would be a
misleading answer for a job that's still running or never started.
`done` is a simple convenience so template code (file 13) and route code
don't have to repeat `status in (COMPLETED, FAILED)` everywhere it matters.

### `Result` — one verdict, for one file (disk) or one whole dump (memory)

```python
class Result(db.Model):
    __tablename__ = "results"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id", ondelete="CASCADE"),
                       nullable=False, index=True)

    probability = db.Column(db.Float, nullable=False)
    threshold = db.Column(db.Float, nullable=False)
    malicious = db.Column(db.Boolean, nullable=False)
    severity = db.Column(db.String(16))
    severity_note = db.Column(db.String(255))
```

This table's shape reflects a real, deliberate design decision recorded
throughout CLAUDE.md: **a disk image can contain hundreds of executables**,
so a disk job produces *one `Result` row per flagged-or-not file*, while a
memory job — where the unit of analysis is the whole dump, not an
individual file — produces exactly **one** `Result` row. The columns below
`severity_note` (next) are what make this table able to represent both
shapes without two separate tables.

`ondelete="CASCADE"` here is the database-level half of the cascade
described above — it's what actually lets `passive_deletes=True` on `Job`
work without SQLAlchemy doing the deletion in application code.

`threshold` is stored on every single row, not looked up fresh each time
from the model — the comment explains why directly: the two pipelines'
operating thresholds are two very specific, non-obvious numbers
(`0.2336726188659668` and `0.5010602922493019` — see file 08), and a report
has to be able to show the exact one that was actually applied to *this*
result, even if a future code change ever altered the live threshold.

```python
    path = db.Column(db.Text)
    partition = db.Column(db.String(64))
    inode = db.Column(db.String(64))
    file_sha256 = db.Column(db.String(64), index=True)
    file_md5 = db.Column(db.String(32))
    file_size = db.Column(db.BigInteger)
    allocated = db.Column(db.Boolean)
    data_offset = db.Column(db.BigInteger)
    mtime = db.Column(db.DateTime)
    atime = db.Column(db.DateTime)
    ctime = db.Column(db.DateTime)
    btime = db.Column(db.DateTime)
```

Every one of these is **disk-only**, and every one is `null` on the single
memory row — the comment states this plainly, and also states the rule
behind why every one of them exists at all: hard rule 16, "no flagged file
ships without path and file_sha256." An analyst reading a report has to be
able to go find the exact file being talked about — `path` is where it
lives inside the image, `file_sha256`/`file_md5` are pivots for threat-intel
lookups, `inode` lets a tool like Autopsy jump straight to the filesystem
record, `data_offset` (nullable, because resident NTFS files have none —
file 09) enables direct byte-level carving, and the four MACB timestamps
(**M**odified/**A**ccessed/**C**hanged/**B**orn — standard forensic
terminology) support timeline reconstruction.

```python
    job = db.relationship("Job", back_populates="results")
    findings = db.relationship("Finding", back_populates="result",
                               cascade="all, delete-orphan", passive_deletes=True)

    @property
    def rank(self):
        return SEVERITY_ORDER.get(self.severity, 0), self.probability
```

Same relationship/cascade pattern as before, one level down. `rank` returns
a **tuple** (a small fixed-size ordered group of values, here two numbers)
specifically so results can be sorted "most severe first, and among equally
severe results, most probable first" in one comparison — Python compares
tuples element by element automatically, so sorting by this one property
does both at once.

### `Finding` — one matched indicator, belonging to one result

```python
class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey("results.id", ondelete="CASCADE"),
                          nullable=False, index=True)

    feature = db.Column(db.String(128), nullable=False)
    weight = db.Column(db.Float)
    rank = db.Column(db.Integer)

    meaning = db.Column(db.Text)
    tag = db.Column(db.String(64))
    mitre_id = db.Column(db.String(16))
    mitre_name = db.Column(db.String(128))
    confidence = db.Column(db.String(16))
```

One `Result` can have *many* `Finding` rows — every distinct forensic
indicator identified for that result gets its own row. `feature` is the raw
technical name (e.g. `"malfind.ninjections"`); `weight` is the LIME
contribution (kept for the report's appendix, but the comment is explicit
that it's **never shown raw** to the analyst directly — CLAUDE.md's rule
about not exposing raw LIME weights); `meaning` is the plain-English
explanation from `forensics/meanings.py` (file 11); `tag`/`mitre_id`/
`mitre_name`/`confidence` are what `forensics/mitre.py`'s matcher produced
for this feature, if anything matched at all (they're all nullable — a
finding can exist with a plain-English explanation but no MITRE
attribution).

```python
    result = db.relationship("Result", back_populates="findings")

    @property
    def mitre_url(self):
        if not self.mitre_id:
            return None
        return "https://attack.mitre.org/techniques/{}/".format(
            self.mitre_id.replace(".", "/"))
```

`mitre_url` is another computed `@property` — rather than storing a full
URL in the database (which would need updating everywhere if MITRE ever
changed their URL scheme), it's built fresh from `mitre_id` every time it's
needed, returning `None` cleanly when there's no MITRE ID to build a URL
from. `.replace(".", "/")` handles sub-technique IDs like `T1055.001`,
which MITRE's own URLs represent as `T1055/001` rather than with a literal
dot.

### `AuditLog` — a running record of who did what

```python
class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), index=True)

    action = db.Column(db.String(32), nullable=False)
    detail = db.Column(db.Text)
    ip = db.Column(db.String(45))
    at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
```

Note that `user_id` here has **no** `nullable=False` — unlike everywhere
else a foreign key appears in this schema, it's explicitly allowed to be
empty, and the comment says exactly why: some audited events (like a
*rejected* login attempt, where nobody was ever actually authenticated as
anybody) have no real, known user to attach to. `ip` is sized `45`
characters specifically because that's long enough to hold the longest
possible IPv6 address in its text form, not just the shorter, more familiar
IPv4 form. This table is written to by the single small `audit()` function
covered in file 06, called from every security-relevant action across the
whole app (login, logout, upload, report download, etc.).

## Migrations: how the schema actually changed over time, and what running one does

A migration is a small Python script, generated (mostly automatically) and
then run by Flask-Migrate/Alembic, that describes exactly how to change the
database's *structure* — not its data — from one known version to the next.
Each one has a unique ID and knows which migration came directly before it,
forming a chain. Running `flask db upgrade` walks that chain forward from
wherever the database currently is to the newest migration; a matching
`downgrade()` function in each file exists to walk the chain *backward* if
ever needed.

This project's migration history, in the order they were actually applied
(you can verify this order by following each file's `down_revision` value
back to `None`):

1. **`01e40b72559d` — "users, jobs, results, findings, audit_log"** — the
   very first migration, `down_revision = None` (nothing came before it).
   Its `upgrade()` function calls `op.create_table(...)` five times, once
   per table, listing every column exactly as `models.py` originally
   defined them, plus `op.create_index(...)` calls for every `index=True`
   column. Its `downgrade()` does the exact reverse in the opposite order —
   drop indexes, then drop tables, working from the most-dependent table
   (`findings`, which depends on `results`) back to the least (`users`,
   which nothing else in this migration depends on).
2. **`eb17c935e9af` — "artifact type nullable pending analyst confirmation"**
   — adds the `detected_as` column and changes `jobs.artifact` from
   required to optional, via `batch_op.alter_column(...)`. This is exactly
   the change that made the `NEEDS_TYPE` status representable at all — before
   this migration, every job had to be assigned a type immediately.
3. **`6c6e0759a49e` — "job progress stage"** — adds `stage` and
   `progress_pct`, enabling the live in-progress display covered in file 07.
4. **`fda781d38f87` — "per-plugin timings"** — adds `plugin_seconds`.
5. **`a2aab2930966` — "per-process memory evidence"** — adds `evidence`.
6. **`249a2a3baaa5` — "volumetric context"** — adds `volumetric`, the most
   recent migration.

Notice the `with op.batch_alter_table("jobs", schema=None) as batch_op:`
pattern used in every migration after the first. SQLite (unlike PostgreSQL)
can't `ALTER TABLE ... ADD COLUMN` quite as flexibly as some other
databases in every case, so Alembic's "batch" mode handles it safely by, if
necessary, creating a new table with the right structure, copying the data
across, and swapping it in — all inside one operation you never have to
think about directly.

## Check your understanding

**Q1. Why does `Job.artifact` allow `null`, when almost every other
required-looking column in this schema has `nullable=False`?**

A: Because a job can genuinely and correctly sit in the `NEEDS_TYPE` state,
where the system has examined the uploaded bytes and honestly cannot tell
whether it's a disk image or a memory dump — a raw memory dump has no
identifying header at all. `artifact` being `null` represents that real,
expected situation, not a bug or an oversight.

**Q2. `Result` has twelve columns (`path` through `btime`) that are always
`null` on a memory job's single result row. Why weren't disk-only and
memory-only results split into two separate tables?**

A: One table lets the rest of the codebase (queries, sorting by severity,
the report renderer) treat "a job's results" uniformly regardless of
pipeline, without needing two parallel code paths everywhere a result is
touched. The cost — a dozen always-null columns on memory rows — is small
and explicit, versus the larger cost of duplicating logic across two tables
that are conceptually "the same kind of thing" (a verdict with a
probability and a severity) in every way that matters to the rest of the
app.

**Q3. What does `cascade="all, delete-orphan"` combined with
`passive_deletes=True` and the database's own `ondelete="CASCADE"`
accomplish together, and why do both the Python side and the database side
need to agree?**

A: Together they mean: deleting a `Job` row automatically and correctly
deletes every `Result` row that belonged to it, and deleting each of those
automatically deletes every `Finding` row that belonged to *them* — no
orphaned rows left pointing at nothing. `passive_deletes=True` tells
SQLAlchemy not to bother loading and individually deleting those child rows
itself, and instead trust the database's own `ondelete="CASCADE"` foreign
key rule to do it directly and efficiently — but that only works because
`app/db.py` explicitly turns on `PRAGMA foreign_keys=ON` for every SQLite
connection; without that pragma, SQLite would silently ignore the
`ondelete="CASCADE"` rule entirely.

**Q4. Why is `AuditLog.user_id` nullable, while `Job.user_id` is not?**

A: Every `Job` genuinely always belongs to exactly one signed-in analyst who
uploaded it — there's no valid state where a job exists with no owner. But
`AuditLog` records events that can happen *before* or *without* successful
authentication (like a failed login attempt for a username that turns out
not to exist), where there is no real user row to attach the event to —
forcing `user_id` to always be set would make it impossible to honestly log
those events at all.

**Q5. If you wanted to add a new column to the `jobs` table today (say,
tracking which physical machine ran the extraction), what are the exact
steps, based on what this file describes?**

A: Add the new `db.Column(...)` line to the `Job` class in `models.py`,
then run `flask db migrate -m "add extraction host to jobs"` to have
Alembic auto-generate a new migration file describing that one change (it
compares your updated model against the current database structure), then
run `flask db upgrade` to actually apply it. The new migration file would
set its `down_revision` to `249a2a3baaa5` (today's most recent migration),
becoming the seventh link in the chain.
