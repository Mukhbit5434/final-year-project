# 03 — Configuration: `app/config.py`

## What "configuration" means, and why it's a separate file

Almost every real program needs a handful of values that change depending on
*where* it's running — a database location on your laptop is different from
one on a server; how large an upload you'll accept in testing is different
from production; a secret key used to protect cookies must never be the same
predictable value in every deployment. **Configuration** is the practice of
pulling all of those environment-specific values out into one place, instead
of writing them directly into the logic that uses them.

**Why hardcoding settings directly in code is a bad idea**, concretely:

- If the database path is typed literally inside twelve different functions,
  changing it means finding and editing all twelve, and missing one causes a
  silent, confusing bug.
- A value that should differ between "running the tests" and "running for
  real" (like whether to load the multi-hundred-megabyte ML models) has
  nowhere to plug that difference in if it's baked into the function body.
- Secrets (a `SECRET_KEY` used to cryptographically sign session cookies)
  should never be committed to source control as a hardcoded literal that
  anyone who reads the code can see and reuse.

This project solves it the standard Flask way: one Python file,
`app/config.py`, holding a `Config` class whose attributes *are* the
settings, plus a `TestConfig` subclass that overrides just the handful of
values the test suite needs to differ. Every other file in the app reads
settings through `current_app.config["SOME_KEY"]` (inside a request) or a
`config` object passed as an argument (outside one) — never by hardcoding a
value directly.

## Reading `app/config.py` from the top

```python
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
```

- `import os` brings in Python's standard operating-system interface module —
  used here specifically for `os.environ`, which is how a running program
  reads **environment variables** (values set outside the program, in the
  shell or the deployment system, before the program starts — the standard
  way to hand a program secrets or per-machine settings without writing them
  into a file at all).
- `Path(__file__)` — `__file__` is a special variable Python fills in
  automatically with the path to the current source file
  (`app/config.py`). `.resolve()` turns it into a full, unambiguous absolute
  path. `.parent.parent` walks up two directory levels: from
  `app/config.py` to `app/`, then to the project root. `ROOT` therefore
  always points at the top of the repository, computed correctly no matter
  which directory the program happens to be *started from* — a common
  source of bugs if you instead assumed the "current directory" was always
  the project root.

```python
def _gb(name, default):
    return int(os.environ.get(name, default)) * 1024 ** 3
```

A tiny helper function. `os.environ.get(name, default)` reads an environment
variable by name, and if it isn't set at all, falls back to `default`
instead of crashing. `1024 ** 3` is `1024` raised to the third power —
1,073,741,824, the number of bytes in one gibibyte. So `_gb("MAX_UPLOAD_GB",
32)` means "read the `MAX_UPLOAD_GB` environment variable as a number of
gigabytes (default 32 if it isn't set), and give me back that many bytes" —
because the actual setting that matters downstream (`MAX_CONTENT_LENGTH`) is
measured in raw bytes, but nobody wants to type `34359738368` by hand.

### The `Config` class, setting by setting

```python
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-not-for-deployment")
```
The key Flask uses to cryptographically sign session cookies and CSRF
tokens, so a browser can't be tricked with a forged one. Read from the
environment in a real deployment; falls back to an obviously-fake
placeholder value for local development, whose name is a permanent reminder
never to actually deploy with it.

```python
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{(ROOT / 'instance' / 'app.db').as_posix()}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```
Where the database actually lives. By default, a SQLite file at
`instance/app.db` under the project root (`.as_posix()` converts the path to
forward-slash form, which the database URL format expects even on Windows).
In a real deployment, `DATABASE_URL` can be set to point at a real
PostgreSQL server instead — the rest of the app never has to know or care
which one it's talking to, because SQLAlchemy abstracts over that (file 04
covers this). `SQLALCHEMY_TRACK_MODIFICATIONS = False` turns off a
Flask-SQLAlchemy feature this project never uses (it tracks every object
change for an optional signalling system) purely to silence its startup
warning and avoid its small performance cost.

```python
    UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", ROOT / "uploads"))
    MAX_CONTENT_LENGTH = _gb("MAX_UPLOAD_GB", 32)
    ALLOWED_EXT = {".dd", ".raw", ".img", ".e01", ".ex01", ".mem", ".dmp", ".vmem"}
```
Where uploaded artifacts are stored on disk — deliberately outside
`app/static/` or anywhere else the web server would ever serve files
directly from (covered in file 07 and again in the security section of file
06). `MAX_CONTENT_LENGTH` is a setting Flask itself understands natively — it
rejects any request whose body exceeds this many bytes before your route
code even runs, which is what produces the HTTP 413 error handled in
`app/__init__.py`. `ALLOWED_EXT` is a Python **set** (an unordered
collection with no duplicates, here used purely for fast "is this extension
in the allowed list?" checks) of every file extension the upload route will
accept — checked in `routes.py:upload()` before anything else happens to an
uploaded file.

```python
    MODELS_DIR = ROOT / "models"
    REFERENCE_DIR = ROOT / "reference_data"
    BASELINE_FILE = Path(os.environ.get(
        "BASELINE_FILE", ROOT / "baselines" / "clean_win10_x64.json"))
```
Three fixed locations the inference and forensics layers read from at
startup: the trained model files, the reference training-data samples (used
for LIME and the out-of-distribution check), and the clean-machine baseline
used for memory severity scoring. `Path / "string"` is Python's
`pathlib`-style way of joining a path segment onto an existing `Path`
object — equivalent to, but safer and more portable than, manually
concatenating strings with slashes.

```python
    MAX_PE_FILES = int(os.environ.get("MAX_PE_FILES", 500))
    MAX_PE_BYTES = int(os.environ.get("MAX_PE_MB", 64)) * 1024 ** 2
```
Practical caps for the disk pipeline, explained directly in the comment
above them in the real file: a 200 GB image could otherwise contain tens of
thousands of executables, which would make one job sit in the queue for a
day. `MAX_PE_FILES` stops after finding this many PE files; `MAX_PE_BYTES`
skips vectorizing any single file bigger than this (measured in MB,
converted to bytes the same way as the upload limit). Files skipped for
either reason are recorded, not silently dropped — the report states what
was skipped and why (file 09, file 12).

```python
    UPLOAD_RATE_LIMIT = os.environ.get("UPLOAD_RATE_LIMIT", "60 per hour")
```
Read as a plain string in Flask-Limiter's own syntax. The comment in the
real file explains *why* this is a configuration value rather than a
hardcoded number: a real capture session might upload five clean dumps, one
malicious one, a disk image, and a few retries in one sitting, and an
earlier hardcoded limit of 10 stopped that workflow halfway through.
Because it's read fresh from config on every request (`routes.py` passes a
`lambda` — a small anonymous function — into the rate-limit decorator rather
than a fixed value), it can be raised for a capture session by changing the
environment, with no code change and no restart-losing-state concern.

```python
    EXECUTOR_TYPE = "thread"
    EXECUTOR_MAX_WORKERS = int(os.environ.get("JOB_WORKERS", 2))
    EXECUTOR_PROPAGATE_EXCEPTIONS = False
```
Settings Flask-Executor itself reads. Note the comment's precision: this is
the **supervisor** pool only — the thread pool that manages job dispatch and
status polling. It is *not* where extraction's actual CPU-heavy or
crash-risky work happens; that goes to a completely separate process pool
(file 07 explains the full reasoning). `EXECUTOR_PROPAGATE_EXCEPTIONS =
False` stops an exception inside a background task from being silently
swallowed in a way that would hide it from the logs — the job's own
try/except in `jobs.run()` is what actually handles failures cleanly.

```python
    LOAD_MODELS = True
    RECOVER_ORPHANS = True
```
Two simple on/off switches read once, at startup, by `create_app()`. Their
entire purpose is to let `TestConfig` turn them off (below) — loading two
multi-hundred-KB model files plus 8 MB of reference data on every single
test run would make the test suite painfully slow, and "recover orphaned
jobs" only makes sense once the database tables actually exist, which they
don't yet on a freshly created test database.

```python
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = bool(os.environ.get("HTTPS"))
    WTF_CSRF_TIME_LIMIT = None
```
Four security settings, matching CLAUDE.md's security checklist directly.
`HTTPONLY` stops any JavaScript running on the page (including a malicious
script injected by an XSS bug elsewhere) from reading the session cookie at
all. `SAMESITE = "Lax"` stops the browser from sending this site's cookie
along with requests that originate from a different site, which blocks a
category of cross-site attack. `SECURE` — whether the cookie is only ever
sent over an encrypted HTTPS connection — is computed from whether an
`HTTPS` environment variable is set at all (`bool(...)` turns any non-empty
string into `True`), rather than hardcoded, because a local development
server usually isn't running behind HTTPS and forcing this on would break
local testing. `WTF_CSRF_TIME_LIMIT = None` disables the default expiry on
CSRF tokens — sensible here because a very long-running upload page could
otherwise have its CSRF token go stale before the analyst finishes filling
in the form.

### The `TestConfig` class

```python
class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test"
    UPLOAD_RATE_LIMIT = "10 per hour"
    LOAD_MODELS = False
    RECOVER_ORPHANS = False
    DISPATCH_JOBS = False
```

`TestConfig(Config)` — the parentheses mean **inheritance**: `TestConfig`
starts as an exact copy of every setting in `Config`, and only the lines
actually written here override that copy. This is a core object-oriented
idea worth internalising once, because it recurs throughout this codebase
(e.g. `User(UserMixin, db.Model)` in file 04): a class can build on another
class instead of repeating everything from scratch.

- `TESTING = True` is a flag Flask itself checks in a few places (e.g. it
  changes how unhandled exceptions are reported) — standard Flask
  convention for "this is a test run."
- `SQLALCHEMY_DATABASE_URI = "sqlite://"` — note there's no file path after
  the two slashes. This is SQLite's special syntax for an **in-memory
  database**: one that exists purely in RAM for the lifetime of the
  connection and vanishes the instant it closes. Perfect for tests, which
  want a completely fresh, disposable database every single time, and don't
  want leftover test data cluttering a real file.
- `WTF_CSRF_ENABLED = False` turns off CSRF token checking for tests, so
  test code can submit forms without first having to scrape a token out of
  a previous page's HTML — a convenience that would be a security hole in
  production, which is exactly why it's confined to `TestConfig`.
- `UPLOAD_RATE_LIMIT = "10 per hour"` is set deliberately *lower* than
  production, with a comment explaining why: the production limit is loose
  enough that a test would have to make dozens of requests to ever actually
  observe the rate limiter working, and the test suite specifically wants
  to exercise that code path.
- `LOAD_MODELS = False` and `RECOVER_ORPHANS = False` are the two switches
  described above, both off by default in tests for speed and correctness;
  any test that specifically needs a loaded model calls `disk.load(...)` or
  `memory.load(...)` itself, deliberately and visibly, rather than relying
  on hidden startup behaviour.
- `DISPATCH_JOBS = False` is a setting that doesn't even exist on the base
  `Config` class at all — it's read with `app.config.get("DISPATCH_JOBS",
  True)` in `jobs.start()`, so its *absence* from `Config` means production
  always dispatches jobs normally, while its presence (and `False` value)
  here means test uploads never actually spawn a real background process
  pool and hand a few hundred fake bytes to Volatility, which would fail
  confusingly. Tests that want to exercise job *processing* logic call
  `jobs.run(...)` directly instead of going through the dispatch path.

## Why this design works well for a project like this

The entire rest of the codebase never has to ask "am I running in a test?"
or "what's the database URL?" directly — it just reads
`current_app.config["X"]`, and whichever `Config` class `create_app()` was
given (`Config` for real use, `TestConfig` for the test suite) supplies the
right answer. Adding a new environment (say, a staging server with its own
tweaks) would mean adding one more small subclass, not touching a single
line of application logic.

## Check your understanding

**Q1. Why does `MAX_CONTENT_LENGTH` get computed from an environment
variable measured in gigabytes, rather than reading the raw byte count
directly from the environment?**

A: Convenience and correctness for whoever sets the environment variable —
nobody wants to compute or type `34359738368` by hand and risk a
typo-driven off-by-orders-of-magnitude bug; `_gb()` does that arithmetic
once, centrally, from a human-friendly number of gigabytes.

**Q2. `TestConfig` sets `SQLALCHEMY_DATABASE_URI = "sqlite://"`. What is
actually different about this database compared to the default
`Config.SQLALCHEMY_DATABASE_URI`, and why does that difference matter for
tests?**

A: The default points at a real file on disk (`instance/app.db`) that
persists between runs. `"sqlite://"` with nothing after the slashes creates
a temporary, in-memory-only database that exists purely for the life of
that one connection and disappears afterward — so every test starts from a
guaranteed-empty database with no risk of leftover data from a previous test
run leaking in.

**Q3. Where does `UPLOAD_DIR` point by default, and why does that location
matter for security (a topic covered more in file 06 and file 07)?**

A: `ROOT / "uploads"` — a folder at the project root, outside `app/static/`
and outside anything Flask's routing would ever serve directly. Storing
uploads there means an uploaded artifact (which could be a malicious file)
is never reachable by simply guessing or requesting its URL in a browser;
it can only ever be read by application code that deliberately opens it for
extraction.

**Q4. `Config.LOAD_MODELS` and `TestConfig.LOAD_MODELS` disagree. Which one
wins if the test suite runs, and how does the rest of the code find out
which value is active?**

A: `TestConfig`'s value (`False`) wins, because inheritance means
`TestConfig`'s own attribute overrides the one it inherited from `Config`.
The rest of the code never checks the *class* directly — `create_app()`
reads `app.config.get("LOAD_MODELS", True)` after `app.config.from_object()`
has already copied every setting from whichever config class was passed in,
so by the time that line runs, it's just reading one merged dictionary of
settings with no idea (and no need to know) which class they originally
came from.

**Q5. Suppose you wanted every deployment of this app to allow a 100 GB
maximum upload instead of the default 32 GB, without touching any Python
code. How would you do it, based on what this file does?**

A: Set the `MAX_UPLOAD_GB` environment variable to `100` before starting the
app. `_gb("MAX_UPLOAD_GB", 32)` reads that environment variable first and
only falls back to the hardcoded `32` default if it isn't set at all — no
code change needed.
