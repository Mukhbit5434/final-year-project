# 05 — How the App Boots: `app/__init__.py`, `wsgi.py`, `run.py`

## The application factory pattern

In a lot of small tutorial examples, a Flask app looks like this:

```python
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "hi"

app.run()
```

That works fine for a five-line example, but it has a real problem the
moment your app needs to exist in more than one *configuration* at once —
which this project genuinely does: a real running server, a test suite that
needs its own throwaway database and no loaded models, and background
worker processes that must, on Windows, avoid accidentally building a second
copy of the whole app (more on that below). If `app = Flask(__name__)` sits
at the top level of a file, it runs the instant that file is imported, with
whatever global settings happen to be in effect at that exact moment — there
is no clean way to say "build me a *test* version of this app" versus "build
me a *real* version," because there's only ever one `app` object, built
once, unconditionally.

The **application factory pattern** solves this by wrapping app creation in
an ordinary function — `create_app(config)` — that you call explicitly,
passing in whichever configuration you want, and that returns a brand new,
fully wired-up app object each time it's called. Nothing happens just from
*importing* `app/__init__.py`; the whole app only gets built when something
actually calls `create_app()`. This is precisely how this project supports
a real server, `pytest` (which calls `create_app(TestConfig)` fresh for
every single test), and `scripts/verify_pipeline.py` (which calls
`create_app(VerifyConfig)` with yet another, custom configuration) — all
from the exact same function, without any of them stepping on each other.

## Reading `app/__init__.py` top to bottom

```python
from pathlib import Path

from flask import Flask, render_template
from flask_executor import Executor
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from .config import Config
from .db import db

executor = Executor()
login = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
```

Every Flask extension this project uses (file 01 covers each one
individually) gets created here as a bare, unattached object, at **module
level** — meaning this code runs once, the first time this file is
imported, and the resulting objects (`executor`, `login`, `migrate`, `csrf`,
`limiter`) live for as long as the Python process does. Crucially, none of
them are tied to any specific Flask `app` yet — that attachment happens
inside `create_app()`, which is what allows `create_app()` to be called
multiple times (once per test, for instance) while still only ever creating
these five extension objects once each.

### `create_app()` itself

```python
def create_app(config=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config.get("TESTING"):
        app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)
```

`config=Config` is a **default argument** — calling `create_app()` with no
arguments at all uses the real production `Config` class from file 03;
passing `create_app(TestConfig)` (as the test suite does) overrides it.
`app.config.from_object(config)` is what actually copies every setting from
whichever config class was passed in onto the live Flask app's own
`app.config` dictionary — this is the exact moment file 03's `Config`
class stops being "just a Python class" and becomes the app's real, active
settings.

`Path(app.instance_path).mkdir(...)` ensures the `instance/` folder (where
the SQLite database and the progress-tracking files live) actually exists
before anything tries to write into it — `exist_ok=True` means "don't
complain if it's already there." The upload directory gets the same
treatment, but only outside test runs (`TESTING` is one of the flags
`TestConfig` sets) — tests use a temporary directory supplied by the test
fixtures instead (file 14), so creating the real `uploads/` folder for
every single test run would be pointless clutter.

```python
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    executor.init_app(app)
    limiter.init_app(app)

    login.init_app(app)
    login.login_view = "auth.login"
    login.login_message_category = "warning"
```

This is the "attach" half of every extension's create-then-attach pattern
from file 01 — each `init_app(app)` call wires that already-created
extension object to *this specific* app instance. `login.login_view =
"auth.login"` tells Flask-Login exactly where to redirect a signed-out
visitor who tries to reach a `@login_required` page; `login_message_category
= "warning"` sets the flash-message category used for the "please sign in"
message that appears when that redirect happens (file 13 covers how flash
categories map to visual styling).

```python
    from . import models

    if app.config.get("LOAD_MODELS", True):
        from . import explain, inference
        from .forensics import baseline
        inference.init(app.config["MODELS_DIR"], app.config["REFERENCE_DIR"])
        explain.init(app.config["MODELS_DIR"], app.config["REFERENCE_DIR"])
        baseline.load(app.config["BASELINE_FILE"])
```

Two things worth noticing here. First, `from . import models` is imported
*inside* the function body rather than at the top of the file — this is a
deliberate pattern used throughout this codebase to avoid **circular
imports** (where module A needs something from module B, but module B also
needs something from module A, and Python can't resolve which one to fully
load first) — `models.py` doesn't actually need anything from
`__init__.py`, but importing it lazily like this keeps the dependency
direction clean and avoids import-order bugs as the codebase grows.

Second — and this is the load-bearing line for the whole project — model
loading is **conditional** on `app.config.get("LOAD_MODELS", True)`. File 03
already covered *why* `TestConfig` sets this to `False` (speed, and tests
that need a model load it explicitly); here is *where* that setting
actually takes effect. When it's `True` (every real run of the app), three
things happen in this exact order: `inference.init(...)` loads both trained
models and runs their startup sanity checks (file 08 covers every one of
those checks in depth — feature counts, threshold sourcing, the scrambled-
column distribution guard); `explain.init(...)` builds both LIME explainers,
which is the expensive, one-time-only setup step LIME needs (file 11);
`baseline.load(...)` reads the seven-capture clean-machine baseline JSON
into memory (file 11). All three are genuinely expensive to do per-request,
which is exactly why they happen exactly once, here, at startup, and are
then held in module-level state for the rest of the process's life — never
reloaded per request.

```python
    @login.user_loader
    def load_user(uid):
        return db.session.get(models.User, int(uid))
```

This is the one function Flask-Login requires you to supply yourself (file
01): given the ID that was stored in the signed cookie, load and return the
matching real `User` row (or `None` if it no longer exists — e.g. the
account was deleted). It's defined as a small nested function right here,
inside `create_app()`, specifically so it has access to the `models` module
that was just imported above.

```python
    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
```

The two blueprints (file 00's glossary; file 06 and file 07 cover their
actual routes) get imported and attached to the app here. Renaming them on
import (`as auth_bp`, `as main_bp`) is just a readability choice — both
files internally call their blueprint object `bp`, and importing two
different things both named `bp` into the same function would otherwise
collide.

```python
    if app.config.get("RECOVER_ORPHANS", True):
        from . import jobs
        try:
            jobs.recover_orphans(app)
        except Exception:
            app.logger.debug("orphan recovery skipped", exc_info=True)
```

Another config-gated step (file 03 explained why `TestConfig` disables
this: on a freshly created test database, the tables don't exist yet, so
querying them would raise an error before the test fixture even finishes
setting up). `jobs.recover_orphans(app)` — covered fully in file 07 — finds
any job left `RUNNING` from before the last shutdown (the server crashed or
was stopped mid-job) and marks it `FAILED` with an honest explanation,
rather than leaving it stuck showing "in progress" forever. The
`try`/`except` around it is a genuine defensive measure with a specific,
named scenario in its comment: on a completely fresh checkout of the repo,
before any migration has ever been run, the `jobs` table doesn't exist at
all yet, and this lets `create_app()` still succeed in that case rather
than crashing before the analyst even gets a chance to run `flask db
upgrade`.

```python
    @app.errorhandler(413)
    def too_large(_e):
        gb = app.config["MAX_CONTENT_LENGTH"] // 1024 ** 3
        return render_template("error.html", code=413,
                               message=f"That artifact is larger than the {gb} GB limit."), 413

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Not found."), 404
```

Two custom error pages, registered with the `@app.errorhandler(code)`
decorator (file 01's Flask section) instead of letting Flask show its
generic default error page. 413 is specifically the status Flask itself
generates automatically when an incoming request body exceeds
`MAX_CONTENT_LENGTH` (file 03) — the handler here just makes that failure
readable, computing the limit back into gigabytes for the message rather
than showing a raw byte count.

```python
    @app.shell_context_processor
    def shell_ctx():
        return {"db": db, "m": models}

    return app
```

A small developer convenience — it makes `db` and `models` (as `m`)
automatically available, with no manual import needed, inside `flask
shell` (Flask's interactive Python console command), useful for poking at
the database by hand during development. And finally, `return app` — the
one line that makes this whole function actually useful: hand back the
fully built, fully wired application object to whoever called
`create_app()`.

## `wsgi.py` versus `run.py`, and the real bug that made the split necessary

```python
# wsgi.py
from app import create_app

app = create_app()
```

```python
# run.py
import multiprocessing

if __name__ == "__main__":
    multiprocessing.freeze_support()

    from app import create_app

    app = create_app()
    app.run(host="127.0.0.1", port=5000, threaded=True)
```

At first glance these look almost redundant — both end up calling
`create_app()`. The reason they're two separate files, rather than one, is
a real, specific bug this project hit during development, and understanding
it is worth doing properly rather than just memorising "always use `run.py`,
never `python -m flask run`."

**The story:** this project's extraction workers run in a separate *process*
(not thread — file 07 explains the distinction and why it's a process),
using Python's standard `ProcessPoolExecutor`. On Windows, Python has no
equivalent of Linux's `fork()` (a fast, cheap way to duplicate an already-
running process); instead, it starts each new worker process by launching a
fresh Python interpreter and having it **re-import the `__main__` module**
— literally, the file that was originally run to start the whole program —
to reconstruct enough of the parent's setup to run the assigned task.

If the file used to launch the server had been something like
`run.py` *without* the `if __name__ == "__main__":` guard — every single
line in that file, including `app = create_app()` and `app.run(...)`, would
run again inside *every worker process the moment it started*. That means:
a second, entirely separate Flask app object gets built (wasteful, and
pointless — the worker doesn't need a Flask app, it just needs to run one
extraction function), and — far worse — **both trained models get loaded a
second time inside every single worker**, an expensive, slow, memory-hungry
operation that has nothing to do with what the worker was actually asked to
do. In one documented instance, a script that additionally tried to write
to the database at module level (outside any guard) crashed every worker
outright the moment it started, and the failure surfaced as
`BrokenProcessPool` — the *entire pool* reported as broken, with a
traceback pointing generically at `concurrent.futures` internals, nowhere
near the real cause.

The fix is exactly what `run.py` does: everything that shouldn't run again
inside a re-imported worker sits inside `if __name__ == "__main__":` — a
standard Python idiom meaning "only run this block if this file was the one
originally executed to start the program, not if it was merely imported."
`multiprocessing.freeze_support()` is called first, which is specifically
required on Windows for multiprocessing to behave correctly at all in this
kind of setup.

`wsgi.py`, in contrast, has **no guard at all**, and that's deliberate —
it exists purely as a stable, minimal **import target**: something a
production WSGI server (or the `flask` command-line tool, via the
`FLASK_APP` environment variable) can point at and reliably find an `app`
object inside, without needing to run anything interactively. Because it
contains nothing *but* `app = create_app()`, there's no risk of it
duplicating expensive setup work even if something does end up importing it
more than once.

**The practical rule that falls out of this story, stated in CLAUDE.md
directly:** run this project with `python run.py`, never
`python -m flask run` pointed at a module that builds the app at import
time outside a guard. And the same discipline has to be applied to *any*
new entry-point script added later that can reach `jobs.pool()` — it needs
the identical `if __name__ == "__main__":` guard, or the exact same failure
mode will resurface.

## Check your understanding

**Q1. Why does `create_app()` take a `config` argument at all, instead of
just always using the real production `Config` class directly?**

A: So the exact same function can build genuinely different versions of the
app for different purposes — a real server, a test run with an in-memory
database and no loaded models, or a verification script with its own
throwaway database — without duplicating any of the wiring logic. Every
caller supplies whichever config class fits its purpose; `create_app()`
itself doesn't need to know or care which one it was given.

**Q2. `inference.init(...)`, `explain.init(...)`, and `baseline.load(...)`
all run inside `create_app()`, gated behind `LOAD_MODELS`. Why do these
three specifically need to happen once at startup, rather than, say, being
loaded fresh the first time a route needs them?**

A: All three are expensive to build (loading multi-hundred-KB model files,
constructing a LIME explainer against thousands of reference rows, parsing
a baseline JSON) and none of their results change between requests — the
trained models are fixed files on disk, not something that changes at
runtime. Doing this work once at startup and holding the result in
module-level state means every actual analysis request reuses already-built
objects instantly, instead of paying that setup cost repeatedly and making
every single upload artificially slower.

**Q3. What specific, concrete bad thing happens if a background worker
process re-runs `app = create_app()` unintentionally, and why does putting
that line inside `if __name__ == "__main__":` prevent it?**

A: A second, unnecessary Flask app gets constructed and — critically — both
multi-hundred-KB trained models get reloaded a second time, inside every
single worker process, for no reason (the worker doesn't need a Flask app
at all, only the one extraction function it was assigned). In one real
instance, this pattern additionally caused every worker to crash outright,
which `concurrent.futures` reported generically as `BrokenProcessPool` —
the whole pool marked broken, with no obvious link back to the real cause.
The guard prevents it because `if __name__ == "__main__":` is only `True`
in the process that was *originally* started to run this exact file — a
worker process that re-imports the same file as a *module* (not as the
thing that was directly executed) sees `__name__` set to something else
entirely, so that whole block is skipped.

**Q4. If you needed to add a brand-new command-line script that imports
`app.jobs` and might end up calling `jobs.pool()`, what would you need to
copy from `run.py` to keep it safe on Windows?**

A: The exact `if __name__ == "__main__":` guard (with
`multiprocessing.freeze_support()` inside it) around any code in that new
script that builds a Flask app, loads models, or does other setup work that
must only ever run once, in the original process — otherwise every worker
spawned from that script would silently repeat that setup work, or worse,
crash the same way the original `BrokenProcessPool` bug did.
