# 21 — Starting the Application

## Visual flow

```
python run.py
  └─ (inside "if this file was run directly")
     └─ create_app()                                   [app/__init__.py]
          ├─ app.config.from_object(config)             sequential
          ├─ Path(instance_path).mkdir()                sequential
          ├─ UPLOAD_DIR.mkdir()                          sequential
          ├─ db.init_app(app)                            sequential
          ├─ migrate.init_app(app, db)                   sequential
          ├─ csrf.init_app(app)                           sequential
          ├─ executor.init_app(app)                       sequential
          ├─ limiter.init_app(app)                         sequential
          ├─ login.init_app(app)                            sequential
          ├─ import models                                   sequential
          │
          ├─ IF LOAD_MODELS:
          │    └─ inference.init(models_dir, reference_dir)  sequential
          │         ├─ memory.load(models_dir, reference_dir)
          │         ├─ disk.load(models_dir, reference_dir)
          │         └─ _check_versions(models_dir)
          │    └─ explain.init(models_dir, reference_dir)    sequential
          │         ├─ build memory LIME explainer
          │         └─ build disk LIME explainer
          │    └─ baseline.load(baseline_file)               sequential
          │
          ├─ register load_user() with Flask-Login
          ├─ register auth_bp, main_bp
          │
          ├─ IF RECOVER_ORPHANS:
          │    └─ jobs.recover_orphans(app)                  sequential
          │
          ├─ register error handlers
          └─ return app
  └─ app.run(host="127.0.0.1", port=5000, threaded=True)   [now waiting for real requests]
```

Every arrow above happens **sequentially, one after another, on the one
and only thread that's running at this point** — there is no background
work and nothing running in parallel anywhere in this whole functionality.
That matters, because it means the order shown above is *exactly* the
order these things happen in reality, every single time the server starts
— nothing here is a race or a "roughly" ordering.

## 1. Trigger

A person runs `python run.py` from a terminal (§5 of the earlier
curriculum covers exactly why `run.py`, and not `wsgi.py` or
`flask run`, is the correct way to start this project). Nothing inside the
application code causes this to happen — it's the one functionality in
this entire guide whose trigger is a human typing a command, not a browser
request or a background worker.

## 2. The full sequence, step by step

**Step 1 — `if __name__ == "__main__":` guard, `run.py`.** Plain language:
checks whether this file is the one that was directly executed (as opposed
to being re-imported by a spawned worker process). Why here: this whole
block, including everything below, must never re-run inside a background
extraction worker — file 05 covers the real crash this guards against in
full. Input: none. Output: if true, proceeds to the next step; a spawned
worker process sees this as false and skips straight past all of it.

**Step 2 — `create_app()`, `app/__init__.py`.** Plain language: builds one
complete, fully-configured Flask application object from scratch. Why
here: this is the one function every other functionality in this whole
curriculum depends on having already run — routes don't exist, the
database isn't wired up, and no model is loaded until this function
finishes. Input: a config class (`Config`, the real production settings —
§3). Output: a fully built Flask `app` object, returned all the way back
to `run.py`.

**Step 3 (inside `create_app()`) — `app.config.from_object(config)`.**
Copies every setting from the `Config` class (§3) onto the live app's own
settings dictionary. Why here, first: every step after this one reads a
setting from `app.config` at least once, so nothing else can safely run
before this. Input: the `Config` class. Output: `app.config` is now fully
populated.

**Step 4 — folder creation.** `Path(app.instance_path).mkdir(...)` and,
outside test runs, `app.config["UPLOAD_DIR"].mkdir(...)`. Plain language:
make sure the folders the database file and uploaded artifacts will need
actually exist on disk. Why here: several of the steps below (database
connection, later, uploads much later) would fail immediately if their
target folder didn't exist yet.

**Step 5 — five extension "attach" calls: `db.init_app(app)`,
`migrate.init_app(app, db)`, `csrf.init_app(app)`, `executor.init_app
(app)`, `limiter.init_app(app)`.** Plain language: each of these objects
was already *created* (empty, unattached) back when `app/__init__.py` was
first imported (§5 covers this two-step "create, then attach" pattern in
full) — these calls wire each one specifically to *this* app instance.
Why here, in this order: nothing strictly forces this exact order among
these five, but `db` genuinely has to be attached before anything that
touches the database (including model loading a few steps later, and
`migrate`, which needs `db` to already be attached to work at all).

**Step 6 — `login.init_app(app)`, then `login.login_view = "auth.login"`,
`login.login_message_category = "warning"`.** Plain language: wires
Flask-Login to this app, then tells it exactly which route to redirect a
signed-out visitor to, and which flash-message styling to use when it does.
Why here: this has to happen before any request can possibly be handled,
since every `@login_required` route (§6, §7) depends on Flask-Login
already knowing where to send someone who isn't signed in.

**Step 7 — `from . import models`.** Plain language: loads
`app/models.py`, which defines the `User`, `Job`, `Result`, `Finding`, and
`AuditLog` classes (§4). Why here: the very next step (model loading) and
the step after that (a `load_user` function referencing `models.User`)
both need this module already loaded.

**Step 8 — `if app.config.get("LOAD_MODELS", True):`.** This condition
gates the three steps below. In real production use it's `True`; under
the test suite's configuration it's `False` (§3 covers exactly why —
loading two multi-hundred-KB models on every single test run would make
the whole suite painfully slow, and tests that specifically need a loaded
model load it themselves, deliberately).

**Step 8a — `inference.init(models_dir, reference_dir)`,
`app/inference/__init__.py`.** Plain language: loads both trained models
and checks the installed library versions against what each model was
actually saved under. Why here: nothing that predicts anything (files 24,
25) can run before this. Input: the folder paths to `models/` and
`reference_data/`. Output: nothing returned — both models are held as
module-level state inside `app/inference/disk.py` and `app/inference/
memory.py` from this point on, for the rest of the process's life.
*Called from elsewhere?* No — this is the only place in the whole codebase
`inference.init()` is ever called. Inside it, in order: `memory.load(...)`
runs every check covered in the earlier curriculum's file 08 (feature
count, threshold not equal to `0.5`, the all-zero/zero-variance column
counts, the bimodal reference-distribution guard); then `disk.load(...)`
runs its own equivalent checks (including the non-monotonic subset-index
assertion); then `_check_versions(models_dir)` compares the real,
installed `xgboost`/`lightgbm`/`sklearn` versions against each model's own
recorded training versions, only warning (never refusing to boot) on a
mismatch.

**Step 8b — `explain.init(models_dir, reference_dir)`, `app/explain.py`.**
Plain language: builds the two LIME explainers, one per pipeline, using
each pipeline's own reference sample data. Why here, and not earlier:
building the memory explainer specifically needs `memory.names()`, which
only exists correctly after `inference.init()` (step 8a) has already run
and loaded the memory model. Output: two explainer objects, held as
module-level state (`_memory`, `_disk` inside `explain.py`) for the rest
of the process's life. *Called from elsewhere?* No — this is the only call
site.

**Step 8c — `baseline.load(baseline_file)`, `app/forensics/baseline.py`.**
Plain language: reads the seven-capture clean-machine baseline JSON file
into memory. Why here: memory severity scoring (file 25) depends on this
data already being loaded; if the file doesn't exist at all, this step
logs that fact and returns `False` rather than crashing the whole startup
— a missing baseline is treated as a real, survivable, disclosed
condition, not a fatal error. *Called from elsewhere?* Also called
directly by `scripts/predict_vector.py` when that script is run
standalone, outside the web app entirely — see file 29 for the full
cross-reference.

**Step 9 — `@login.user_loader def load_user(uid): ...`.** Plain
language: registers, but does not yet run, the one function Flask-Login
needs to turn a signed cookie's stored ID back into a real `User` row.
It only actually *runs* later, on a per-request basis, once real requests
start arriving (§6).

**Step 10 — blueprint registration: `app.register_blueprint(auth_bp)`,
`app.register_blueprint(main_bp)`.** Plain language: attaches every route
defined in `auth.py` and `routes.py` to the live app. Why here: this is
the step that makes URLs like `/login` and `/upload` exist at all;
nothing before this point could have handled a real HTTP request even if
one arrived.

**Step 11 — `if app.config.get("RECOVER_ORPHANS", True): jobs.
recover_orphans(app)`, `app/jobs.py`.** Plain language: finds any job left
`RUNNING` from before the server's last shutdown and marks it `FAILED`
with an honest explanation. Why here, this late: it needs the database
tables to already exist (a fresh, never-migrated checkout would fail this
step, which is why it's wrapped in its own `try`/`except` right here in
`create_app()` — a fresh checkout can still finish booting even though
this one step fails). This step is covered in full, alongside live job
failure, in file 28.

**Step 12 — error handler registration, `@app.errorhandler(413)` and
`@app.errorhandler(404)`.** Registers, but doesn't yet run, the two
functions that produce this project's custom error pages.

**Step 13 — `return app`.** The fully built app object is handed back to
whoever called `create_app()` — in this real trigger's case, back to
`run.py`.

**Step 14 (back in `run.py`) — `app.run(host="127.0.0.1", port=5000,
threaded=True)`.** Plain language: starts Flask's built-in development web
server, which now sits and waits, listening for real HTTP requests. This
is the literal moment "starting the application" ends and every other
functionality in this curriculum (which all begin with an incoming
request, or a background worker being handed a task) becomes possible for
the first time.

## 3. Sequential versus background/parallel

**Everything in this functionality is sequential.** There is no
background work anywhere in the startup sequence itself — every step
above genuinely waits for the one before it to finish before it begins.
This is worth contrasting directly with file 24/25 (where extraction is
explicitly handed off to a separate process while the web server keeps
answering other requests) and file 27 (where a worker process and a
supervisor thread genuinely run alongside each other) — startup has none
of that. The only thing that changes once `app.run(...)` is reached is
that the *server itself* then starts handling many separate, independent
requests, each one its own new, separate call chain (documented in the
other seven files) — but starting up to reach that point is one single,
linear, uninterrupted sequence.

## 4. Where this functionality starts and ends

**Starts:** the moment a human runs `python run.py`.
**Ends:** the moment `app.run(...)` actually begins listening on port
5000 — at which point this functionality is genuinely finished, and the
server sits idle until the first real request (or, on Windows, until a
worker process re-imports parts of this same startup code for an entirely
different reason — see file 05's `wsgi.py`/`run.py` discussion) triggers
one of the other seven functionalities in this curriculum.

## 5. Check your understanding

**Q1. If `LOAD_MODELS` were `False` (as it is under the test suite's
configuration), which three specific function calls inside `create_app()`
would never happen, and which functionality files (24, 25) would that
directly prevent from working correctly?**

A: `inference.init(...)`, `explain.init(...)`, and `baseline.load(...)`
would all be skipped. Without them, `jobs._disk()`'s and `jobs._memory()`'s
calls to `model.predict(...)`, `explain.disk_findings(...)`/
`explain.memory_findings(...)`, and `baseline.compare(...)` (all covered
in files 24 and 25) would fail, since none of the module-level state those
calls depend on would ever have been built.

**Q2. Why does `jobs.recover_orphans(app)` run wrapped in its own
`try`/`except` right inside `create_app()`, rather than being allowed to
fail and stop the whole application from starting?**

A: Because on a completely fresh checkout of the project, before `flask db
upgrade` has ever been run, the database tables this function queries
don't exist yet at all — querying them would raise an error. Wrapping just
this one step means a fresh checkout can still finish booting successfully
(with orphan recovery simply skipped, logged at debug level) rather than
being unable to start at all until migrations are run first.

**Q3. Put these four steps in the order they actually happen inside
`create_app()`: (a) registering the blueprints, (b) loading both trained
models, (c) attaching the database extension, (d) recovering orphaned
jobs.**

A: (c) attaching the database → (b) loading both trained models →
(a) registering the blueprints → (d) recovering orphaned jobs. The
database has to be attached before model loading even begins (model
loading doesn't strictly need it, but it happens after in the real code);
blueprints are registered after model loading; and orphan recovery — which
needs both the database *and* real routes to make sense of — runs last of
the four.
