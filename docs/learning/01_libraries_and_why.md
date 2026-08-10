# 01 — Every Library This Project Uses, and Why

This file covers every third-party library actually imported somewhere in
`app/` or `scripts/` (verified by searching every `import` statement in the
codebase — nothing here is "in requirements.txt but unused"). Standard-library
modules that ship with Python itself (`json`, `hashlib`, `pathlib`, `csv`,
`sqlite3`, `struct`, `concurrent.futures`, etc.) are not covered here as
"libraries" since nothing had to be installed for them — they're mentioned in
later files exactly where they're used.

For each library: what it is, why this kind of project needs it at all, why
*this* library rather than an obvious alternative (where that reasoning is
recorded), the specific things this codebase actually calls, and a tiny
unrelated example to build intuition before you see it for real.

---

## Flask

**What it is, in one sentence:** Flask is a Python web framework — a
pre-built toolkit that listens for requests from a browser and lets you write
Python functions that decide what to send back.

**Why a project like this needs it:** Somebody has to accept an HTTP request
(a browser asking for a page or submitting a form), figure out which piece of
your code should handle it, and turn your Python return value into a proper
HTTP response with the right headers and status code. Writing that networking
and parsing layer from scratch for every project would be enormous, repeated
effort — Flask has already solved it.

**Why Flask specifically:** CLAUDE.md names the whole web stack as a
deliberate, fixed decision — Flask, SQLAlchemy, Flask-Executor, and a short
list of Flask extensions — and explicitly rejects Django-style "batteries
included" frameworks, any SPA framework (React etc.), and any cloud/container
infrastructure (Celery, Redis, Docker, Nginx, Gunicorn). This is a
two-person, one-semester project, and Flask's minimalism — you add only the
pieces you need — fits a project of this scope far better than a larger
framework that assumes a bigger team and more infrastructure.

**What this codebase actually calls:**
- `Flask(__name__, instance_relative_config=True)` — creates the actual
  application object. `instance_relative_config=True` tells Flask that a
  special `instance/` folder (for things like the SQLite database file)
  should be resolved relative to where the app runs, not the code.
- `Blueprint("auth", __name__)` / `Blueprint("main", __name__)` — a way to
  group a set of related routes together before attaching them to the app
  (see the Blueprint entry in the glossary in file 00).
- `render_template(name, **context)` — loads an HTML template file and fills
  in the blanks with Python values (covered fully in file 13).
- `redirect(url)`, `url_for(endpoint)` — send the browser to a different
  page, and build that page's URL from a route's name rather than hardcoding
  the path as a string.
- `request` — the object representing the incoming HTTP request: form data,
  uploaded files, query parameters, the client's IP address.
- `flash(message, category)` — queue a one-time message ("Uploaded and
  queued...") to show on the *next* page the browser loads.
- `current_app` — a reference to the running Flask app usable from
  anywhere, without having to pass the `app` object into every function.
- `abort(404)` — immediately stop and return an HTTP error status.
- `@app.errorhandler(413)` — register a function to run whenever a
  particular HTTP error code occurs (413 = "your upload was too large").

**Tiny standalone example:**
```python
from flask import Flask
app = Flask(__name__)

@app.route("/hello/<name>")
def hello(name):
    return f"Hello, {name}!"
```
Visiting `/hello/Sam` in a browser would show the text "Hello, Sam!" — the
`<name>` part of the URL becomes the `name` argument to the function.

---

## Werkzeug

**What it is:** Werkzeug is the lower-level HTTP toolkit that Flask itself
is built on top of. You rarely import it directly for routing (Flask hides
that), but this project reaches into it directly for two specific jobs.

**Why this project needs it directly:** password security and file-upload
safety are both solved problems with sharp edges if you get them wrong, and
Werkzeug already ships correct, audited implementations.

**What this codebase actually calls:**
- `werkzeug.security.generate_password_hash(password)` — turns a plain
  password into a salted, one-way hash safe to store in the database. Used in
  `User.set_password`.
- `werkzeug.security.check_password_hash(hash, password)` — checks a
  plain password attempt against a stored hash without ever needing to
  "unhash" it. Used in `User.check_password`.

**Tiny standalone example:**
```python
from werkzeug.security import generate_password_hash, check_password_hash
h = generate_password_hash("correct horse battery staple")
check_password_hash(h, "correct horse battery staple")   # True
check_password_hash(h, "wrong guess")                    # False
```

---

## SQLAlchemy and Flask-SQLAlchemy

**What it is:** SQLAlchemy is Python's most widely used ORM (see the
glossary in file 00) — it lets you describe database tables as Python classes
and query them with Python method calls instead of writing raw SQL text.
Flask-SQLAlchemy is a thin integration layer that wires SQLAlchemy into a
Flask app's lifecycle (so it knows which database to connect to, and manages
one "session" per request).

**Why this project needs an ORM at all:** the project has to track users,
jobs, results and findings and their relationships (one job has many
results, one result has many findings) in a durable, queryable way that
survives a server restart. Hand-writing SQL strings for every operation
works, but is far more error-prone (string-building SQL is exactly how SQL
injection vulnerabilities happen) and far more tedious for anything with
relationships between tables.

**Why SQLAlchemy specifically:** it's the de facto standard Python ORM, it
supports SQLite (used in development, per CLAUDE.md) and PostgreSQL (the
intended production database) through the exact same code, and
Flask-SQLAlchemy is the natural glue for a Flask project — there's no
competing choice CLAUDE.md considers.

**What this codebase actually calls:**
- `db = SQLAlchemy()` then `db.init_app(app)` — creates the extension, then
  attaches it to a specific Flask app once one exists (see file 05 for why
  it's split into two steps).
- `db.Model` — the base class every table (`User`, `Job`, `Result`,
  `Finding`, `AuditLog`) inherits from.
- `db.Column(db.Integer, primary_key=True)` and friends (`db.String`,
  `db.Text`, `db.Boolean`, `db.DateTime`, `db.JSON`, `db.BigInteger`) —
  describe one column's type and constraints.
- `db.ForeignKey("users.id")` — declares that a column's value must match
  a row's id in another table (the relational part of "relational database").
- `db.relationship(...)` / `back_populates=...` — lets you write
  `job.results` in Python and get the list of matching `Result` rows,
  without writing a `SELECT ... WHERE job_id = ...` by hand.
- `db.session.add(obj)`, `db.session.commit()`, `db.session.query(...)`,
  `db.session.get(Model, id)` — the actual read/write operations: stage a
  new row, save all staged changes, run a query, fetch one row by its
  primary key.
- `sqlalchemy.event.listens_for(Engine, "connect")` — a low-level hook this
  project uses once, in `app/db.py`, to run SQLite-specific setup commands
  (`PRAGMA` statements) every time a new database connection opens (see file
  04 for exactly why).

**Tiny standalone example:**
```python
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class Pet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))

# later, inside an app: db.session.add(Pet(name="Rex")); db.session.commit()
# db.session.query(Pet).filter_by(name="Rex").first()
```

---

## Flask-Migrate (and Alembic underneath it)

**What it is:** Alembic is a library that generates and runs "migrations" —
small, ordered scripts that change a database's structure over time (see the
glossary in file 00). Flask-Migrate is the thin wrapper that lets you drive
Alembic through Flask's command-line interface (`flask db upgrade`, etc.).

**Why this project needs it:** the database schema was not designed
perfectly on day one and then frozen — six migrations exist in this project
(see file 04), each adding something as a new need appeared (progress
tracking, per-plugin timings, per-process evidence, volumetric context).
Without migrations, upgrading a database that already has real data in it
(without losing that data) would mean hand-writing and hand-running `ALTER
TABLE` statements and hoping every deployment did it in the same order.

**Why this pairing specifically:** it's the standard companion to
SQLAlchemy in the Flask ecosystem, and CLAUDE.md lists it directly in the
web stack without considering an alternative.

**What this codebase actually calls:**
- `migrate = Migrate()` then `migrate.init_app(app, db)` — same
  create-then-attach pattern as Flask-SQLAlchemy, wiring Alembic to this
  specific app and this specific `db` object.
- Everything else (the actual migration files under `migrations/versions/`)
  is *generated* by the `flask db migrate` command and then run by
  `flask db upgrade` — you rarely call Alembic's Python API directly.

**Tiny standalone example (command line, not Python code):**
```
flask db migrate -m "add a favourite_colour column to pets"
flask db upgrade
```
The first command inspects your model classes, compares them to the current
database, and writes a new file describing the difference. The second
command actually runs that file against the database.

---

## Flask-Login

**What it is:** a small library that manages "who is currently signed in"
for a Flask app — tracking a logged-in user across multiple page loads via a
secure cookie, and providing decorators to protect routes.

**Why this project needs it:** HTTP is stateless — every request is, from
the server's point of view, a stranger, unless something ties requests
together. Flask-Login is that something: it writes an encrypted marker into
the browser's session cookie after a successful login, and on every
subsequent request it reads that cookie back and loads the matching user.

**Why Flask-Login specifically:** it's the standard, minimal choice for
Flask session-based auth — CLAUDE.md's "implement properly, this is a
forensics tool" security list assumes exactly this kind of mechanism
(`HttpOnly`, `SameSite=Lax` cookies) rather than something heavier like a
full OAuth provider, which this single-analyst-per-account lab tool has no
need for.

**What this codebase actually calls:**
- `login = LoginManager()` then `login.init_app(app)` — same pattern again.
- `login.login_view = "auth.login"` — where to send someone who tries to
  visit a protected page while signed out.
- `@login.user_loader` — a function you register that, given the ID stored
  in the cookie, loads and returns the matching `User` row.
- `login_user(user, remember=...)` / `logout_user()` — actually sign a user
  in or out.
- `current_user` — a special object usable anywhere that represents
  whoever is signed in for the current request (or an "anonymous" stand-in
  if nobody is).
- `@login_required` — a decorator placed on a route function to force a
  redirect to the login page if nobody is signed in.
- `UserMixin` — a class `User` inherits from that supplies the handful of
  properties/methods Flask-Login expects every user object to have
  (`is_authenticated`, `is_active`, `get_id()`, etc.) so you don't write
  them by hand.

**Tiny standalone example:**
```python
from flask_login import login_required, current_user

@app.route("/secret")
@login_required
def secret():
    return f"Only {current_user.username} can see this."
```

---

## Flask-WTF and WTForms

**What it is:** WTForms is a library for defining web forms as Python
classes (one attribute per form field) with built-in validation rules.
Flask-WTF integrates it with Flask and adds CSRF protection automatically.

**Why this project needs it:** every form in this app (login, register,
upload, confirm-type) needs its submitted data checked — is the username
non-empty, is the password long enough, do the two password fields match,
was a file actually attached — and needs protection against Cross-Site
Request Forgery (a hidden token, invisible to the user, that proves a form
submission really came from this site's own page and not from a malicious
page tricking a signed-in browser into submitting it).

**Why this pairing specifically:** CLAUDE.md's security checklist requires
"CSRF protection on all state-changing forms," and Flask-WTF is the
standard way to get that inside Flask essentially for free — every form
class automatically gets a hidden CSRF field, and `CSRFProtect` (see below)
rejects any POST request missing a valid one.

**What this codebase actually calls:**
- `FlaskForm` — the base class every form (`LoginForm`, `RegisterForm`,
  `UploadForm`, `ConfirmTypeForm`) inherits from.
- Field types: `StringField`, `PasswordField`, `BooleanField`,
  `RadioField`, `SubmitField`, and Flask-WTF's own `FileField`.
- Validators: `DataRequired()` (must not be empty), `Length(min, max)`,
  `EqualTo("password")` (must match another field, used for "confirm
  password"), `Optional()` (skip other validators if this field is blank),
  `FileRequired()` (a file must actually be attached).
- `form.validate_on_submit()` — the one call that does "was this a POST
  request, and did every field pass its validators" in one step.
- `form.hidden_tag()` — used inside a template to render the hidden CSRF
  token field.
- `CSRFProtect()` then `csrf.init_app(app)` — the global protection that
  rejects any state-changing request without a valid token, even outside
  a `FlaskForm` (e.g. the plain HTML logout button in `base.html` includes
  a hand-written hidden `csrf_token()` field for exactly this reason).

**Tiny standalone example:**
```python
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class NameForm(FlaskForm):
    name = StringField("Your name", validators=[DataRequired()])
    submit = SubmitField("Go")

# in a route: form = NameForm(); if form.validate_on_submit(): ...
```

---

## Flask-Executor

**What it is:** a small Flask extension that wraps Python's standard-library
thread pool (`concurrent.futures.ThreadPoolExecutor`) so a Flask route can
say "start this function running in the background" and immediately respond
to the browser without waiting for it to finish.

**Why this project needs it:** analysing a disk image or memory dump takes
minutes, not seconds (CLAUDE.md hard rule 10). If the `upload()` route ran
extraction directly, the browser (and the single worker handling that
request) would hang for the entire duration. Flask-Executor hands the job to
a background thread and returns immediately, so the web server stays
responsive to every other request and page.

**Why Flask-Executor specifically, and not Celery:** CLAUDE.md explicitly
rejects Celery and Redis as "scope creep, not improvement" for a two-person
semester project — they add real infrastructure (a message broker, a
separate worker service to deploy and monitor) for a problem this project
solves adequately with something that ships as a plain pip package and
needs no extra moving parts.

**What this codebase actually calls:**
- `executor = Executor()` then `executor.init_app(app)` — same pattern.
- `executor.submit(function, *args)` — hand a function and its arguments off
  to run on a background thread from the pool. Called exactly once, in
  `jobs.start()`.

**Tiny standalone example:**
```python
from flask_executor import Executor
executor = Executor(app)

def slow_task(n):
    import time; time.sleep(n); print("done")

@app.route("/go")
def go():
    executor.submit(slow_task, 5)
    return "started!"   # returns immediately, doesn't wait 5 seconds
```

**One important subtlety this project relies on:** Flask-Executor's thread
pool is only the *supervisor*. The actual CPU-heavy extraction work is
handed off *again*, from inside that thread, to a completely separate
**process** pool (plain `concurrent.futures.ProcessPoolExecutor`, standard
library, not a third-party package) — covered in depth in file 07. Two
different reasons drive that second hand-off: a native code crash while
parsing a hostile file must not take the whole web server down with it, and
CPU-bound Python work would otherwise hold the GIL and freeze every other
thread in the same process, defeating the point of a thread pool.

---

## Flask-Limiter

**What it is:** a Flask extension that limits how many times a client can
hit a given route in a given time window, returning an HTTP 429 ("Too Many
Requests") once the limit is exceeded.

**Why this project needs it:** without a limit, one account (or one script)
could hammer the `/upload` endpoint continuously, each upload spinning up an
extraction job that consumes real CPU and disk I/O — a basic form of
resource-exhaustion protection CLAUDE.md's security checklist calls for
directly ("rate-limit uploads per user").

**Why this specific library:** it's a small, dependency-light Flask
extension, and its in-memory storage backend needs no external service —
consistent with the project's explicit rejection of Redis. The trade-off,
stated directly in the code, is that limits reset whenever the process
restarts, which is acceptable for a single-node lab tool.

**What this codebase actually calls:**
- `Limiter(key_func=get_remote_address, storage_uri="memory://")` — build
  the limiter, identifying clients by IP address, storing counts purely in
  this process's memory.
- `@limiter.limit(lambda: current_app.config["UPLOAD_RATE_LIMIT"],
  methods=["POST"])` — applied to the `upload()` route. Notice it's a
  function, not a plain string — read every request, so the limit can be
  changed via configuration without a code change or restart.
- `limiter.reset()` — used only in the test suite's fixtures, to clear
  counters between tests so one test's uploads don't count against the next
  test's limit.

**Tiny standalone example:**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/ping")
@limiter.limit("5 per minute")
def ping():
    return "pong"
```

---

## NumPy

**What it is:** the foundational Python library for working with arrays of
numbers efficiently — instead of a plain Python list (slow for large-scale
math, one number handled at a time), NumPy stores numbers in a compact block
of memory and lets you do math on the whole array at once, implemented in
fast C code underneath.

**Why this project needs it:** every feature vector in this system — the 55
memory numbers, the 2,381 raw disk numbers reduced to 150 — is a NumPy
array by the time it reaches a model. Both LightGBM and XGBoost expect
NumPy arrays (or something array-like) as input, and the reference sample
files used for LIME and startup validation are stored as `.npy` files (see
file 04's discussion of `reference_data/`), NumPy's own compact binary
format.

**Why NumPy specifically:** there's no real alternative for numerical array
work in Python — it's the base layer nearly every scientific Python library
(including LightGBM, XGBoost and LIME) is built to interoperate with.

**What this codebase actually calls:**
- `np.load(path)` — read a `.npy` file back into an array (used for
  `reference_data/*.npy`).
- `np.asarray(x, dtype=...)` / `np.ascontiguousarray(x, dtype=...)` — make
  sure a value really is a NumPy array of the right numeric type and memory
  layout before handing it to a model.
- Array indexing with a list of positions, e.g. `vec[..., _idx]` in
  `app/inference/disk.py` — pick out the 150 selected columns from the full
  2,381, in one operation, using the pre-computed index list (file 08 covers
  exactly why this has to be done this way).
- `arr.min(0)`, `arr.max(0)`, `arr.std()`, `.any()` — per-column statistics
  used by the startup sanity checks (file 08) and by `ood()` (out-of-
  distribution detection, file 08 and file 10).
- `np.isfinite(arr).all()` — confirms an array has no `NaN` (not-a-number)
  or infinite values, used as a startup safety check on the reference data.
- `np.flatnonzero(condition)` — returns the positions where a true/false
  array is true; used to list *which* features are out of range.

**Tiny standalone example:**
```python
import numpy as np
a = np.array([1.0, 5.0, 9.0])
b = a[[0, 2]]        # pick out positions 0 and 2 -> array([1.0, 9.0])
a.max(), a.min()      # (9.0, 1.0)
```

---

## LightGBM

**What it is:** a gradient-boosted decision tree library — a specific,
widely-used kind of machine-learning model made of many small decision trees
that each correct the errors of the ones before them.

**Why this project needs it:** it's the library the **disk pipeline's**
already-trained model was built with (per CLAUDE.md, this model won the
disk-side model comparison during training) — so the application has to load
and run predictions through a LightGBM model file at inference time.
CLAUDE.md is explicit that this project never retrains it; it only loads and
uses the finished file.

**Why LightGBM was the shipped choice (recorded, not re-derived here):**
CLAUDE.md states plainly that LightGBM won the disk pipeline's internal
model comparison against XGBoost, while XGBoost won the memory pipeline's —
"this is not a mistake and not something to normalize." The two pipelines
genuinely ship two different libraries, and inference code has to speak
both.

**What this codebase actually calls:**
- `lgb.Booster(model_file=str(path))` — load a previously trained model
  from its saved text file (`models/disk/lightgbm_model.txt`).
- `booster.num_feature()` — how many input columns the loaded model
  expects; checked at startup against the feature list length.
- `booster.predict(matrix)` — run one or more feature vectors through the
  model and get back probabilities.

**Tiny standalone example (illustrative, not from this project):**
```python
import lightgbm as lgb
booster = lgb.Booster(model_file="my_model.txt")
probs = booster.predict(some_2d_array_of_features)
```

---

## XGBoost

**What it is:** another gradient-boosted decision tree library, a close
cousin of LightGBM built by a different team with a different internal
implementation and a different Python API.

**Why this project needs it:** it's the library the **memory pipeline's**
already-trained model was built with — XGBoost won that pipeline's internal
model comparison. Same "load and use, never retrain" rule applies.

**What this codebase actually calls:**
- `xgb.Booster()` then `booster.load_model(str(path))` — construct an empty
  booster object, then load the saved model weights into it from
  `models/memory/xgboost_model.json`.
- `booster.num_features()` — same startup check as LightGBM's
  `num_feature()`.
- `booster.inplace_predict(array, iteration_range=(0, 173))` — run a
  prediction directly against a plain NumPy array, explicitly telling
  XGBoost to use all 173 trees rather than trusting a version-dependent
  default (file 08 explains why `inplace_predict` specifically, rather than
  the more common `DMatrix`-based `predict`, is required here).

**Tiny standalone example (illustrative):**
```python
import xgboost as xgb
booster = xgb.Booster()
booster.load_model("my_model.json")
probs = booster.inplace_predict(some_2d_array_of_features)
```

---

## scikit-learn

**What it is:** the single most widely used general-purpose machine-learning
library in Python, providing everything from simple models to data
preprocessing utilities.

**Why this project needs it:** this project doesn't call scikit-learn's own
models directly for inference (that's LightGBM's and XGBoost's job), but two
things underneath other libraries depend on it. First, `ember`'s feature
extractor (used by the disk pipeline) uses scikit-learn's
`FeatureHasher` internally to build the `imports_hash`/`exports_hash`
feature groups. Second, the version-check code at startup
(`app/inference/__init__.py`) compares the installed scikit-learn version
against what was recorded when the models were trained, because a mismatch
there could subtly change downstream behaviour.

**Why scikit-learn specifically:** it's what `ember`'s original authors
built against, and it's the standard choice for exactly this kind of hashing
utility in Python — not a decision this project made independently.

**What this codebase actually calls (directly):**
- `import sklearn` purely to read `sklearn.__version__` for the startup
  version check — no scikit-learn function is called directly from
  application code. (`FeatureHasher` is called from inside `ember`'s own
  `features.py`, not from this project's code.)

**Tiny standalone example (of the class ember uses internally):**
```python
from sklearn.feature_extraction import FeatureHasher
h = FeatureHasher(10, input_type="string")
vec = h.transform([["CreateFileA", "ReadFile"]]).toarray()
```

---

## LIME

**What it is:** "Local Interpretable Model-agnostic Explanations" — a
library that explains one single prediction from *any* black-box model, by
approximating the model's local behaviour around that one input with a much
simpler, understandable model.

**Why this project needs it:** a probability like "0.94" tells an analyst
nothing about *why*. LIME is what turns a bare number into "these
particular features pushed this prediction toward malicious," which is then
looked up against a plain-English meaning table (file 11) to produce the
findings shown in the report.

**Why LIME specifically:** CLAUDE.md notes LIME is "unmaintained since
2020" and calls it "the only real option" — it was tested early against the
project's chosen numpy/scikit-learn versions specifically because of that
unmaintained status, rather than trusted blindly.

**What this codebase actually calls:**
- `LimeTabularExplainer(sample, feature_names=..., class_names=["Benign",
  "Malware"], discretize_continuous=True, mode="classification",
  random_state=42)` — built once at startup per pipeline (memory and disk
  each get their own), using a saved sample of real training data as the
  reference distribution LIME needs to understand what "normal" values look
  like.
- `explainer.explain_instance(vector, predict_fn, num_features=15,
  labels=(1,))` — the actual per-prediction call: explain this one vector's
  route to the "malicious" class (label 1), considering up to 15
  contributing features.
- `explanation.as_map()[1]` — extract the explanation as
  `[(feature_index, weight), ...]` pairs for the malicious class. Deliberately
  **not** `as_list()`, which returns human-readable but hard-to-parse
  condition strings like `"malfind.ninjections > 5.00"` instead of clean
  feature indices — file 11 covers this distinction in full.

**Tiny standalone example (illustrative):**
```python
from lime.lime_tabular import LimeTabularExplainer
explainer = LimeTabularExplainer(training_data, feature_names=names,
                                  class_names=["No", "Yes"])
exp = explainer.explain_instance(one_row, model.predict_proba)
exp.as_map()[1]   # [(3, 0.21), (7, -0.05), ...]
```

---

## pytsk3

**What it is:** Python bindings for The Sleuth Kit (TSK), a well-established
C/C++ library for reading filesystems directly from a raw disk image, the
way a forensic tool needs to — without needing the operating system to
"mount" the image as a real drive.

**Why this project needs it:** to find files inside a disk image at all,
something has to understand partition tables, filesystem structures (NTFS,
etc.), and how to walk directories and read file contents from raw bytes.
Writing that from scratch is a huge, error-prone undertaking; pytsk3 gives
Python access to a mature, purpose-built implementation.

**Why pytsk3 specifically:** The Sleuth Kit is the standard forensic
filesystem toolkit (the same one behind tools like Autopsy), and CLAUDE.md
confirms it installs cleanly as a prebuilt wheel on the target machine with
no compiler needed — a real, verified constraint for a Windows-based student
project without an MSVC toolchain guaranteed to be present.

**What this codebase actually calls:**
- `pytsk3.Img_Info(path)` — open a raw disk image file.
- `pytsk3.Img_Info.__init__` subclassed as `_EWFImg` — a custom class this
  project defines so that an E01 (EWF) image, which pytsk3 doesn't read
  natively, can still be handed to pytsk3 by wrapping `pyewf`'s reader
  underneath (see below).
- `pytsk3.Volume_Info(img)` — read the partition table, if any.
- `pytsk3.FS_Info(img, offset=...)` — open a filesystem at a given byte
  offset inside the image.
- `fs.open_dir(path="/")` — open the root directory to start walking it.
- `entry.info.meta`, `entry.info.name` — metadata (size, timestamps,
  allocation status) and the filename for a directory entry.
- `entry.read_random(offset, size)` — read a chunk of a file's actual
  content directly from the image.
- `entry.as_directory()` — treat a directory entry as a directory you can
  iterate into (used when the filesystem walk descends into subfolders).
- Constants like `pytsk3.TSK_FS_META_TYPE_DIR`, `pytsk3.TSK_FS_META_TYPE_REG`,
  `pytsk3.TSK_FS_META_FLAG_ALLOC`, `pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA` — named
  values from TSK's own vocabulary for "this is a directory," "this is a
  regular file," "this entry is allocated (not deleted)," and "this is an
  NTFS data attribute."

**Tiny standalone example (illustrative):**
```python
import pytsk3
img = pytsk3.Img_Info("evidence.dd")
fs = pytsk3.FS_Info(img)
for entry in fs.open_dir(path="/"):
    print(entry.info.name.name)
```

---

## libewf / pyewf

**What it is:** `libewf` is a C library for reading the "Expert Witness
Format" (EWF, commonly seen as `.E01` files) — a forensic disk-image
container format that supports compression and embedded case metadata.
`pyewf` is its Python binding. Note the naming trap CLAUDE.md flags
directly: the pip package that provides `import pyewf` is called
**`libewf-python`** — there is no PyPI package literally named `pyewf`.

**Why this project needs it:** `.E01` is one of the two disk-image formats
this project accepts (alongside raw `.dd`/`.img`), and it is a genuinely
different container format from a raw image — pytsk3 alone cannot open one
directly.

**Why this specific library, and why it was nearly dropped:** CLAUDE.md's
build plan explicitly considered dropping `.E01`/`.EX01` support entirely if
`libewf-python` wouldn't build on Windows — it only kept E01 support because
it was verified to install from a prebuilt wheel with no compiler needed.

**What this codebase actually calls:**
- `pyewf.glob(path)` — given one segment of a (possibly multi-part) EWF
  image, find every segment file that belongs to the same image.
- `pyewf.handle()` then `handle.open(segments)` — open the full set of
  segments as one logical image.
- `handle.seek(offset)`, `handle.read(size)`, `handle.get_media_size()` —
  read raw bytes from the decompressed image content; this project wraps
  these three calls inside its own `_EWFImg` class so pytsk3 can treat an
  EWF image exactly like a plain raw one (see the pytsk3 section above).
- `handle.get_header_values()` — read acquisition metadata (examiner name,
  case notes, acquisition date) that the imaging tool wrote into the E01
  file itself, surfaced in the report's chain-of-custody section.

**Tiny standalone example (illustrative):**
```python
import pyewf
segments = pyewf.glob("evidence.E01")
h = pyewf.handle()
h.open(segments)
h.seek(0)
first_bytes = h.read(16)
```

---

## Volatility 3

**What it is:** the current major version of Volatility, the standard
open-source framework for analysing memory dumps — reconstructing process
lists, loaded modules, open handles, and dozens of other structures directly
from a raw block of captured RAM, without the operating system's cooperation
(the machine that produced the dump may no longer even exist).

**Why this project needs it:** everything the memory pipeline measures (55
features spanning nine categories) starts life as output from Volatility 3
plugins. There is no realistic alternative to writing this kind of raw
memory analysis from scratch.

**Why version 3 specifically, and the trade-off that comes with it:**
CLAUDE.md documents a real complication here — the training dataset
(CIC-MalMem-2022) was generated with the older Volatility 2, whose plugin
output doesn't map cleanly one-to-one onto Volatility 3's. A large section of
CLAUDE.md (and a whole file in this curriculum, file 10) is dedicated to how
the extractor bridges that gap honestly rather than papering over it.
Volatility 2 itself is explicitly ruled out as a fallback — it's Python 2.7
only, has no profile for modern Windows builds, and its repository was
archived in 2025.

**What this codebase actually calls:**
- `volatility3.framework.import_files(module, True)` then
  `framework.list_plugins()` — discover every plugin class Volatility 3
  knows about (the "catalog").
- `volatility3.framework.contexts.Context()` — build a fresh analysis
  context, into which a specific dump file and its configuration get loaded.
- `volatility3.framework.automagic.available(ctx)` /
  `automagic.choose_automagic(...)` — Volatility 3's own mechanism for
  automatically figuring out things like which memory layout and OS profile
  a dump uses, without the analyst specifying it by hand.
- `volatility3.framework.plugins.construct_plugin(...)` — actually build a
  runnable instance of one plugin class (e.g. the process-list plugin),
  wired up to the prepared context.
- `plugin.run()` — execute the plugin and get back a "tree grid" of result
  rows.
- `grid.populate(visit_function, None)` — walk every row the plugin
  produced, calling your own function once per row (this project's `visit`
  function just collects each row into a plain dictionary).
- `volatility3.framework.layers.intel.Intel32e` — the specific memory-layer
  class Volatility 3 constructs for a 64-bit x86 memory image; this
  project checks `isinstance(layer, Intel32e)` as the definitive test for
  "is this a 64-bit capture," since a raw dump carries no explicit
  architecture header of its own (file 10 covers this in full).
- `volatility3.symbols.__path__` — a list of folders Volatility 3 searches
  for cached kernel symbol files; this project prepends its own repo-local
  `symbols/` folder to it at extraction time (see `scripts/fetch_symbols.py`
  in file 15, and file 10).
- `volatility3.framework.constants.OFFLINE` — a flag some of this project's
  scripts set to `True` to prove extraction can run with zero network
  access once symbols are staged locally.

**Tiny standalone example (illustrative — Volatility 3's real usage is
considerably more involved, as file 10 shows):**
```python
from volatility3.framework import contexts
ctx = contexts.Context()
ctx.config["automagic.LayerStacker.single_location"] = "file:///dump.raw"
# ... build and run a specific plugin against ctx ...
```

---

## lief and ember

**What `lief` is:** a library (written in C++, with Python bindings) for
parsing executable file formats — PE (Windows), ELF (Linux), Mach-O
(macOS) — and reading out their internal structure: sections, imports,
headers, resources.

**What `ember` is:** Endgame's "EMBER" project, a reference implementation
that turns a parsed PE file (via `lief`) into a fixed 2,381-number feature
vector, originally built alongside the public EMBER malware dataset. This
project's disk model was trained on those same 2,381 EMBER features.

**Why this project needs both:** the disk pipeline's whole job is: find a
PE file inside a disk image, and turn it into the same shape of feature
vector the model was trained on. `ember`'s `PEFeatureExtractor` is that
exact, already-defined transformation; `lief` is what it uses internally to
actually read the PE file's bytes.

**Why this specific, unusually complicated setup (recorded directly in
CLAUDE.md, not simplified here because the complication is real and
load-bearing):**
- The originally-pinned `lief==0.11.5` has no wheel for the Python version
  this project runs, so the project instead runs `lief==1.0.0` — matching
  the exact version that produced the *training* features, not the
  `0.9.0` version `ember`'s own `setup.py` was written against.
- Because of that version gap, `ember`'s `features.py` needs three small
  source patches to even run at all under the newer `lief` and a newer
  `numpy` (see `scripts/patch_ember.py`, covered fully in file 15). None of
  the three patches changes a feature *value* — they only fix things that
  would otherwise crash before producing any output.
- `ember`'s own `__init__.py` is deliberately never imported, because it
  drags in `pandas`, `lightgbm`, and `sklearn.model_selection` for training
  helpers this project has no use for — and `pandas`'s native C extensions
  are blocked outright by Windows Application Control on the deployment
  target. This project loads `ember/features.py` directly as a standalone
  file instead (`scripts/patch_ember.py:load_features()`).
- `lief` is never allowed to run inside the main Flask process — it is
  native code parsing hostile, potentially malformed input, so a crash
  (segfault) must be contained to a disposable worker process rather than
  taking the whole web server down (hard rule 20; see file 07 and file 09).

**What this codebase actually calls:**
- (via `ember`'s `PEFeatureExtractor`, not called directly)
  `PEFeatureExtractor(feature_version=2).feature_vector(raw_bytes)` — the
  single call that turns a PE file's raw bytes into the full 2,381-value
  vector, used inside the disk extractor's worker process (file 09).
- `PEFeatureExtractor(...).process_raw_features(json_obj)` — used only by
  `scripts/ember_holdout.py` to vectorise an already-parsed, published
  EMBER test row without ever opening a real PE file (file 15).
- Underneath `ember`, `lief.parse(bytes)` and various `lief.PE.*` accessors
  do the actual byte-level parsing — this project never calls `lief`
  directly, only through `ember`'s extractor.

**Tiny standalone example (of what `ember` does internally, illustrative):**
```python
import lief
binary = lief.parse("notepad.exe")
print(binary.header.machine, len(binary.sections))
```

---

## ReportLab

**What it is:** a pure-Python library for generating PDF documents
programmatically — describing a page's content (paragraphs, tables, styles)
in Python and getting back real PDF bytes.

**Why this project needs it:** the forensic report is delivered as a PDF,
and that PDF has to be built fresh from live database rows every time it's
requested (no PDF is ever cached or stored — file 12 covers `report.py` in
full).

**Why ReportLab specifically, over the more design-friendly WeasyPrint:**
CLAUDE.md states this directly — WeasyPrint needs native GTK/Pango/Cairo
system libraries to be separately installed, "a well-known install failure"
on Windows. ReportLab is pure Python with no native dependency to fight
with, which for a project already juggling several native-code dependencies
(`lief`, `pytsk3`, `libewf-python`, Volatility 3) was decisive. **WeasyPrint
is not present anywhere in this codebase** — it was considered and
explicitly rejected, never installed.

**What this codebase actually calls:**
- `SimpleDocTemplate(buffer, pagesize=A4, ...)` — the top-level object that
  a whole document's content gets built into, writing out to an in-memory
  byte buffer rather than a file on disk.
- `Paragraph(text, style)` — one block of styled text.
- `Table(data, colWidths=...)` then `.setStyle(TableStyle([...]))` — a grid
  of cells (used for the chain-of-custody key/value block and the findings
  tables), with styling rules like borders, background colour, and padding
  applied as a list of instructions.
- `Spacer(width, height)` — a deliberate blank gap between elements.
- `KeepTogether([...])` — a hint that a group of elements should not be
  split across a page break (used so one file's whole findings block stays
  together).
- `PageBreak()` — force the next content onto a new page.
- `getSampleStyleSheet()` then `ParagraphStyle(..., parent=base["Normal"],
  ...)` — start from ReportLab's built-in style presets and customise them
  (font size, colour, spacing) for this report's own look.
- `doc.build(flow)` — the final call that takes the whole list of
  paragraphs/tables/spacers built up (`flow`) and actually renders them into
  pages, writing PDF bytes into the buffer.

**Tiny standalone example:**
```python
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

buf = io.BytesIO()
doc = SimpleDocTemplate(buf)
style = getSampleStyleSheet()["Normal"]
doc.build([Paragraph("Hello, PDF!", style)])
pdf_bytes = buf.getvalue()
```

---

## Bootstrap and Chart.js (frontend, not pip-installed)

These two are not Python libraries — nothing in `requirements.txt` mentions
them — but they are genuine third-party libraries this project depends on,
living as plain files under `app/static/vendor/`
(`bootstrap.min.css`, `bootstrap.bundle.min.js`, `chart.umd.min.js`).
Covered in full in file 13; named here for completeness since the brief
asked for every library actually used, not just the Python ones.

**Bootstrap:** a CSS (and small JS) framework providing ready-made,
consistent styling for buttons, forms, cards, tables and a responsive grid
layout, so the project doesn't hand-write every visual detail from scratch.

**Chart.js:** a JavaScript charting library used to draw the severity-
distribution doughnut charts on the dashboard and job-detail pages.

**Why vendored (downloaded once and stored in the repo) instead of loaded
from a CDN:** CLAUDE.md is explicit that this is "an offline tool" — a CDN
reference would silently fail (or leak the fact that an analysis is
happening) on a machine with no internet access, which is a realistic
deployment scenario for a forensic lab tool.

---

## What's *not* here, on purpose

Two things worth naming precisely because their **absence** is a real,
recorded decision rather than an oversight:

- **pandas** is never imported anywhere in `app/` or `scripts/`. CLAUDE.md
  states this outright (hard rule/§16) — `ember`'s own `__init__.py` wants
  it, which is exactly why this project bypasses that file entirely and
  loads `ember/features.py` standalone instead.
- **WeasyPrint** is not installed or imported anywhere — considered for PDF
  generation, rejected in favour of ReportLab for the native-dependency
  reason explained above.
