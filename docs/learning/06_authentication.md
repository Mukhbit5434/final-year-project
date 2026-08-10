# 06 — Authentication: `app/auth.py`, plus `app/audit.py`

## The concepts, plainly

**Authentication** is the process of a system confirming *who you are* —
distinct from **authorization**, which is confirming *what you're allowed to
do* once it knows who you are (this project's authorization is simple: an
analyst can only ever see their own jobs, enforced in `routes.py:_owned()`,
covered in file 07).

**A password hash** is the result of running a password through a one-way
mathematical function (file 01's Werkzeug section) that produces a fixed-
length scrambled value which cannot practically be reversed back into the
original password, but which will always produce the *exact same* scrambled
value again if you feed it the exact same password. This project **never**
stores a plain password anywhere, in any table, at any point — only the
hash. When someone logs in, the system doesn't "decrypt" the stored hash to
compare it to what was typed; it hashes what was typed *again*, the same
way, and compares the two hashes. If the account's stored hash is ever
stolen (a database breach, for instance), the attacker still doesn't have
anyone's actual password — they'd have to guess passwords and hash each
guess to check it, which a well-designed hash function makes deliberately
slow to do at scale.

**A session** is how a web server remembers "this browser is the one that
successfully logged in five minutes ago," across what is otherwise a series
of completely independent, memory-less HTTP requests. **A cookie** is the
mechanism that makes a session possible: a small piece of data the server
asks the browser to store and automatically send back with every future
request to this same site. Flask-Login (file 01) writes a signed,
tamper-evident marker into the session cookie on a successful login, and
reads it back on every subsequent request to figure out who's making it —
"signed" meaning the server can detect if a user tried to edit the cookie's
contents themselves, because doing so would break the cryptographic
signature (computed using `SECRET_KEY` from file 03).

## `app/auth.py`, route by route

```python
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func

from .audit import log
from .db import db
from .forms import LoginForm, RegisterForm
from .models import User

bp = Blueprint("auth", __name__)


def _by_name(username):
    return db.session.query(User).filter(
        func.lower(User.username) == username.strip().lower()).first()
```

`bp = Blueprint("auth", __name__)` creates this file's blueprint (file 00's
glossary) — every route defined below with `@bp.route(...)` becomes part of
it, and `app/__init__.py` attaches the whole group to the running app in one
call (`app.register_blueprint(auth_bp)`, file 05). Every URL this blueprint
defines is reachable under names like `auth.login` (used with `url_for`)
rather than a bare `login`, which is what stops two different blueprints
from ever colliding if they happened to define a route with the same
function name.

`_by_name(username)` is a small helper, prefixed with an underscore by
convention to signal "this is private to this file, not meant to be
imported elsewhere." `func.lower(...)` is SQLAlchemy's way of calling the
database's own `LOWER()` SQL function as part of the query, and
`username.strip().lower()` does the matching normalisation on the Python
side before comparing — together, this makes username lookup
**case-insensitive** (`"Farooq"` and `"farooq"` are treated as the same
account) while `.strip()` additionally tolerates accidental leading/trailing
whitespace a user might paste in by mistake. `.first()` returns the single
matching row, or `None` if nothing matched — never an error just for
finding nothing.

### `login()`

```python
@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.jobs"))

    form = LoginForm()
    if form.validate_on_submit():
        user = _by_name(form.username.data)
        if user is None or not user.check_password(form.password.data):
            log("login_failed", detail=f"username={form.username.data!r}")
            db.session.commit()
            flash("Incorrect username or password.", "danger")
            return render_template("auth/login.html", form=form), 401
```

`methods=["GET", "POST"]` means this one route function handles *both*
displaying the empty login form (a `GET` request, when the page is first
loaded) and processing a submitted form (a `POST` request) — a very common
Flask pattern, distinguishing the two cases internally rather than needing
two separate routes.

If someone who's already signed in visits `/login` again, they're
immediately redirected to the jobs list rather than shown a login form
again — there's nothing useful for them to do there.

`form.validate_on_submit()` (file 01's WTForms section) is `True` only on a
`POST` request where every field passed its validators (username present,
password present). Inside that block: look up the user by name; if either
the user doesn't exist *or* the password doesn't match, do the exact same
thing either way — log a `"login_failed"` audit event, flash the message
**"Incorrect username or password"**, and return a 401 status. The comment
in the real source explains the security reasoning behind that
"either way, same message" choice directly: telling an attacker *which*
half was wrong (a real username but wrong password, versus a username that
doesn't exist at all) would hand them a **user-enumeration oracle** — a way
to silently check which usernames exist on the system at all, one guess at
a time, purely from the wording of the error.

```python
        if not user.is_active:
            log("login_denied", detail="account disabled", user=user)
            db.session.commit()
            flash("That account is disabled.", "danger")
            return render_template("auth/login.html", form=form), 403

        login_user(user, remember=form.remember.data)
        log("login", user=user)
        db.session.commit()
```

If the credentials *did* match, but the account has been deliberately
disabled (`User.is_active`, file 04), the login is still refused, with a
distinct, honest message and a distinct audit action name
(`"login_denied"`) — this case genuinely is different from a wrong
password, and there's no user-enumeration risk in saying so, because the
attacker would already have needed the correct password to reach this
branch at all.

Only past both of those checks does `login_user(user, remember=...)`
actually run — this is the single call that establishes the session, the
one moment `current_user` starts meaning something for this browser going
forward. `remember=form.remember.data` reads the "Stay signed in" checkbox
(file 01's Flask-Login section) and, if checked, tells Flask-Login to set a
longer-lived cookie that survives the browser being closed and reopened,
rather than one that expires the moment the browser session ends.

```python
        nxt = request.args.get("next", "")
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = url_for("main.jobs")
        return redirect(nxt)

    return render_template("auth/login.html", form=form)
```

`request.args.get("next", "")` reads a `?next=/some/page` query parameter —
this is how Flask-Login's automatic redirect-to-login (file 05,
`login.login_view`) tells the login page where to send someone *back to*
after they successfully sign in, so trying to visit a protected page while
signed out and then logging in lands you back where you were headed, rather
than dumping you on a generic default page. The validation right below it
is a genuine, deliberate security check, and the comment explains exactly
what it's defending against: an **open redirect**. If `nxt` were trusted
blindly, an attacker could craft a link like
`/login?next=https://evil-site.example/steal-password` — a real link to
*this* trusted site's own login page, which a user might reasonably click,
that would then redirect them somewhere malicious immediately after a
successful login. Requiring `nxt` to start with a single `/` (a path on
*this* site) and rejecting anything starting with `//` (which browsers can
interpret as "same scheme, different host" — still an open redirect risk
despite superficially looking like a relative path) closes that hole.
Anything that fails those checks falls back to the safe, known destination,
`main.jobs`.

### `register()`

```python
@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.jobs"))

    form = RegisterForm()
    if form.validate_on_submit():
        if _by_name(form.username.data):
            flash("That username is taken.", "warning")
            return render_template("auth/register.html", form=form)

        user = User(username=form.username.data.strip(), email=form.email.data or None)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        log("register", user=user)
        db.session.commit()

        flash("Account created. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)
```

Same "already signed in? skip ahead" guard. If the username is already
taken (checked via the same case-insensitive `_by_name` helper), the form
is shown again with a warning rather than a hard error — the analyst just
needs to pick a different name.

Building the new `User`: `email=form.email.data or None` is a small but
meaningful piece of Python — `form.email.data` is an empty string `""` if
the field was left blank (`Optional()` in `forms.py`, covered below, allows
that), and `"" or None` evaluates to `None` because an empty string is
"falsy" in Python. This matters because it stores a genuine SQL `NULL`
for "no email given" rather than an empty string, which is the cleaner,
more honest representation. `user.set_password(...)` is the `User` method
from file 04 that immediately hashes the plain password — at no point does
the plain password touch the database.

`db.session.add(user)` stages the new row; `db.session.flush()` sends it to
the database immediately (assigning it a real `id`) *without* fully
committing the transaction yet — done here specifically so `log("register",
user=user)` right after it can reference `user.id`, which wouldn't exist
yet without the flush. `db.session.commit()` then finalises everything —
both the new user row and the audit log entry — together, as one durable
transaction. Notably, registration does **not** automatically log the new
user in; it redirects to the login page instead, requiring them to sign in
explicitly with the credentials they just created.

### `logout()`

```python
@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log("logout")
    db.session.commit()
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))
```

Two details worth noticing. First, `methods=["POST"]` only — there is no
`GET` version of this route at all, meaning simply *visiting* `/logout` in
a browser (or being tricked into loading it as an image, a classic
CSRF-style attack against a `GET`-based logout) does nothing; only an
actual form submission works, and `base.html`'s logout button (file 13) is
a real `<form method="post">` with a CSRF token, not a plain link.

Second, the order of operations: `log("logout")` records the audit event
*before* `logout_user()` actually clears the session, specifically so
`current_user` is still the real, signed-in user at the moment `log()`
reads it (`audit.py`, below, defaults to `current_user` when no user is
explicitly passed) — reversing that order would silently record the logout
event with no user attached.

## `app/forms.py` — the two auth-related forms

```python
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Stay signed in")
    submit = SubmitField("Sign in")
```

Each field is declared once, as a class attribute, with its label (shown to
the user) and its list of validators. `Length(max=64)` matches the
`db.String(64)` column size from `models.py` exactly — a deliberate
consistency, catching an over-long username before it ever reaches the
database rather than letting the database itself reject it with a less
friendly error.

```python
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 64)])
    email = StringField("Email", validators=[Optional(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12)])
    confirm = PasswordField("Confirm password",
                            validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create account")
```

`Length(3, 64)` requires a username between 3 and 64 characters — WTForms'
`Length` accepts `min` and `max` either as keyword arguments or as the
first two positional ones. `email`'s only validators are `Optional()` and a
max length — genuinely no format checking at all, and the comment in the
real source explains a real, specific reason why: WTForms' own `Email()`
validator raises a bare `Exception` unless a separate `email_validator`
package happens to be installed, which would 500 (crash) the *entire*
registration route the moment anyone tried to register, rather than
failing gracefully — and since nothing in this project ever actually sends
mail to that address, a strict format check wasn't judged worth adding a
whole extra dependency for. `password` requires a minimum of 12 characters
— a real, meaningful minimum-strength requirement, not just "not empty."
`confirm`'s `EqualTo("password")` validator automatically fails if it
doesn't exactly match whatever was typed into the `password` field, which
is the standard "confirm password" pattern.

## `app/audit.py` — the whole file

```python
from flask import has_request_context, request
from flask_login import current_user

from .db import db
from .models import AuditLog


def log(action, detail=None, job=None, user=None):
    if user is None and has_request_context() and current_user.is_authenticated:
        user = current_user

    ip = None
    if has_request_context():
        ip = request.remote_addr

    db.session.add(AuditLog(
        user_id=getattr(user, "id", None),
        job_id=getattr(job, "id", None) if job is not None else None,
        action=action, detail=detail, ip=ip))
```

This entire file is one function, and it's a good example of a small,
focused utility used everywhere something security-relevant happens
(logins, uploads, report downloads — you'll see `log(...)` called again in
file 07 and file 12). Its parameters are all designed around real use:
`action` is a short name (`"login"`, `"upload"`, `"report_download"`),
`detail` is optional free text for extra context, `job`/`user` let a caller
explicitly say which job or user this event concerns when that's known.

`has_request_context()` is a genuinely important guard: it checks whether
this code is currently running *inside* an active Flask web request at all.
This matters because `log()` gets called from places that are **not**
always inside a request — for instance, `jobs.recover_orphans()` (file 07)
runs at application startup, entirely outside any browser request, where
`current_user` and `request` wouldn't be meaningful (or might even raise an
error if accessed). Guarding both `current_user.is_authenticated` and
`request.remote_addr` behind this check is what lets the exact same `log()`
function work correctly both inside a live request and from background/
startup code.

`getattr(user, "id", None)` reads `.id` off whatever `user` turned out to
be, but returns `None` instead of crashing if `user` is `None` itself (a
plain `user.id` would raise an `AttributeError` on `None`) — a small,
common Python defensive pattern. Note that `log()` calls `db.session.add(...)`
but **never** calls `db.session.commit()` itself — every caller shown in
`auth.py` above explicitly commits afterward. This is a deliberate
separation: `log()` only *stages* the audit row; whether and when it
actually becomes permanent is left to the calling code, which usually wants
to commit the audit entry together with whatever other change (the new
user row, the login state) triggered it, as one atomic transaction.

## Check your understanding

**Q1. Why does `login()` show the exact same error message,
"Incorrect username or password," whether the username doesn't exist at
all or the password was simply wrong?**

A: To avoid a user-enumeration vulnerability — if the message revealed
*which* half was wrong, an attacker could feed in a list of guessed
usernames and learn, one at a time and with certainty, which ones are real
registered accounts on the system, purely from the wording of the error,
without ever needing a correct password.

**Q2. What specifically stops someone from crafting a link like
`https://this-site/login?next=https://evil.example` and using it to
redirect a victim somewhere malicious right after they log in?**

A: The check `if not nxt.startswith("/") or nxt.startswith("//"):` in
`login()`. A full external URL like `https://evil.example` doesn't start
with a single `/`, so it fails the first condition and gets replaced with
the safe default (`main.jobs`). The second condition additionally catches
`//evil.example`-style values, which some browsers would still interpret as
pointing to a different host despite superficially looking like a relative
path.

**Q3. `logout()` only accepts `POST` requests, never `GET`. What specific
kind of problem does that prevent?**

A: It stops logout from being triggered just by *visiting* the URL — for
example, by a malicious page embedding `<img src="https://this-site/logout">`,
which a browser would automatically request the moment the page loaded, for
any visitor who happened to be signed in at the time. Requiring a real
`POST` (which additionally needs a valid CSRF token, from `form.hidden_tag()`
or the hand-written hidden field in `base.html`) means logout can only
happen from a genuine form submission on this site's own page.

**Q4. Why does `audit.py`'s `log()` function check
`has_request_context()` before touching `current_user` or `request`?**

A: Because `log()` is called from code that doesn't always run inside a
live web request — for instance, from startup code that recovers orphaned
jobs when the server boots, long before any browser has made a request.
`current_user` and `request` are only meaningful (and safe to access)
inside an active request; the guard lets the same function be safely
reused both inside a request and from background/startup contexts.

**Q5. `register()`'s form stores `email=form.email.data or None` rather
than just `email=form.email.data`. What real difference does that make in
the database, and why does it matter?**

A: If the email field was left blank, `form.email.data` is an empty string
`""`. Because an empty string is "falsy" in Python, `"" or None` evaluates
to `None`, so the stored value is a genuine SQL `NULL` ("no email
provided") rather than an empty-but-present string. It's a small
correctness detail: `NULL` unambiguously means "not given," whereas an
empty string could be mistaken elsewhere in the codebase for "given, and
happens to be empty."
