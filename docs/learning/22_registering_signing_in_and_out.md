# 22 — Registering, Signing In, and Signing Out

This file covers three separate, small functionalities that all live in
`app/auth.py` and share the same handful of helper functions — grouped
into one file because each one's call chain is short enough that three
separate files would mostly be white space, and seeing them together makes
the small differences between them easier to spot.

## Visual flow

```
REGISTER                              LOGIN                                LOGOUT
--------                              -----                                ------
register()            [routes]        login()              [routes]        logout()        [routes]
  -> form.validate_on_submit()          -> form.validate_on_submit()          -> log()
  -> _by_name()          (check taken)  -> _by_name()          (find user)    -> db.session.commit()
  -> User()                             -> user.check_password()              -> logout_user()
  -> user.set_password()                -> log()                              -> redirect(login)
  -> db.session.add()                   -> db.session.commit()
  -> db.session.flush()                 -> login_user()
  -> log()                              -> db.session.commit()
  -> db.session.commit()                -> redirect(jobs or "next")
  -> redirect(login)

  All sequential. No background work, no separate process, no
  separate thread anywhere in any of the three chains above.
```

## 1. Trigger

All three: an analyst's browser submitting a form — `POST /register`,
`POST /login`, or `POST /logout` — by clicking the corresponding button.

## 2. The full sequence, step by step

### Registering

**Step 1 — `register()`, `app/auth.py`.** The entry point. Plain
language: handles both showing the empty registration form (`GET`) and
processing a submitted one (`POST`). Why the whole functionality starts
here: nothing about creating an account happens anywhere else in the
codebase.

**Step 2 — `RegisterForm().validate_on_submit()`, from the `Flask-WTF`
library (§1), backed by the field definitions in `app/forms.py` (§6).**
Plain language: checks this was really a `POST` request and that every
field (username, password, confirm-password) passed its validators. Why
here: nothing below should run at all against invalid or incomplete data.
Input: the raw submitted form fields. Output: `True`/`False`; if `False`,
the whole chain stops right here and the form is re-shown with error
messages.

**Step 3 — `_by_name(form.username.data)`, `app/auth.py`.** Plain
language: a small private helper that looks up a user by username,
matching case-insensitively. Why here: to check the requested username
isn't already taken. Input: the typed username. Output: a `User` row, or
`None`. *Called from elsewhere?* Yes — `login()` (below) calls this exact
same function too, for a completely different reason (finding the account
to check a password against, rather than checking for a name clash). See
file 29.

**Step 4 — `User(username=..., email=...)`, `app/models.py` (§4).** Plain
language: constructs a new, not-yet-saved `User` object in memory. Input:
the cleaned username and optional email. Output: a new `User` instance,
not yet in the database.

**Step 5 — `user.set_password(form.password.data)`, `app/models.py`.**
Plain language: hashes the typed password (via Werkzeug's
`generate_password_hash`, §1, §6) and stores only that hash on the new
user object. Why here, immediately after construction: the plain password
must never be held anywhere longer than necessary, and never written to
the database at all.

**Step 6 — `db.session.add(user)`, then `db.session.flush()`.** Plain
language: stages the new row, then immediately sends it to the database
(without fully finishing the transaction yet) so it's assigned a real ID.
Why the flush happens here specifically: the very next step needs that
real ID to exist already.

**Step 7 — `log("register", user=user)`, `app/audit.py` (§6).** Plain
language: stages one new `AuditLog` row recording this registration. Why
here: needs the just-flushed user's real ID from step 6. *Called from
elsewhere?* Yes — extensively. `log()` is one of this whole codebase's most
reused functions; see file 29 for the complete list of every call site.

**Step 8 — `db.session.commit()`.** Plain language: makes both the new
user row and the new audit-log row permanent together, as one durable
unit. Output: nothing returned; the account now genuinely exists.

**Step 9 — `redirect(url_for("auth.login"))`.** The browser is sent to
the login page. **Registering never signs the new account in
automatically** — this is the deliberate end of this particular
functionality; signing in is a separate, subsequent action the analyst has
to take themselves.

### Logging in

**Step 1 — `login()`, `app/auth.py`.** The entry point.

**Step 2 — `form.validate_on_submit()`.** Same mechanism as registration's
step 2, applied to `LoginForm`.

**Step 3 — `_by_name(form.username.data)`.** The same shared helper from
registration, called here to find the account being logged into, not to
check for a name clash.

**Step 4 — `user.check_password(form.password.data)`, `app/models.py`.**
Plain language: hashes the typed password the same way `set_password` did
originally, and compares the two hashes (via Werkzeug's
`check_password_hash`, §1). Why here: this is the actual authentication
check — everything before it was just finding the right account to check.
Output: `True`/`False`.

**Step 5a (only if step 3 or 4 failed) — `log("login_failed", ...)`, then
`db.session.commit()`, then the exact same error message is shown either
way, before this chain ends here.** (§6 covers in full why the message is
deliberately identical whether the username or the password was wrong.)

**Step 5b (only if the account exists and the password is right, but the
account is disabled) — `log("login_denied", ...)`, then commit, then a
distinct message, chain ends here too.**

**Step 6 (only on genuine success) — `login_user(user, remember=form.
remember.data)`, from Flask-Login (§1, §6).** Plain language: this is the
actual moment a session is established — it writes the signed marker into
this browser's session cookie. Nothing before this point in the whole
`login()` chain has changed anything about who this browser is considered
to be; this single call is what does it.

**Step 7 — `log("login", user=user)`, then `db.session.commit()`.** Same
shared audit function as before, recording a successful login this time.

**Step 8 — redirect, honouring `?next=` if it's a genuinely safe local
path (§6's open-redirect explanation), otherwise `url_for("main.jobs")`.**

### Logging out

**Step 1 — `logout()`, `app/auth.py`.** The entry point — reachable only
via a `POST` request (§6 explains why a `GET`-based logout would be
unsafe).

**Step 2 — `log("logout")`.** Notice this runs *before* the session is
actually cleared, deliberately — `current_user` still resolves to the real
signed-in user at this exact moment, which is what lets the audit function
correctly default to recording *who* logged out (`log()`'s own logic,
covered in §6 and file 29, reads `current_user` automatically when no
explicit user is passed in).

**Step 3 — `db.session.commit()`.** Commits the audit row while the
session is still genuinely authenticated.

**Step 4 — `logout_user()`, from Flask-Login.** Plain language: this is
the moment the session is actually cleared — the exact reverse of
`login_user()` above.

**Step 5 — redirect to the login page**, with a flashed "Signed out"
message.

## 3. Sequential versus background/parallel

All three chains, in full, are entirely sequential — every single step
above genuinely waits for the one before it, on the one thread handling
that one HTTP request. Nothing in any of these three functionalities is
handed off to a background process or a separate worker anywhere — that
distinction only starts to matter starting with file 23 (upload) and
becomes central in files 24, 25, and 27.

## 4. Where this functionality starts and ends

**Registration starts** the moment a `POST /register` request arrives and
**ends** the instant the redirect response to `/login` is sent — the
analyst is not yet signed in at that point.

**Login starts** the moment a `POST /login` request arrives and **ends**
the instant the redirect response (to the jobs list, or wherever `?next=`
safely pointed) is sent — by this point the analyst genuinely is signed in,
and every subsequent request from this browser will carry that session
cookie automatically, which is what makes `@login_required` (used by every
route covered in files 23, 26, and 27) work without needing to repeat any
of this logic.

**Logout starts** the moment a `POST /logout` request arrives and **ends**
the instant the redirect to `/login` is sent — the analyst's session is
gone by that point.

## 5. Check your understanding

**Q1. `_by_name()` is called by both `register()` and `login()`. What is
it actually being used to check in each case, and why is it the exact same
function both times even though the two purposes sound different?**

A: In `register()`, it's used to check whether the requested username is
*already taken* (a match means "reject this registration"). In `login()`,
it's used to *find* the account the typed password should be checked
against (a match is expected and necessary — no match means the username
doesn't exist). Both purposes reduce to the identical underlying operation
— "look up a user row by username, case-insensitively" — so one shared
function correctly serves both, rather than two nearly-identical lookup
functions existing separately and risking drifting out of sync (for
instance, one becoming case-sensitive by accident while the other stays
case-insensitive).

**Q2. In the login chain, at what exact step does the browser actually
become "signed in," and what specifically happens at that step that makes
every later request from that browser carry that identity automatically?**

A: At `login_user(user, remember=form.remember.data)`, from the
Flask-Login library — this is the single call that writes a signed marker
into the browser's session cookie. Because the browser automatically sends
its cookies back on every subsequent request to the same site, and because
`create_app()` (file 21) already registered a `load_user()` function that
turns that cookie's stored ID back into a real `User` row on every request,
every later request from this same browser is automatically recognised as
this same signed-in analyst, with no further login step needed.

**Q3. Why does `logout()` call `log("logout")` and commit it to the
database *before* calling `logout_user()`, rather than after?**

A: Because `log()` automatically records whichever user is currently
signed in when it isn't explicitly told otherwise (reading `current_user`,
§6). If `logout_user()` ran first, the session would already be cleared by
the time `log()` ran, and `current_user` would no longer resolve to the
account that was actually logging out — the audit entry would be recorded
with no user attached at all, losing exactly the information a "who logged
out" audit record needs to be useful.
