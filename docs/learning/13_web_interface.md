# 13 — The Web Interface: Templates, Styling, and the Remaining Routes

This file covers everything a browser actually renders: the Jinja2
templates under `app/templates/`, the stylesheet under `app/static/`, and
the handful of `routes.py` functions not already covered in file 07
(upload) and file 12 (report/export).

## What Jinja2 templating actually is

Flask uses **Jinja2** (bundled with Flask itself, not a separately-chosen
library) as its templating engine. A template is an HTML file with two
extra kinds of syntax mixed in: `{{ ... }}` for printing a Python value
directly into the page, and `{% ... %}` for control flow — loops,
conditionals, template inheritance. When `render_template("job_detail.html",
job=job, results=results, ...)` (file 07, file 12) runs, Jinja2 takes that
HTML file, substitutes every `{{ job.filename }}`-style expression with the
real value from the Python variables passed in, evaluates every `{% if %}`/
`{% for %}` block, and produces a plain string of final HTML — that string
*is* what gets sent back to the browser as the actual HTTP response body.
Critically, Jinja2 **auto-escapes** any value it prints this way by
default: if `job.filename` happened to contain HTML-special characters
(like `<script>`), Jinja2 automatically converts them into their harmless
text-equivalent form before inserting them into the page, which is what
prevents a maliciously-named uploaded file from being able to inject its
own executable JavaScript into the page that displays it — a real security
property, not just a formatting convenience.

## Template inheritance: `base.html`

```html
<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  ...
  <link rel="stylesheet" href="{{ url_for('static', filename='vendor/bootstrap.min.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='app.css') }}">
</head>
<body>

<nav class="fx-nav">
  ...
  {% if current_user.is_authenticated %}
    <a ... href="{{ url_for('main.dashboard') }}">Dashboard</a>
    <a ... href="{{ url_for('main.jobs') }}">Jobs</a>
    <a ... href="{{ url_for('main.upload') }}">Upload</a>
    ...
    <form method="post" action="{{ url_for('auth.logout') }}" class="d-inline">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button class="btn btn-sm btn-outline-secondary">Sign out</button>
    </form>
  {% else %}
    <a ... href="{{ url_for('auth.login') }}">Sign in</a>
    <a ... href="{{ url_for('auth.register') }}">Create account</a>
  {% endif %}
</nav>

{% block shell %}
<main class="container py-4">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, msg in messages %}
      <div class="alert alert-{{ category }} py-2">{{ msg }}</div>
    {% endfor %}
  {% endwith %}

  {% block content %}{% endblock %}
</main>
{% endblock %}

<script src="{{ url_for('static', filename='vendor/bootstrap.bundle.min.js') }}"></script>
{% block scripts %}{% endblock %}
</body>
</html>
```

`base.html` is the shell **every other page template extends** — the
`<!doctype html>`, the `<head>` linking Bootstrap and this project's own
`app.css` (both loaded from `static/vendor/` and `static/`, file 01 covers
why these are vendored rather than loaded from a CDN), and the navigation
bar are all written exactly once, here, rather than repeated in every
individual page.

`{% if current_user.is_authenticated %}` uses Flask-Login's `current_user`
proxy (file 06) directly inside a template — the exact same object routes
use — to decide which navigation links to show: a signed-in analyst sees
Dashboard/Jobs/Upload plus a sign-out button, a signed-out visitor sees
Sign in/Create account instead. The sign-out button is a real
`<form method="post">` (file 06 already explained *why* logout has to be a
POST, not a plain link), and `{{ csrf_token() }}` inside a hidden input
supplies the CSRF token this specific hand-written form needs, since it
isn't built through a `FlaskForm` class the way the login/register/upload
forms are (file 01's Flask-WTF section covers `form.hidden_tag()`, the
equivalent shortcut those real form objects use).

`{% block shell %}...{% endblock %}` and, nested inside it, `{% block
content %}{% endblock %}` are Jinja2's **inheritance** mechanism —
`{% block name %}` marks a named, replaceable region. A child template
(like `dashboard.html`) declares `{% extends "base.html" %}` at its very
top, then defines its own `{% block content %}...its real page
content...{% endblock %}`, and Jinja2 splices that content into exactly
that spot inside `base.html`'s structure, while everything else in
`base.html` (the head, the nav, the flash-message loop) stays identical
across every page. `landing.html` overrides the *outer* `shell` block
entirely instead of just `content` (covered below) — because it wants a
different overall page layout (no `<main class="container">` wrapper) for
its full-width hero section.

`{% with messages = get_flashed_messages(with_categories=true) %}` pulls in
whatever messages were queued by a `flash(message, category)` call
somewhere in the route that led to this page (file 06's login/register,
file 07's upload) — `with_categories=true` retrieves both the message text
and its category (`"success"`, `"danger"`, `"warning"`, `"info"`) together,
which is what lets `class="alert alert-{{ category }}"` map directly onto
Bootstrap's own colour-coded alert styles.

`{% block scripts %}{% endblock %}` is an empty block by default, deferred
right before `</body>` — any child page that needs its own JavaScript
(most do, for live polling or charts) defines its own `{% block scripts
%}...{% endblock %}`, which gets appended after Bootstrap's own script is
already loaded, guaranteeing Bootstrap's JavaScript is always available
first.

## `routes.py`: `dashboard()` and `jobs()`

```python
@bp.route("/dashboard")
@login_required
def dashboard():
    from .models import COMPLETED, Result

    rows = (db.session.query(Job)
            .filter_by(user_id=current_user.id)
            .order_by(Job.created_at.desc())
            .all())
    done = [j for j in rows if j.status == COMPLETED]

    sev = Counter()
    for r in (db.session.query(Result)
              .join(Job).filter(Job.user_id == current_user.id).all()):
        sev[r.severity or "Unrated"] += 1

    stats = {
        "jobs": len(rows), "running": sum(1 for j in rows if j.status in ("PENDING", "RUNNING")),
        "disk": sum(1 for j in done if j.artifact == DISK),
        "memory": sum(1 for j in done if j.artifact == MEMORY),
        "files": sum(j.files_scanned or 0 for j in done),
        "flagged": sum(j.files_flagged or 0 for j in done),
        "bytes": sum(j.size_bytes or 0 for j in done),
    }
    return render_template("dashboard.html", stats=stats, recent=rows[:8],
                           severity_counts=sev)
```

This route computes every number `dashboard.html` displays, in plain
Python, entirely in memory — there's no separate "statistics" table
anywhere in the database (file 04); every dashboard number is derived fresh
from the same `jobs`/`results` rows every other page reads. `Counter()`
(from Python's standard library `collections` module) is a dictionary
subclass specialised for exactly this kind of tallying — `sev[severity] +=
1` for every result automatically starts each new key at zero the first
time it's seen, no manual `if key not in sev:` check needed.

Notice the query itself already filters to `filter_by(user_id=current_user.id)`
— this is where the "an analyst only ever sees their own jobs" rule (file
07's `_owned()` was the *per-job* enforcement of this; this is the *list*-
level enforcement of the same rule) actually gets applied for a whole-
account view. `stats["files"]`/`stats["flagged"]`/`stats["bytes"]` are all
computed only from `done` (completed jobs) — an in-progress job's numbers
aren't final yet and would misrepresent the totals if included.

```python
@bp.route("/jobs")
@login_required
def jobs():
    rows = (db.session.query(Job)
            .filter_by(user_id=current_user.id)
            .order_by(Job.created_at.desc())
            .all())
    worst = {j.id: max((r.severity for r in j.results if r.severity),
                       key=lambda s: SEVERITY_ORDER.get(s, 0), default=None)
             for j in rows}
    return render_template("jobs.html", jobs=rows, worst=worst)
```

The full jobs list — same ownership-filtered query, but every row shown,
not just eight. `worst` is a dictionary comprehension precomputing, for
every job, its single worst severity across all of its results (the same
"compare by `SEVERITY_ORDER` rank" idiom used throughout this project) —
computed once here in Python, rather than asking the template to repeat
that comparison logic itself for every row it renders.

### `dashboard.html` and `jobs.html`

`dashboard.html` renders the four `stats` values into small stat tiles
(`fx-stat` — one of `app.css`'s own custom CSS classes, covered below),
shows a severity doughnut chart (via Chart.js, file 01) **only if**
`severity_counts` is non-empty (`{% if severity_counts %}`), and lists the
eight most recent jobs in a small table, each linking to its own detail
page via `url_for('main.job_detail', job_id=job.id)` — this is Flask's
`url_for` again (file 01), building the actual URL from the route's name
rather than a hand-typed string, which means if the route's URL pattern
ever changed, every template link built this way would automatically stay
correct.

`jobs.html` shows every job in one sortable table, with a small piece of
plain client-side JavaScript for filtering:

```javascript
const box = document.getElementById("jobFilter");
const rows = [...document.querySelectorAll("#jobTable tbody tr")];
const none = document.getElementById("noMatch");
box.addEventListener("input", () => {
  const q = box.value.trim().toLowerCase();
  let shown = 0;
  for (const tr of rows) {
    const hit = !q || tr.dataset.filter.includes(q);
    tr.classList.toggle("d-none", !hit);
    shown += hit;
  }
  none.classList.toggle("d-none", shown > 0);
});
```

Each table row carries a `data-filter="..."` attribute (built server-side
in the template, from `job.filename|lower`, the job's type, and its
status) — this small script listens for typing in the search box and, for
every row, checks whether the typed text appears anywhere in that row's
pre-built filter string, hiding rows that don't match (`classList.toggle
("d-none", !hit)` — Bootstrap's own `d-none` utility class, applied or
removed depending on whether this row matched) and showing a "no job
matches" message if literally none did. This filtering happens entirely in
the browser, on data already loaded on the page — no additional request to
the server is made while typing.

## `job_detail()` — the busiest route in the project

```python
@bp.route("/jobs/<int:job_id>")
@login_required
def job_detail(job_id):
    from . import report
    from .forensics import baseline

    job = _owned(job_id)
    results = sorted(job.results,
                     key=lambda r: (-SEVERITY_ORDER.get(r.severity, 0), -r.probability))
    counts = Counter(r.severity or "Unrated" for r in results)
    return render_template("job_detail.html", job=job, results=results,
                           severity_counts=counts, baseline=baseline.info(),
                           severity_rank=lambda s: SEVERITY_ORDER.get(s, 0),
                           evidence=report.evidence_rows(job),
                           limitations=report.limitations(job))
```

This route pulls together content from nearly every layer covered so far:
`_owned(job_id)` (file 07) enforces ownership; results are sorted the same
"most severe, then most probable, first" way as the PDF (file 12);
`report.evidence_rows(job)` and `report.limitations(job)` (file 12) are
called **directly** — the literal, concrete mechanism by which this page
and the PDF share identical content, not just similarly-worded content.
`severity_rank=lambda s: SEVERITY_ORDER.get(s, 0)` passes a small function
*into* the template itself, letting the template call `severity_rank(r.
severity)` directly inside its own JavaScript-data-building logic (used for
the client-side sortable per-file table, below) without needing to
duplicate the `SEVERITY_ORDER` lookup as a separate piece of JavaScript
logic.

### Walking `job_detail.html`

**The hero block** (severity, findings count, live progress) is built from
several conditional sections. While a job is still running:

```html
{% if not job.done and job.status in ('PENDING', 'RUNNING') %}
<div class="card mb-3">
  <div class="card-body">
    <strong id="stageText">{{ job.stage or 'Queued' }}</strong>
    <div class="progress mb-2">
      <div id="stageBar" class="progress-bar progress-bar-striped progress-bar-animated"
           style="width: {{ job.progress_pct }}%"></div>
    </div>
    <p class="small text-body-secondary mb-0">This page updates itself.</p>
  </div>
</div>
{% endif %}
```

This block is only rendered at all while a job genuinely hasn't finished
yet — `job.stage` and `job.progress_pct` are exactly the two fields file
07's `_await()` mechanism keeps updating on the `Job` row while extraction
runs in the background. The `{% block scripts %}` at the bottom of this
same template is what actually keeps this content current *without* a full
page reload:

```javascript
setInterval(async () => {
  const r = await fetch(url);
  if (!r.ok) return;
  const j = await r.json();
  if (j.done) { location.reload(); return; }
  if (text && j.stage) text.textContent = j.stage;
  if (bar && j.progress_pct !== null) bar.style.width = j.progress_pct + "%";
}, 3000);
```

`setInterval(..., 3000)` runs this function every 3,000 milliseconds (3
seconds). `fetch(url)` — `url` being `{{ url_for('main.job_status',
job_id=job.id) }}`, this exact route covered next — makes a small
background HTTP request without navigating away from the page at all
(that's the entire point of the browser's `fetch` API), and the returned
JSON's `stage`/`progress_pct` values are written directly into the page's
existing text and progress-bar elements. If the job's `done` flag ever
comes back true, `location.reload()` triggers a full, normal page reload —
at that point the server will render the completed job's real results
instead of the "still running" view, which is far simpler than trying to
build the entire results display purely in JavaScript.

**When results exist**, the severity hero and, for memory jobs
specifically, the OOD note appear:

```html
{% if job.artifact == 'memory' %}
  {# Hard rule 22: memory leads with what was observed, never the probability. #}
  <p class="mb-2">
    {{ results[0].findings|length }} forensic indicator(s) observed in this capture.
    {{ results[0].severity_note or '' }}
  </p>
  {% if job.ood_count is not none %}
  <div class="fx-note fx-note-warn">
    <strong>Model verdict is secondary for memory captures.</strong>
    {{ job.ood_count }} of 55 features fall outside the range observed in the
    training data, so the model is extrapolating and its probability
    ({{ '%.4f'|format(results[0].probability) }}) is reported for reference only.
    ...
  </div>
  {% endif %}
{% else %}
  <p class="mb-0">{{ results[0].severity_note or 'No indicator categories matched.' }}</p>
{% endif %}
```

Notice this template literally has a comment (`{# ... #}`, Jinja2's own
comment syntax, stripped out and never sent to the browser at all) citing
"Hard rule 22" directly at the exact point in the page where that rule is
actually being enforced visually — the findings count and observed-
indicator language appears first, and the model's own probability, when
shown at all, is visually demoted into a distinctly-styled note box
(`fx-note fx-note-warn`) rather than being the headline number on the page.
This is the same evidence-led ordering already established in the PDF
(file 12), independently implemented here in the HTML, because both are
following the same underlying design rule even though this particular
paragraph's exact wording lives in the template rather than in
`report.py`.

**The per-file table** (disk jobs with more than one result) is
client-side sortable:

```javascript
table.querySelectorAll("th.fx-sort").forEach((th, col) => th.addEventListener("click", () => {
  const dir = th.dataset.dir === "asc" ? "desc" : "asc";
  ...
  const sign = dir === "asc" ? 1 : -1;
  const key = th.dataset.key;
  [...body.rows].sort((a, b) => {
    if (key === "sev") return sign * (a.dataset.sev - b.dataset.sev);
    const x = a.cells[col], y = b.cells[col];
    if (key === "num") return sign * (parseFloat(x.dataset.v) - parseFloat(y.dataset.v));
    return sign * x.textContent.trim().localeCompare(y.textContent.trim());
  }).forEach(tr => body.appendChild(tr));
}));
```

Every sortable column header carries a `data-key` (`"sev"`, `"num"`, or
`"text"`, set server-side in the template) telling this script *how* to
compare two rows for that column — a plain text comparison
(`localeCompare`), a numeric comparison (reading a `data-v` attribute the
template also writes onto each cell, avoiding needing to re-parse
formatted, comma-separated display text back into a number), or, for
severity specifically, comparing the precomputed `severity_rank(...)` value
the route already passed in (stored as `data-sev` on each row) rather than
trying to compare the severity *text* alphabetically, which would sort
"Critical" and "Low" in the wrong order relative to their actual meaning.
`[...body.rows]` copies the table's live row collection into a plain
JavaScript array (spreading it with `...`) so `.sort()` can be called on
it, and `.forEach(tr => body.appendChild(tr))` re-inserts every row back
into the table body in its new sorted order — appending an element that's
already in the DOM elsewhere *moves* it, rather than duplicating it, which
is what makes this whole re-sort visually happen in place.

**Evidence and limitations** at the bottom of the page simply loop over
exactly what the route passed in:

```html
{% for heading, columns, rows, total, shown in evidence %}
...
{% endfor %}

<h2 class="h5 mt-4 mb-2">Scope and limitations</h2>
<div class="card">
  <div class="card-body small">
    {% include "_limitations.html" %}
  </div>
</div>
```

`{% include "_limitations.html" %}` pulls in the shared partial template
covered next, right here, inline. This is the literal template-level half
of the "PDF and web page can never structurally drift apart" guarantee
already discussed in file 12.

## `_limitations.html` — the whole file

```html
{% for heading, paragraphs in limitations %}
  <h3 class="h6 mt-3">{{ heading }}</h3>
  {% for text in paragraphs %}
    <p class="text-body-secondary mb-1">{{ text }}</p>
  {% endfor %}
{% endfor %}
```

This entire file is five lines, and its simplicity is exactly the point —
it contains **zero actual limitations content of its own**. It's a purely
mechanical rendering of whatever `report.limitations(job)` (file 12)
returned, looped over generically. Every single sentence a reader actually
sees under "Scope and limitations" comes from `report.py`, not from this
template — which is precisely why editing the wording of a limitation only
ever needs to happen in one place, and why it's structurally impossible for
this template to accidentally show different content than the PDF does.

## `job_status()` — the tiny endpoint the polling script calls

```python
@bp.route("/jobs/<int:job_id>/status")
@login_required
def job_status(job_id):
    job = _owned(job_id)
    return {"id": job.id, "status": job.status, "error": job.error,
            "done": job.done, "duration": job.duration,
            "stage": job.stage, "progress_pct": job.progress_pct,
            "files_scanned": job.files_scanned, "files_flagged": job.files_flagged,
            "ood_count": job.ood_count, "results": len(job.results)}
```

Returning a plain Python dictionary directly from a Flask route is a
built-in convenience — Flask automatically serializes it to a JSON HTTP
response, without needing to call `json.dumps(...)` or set the content type
by hand. The comment right above this route in the real source explains
its deliberately narrow scope: "counts only. The per-file table can run to
hundreds of rows and the page polls this every few seconds until the job
settles" — sending the *entire* results list on every 3-second poll, for a
disk job with hundreds of flagged files, would be wasteful; this endpoint
exists purely to answer "what's the current status," and the browser only
does a full page reload (which fetches the real, full results) once,
exactly when the job actually finishes.

## `upload.html`, `confirm_type.html`, `error.html`, and the auth templates

`upload.html`'s drag-and-drop area is plain vanilla JavaScript, no library
involved:

```javascript
drop.addEventListener("drop", ev => {
  if (ev.dataTransfer.files.length) {
    input.files = ev.dataTransfer.files;
    show();
  }
});
```

`ev.dataTransfer.files` is the browser's own built-in way of exposing
whatever file(s) were physically dragged onto an element; assigning them
directly onto the real, hidden `<input type="file">` element's `.files`
property is what makes the browser treat a drag-and-dropped file exactly
as if the user had picked it through the normal file-picker dialog — the
form submission behaves identically either way.

`confirm_type.html` is a small, focused page shown only when a job's status
is `NEEDS_TYPE` (file 04, file 07) — it explains directly, in plain
language, *why* the system couldn't tell ("this is expected for raw memory
dumps... the absence of a disk signature is not proof of anything on its
own" — the same honest framing already established in `artifacts.sniff()`
itself, file 07), then presents the `ConfirmTypeForm`'s two radio choices.

`error.html` is the generic template both `@app.errorhandler` functions in
`app/__init__.py` (file 05) render — a bare `code` and `message`, with a
single link back to the homepage; deliberately minimal, since an error page
by definition might be reached in a state where more elaborate content
can't be trusted to render correctly.

`auth/login.html` and `auth/register.html` (already introduced structurally
in file 06's discussion of the routes behind them) are both simple, single-
card forms — worth noting here only that `register.html` loops generically
over its form fields (`{% for field in [form.username, form.email,
form.password, form.confirm] %}`) rather than writing out four nearly-
identical blocks by hand, and specifically renders any validation errors
attached to each field (`{% for err in field.errors %}`) directly beneath
it — this is standard Flask-WTF error handling: after a failed
`validate_on_submit()`, each field object carries its own list of
human-readable validation failure messages, ready to display.

## `app/static/app.css` — the project's own design system

```css
:root {
  --fx-bg: #0d1117;
  --fx-panel: #141a22;
  --fx-ink: #e6edf3;
  --fx-dim: #8b98a8;
  --fx-accent: #4c8dff;

  --fx-critical: #f4516c;
  --fx-high: #f0932b;
  --fx-medium: #4cc9e6;
  --fx-low: #6b7c93;
}

[data-bs-theme="dark"] {
  --bs-body-bg: var(--fx-bg);
  --bs-body-color: var(--fx-ink);
  --bs-border-color: var(--fx-line);
  --bs-primary: var(--fx-accent);
  ...
}
```

`:root { --name: value; }` defines **CSS custom properties** (informally
"CSS variables") — named values that can be reused anywhere else in the
stylesheet via `var(--name)`, and, importantly, can be reassigned in one
place to restyle everything that references them. This project defines its
own small palette (`--fx-bg`, `--fx-panel`, `--fx-ink`, etc.) once, and then
maps several of Bootstrap's *own* variables (`--bs-body-bg`, `--bs-primary`,
etc., prefixed `--bs-` because they're Bootstrap's own naming convention)
directly onto this project's custom ones — this is what lets the whole
Bootstrap framework's components (buttons, cards, forms) automatically pick
up this project's specific dark colour scheme, without needing to override
every individual Bootstrap component's styling by hand.

```css
.sev-Critical { color: var(--fx-critical); }
.sev-High     { color: var(--fx-high); }
.sev-Medium   { color: var(--fx-medium); }
.sev-Low      { color: var(--fx-low); }
.bg-sev-Critical { background: var(--fx-critical); }
...
```

Four severity-specific colours, each exposed as both a text-colour class
(`sev-*`, used for badges and headline verdict text) and a background-
colour class (`bg-sev-*`, used for the coloured accent bar down the side of
the severity hero block, and for chart segments) — this is the **one
place** this project's severity colour scale is actually defined; the
inline `<script>` blocks in `dashboard.html` and `job_detail.html` that
configure Chart.js's doughnut charts (file 01) duplicate these same four
hex values directly in JavaScript (Chart.js has no way to read a CSS custom
property for its own canvas-drawn chart segments), which is exactly the
kind of small, deliberate duplication worth being aware of — the comment
embedded in this project's own documentation notes this directly: "change
both together."

```css
.status-PENDING, .status-NEEDS_TYPE { color: var(--fx-high); }
.status-RUNNING   { color: var(--fx-medium); }
.status-COMPLETED { color: var(--fx-clean); }
.status-FAILED    { color: var(--fx-critical); }
.status-RUNNING::before { animation: fx-pulse 1.4s ease-in-out infinite; }

@keyframes fx-pulse { 0%, 100% { opacity: 1; } 50% { opacity: .25; } }

@media (prefers-reduced-motion: reduce) {
  .status-RUNNING::before { animation: none; }
}
```

Every job's status badge (`<span class="fx-status status-{{ job.status
}}">`, built directly from the literal status string stored on the `Job`
row, file 04) picks up its colour purely from CSS, keyed by that exact
string — no JavaScript involved in colouring a status badge at all.
`.status-RUNNING::before` targets a small dot rendered via the `::before`
pseudo-element (defined once, generically, for every `.fx-status` earlier
in the file, as a small circular block using `content: ""`), and gives it
a gentle pulsing animation (`@keyframes fx-pulse` fading its opacity up and
down) specifically for the running state, as a small, immediate visual cue
that something is actively in progress. The `@media
(prefers-reduced-motion: reduce)` block is a genuine accessibility
consideration: it detects a setting some users enable at the operating-
system level specifically because animation can trigger discomfort or
distraction for them, and disables just this one animation when that
preference is active, without needing any JavaScript or server-side logic
at all — pure CSS respecting a browser-exposed user preference.

## Check your understanding

**Q1. What does `{% block content %}{% endblock %}` in `base.html`
actually accomplish, and how does a page like `dashboard.html` make use of
it?**

A: It marks a named, empty placeholder region inside the shared page
shell. A child template that starts with `{% extends "base.html" %}` and
then defines its own `{% block content %}...its real content...{% endblock
%}` has that content spliced directly into that exact spot — everything
else in `base.html` (the `<head>`, the navigation bar, the flash-message
area) stays identical and is written only once, in one place, rather than
being copy-pasted into every individual page template.

**Q2. Why does the job-detail page poll a small, separate JSON endpoint
(`job_status()`) every few seconds while a job is running, instead of just
reloading the entire page on a timer?**

A: `job_status()` returns only a handful of small fields — status, stage,
progress percentage, a few counts — deliberately excluding the potentially
large full results list. Polling that small endpoint every 3 seconds is
cheap; reloading the *entire* page (including, for a disk job, a table that
could hold hundreds of rows) that often would be wasteful and could make
the page visibly flicker. A full reload only happens once, via
`location.reload()`, exactly when the polled status finally reports the
job as done.

**Q3. `_limitations.html` is five lines long and contains no actual
limitation text. Where does the real content it displays come from, and
why is the template built this way?**

A: Every word of the actual limitations content comes from
`report.limitations(job)` in `report.py` (file 12) — the template merely
loops generically over whatever that function returns. It's built this way
specifically so the web page and the PDF report can never structurally
diverge: since both call the exact same Python function to get their
content, there is only one place in the entire codebase where a limitation
paragraph's wording is ever actually written.

**Q4. Why does the severity colour scale defined in `app.css` need to be
duplicated as literal hex values inside the inline `<script>` blocks that
configure Chart.js, rather than being read from the stylesheet directly?**

A: Chart.js draws its doughnut charts onto an HTML `<canvas>` element using
JavaScript colour values it's given directly — a `<canvas>`'s drawing
commands have no way to reference a CSS custom property the way regular
HTML/CSS elements can. So the same four severity colours genuinely have to
be written twice: once in `app.css` (governing badges, the hero accent bar,
and general page styling) and once as plain hex strings inside each
chart-configuring script — a small, acknowledged duplication that has to be
kept in sync by hand whenever the colours change.

**Q5. If an uploaded file were maliciously named
`<script>alert('hacked')</script>.raw`, what specifically stops that from
executing as real JavaScript when the job's filename is later displayed on
the job-detail page?**

A: Jinja2's automatic HTML escaping. Every value inserted into a template
via `{{ ... }}` — including `{{ job.filename }}` — is, by default,
automatically converted so that HTML-special characters like `<` and `>`
are rendered as their harmless literal text equivalents rather than being
interpreted as real HTML/JavaScript by the browser. The malicious filename
would display on the page as inert, visible text reading
`<script>alert('hacked')</script>.raw`, not execute as a script.
