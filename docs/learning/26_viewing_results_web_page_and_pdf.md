# 26 — Viewing Results: the Web Job-Detail Page and the PDF Report

Two different functionalities, triggered two different ways, covered
together in one file because of exactly what makes them worth
understanding together: both of them call the **same two functions** —
`report.evidence_rows()` and `report.limitations()` — to get their
content, which is the concrete reason these two visibly very different
outputs (an HTML page, a downloadable PDF) can never structurally
disagree with each other.

## Visual flow

```
BROWSER PAGE VIEW                              PDF DOWNLOAD
------------------                             ------------
job_detail()              [routes.py]          report()                [routes.py]
  -> _owned(job_id)                              -> _owned(job_id)
  -> sort results                                -> renderer.render(job)   [report.py]
  -> Counter(severities)                              -> _summary(job, results)
  -> report.evidence_rows(job)   [report.py]           -> _kv(...)  (many times)
  -> report.limitations(job)     [report.py]           -> limitations(job)      <-- SAME FUNCTION
  -> render_template(                                  -> evidence_rows(job)    <-- SAME FUNCTION
       job_detail.html, ...)     [Jinja2]               -> doc.build(flow)
                                                    -> log("report_download")
                                                    -> return PDF bytes

  Both entirely sequential. Neither one hands anything off to a
  background thread or a separate process -- both build their whole
  output, start to finish, within the one request that asked for it.
```

## 1. Trigger

**Web page:** an analyst's browser requests `GET /jobs/<id>` — either by
following the redirect at the end of file 23's upload functionality, by
clicking a job in the dashboard or jobs list, or by the page's own
JavaScript triggering a full reload once a poll (file 27) reports the job
as finished.

**PDF:** an analyst clicks "PDF report" on an already-loaded job-detail
page, sending `GET /jobs/<id>/report.pdf`.

## 2. The full sequence, step by step

### The web page

**Step 1 — `job_detail(job_id)`, `app/routes.py`.** The entry point.

**Step 2 — `_owned(job_id)`, `app/routes.py`.** Plain language: fetches
the job and confirms it belongs to the signed-in analyst, returning a
plain 404 if not (§7's authorization pattern — the same helper file 23
uses too, and the same one `report()` below also calls). *Called from
elsewhere?* Yes, extensively — see file 29.

**Step 3 — sort `job.results`** by severity rank then probability, using
the same descending-tuple idiom seen throughout this project (§4, §13).

**Step 4 — `Counter(r.severity or "Unrated" for r in results)`**, from
Python's standard library. Tallies how many results fall into each
severity bucket, for the doughnut chart.

**Step 5 — `report.evidence_rows(job)`, `app/report.py`.** Plain
language: for a memory job, turns `job.evidence` (the capped, sorted
locator lists built all the way back in file 25's extraction step) into
`(heading, columns, rows, total, shown)` tuples ready for a table — one
per evidence category that actually has anything in it. For a disk job,
`job.evidence` is simply empty, so this returns an empty list. *Called
from elsewhere?* Yes — `report.render()` (the PDF path, below) calls this
exact same function too.

**Step 6 — `report.limitations(job)`, `app/report.py`.** Plain language:
builds the full `[(heading, [paragraph, ...])]` list — files not
examined, and, for memory jobs, extraction gaps, the out-of-distribution
count with its saturation caveat, the baseline note, and the
reference-environment scope statement (§12 covers every one of these
sections' content in full). *Called from elsewhere?* Yes — `report.
render()` calls this exact same function too. This is the literal
mechanism (not just a design description) behind "the web page and the
PDF can never structurally disagree" — there's only one place this
content is computed.

**Step 7 — `render_template("job_detail.html", job=job, results=results,
severity_counts=counts, baseline=baseline.info(), severity_rank=...,
evidence=..., limitations=...)`, Jinja2 (§13).** Everything gathered in
steps 2–6 is handed to the template, which loops over it — `{% for
heading, paragraphs in limitations %}`, `{% for heading, columns, rows,
total, shown in evidence %}` — producing the final HTML string sent back
to the browser. Nothing in the template itself computes any of this
content; it only arranges what was already computed above.

### The PDF

**Step 1 — `report(job_id)`, `app/routes.py`.** (Named `report` in the
route file, aliased as `renderer` where it's imported to avoid a name
clash with the `report.py` module itself.) The entry point.

**Step 2 — `_owned(job_id)`.** The exact same authorization helper as the
web page's step 2.

**Step 3 — `renderer.render(job)`, `app/report.py`.** Plain language:
builds a complete PDF, as raw bytes, from scratch, every single time this
is called — nothing about a report is ever cached (§12). Inside it, in
order:

- **Step 3a — `_summary(job, results)`, `app/report.py`.** Computes the
  overall severity and the executive-summary paragraph text — genuinely
  different wording depending on whether this is a disk or memory job
  (§12's full walkthrough of both branches).
- **Step 3b — repeated `_kv(...)` calls, `app/report.py`.** A small
  helper building two-column key/value tables — used for chain of
  custody, verdict detail, and per-file locator blocks. Not a
  functionality of its own, just a formatting helper called many times
  throughout `render()`.
- **Step 3c — `limitations(job)`, `app/report.py`.** The **exact same
  function**, called the **exact same way**, as the web page's step 6
  above — this is not a similar function, it is the identical one.
- **Step 3d — `evidence_rows(job)`, `app/report.py`.** Also identical to
  the web page's step 5.
- **Step 3e — `doc.build(flow)`, from the ReportLab library (§1, §12).**
  The one call that actually turns the whole accumulated list of
  paragraphs, tables, and spacers into real PDF byte content.

**Step 4 (back in the route) — `log("report_download", job=job, detail=
f"{len(pdf)} bytes")`, `app/audit.py` (§6).** *Called from elsewhere?*
Yes — the same shared audit function used throughout every other
functionality in this curriculum; see file 29.

**Step 5 — `db.session.commit()`, then the PDF bytes are returned** with
an `inline` `Content-Disposition` header, so the browser displays them
directly rather than forcing a download dialog.

## 3. Sequential versus background/parallel

Both chains are **entirely sequential, start to finish, within the one
request that triggered them** — this stands in direct contrast to files
23–25, where a background hand-off was the whole point. Neither viewing
the web page nor generating the PDF ever hands anything off to a separate
thread or process; both simply read already-finished data (the job's
`Result` and `Finding` rows, already fully computed by files 24 or 25 long
before either of these requests ever arrived) and format it.

## 4. Where this functionality starts and ends

**Web page starts** the moment `GET /jobs/<id>` arrives and **ends** the
moment the rendered HTML string is sent back to the browser.

**PDF starts** the moment `GET /jobs/<id>/report.pdf` arrives and **ends**
the moment the PDF bytes are sent back. Both are entirely self-contained,
single-request functionalities — neither one modifies the job's actual
analysis results at all; they only read and present what files 24/25
already produced.

## 5. Check your understanding

**Q1. If a memory job's `severity_note` text were somehow wrong, and you
fixed the bug that produced it, would you need to change anything in
`report.py`, `job_detail.html`, or both, to make the PDF and the web page
both show the corrected text?**

A: Neither — that text is computed by `severity.for_memory()` back in file
25's chain, long before either the web page or the PDF is ever requested,
and stored directly on the `Result` row. Both `render()` and
`job_detail()` simply read `result.severity_note` from the database as-is;
fixing the bug in `severity.py` (and re-running the job) is what would
actually change what both outputs show.

**Q2. What specifically would break, or start to disagree, if a future
change added a brand-new limitations paragraph directly inside
`job_detail.html`'s own template code, instead of adding it inside
`report.limitations()`?**

A: The web page would show the new paragraph, but the PDF would not — because
`render()` gets its limitations content by calling `report.limitations(job)`
directly, which wouldn't know anything about content added only inside the
template. This is exactly the kind of structural drift the current design
(both callers using the one shared function) is built to prevent.

**Q3. Both `job_detail()` and `report()` call `_owned(job_id)` as their
very first real step. What does that call actually protect against, and
what HTTP status code does an analyst see if they try to view or download
a job that exists but belongs to someone else?**

A: It protects against one analyst viewing or downloading another
analyst's job results. `_owned()` checks that the job both exists and
belongs to the currently signed-in user; if either check fails, it raises
a plain 404 Not Found — deliberately not a 403 Forbidden, so that an
outside observer can't even tell the difference between "this job doesn't
exist" and "it exists, but isn't yours" (§7).
