# 12 — Reporting: `app/report.py`

This file turns everything computed in files 07–11 — a job's stored
`Result` and `Finding` rows — into the actual PDF an analyst downloads, and
into the data structures the web job-detail page (file 13) renders from.
The single most important idea in this file is that **the PDF and the web
page are never allowed to structurally drift apart**, because both are
built from the exact same handful of functions.

**A note on this file's own history, since it matters for reading the code
below honestly.** The report has been trimmed twice since it was first
built, both times a deliberate, dated, user-approved decision recorded in
`CLAUDE.md` §18 — not a regression. The fifth pass (2026-08-11) removed the
memory pipeline's "Model applicability" and "Reference environment and
scope" limitations paragraphs (the SMOTE/dataset-saturation caveat and the
Windows-10-x64 scope statement) — the reasoning being presented verbally at
viva instead of printed in every report. The sixth pass (same day) went
further: every remaining display of the raw out-of-distribution *number*
was removed too (it used to appear three more places — the executive
summary, the verdict-detail table, and the job-detail hero note — plus the
Appendix's list of the specific out-of-range feature names), and the whole
document was given a real typographic and colour system, described in its
own section below. **None of this touched the underlying gate.**
`memory.ood()`/`dominant_ood()` (file 08) still compute exactly the same
thing, still decide exactly the same way whether the model's probability
can be trusted — only what gets *printed* about that decision changed.

## The mandatory-strings mechanism, and what it's actually for

```python
REQUIRED_ALWAYS = [
    "Scope and limitations",
]
REQUIRED_DISK = []
REQUIRED_MEMORY = []
```

These three lists exist so the automated test suite (file 14) can assert,
against the **actual rendered bytes of a real PDF**, that certain specific
pieces of honesty never silently disappear from a report — not because
someone remembered to check by eye, but because a test fails hard the
moment a required substring goes missing. The comment above them states
this plainly: "removing a limitation from the renderer fails the build
rather than quietly shipping a report that overstates its own confidence."

**Both `REQUIRED_DISK` and `REQUIRED_MEMORY` are empty today** — worth
understanding *why* that's not the same as "nothing is mandatory anymore."
`REQUIRED_ALWAYS`'s one entry, `"Scope and limitations"`, still forces that
whole section to exist on every report, for both pipelines — file 04's
`limitations()` (below) still unconditionally builds "Files not examined"
for every job, and "Extraction gaps" plus "Baseline for the observed
indicators" for every memory job. What changed across the fifth and sixth
passes wasn't *whether* the limitations section is mandatory — it still
is — it's *which specific sentences* within it the test suite pins down
word-for-word. Earlier drafts of this project pinned five specific memory
substrings (the SMOTE caveat, the scope statement, an out-of-distribution
sentence); today none of those specific sentences exist to pin, because
none of them are printed anymore. If you're reading an older version of
this curriculum, `CLAUDE.md` §18 is the authoritative, dated record of
exactly what was pinned, then unpinned, and why — trust that over any
snapshot of this file.

## `limitations()` — the single function both the PDF and the web page share

```python
def limitations(job):
    out = []

    skipped = job.skipped or []
    if skipped:
        reasons = {}
        for entry in skipped:
            reasons[entry["reason"]] = reasons.get(entry["reason"], 0) + 1
        lines = [f"{n} file(s): {reason}" for reason, n in
                 sorted(reasons.items(), key=lambda kv: -kv[1])]
        out.append(("Files not examined",
                    ["An analyst must be able to tell 'scanned and clean' from 'never "
                     "examined'. The following were skipped:"] + lines))
    else:
        out.append(("Files not examined", ["None recorded."]))
```

`limitations(job)` returns a list of `(heading, [paragraph, ...])` pairs —
a simple, generic structure that both the PDF renderer (below) and the
`_limitations.html` template (file 13) can loop over identically, which is
exactly what makes it impossible for the two to structurally diverge: there
is only one place this content is actually assembled.

The first section, "Files not examined," is built for **every** job type,
disk or memory, and it's built to answer a specific, important question
directly: not just *how many* files were skipped, but *why*, grouped and
counted (`reasons[entry["reason"]] = reasons.get(entry["reason"], 0) + 1`
is a manual tally — building a count per distinct reason string — sorted
so the most common reason for skipping appears first). Even when nothing
was skipped, the section still appears, explicitly saying so ("None
recorded.") — this section is never simply absent, which matters because
an *absent* section could be mistaken for "the developer forgot this job
type," whereas an explicit "none recorded" is an honest, positive
statement that nothing needed disclosing.

```python
    if job.artifact == MEMORY:
        gaps = job.extraction_gaps or []
        missing = [g for g in gaps if g["confidence"] == "missing"]
        inferred = [g for g in gaps if g["confidence"] == "inferred"]

        lines = []
        if missing:
            lines.append(f"{len(missing)} feature(s) could not be produced by Volatility 3 "
                         "at all and were emitted as 0.0 rather than estimated:")
            lines += [f"{g['field']} — {g['reason']}" for g in missing]
        else:
            lines.append("No features were missing.")
        if inferred:
            lines.append(f"{len(inferred)} further feature(s) carry a value whose "
                         "derivation was reconstructed from the reference data rather "
                         "than documented by the dataset authors:")
            lines += [f"{g['field']} — {g['reason']}" for g in inferred]
        out.append(("Extraction gaps", lines))
        out.append(("Baseline for the observed indicators", [baseline.NOTE]))

    return out
```

For memory jobs only, the extraction gaps (file 10 covers exactly how
`extraction_gaps` gets built, feature by feature) are split into the two
distinct categories the extractor itself already tags them with — features
genuinely **missing** (Volatility 3 simply has no equivalent, emitted
honestly as `0.0`) versus features whose value was emitted but whose exact
**derivation** was reconstructed rather than documented by the original
dataset authors. Presenting these as two visibly separate lists, each with
its own count and its own explanation, is a small but deliberate honesty
choice — collapsing them into one undifferentiated list would blur "we
genuinely couldn't measure this at all" together with "we measured
something, but aren't 100% certain our reconstruction of its meaning is
exactly right," which are two different levels of confidence worth
distinguishing.

**This is the whole function, for a memory job — two sections, always.**
`baseline.NOTE` (file 11 — the standing note that these indicators only
mean something when substantially elevated or seen in combination) is
still printed unconditionally. What used to follow it — a "Model
applicability" section (the out-of-distribution count plus the SMOTE
caveat) and a "Reference environment and scope" section (the Windows-10-x64
scope statement) — is gone as of the fifth pass; nothing was left in its
place, because both of those sections' entire content was the paragraph
being removed, so there was nothing left to head a section with. For a
disk job, `limitations()` still returns just the one "Files not examined"
section — nothing else currently applies, unchanged from before either
pass.

## `evidence_rows()` — the same "shared function" pattern, for per-process locators

```python
EVIDENCE_SECTIONS = [
    ("injected_regions", "Injected executable memory",
     ("Process", "PID", "Region", "Size", "Protection", "Parent process"),
     lambda d: (d.get("process") or "?", d.get("pid"),
                f"{d.get('start') or '?'}–{d.get('end') or '?'}",
                f"{d['size']:,} B" if d.get("size") else "?",
                d.get("protection") or "?", _parent_cell(d))),
    ...
]

def evidence_rows(job):
    data = job.evidence or {}
    totals = data.get("totals", {})
    out = []
    for key, heading, columns, render in EVIDENCE_SECTIONS:
        items = data.get(key) or []
        if not items:
            continue
        out.append((heading, columns, [render(d) for d in items],
                    totals.get(key, len(items)), len(items)))
    return out
```

`EVIDENCE_SECTIONS` is a small, data-driven table — for each of the four
evidence categories `extractors/memory.py`'s `evidence()` function (file
10) produces, it defines the section's heading, its table column names,
and a small `lambda` (an anonymous function, used here purely as a compact
way to describe "how do I turn one evidence dictionary into one table
row") that formats one item into a row of display values. Every row also
runs through `_parent_cell(d)` where a parent process applies — a small
helper (defined just above `EVIDENCE_SECTIONS` in the real source) that
resolves a locator's parent process name and PID into one plain-ASCII cell
like `"python.exe, PID 4400"`, falling back to `"unknown, PID 4400"` or
`"n/a"`. Its own docstring records a real lesson worth knowing: an earlier
draft rendered `"name (pid)"` with real parentheses, which ReportLab
escapes inside a PDF's text streams — silently breaking any check that
scans the raw stream for an exact substring, the same trap the old
`SCOPE_STATEMENT` string had to be written around before it was removed.
Swapping to a comma-separated format sidesteps it entirely.

`evidence_rows(job)` loops over `EVIDENCE_SECTIONS`, skips any category
with nothing to show, and returns `(heading, columns, rows, total, shown)`
tuples — `total` being the true full count (from `job.evidence["totals"]`,
file 10) and `shown` being how many rows are actually included (after the
25-per-category cap already applied back in the extractor) — this is
exactly what lets both the PDF and the web page honestly say "showing the
first 25 of 267" rather than silently under-reporting how much was
actually found.

## `_summary()` — building the executive summary, per pipeline

```python
def _summary(job, results):
    flagged = [r for r in results if r.malicious]
    worst = max((r.severity for r in results if r.severity),
                key=lambda s: SEVERITY_ORDER.get(s, 0), default=None)

    if job.artifact == DISK:
        if not flagged:
            body = (f"{job.files_scanned or 0:,} files were examined and "
                    f"{len(results)} executable(s) analysed. None crossed the "
                    "detection threshold.")
        else:
            tags = sorted({f.tag for r in flagged for f in r.findings if f.tag})
            body = (f"{len(flagged)} of {len(results)} executable(s) analysed were "
                    f"flagged. The behaviours most consistent with the detections are: "
                    f"{', '.join(tags) if tags else 'not characterised'}. Each flagged "
                    "file is listed below with its full path and SHA-256 so it can be "
                    "retrieved for manual examination.")
        return worst, body
```

`worst` is computed once, using `max(...)` with a `key` function drawing on
`SEVERITY_ORDER` (file 04) — this is the same "compare by a computed
numeric rank rather than by the raw string" pattern seen throughout the
project. For disk, the summary body is genuinely different depending on
whether anything was flagged at all — a clean image gets a short, factual
statement of how many files were examined; a flagged image gets a summary
naming every distinct behaviour tag found across every flagged file
(`{f.tag for r in flagged for f in r.findings if f.tag}` — a set
comprehension nested across two loops: for every flagged result, for every
finding in that result, collect its tag if it has one, automatically
deduplicating), plus a direct pointer to the path-and-hash detail below,
matching hard rule 16's requirement that a flagged file must always be
actionable.

```python
    tags = sorted({f.tag for r in results for f in r.findings if f.tag})
    body = ("This report leads with what was observed in the capture rather than with a "
            "model score. ")
    body += (f"The artifacts present are consistent with: {', '.join(tags)}. "
             if tags else "No indicator categories matched. ")
    if job.ood_count:
        body += ("The model's own verdict is reported for reference only: this capture "
                 "falls outside the range it was trained on.")
    return worst, body
```

The memory summary is structurally distinct in exactly the way hard rule
22 demands: its very first sentence states the report's own ordering
principle directly, in plain English, rather than simply *following* that
principle silently. Tags are gathered the same way as disk's (but for
memory there's always exactly one `Result` row, file 04, so the loop is
simpler). And only as the *last* sentence, and only when the capture is
out of distribution at all, does the model's own probability get mentioned
— worded explicitly as "for reference only," never presented as the
headline finding, and — since the sixth pass — **without printing the
actual out-of-distribution number**. `if job.ood_count:` still gates
whether this sentence appears at all (so a fully in-distribution capture,
`ood_count == 0`, correctly says nothing here), but the sentence itself no
longer states how many of the 55 features triggered it — that specific
digit was the thing removed; the qualitative disclosure ("this capture
falls outside the range it was trained on") survives.

## `render()` — assembling the actual PDF

```python
def render(job, compress=True, generated_by=None):
    st = _styles()
    generated_by = generated_by or job.user.username
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Forensic report - job {job.id}",
                            leftMargin=25 * mm, rightMargin=25 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            pageCompression=1 if compress else 0)
    results = sorted(job.results,
                     key=lambda r: (-SEVERITY_ORDER.get(r.severity, 0), -r.probability))
    flow = []
```

`compress` defaults to `True` for real use, but the comment explains
exactly why it exists as a parameter at all: the test suite (file 14) calls
`render(job, compress=False)` specifically so it can search the PDF's
actual internal page-content streams for the mandatory strings covered
above, without needing a full PDF-parsing library the project otherwise has
no use for — ReportLab's page-compression, when enabled, would leave those
strings inside binary-compressed data that a simple text search couldn't
find at all; turning it off keeps the underlying text readable while
changing nothing about the report's actual visible content.

`generated_by` is the analyst who requested *this specific rendering* —
distinct in principle from `job.user` (the job's owner), even though every
route that can reach `render()` already enforces the two being the same
person (`_owned()` in `routes.py`). Callers with a real request context
(`routes.py:report()`) pass `current_user.username` explicitly; callers
with none — `scripts/verify_pipeline.py`, the test suite — get an honest
fallback to the job's own owner instead of a blank or a crash.

`results` are sorted **most severe first, and within equal severity, most
probable first** — this uses the same descending-tuple sort pattern
(negating both values so Python's normal ascending sort produces a
descending order) already seen in `Result.rank` (file 04) and in
`routes.py` (file 07/13). `flow` is simply a plain Python list that every
subsequent piece of the report gets appended onto — ReportLab's own
convention (file 01) is to build up a whole document as one big ordered
list of elements, then hand the whole list to `doc.build(...)` once, right
at the very end.

## The type and colour system — `_styles()`, `_rule()`, `_kv()`, `_table()`

This is new as of the sixth pass (2026-08-11) — before it, the PDF used
ReportLab's own default sample stylesheet with a handful of ad-hoc grey
hex codes scattered through the file (`#dddddd` here, `#666666` there,
`#f0f0f0` somewhere else), each chosen independently with no shared
reasoning. The whole document now draws from one small, named palette:

```python
INK_HEX = "#1b2430"        # body text
INK_SOFT_HEX = "#5c6b7a"   # muted labels, captions, footer
ACCENT_HEX = "#2c5a82"     # section headings
RULE_HEX = "#b9c6d3"       # section dividers - a tint of the accent, not full strength
PANEL_HEX = "#eef1f4"      # table header fill
LINE_HEX = "#d7dde3"       # table grid / kv row dividers
ZEBRA_HEX = "#f7f9fb"      # alternate row tint on multi-row tables

SEVERITY_HEX = {
    "Critical": "#b0273f", "High": "#b8650b", "Medium": "#1d7690", "Low": "#5c6b7a",
}
```

The comment above these constants explains the specific choice behind the
severity colours: they sit in the **same hue family** as the web
dashboard's own severity scale (`app/static/app.css`'s `--fx-critical`,
`--fx-high`, `--fx-medium`, `--fx-low`), just deepened for legibility on
white paper rather than the dashboard's dark background — critical is
still recognisably red, high still amber, medium still teal, low still a
muted slate — so an analyst who has looked at the dashboard and then opens
the PDF isn't reading two unrelated colour languages for the same concept.
`_sev_hex(severity)` looks a severity string up in this table, falling
back to plain `INK_HEX` for an unrated result rather than guessing a
colour for a state that doesn't map to any real severity.

```python
def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=21, leading=24, textColor=INK, spaceAfter=3),
        ...
        "h": ParagraphStyle("h", parent=base["Heading2"], fontName="Helvetica-Bold",
                            fontSize=13, leading=16, textColor=ACCENT, ...),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName="Helvetica-Bold",
                             fontSize=10.5, leading=13, textColor=INK, ...),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=9, leading=13,
                            textColor=INK, ...),
        "small": ParagraphStyle("sm", ..., fontSize=7.6, leading=10.5, textColor=INK),
        "label": ParagraphStyle("lb", ..., fontSize=7.6, leading=10.5, textColor=INK_SOFT),
    }
```

Every style still builds on ReportLab's own `getSampleStyleSheet()` bases
(`base["Title"]`, `base["Heading2"]`, `base["Heading3"]`, `base["Normal"]`
— file 01 covers what these are), the same as before — nothing about
*where the styles come from* changed, only *what each one specifies*. The
practical effect of the new hierarchy: a genuinely large, bold title;
section headings that are visibly bolder and coloured (`ACCENT`), clearly
outranking the smaller, still-bold-but-neutral-coloured `h3` subheadings;
and body text nudged up slightly (8.6pt → 9pt for paragraphs, 7.4pt →
7.6pt for table cells) for readability. `"label"` is new — it exists so
`_kv()`'s key column can be visibly de-emphasised (`INK_SOFT`) relative to
its value column (`INK`), a small but real hierarchy cue that a plain grey
key/value table didn't have before. The old `"mono"` style was deleted —
it existed for exactly one purpose, printing the Appendix's out-of-range
feature list in a monospace font, and that block no longer exists.

```python
def _rule(flow):
    flow.append(HRFlowable(width="100%", thickness=0.75, spaceBefore=14, spaceAfter=9,
                           color=RULE))
```

A tiny helper, but a meaningful one: every numbered section in the
document used to open with its own separately-typed
`HRFlowable(width="100%", thickness=0.5, spaceBefore=10, spaceAfter=2,
color=colors.HexColor("#dddddd"))` call, repeated six times with the
values hand-copied each time — genuinely error-prone if a future edit
needed to change the spacing or colour, since it would have to be changed
identically in six places. `_rule(flow)` is called before every section
heading now (including "1. Chain of custody," which didn't get a rule
before the sixth pass — the header block now reads as one more section
among equals rather than a special case), so the whole document's
divider rhythm is guaranteed consistent by construction, not by six
separate people remembering to copy the same four numbers correctly.

```python
def _table(data, col_widths, zebra=True):
    t = Table(data, colWidths=col_widths)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    if zebra and len(data) > 2:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]))
    t.setStyle(TableStyle(style))
    return t
```

The findings table (section 4, per result) and the per-process evidence
tables (section 5) both used to build their own near-identical
`Table`/`TableStyle` pair inline, with the same grey backgrounds and grid
lines as everything else. `_table()` consolidates that into one function,
and adds one real visual improvement neither table had before: light
**zebra striping** (`ROWBACKGROUNDS`, alternating white and a barely-there
`ZEBRA` tint) on any table with more than one data row, so a long findings
or evidence table stays scannable at a glance rather than reading as one
undifferentiated grid — the classic hallmark of a table designed to be
*read*, not just *rendered*. It's gated on `len(data) > 2` (header row plus
at least two data rows) so a table with only one real row of data — where
alternating stripes would carry no information — doesn't get one anyway.
`_kv()` (the two-column key/value table used for chain-of-custody, verdict
detail, and the appendix) deliberately does **not** go through `_table()`
— it keeps its own distinct look (a light `LINEBELOW` divider between rows,
no grid, no header band), because a key/value block and a genuine data
table are different kinds of content and reading as visually different
things is the correct signal, not an inconsistency to fix.

## Severity colour, applied where severity is stated

```python
    flow.append(Paragraph(
        f"<font color='{_sev_hex(severity)}'><b>Overall severity: "
        f"{severity or 'not scored'}</b></font>", st["p"]))
```

The executive summary's headline severity line, and each per-result
finding block's leading `<b>{severity}</b> · probability ...` line
(section 4), are both coloured through `_sev_hex()` now — Critical reads
in a deep red, High in amber, Medium in teal, Low in slate, consistently
everywhere severity is stated in the document, matching the same colours
the web dashboard already used. An unrated result (`severity is None`)
still prints "not scored" — the "never fall back to Low" reasoning from
before this pass is completely unchanged, only now that honest "not
scored" text is coloured with the same neutral `INK` a normal sentence
would be, rather than any severity colour, since it isn't one.

### Sections 1–5, unchanged in content, now uniformly ruled and coloured

Sections 1 (Chain of custody), 2 (Executive summary), 3 (Verdict detail),
4 (Findings), and 5 (Where these indicators were observed, memory-only) all
still exist in the exact same order, contain the exact same information
they did before the sixth pass, and are still built the same way —
`_kv()` for key/value blocks, `_table()` (formerly inline `Table`/
`TableStyle`) for the findings and evidence tables, `KeepTogether` so one
result's whole findings block never splits awkwardly across a page. The
one content change inside this range: **Verdict Detail's memory-only table
no longer carries a "Features out of training range" row.** That row
existed purely to print the same raw OOD number the sixth pass removed
everywhere else; removing the row (rather than leaving a label with no
value) was the only sensible option once the number itself had to go.
Section numbering is still computed dynamically (`scope_no = 6 if sections
else 5`) for exactly the reason it always was — section 5 only exists for
a memory job with real per-process evidence to show, so "Scope and
limitations" and "Appendix" renumber accordingly rather than ever
colliding on the same section number.

### Scope and limitations, and the Appendix

```python
    flow.append(PageBreak())
    flow.append(Paragraph(f"{scope_no}. Scope and limitations", st["h"]))
    for heading, paragraphs in limitations(job):
        flow.append(Paragraph(heading, st["h3"]))
        for text in paragraphs:
            flow.append(Paragraph(text, st["small"]))
            flow.append(Spacer(1, 2))

    _rule(flow)
    flow.append(Paragraph(f"{scope_no + 1}. Appendix", st["h"]))
    if baseline.info():
        flow.append(Paragraph("Clean-system baseline", st["h3"]))
        info = baseline.info()
        flow.append(_kv([(k.replace("_", " ").capitalize(), v)
                         for k, v in info.items() if not isinstance(v, dict)], st))

    doc.build(flow, canvasmaker=_canvas_maker(job.sha256))
    return buf.getvalue()
```

`PageBreak()` still forces the limitations section to start on a fresh
page, unchanged. The loop over `limitations(job)` is still the *exact same
call* the web page's `_limitations.html` template makes (file 13) — still
the one place this content is assembled for both surfaces.

**The Appendix is shorter than it used to be.** It used to open with a
"Features outside the training range" subsection — the literal list of
out-of-range feature names (`job.ood_fields`), comma-joined in monospace.
That block is gone as of the sixth pass, for the same reason as everything
else removed that day: it was another way of displaying the out-of-
distribution information, just as a list of names rather than a count.
What's left is exactly the "Clean-system baseline" subsection — when a
clean baseline is currently loaded (file 11), a small key/value summary of
the baseline itself (its label, when it was captured, what OS/hypervisor/
tool produced it) — unchanged, and now the Appendix's only content.

`doc.build(flow, canvasmaker=_canvas_maker(job.sha256))` is the one call
that actually turns the accumulated `flow` list into real PDF bytes.
`_canvas_maker` (defined at the bottom of the file, alongside the
`_NumberedCanvas` class) is what adds the running "Page N of M" and the
artifact's own SHA-256 to the bottom of every single page — a small
top-to-bottom flourish, unrelated to any of the content changes above,
that was added in an earlier pass (CLAUDE.md §18's fourth) and is
untouched here beyond one visual tweak: the footer now sits below a thin
rule in the same muted `RULE` colour as the section dividers, rather than
floating with no visual anchor. Notice there's still no file ever written
to disk anywhere in this function, and nothing is cached — every single
time `routes.py:report()` is hit, this whole function runs fresh, from
whatever the database currently holds for that job.

## Check your understanding

**Q1. Why does `render()` accept a `compress` parameter at all, when
production code always wants a properly compressed PDF?**

A: Purely so the test suite can verify the report's actual text content —
including every mandatory limitation string — by searching the PDF's raw
page-content streams directly, without needing a full PDF-parsing library
this project has no other use for. With compression enabled (the normal,
production default), that text would be embedded inside binary-compressed
data a simple text search couldn't find; disabling it for tests keeps the
underlying text readable while producing an otherwise identical report.

**Q2. What structural fact about this codebase makes it genuinely
impossible — not just unlikely — for the PDF and the job-detail web page to
show different limitations content?**

A: Both are built by calling the exact same function, `report.limitations
(job)`. The PDF renderer loops over its return value directly inside
`render()`; the web page's `_limitations.html` template (file 13) loops
over the identical return value, passed in by the `job_detail` route. There
is only one place this content is ever assembled — nothing about either
rendering path recomputes or duplicates the logic independently.

**Q3. The sixth pass removed the raw out-of-distribution number from
every remaining place it was displayed. Does that mean hard rule 17
("never ship a memory verdict without the out-of-distribution count") is
no longer being followed?**

A: No — hard rule 17 is about the count being **computed and available**,
not about a specific digit being printed on the page. `memory.ood()` (file
08) still runs on every memory job, `job.ood_count` still gets stored on
every memory `Job` row, and it still gates whether the "for reference
only" sentence appears in the executive summary at all (`if job.ood_count:`
is unchanged). What changed is purely presentational: the specific number
of features that triggered the gate is no longer printed anywhere a reader
sees it. `tests/test_report.py`'s
`test_the_ood_count_is_computed_but_no_longer_displayed` asserts both
halves of this directly — the job genuinely has a real, nonzero
`ood_count`, and that number's digits are genuinely absent from the
rendered report.

**Q4. `flow.append(Paragraph(f"<font color='{_sev_hex(severity)}'><b>Overall
severity: {severity or 'not scored'}</b></font>", ...))` deliberately never
falls back to showing "Low" when `severity` is `None`. Why does that
specific choice matter, and is it affected by the sixth pass's colour
system?**

A: A missing severity means the scoring computation genuinely didn't run
or failed for some reason — it's a different situation from a computation
that ran and concluded the risk was low. Defaulting to "Low" in that
situation would silently misrepresent an unknown, unscored result as a
calm, reassuring one — exactly the wrong direction to fail in for a
forensic tool. This is completely unaffected by the new colour system:
`_sev_hex(None)` falls back to plain `INK_HEX`, the same neutral colour as
ordinary body text, specifically because "not scored" isn't one of the
four real severities and shouldn't visually borrow any of their colours —
coloured text here would itself misrepresent an absent result as a scored
one.

**Q5. Why does `_table()` apply zebra striping only when a table has more
than one data row, and why doesn't `_kv()` use `_table()` at all?**

A: Zebra striping exists to help a reader's eye track across many rows of
similar-looking data — with only one data row, there's nothing to track
between, so alternating a single row against nothing would add visual
noise without adding any real legibility. `_kv()` renders key/value blocks
(chain of custody, verdict detail, the appendix baseline summary) —
conceptually a short list of labelled facts, not a repeating dataset — so
it keeps its own distinct, simpler styling (light dividers, no grid, no
header band) on purpose. Making every table in the document look
identical wouldn't be more consistent; it would erase a real, useful
distinction between "here is a short list of facts about this job" and
"here is a table of many similar rows," which is exactly the kind of
structural signal a reader benefits from seeing represented differently.
