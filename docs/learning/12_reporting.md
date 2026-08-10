# 12 — Reporting: `app/report.py`

This file turns everything computed in files 07–11 — a job's stored
`Result` and `Finding` rows — into the actual PDF an analyst downloads, and
into the data structures the web job-detail page (file 13) renders from.
The single most important idea in this file is that **the PDF and the web
page are never allowed to structurally drift apart**, because both are
built from the exact same handful of functions.

## The mandatory-strings mechanism, and what it's actually for

```python
REQUIRED_ALWAYS = [
    "Scope and limitations",
]
REQUIRED_DISK = []
REQUIRED_MEMORY = [
    "out of the 55 features",
    "unusually high separability",
    "SMOTE",
    "controlled reference environment",
    "per-machine clean baseline",
]
```

These three lists exist purely so the automated test suite (file 14) can
assert, against the **actual rendered bytes of a real PDF**, that certain
specific pieces of honesty never silently disappear from a report — not
because someone remembered to check by eye, but because a test fails hard
the moment any of these substrings is missing. The comment above them
states this plainly: "removing a limitation from the renderer fails the
build rather than quietly shipping a report that overstates its own
confidence." Notice these lists were **trimmed** relatively recently — a
comment records that the triage-note, lief-version caveat, and MITRE
disclaimer paragraphs that used to be required here were deliberately
removed from the report's content (a UI/report design decision, not a
change to any underlying fact), and their required substrings were removed
from these lists to match. `REQUIRED_DISK` is now empty — there's nothing
disk-specific this project currently forces into every disk report beyond
the one item in `REQUIRED_ALWAYS`.

`REQUIRED_MEMORY`'s five entries map directly onto specific, hard-won
findings from earlier in this project's development, each one covered
elsewhere in this curriculum: the out-of-distribution count (hard rule 17,
file 08), the dataset-saturation caveat (CLAUDE.md §2, referenced below),
and the reference-environment scope statement (CLAUDE.md §11.1). These
aren't arbitrary strings — each one is a specific, previously-litigated
piece of honesty this project has decided must never silently disappear
from a memory report again.

## `SATURATION_CAVEAT` and `SCOPE_STATEMENT` — the two paragraphs behind those required strings

```python
SATURATION_CAVEAT = (
    "The benchmark dataset behind the memory model, CIC-MalMem-2022, shows unusually "
    "high separability: 21 of its 55 features individually exceed 0.95 AUC. Its benign "
    "half was balanced using SMOTE oversampling, so a substantial part of it is "
    "interpolated rather than captured, and interpolated points cannot exceed the range "
    "of the samples they were drawn from. Reported benchmark performance should be read "
    "in that light, and real-world performance may differ substantially.")
```

This paragraph is the report-facing summary of one of this project's most
significant investigation findings (CLAUDE.md §2 covers the full story):
the memory model's apparently perfect test performance was traced not to
an unusually good model, but to the training dataset itself — its benign
half was heavily supplemented with SMOTE-generated synthetic data (points
mathematically interpolated between real examples, which structurally
cannot ever exceed the range of the real points they were drawn from),
meaning the model partly learned to distinguish "real capture" from
"interpolated point" rather than purely "benign" from "malicious." This
text exists specifically so that anyone reading a memory report — not just
someone who has read the full CLAUDE.md investigation history — encounters
this caveat directly, every single time.

```python
SCOPE_STATEMENT = (
    "Demonstrated on a controlled reference environment (Windows 10 x64). Severity is "
    "calibrated against a per-machine clean baseline and is valid for that machine. "
    "Cross-machine deployment would require a per-machine baseline established in "
    "advance.")
```

This is the report-facing wording of CLAUDE.md §11.1's binding scope
decision — the memory pipeline only genuinely supports one specific,
controlled reference machine, and its severity scoring (file 11's baseline
comparison) is only meaningful for a capture of that same machine. The
comment right above it in the real source flags a small but genuinely
important technical detail: the fragments checked by `REQUIRED_MEMORY`
("controlled reference environment", "per-machine clean baseline")
deliberately contain **no parentheses** — because `scripts/verify_pipeline.py`
(file 14) checks these strings against the *raw, uncompressed PDF byte
stream*, where ReportLab escapes literal parentheses as `\(` internally —
a fragment spanning `"(Windows 10 x64)"` would pass a Python-level test
that strips parentheses out first, but fail that stricter raw-byte check.
Both fragments were deliberately chosen to be parenthesis-free so they pass
both kinds of check consistently.

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
so the most common reason for skipping appears first). CLAUDE.md's own
wording for why this section exists at all is embedded directly in the
text itself: "an analyst must be able to tell 'scanned and clean' from
'never examined'." Even when nothing was skipped, the section still
appears, explicitly saying so ("None recorded.") — this section is never
simply absent, which matters because an *absent* section could be mistaken
for "the developer forgot this job type," whereas an explicit "none
recorded" is an honest, positive statement that nothing needed disclosing.

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

```python
        ood = job.ood_count
        if ood is not None:
            out.append(("Model applicability", [
                f"{ood} out of the 55 features fall outside the range observed in the "
                "training data. On those inputs the model is extrapolating and its "
                "probability should be treated as low-confidence. The findings above "
                "are direct measurements of this capture and do not depend on it.",
                SATURATION_CAVEAT]))
        out.append(("Baseline for the observed indicators", [baseline.NOTE]))
        out.append(("Reference environment and scope", [SCOPE_STATEMENT]))

    return out
```

The out-of-distribution count (file 08's `model.ood()`, hard rule 17) gets
its own section, directly paired with `SATURATION_CAVEAT` — the two pieces
of context genuinely belong together: "here's how far outside its training
range this specific capture is" immediately followed by "and here's why
the training range itself is narrower and more separable than it should
honestly be." `baseline.NOTE` (file 11 — the standing note that these
indicators only mean something when substantially elevated or seen in
combination) and `SCOPE_STATEMENT` round out the memory-only sections. For
a disk job, `limitations()` returns just the one "Files not examined"
section — nothing else currently applies.

## `evidence_rows()` — the same "shared function" pattern, for per-process locators

```python
EVIDENCE_SECTIONS = [
    ("injected_regions", "Injected executable memory",
     ("Process", "PID", "Region", "Size", "Protection"),
     lambda d: (d.get("process") or "?", d.get("pid"),
                f"{d.get('start') or '?'}–{d.get('end') or '?'}",
                f"{d['size']:,} B" if d.get("size") else "?",
                d.get("protection") or "?")),
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
row") that formats one item into a row of display values. `evidence_rows(job)`
loops over that table, skips any category with nothing to show, and returns
`(heading, columns, rows, total, shown)` tuples — `total` being the true
full count (from `job.evidence["totals"]`, file 10) and `shown` being how
many rows are actually included (after the 25-per-category cap already
applied back in the extractor) — this is exactly what lets both the PDF and
the web page honestly say "showing the first 25 of 267" rather than
silently under-reporting how much was actually found.

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
        body += (f"The model's own verdict is reported for reference only: {job.ood_count} "
                 "of its 55 inputs fall outside the range it was trained on.")
    return worst, body
```

The memory summary is structurally distinct in exactly the way hard rule
22 demands: its very first sentence states the report's own ordering
principle directly, in plain English, rather than simply *following* that
principle silently. Tags are gathered the same way as disk's (but for
memory there's always exactly one `Result` row, file 04, so the loop is
simpler). And only as the *last* sentence, and only when the out-of-
distribution count is nonzero, does the model's own probability get
mentioned at all — worded explicitly as "for reference only," never
presented as the headline finding.

## `render()` — assembling the actual PDF

```python
def render(job, compress=True):
    st = _styles()
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

`results` are sorted **most severe first, and within equal severity, most
probable first** — this uses the same descending-tuple sort pattern
(negating both values so Python's normal ascending sort produces a
descending order) already seen in `Result.rank` (file 04) and in
`routes.py` (file 07/13). `flow` is simply a plain Python list that every
subsequent piece of the report gets appended onto — ReportLab's own
convention (file 01) is to build up a whole document as one big ordered
list of elements, then hand the whole list to `doc.build(...)` once, right
at the very end.

### Section 1 — Chain of custody

```python
    flow.append(Paragraph("1. Chain of custody", st["h"]))
    flow.append(_kv([
        ("Artifact", job.filename),
        ("SHA-256", f"<font face='Courier' size='7'>{job.sha256}</font>"),
        ...
        ("Retention", "The uploaded artifact is retained indefinitely on the analysis "
                      f"host as <font face='Courier' size='7'>{job.stored_name}</font>, "
                      "so the SHA-256 above remains verifiable against it."),
    ], st))
```

`_kv(rows, st)` (a small helper defined earlier in the file) builds a
two-column key/value table using ReportLab's `Table`/`TableStyle` (file 01)
— every row here maps directly to something a chain-of-custody section is
expected to answer forensically: what the file was called, its real
hash, its size, its determined type, who ran it, when, how long it took,
and — the "Retention" row specifically — an honest statement that the
uploaded artifact is kept indefinitely and exactly what it's stored as,
directly grounding the project's no-purge retention policy in each
individual report rather than leaving it as an undocumented property of the
hosting system.

### Section 2 — Executive summary

```python
    severity, summary = _summary(job, results)
    flow.append(Paragraph("2. Executive summary", st["h"]))
    flow.append(Paragraph(f"<b>Overall severity: {severity or 'not scored'}</b>", st["p"]))
    flow.append(Paragraph(summary, st["p"]))
```

Straightforward — call `_summary()`, print its severity and its body. The
comment right above the severity line is worth noting directly: "never
fall back to Low. An absent severity means it could not be computed, and
defaulting to the reassuring end of the scale is the wrong direction to
fail in." `severity or 'not scored'` deliberately shows an honest "not
scored" rather than letting `None` silently coerce into something that
*looks* like a real, calm result — a subtle but important failure-mode
choice: if severity scoring genuinely broke for some reason, the report
should say so plainly, not quietly claim everything is fine.

### Section 3 — Verdict detail

```python
    flow.append(Paragraph("3. Verdict detail", st["h"]))
    if job.artifact == MEMORY and results:
        r = results[0]
        flow.append(Paragraph(
            "For memory captures the model score is a secondary triage signal, not the "
            "headline. It is shown here with the applicability check that governs it.",
            st["p"]))
        flow.append(_kv([
            ("Model", "XGBoost, 55 features, memory pipeline"),
            ("Probability", f"{r.probability:.4f}"),
            ("Operating threshold", f"{r.threshold:.10f}"),
            ("Raw verdict", "malicious" if r.malicious else "benign"),
            ("Features out of training range", f"{job.ood_count} of 55"),
            ("Severity basis", r.severity_note or "n/a"),
        ], st))
```

This is where hard rule 22's ordering becomes concretely visible in the
document's own structure: the model's actual probability is genuinely
present in the report (the project's own trained model is a real
deliverable and belongs in the report), but it appears here, in **section
3**, only after the executive summary (section 2) has already led with
observations — never as the headline. The sentence right above the number
states the reason directly, in the report itself, rather than assuming an
analyst already knows this project's design philosophy. `threshold` is
printed to ten decimal places (`{r.threshold:.10f}`) specifically because
the real threshold (`0.2336726188659668`) is a long, precise value, and
truncating it in display would misrepresent exactly what was actually
compared against.

```python
    else:
        flow.append(_kv([
            ("Model", "LightGBM, 150 of 2,381 EMBER features, disk pipeline"),
            ("Operating threshold",
             f"{results[0].threshold:.10f}" if results else "n/a"),
            ("Executables analysed", len(results)),
            ("Flagged", sum(1 for r in results if r.malicious)),
            ("Files examined", f"{job.files_scanned or 0:,}"),
        ], st))
```

Disk's verdict detail is a simple summary table — there's no equivalent
ordering concern here, because disk severity genuinely is verdict-led
(file 11), so leading with the model's own numbers in this section is
consistent with, not in tension with, how disk results are actually
scored.

### Sections 4–5 — Findings, and per-process evidence

```python
    flow.append(Paragraph("4. Findings", st["h"]))
    if not results:
        flow.append(Paragraph("No results were recorded for this job.", st["p"]))
    for r in results:
        block = [Paragraph(
            f"<b>{r.severity or 'Unrated'}</b> &middot; probability "
            f"{r.probability:.4f} &middot; {r.path or 'whole memory dump'}", st["h3"])]
        if r.severity_note:
            block.append(Paragraph(r.severity_note, st["small"]))
        if r.file_sha256:
            block.append(Spacer(1, 3))
            block.append(_kv([...], st))
```

For every result, a small `block` list is built up first, then wrapped in
`KeepTogether(block)` before being appended to `flow` — the earlier
introduction to ReportLab (file 01) already covered what `KeepTogether`
does: it's a hint to ReportLab's page-layout engine not to split this one
result's whole findings block awkwardly across a page boundary, keeping a
single file's severity, notes, locators, and findings table together as
one visual unit. The `if r.file_sha256:` block only appears at all for
disk results (memory's single result row has no per-file locators, file 04)
— this is a direct, concrete instance of hard rule 16, printing SHA-256,
MD5, size, inode, byte offset, allocation status and MACB timestamps for
every result that has them.

```python
    volumetric = (job.volumetric or {}) if job.artifact == MEMORY else {}
    if volumetric.get("note"):
        flow.append(Paragraph("Configuration context", st["h3"]))
        flow.append(Paragraph(volumetric["note"], st["small"]))
        flow.append(Spacer(1, 6))
```

The comment right above this in the real source states the reasoning
directly: "kept visually apart from the findings above so it is never read
as an indicator. It cannot reach severity by construction" (file 11 covered
exactly why that "cannot" is architecturally true, not just a promise).
Placing this content in its own clearly-labelled section, physically
separated from the findings list, reinforces visually what's also true
structurally — a reader shouldn't be able to mistake a "your machine has
more services than the baseline" observation for a real finding.

```python
    sections = evidence_rows(job) if job.artifact == MEMORY else []
    scope_no = 6 if sections else 5

    if sections:
        flow.append(Paragraph("5. Where these indicators were observed", st["h"]))
        flow.append(Paragraph(
            "These are the processes, addresses and modules behind the indicators "
            "above, so they can be examined directly in the capture.",
            st["p"]))
        for heading, columns, rows, total, shown in sections:
            head = f"{heading} — {total}"
            if shown < total:
                head += f", showing the first {shown}"
            ...
```

Section numbering is computed **dynamically** (`scope_no = 6 if sections
else 5`) precisely because the per-process evidence section only exists at
all for memory jobs that actually have some evidence to show — the comment
explains this directly: "so Scope and Appendix renumber accordingly rather
than colliding on '5'." This is a small but genuinely careful detail: a
disk report and an empty memory report both correctly show "5. Scope and
limitations," while a memory report *with* evidence correctly shows that
same content as section 6, because section 5 was legitimately used for
"Where these indicators were observed" instead — no report ever has two
different sections both claiming to be "5."

### Section — Scope and limitations, and the Appendix

```python
    flow.append(PageBreak())
    flow.append(Paragraph(f"{scope_no}. Scope and limitations", st["h"]))
    for heading, paragraphs in limitations(job):
        flow.append(Paragraph(heading, st["h3"]))
        for text in paragraphs:
            flow.append(Paragraph(text, st["small"]))
            flow.append(Spacer(1, 2))

    flow.append(Paragraph(f"{scope_no + 1}. Appendix", st["h"]))
    if job.artifact == MEMORY and job.ood_fields:
        flow.append(Paragraph("Features outside the training range", st["h3"]))
        flow.append(Paragraph(", ".join(job.ood_fields), st["mono"]))
        flow.append(Spacer(1, 4))
    if baseline.info():
        flow.append(Paragraph("Clean-system baseline", st["h3"]))
        info = baseline.info()
        flow.append(_kv([(k.replace("_", " ").capitalize(), v)
                         for k, v in info.items() if not isinstance(v, dict)], st))

    doc.build(flow)
    return buf.getvalue()
```

`PageBreak()` forces the limitations section to start on a fresh page —
deliberately, so it always reads as its own clearly bounded unit rather
than blending visually into whatever findings content happened to end just
above it. The loop over `limitations(job)` here is the *exact same call*
the web page's `_limitations.html` template makes (file 13) — this is the
literal mechanism, not just a design description, by which the PDF and the
web page's limitations content can never structurally diverge: there is
genuinely only one function computing this content, called from two
different rendering paths.

The Appendix lists the specific feature names that were out of the
training range (for memory jobs, when there are any), and — when a clean
baseline is currently loaded (file 11) — a small key/value summary of the
baseline itself (its label, when it was captured, what OS/hypervisor/tool
produced it), giving a reader concrete, checkable context for every
baseline comparison made earlier in the report, without repeating the
whole baseline JSON.

Finally, `doc.build(flow)` is the one call that actually turns this entire
accumulated list of ReportLab elements into real PDF byte content, written
into the in-memory buffer `buf` — and `return buf.getvalue()` hands back
those raw bytes. Notice there's no file ever written to disk anywhere in
this whole function, and nothing is cached — the docstring says so
directly: "Rendered on demand from stored results; nothing is cached."
Every single time `routes.py:report()` (file 07) is hit, this whole
function runs fresh, from whatever the database currently holds for that
job — which is exactly what guarantees a downloaded PDF can never go stale
relative to the underlying stored results.

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

**Q3. Why does `_summary()`'s memory-pipeline branch only mention the
model's probability in its very last sentence, and only when `job.ood_count`
is truthy?**

A: This is the concrete implementation of hard rule 22 inside the report's
executive summary specifically — memory reports must lead with what was
observed, never with the model's score. Placing the probability mention
last, and wording it explicitly as "for reference only," keeps the model's
number from ever being the first or most prominent thing a reader
encounters. Gating it on `job.ood_count` being nonzero additionally avoids
mentioning the out-of-distribution framing at all for the rare case where a
capture happens to be fully in-distribution.

**Q4. `flow.append(Paragraph(f"<b>Overall severity: {severity or 'not
scored'}</b>", ...))` deliberately never falls back to showing "Low" when
`severity` is `None`. Why does that specific choice matter?**

A: A missing severity means the scoring computation genuinely didn't run
or failed for some reason — it's a different situation from a computation
that ran and concluded the risk was low. Defaulting to "Low" in that
situation would silently misrepresent an unknown, unscored result as a
calm, reassuring one — exactly the wrong direction to fail in for a
forensic tool. Showing "not scored" honestly instead makes the gap visible
rather than papering over it with a falsely comforting default.

**Q5. Why is the "Configuration context" (volumetric) paragraph placed in
its own visually separate section rather than mixed into the findings list
above it, even though both sections ultimately come from the same job's
data?**

A: Because volumetric/configuration data (service counts, process counts,
etc.) is structurally incapable of ever affecting severity (file 11), and
keeping it visually separate from the actual findings reinforces that
distinction for a human reader, not just in the underlying code. The
comment in the real source states this directly — placing it apart is
meant to stop it from ever being mistaken for "an indicator," even though
nothing about the surrounding layout enforces that on its own; the visual
separation matches, and reinforces, the deeper structural separation
already guaranteed by which data actually reaches `severity.for_memory()`.
