import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (HRFlowable, KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from .forensics import baseline
from .models import DISK, MEMORY, SEVERITY_ORDER

# Strings that must survive into every report of the relevant kind. The test suite
# asserts each one, so removing a limitation from the renderer fails the build
# rather than quietly shipping a report that overstates its own confidence.
# Trimmed 2026-08-06 (CLAUDE.md §18): the triage-note, lief-version caveat and MITRE
# disclaimer paragraphs are no longer emitted, so their required substrings dropped
# out of these lists along with them.
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

SATURATION_CAVEAT = (
    "The benchmark dataset behind the memory model, CIC-MalMem-2022, shows unusually "
    "high separability: 21 of its 55 features individually exceed 0.95 AUC. Its benign "
    "half was balanced using SMOTE oversampling, so a substantial part of it is "
    "interpolated rather than captured, and interpolated points cannot exceed the range "
    "of the samples they were drawn from. Reported benchmark performance should be read "
    "in that light, and real-world performance may differ substantially.")

# CLAUDE.md 11.1. Memory severity is calibrated against one reference machine's own
# known-good baseline, so reading a memory report against any other machine is misuse.
# Mandatory rather than conditional: the fragments asserted in REQUIRED_MEMORY carry no
# parentheses, because verify_pipeline.py matches the raw PDF stream where "(" is escaped.
SCOPE_STATEMENT = (
    "Demonstrated on a controlled reference environment (Windows 10 x64). Severity is "
    "calibrated against a per-machine clean baseline and is valid for that machine. "
    "Cross-machine deployment would require a per-machine baseline established in "
    "advance.")


def limitations(job):
    """-> [(heading, [paragraph, ...])], identical for the PDF and the dashboard."""
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

    if job.artifact == MEMORY:
        gaps = job.extraction_gaps or []
        missing = [g for g in gaps if g["confidence"] == "missing"]
        inferred = [g for g in gaps if g["confidence"] == "inferred"]

        lines = []
        if missing:
            lines.append(
                f"{len(missing)} feature(s) could not be produced by Volatility 3 at all "
                "and were emitted as 0.0 rather than estimated:")
            lines += [f"{g['field']} — {g['reason']}" for g in missing]
        else:
            lines.append("No features were missing.")
        if inferred:
            lines.append(
                f"{len(inferred)} further feature(s) carry a value whose derivation was "
                "reconstructed from the reference data rather than documented by the "
                "dataset authors:")
            lines += [f"{g['field']} — {g['reason']}" for g in inferred]
        out.append(("Extraction gaps", lines))

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


def _parent_cell(d):
    """'python.exe, PID 4400' / 'unknown, PID 4400' / 'n/a'. Only ever called
    for the processes already named elsewhere in this evidence section - see
    extractors/memory.py:_parent(), which is where the actual lookup happens.

    Plain ASCII only, deliberately. ReportLab escapes literal '(' and ')'
    inside a PDF's text streams (SCOPE_STATEMENT above hit that trap first),
    and - measured while building this function - it octal-escapes the em
    dash too (a non-WinAnsi-trivial byte). Both break any check that scans
    the raw stream for an exact substring (verify_pipeline.py does exactly
    that). A comma has neither problem.
    """
    p = d.get("parent")
    if not p:
        return "n/a"
    name = p.get("name") or "unknown"
    return f"{name}, PID {p['pid']}" if p.get("pid") is not None else name


EVIDENCE_SECTIONS = [
    ("injected_regions", "Injected executable memory",
     ("Process", "PID", "Region", "Size", "Protection", "Parent process"),
     lambda d: (d.get("process") or "?", d.get("pid"),
                f"{d.get('start') or '?'}–{d.get('end') or '?'}",
                f"{d['size']:,} B" if d.get("size") else "?",
                d.get("protection") or "?", _parent_cell(d))),
    ("hidden_modules", "Modules absent from the PEB loader lists",
     ("Process", "PID", "Base", "Absent from", "Mapped path", "Parent process"),
     lambda d: (d.get("process") or "?", d.get("pid"), d.get("base") or "?",
                ", ".join(d.get("absent_from") or []), d.get("path") or "—",
                _parent_cell(d))),
    ("hidden_processes", "Processes visible to some enumeration methods only",
     ("Name", "PID", "Missing from", "Exit time", "Parent process"),
     lambda d: (d.get("name") or "?", d.get("pid"),
                ", ".join(d.get("missing_from") or []),
                d.get("exit_time") or "still running", _parent_cell(d))),
    ("unbacked_callbacks", "Kernel callbacks with no backing module",
     ("Type", "Callback", "Module", "Symbol"),
     lambda d: (d.get("type") or "?", d.get("callback") or "?",
                d.get("module") or "?", d.get("symbol") or "—")),
]


def evidence_rows(job):
    """-> [(heading, columns, [row, ...], total, shown)], shared by PDF and UI.

    Same reasoning as limitations(): defined once so the report and the dashboard
    cannot drift apart.
    """
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


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=17, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9,
                              textColor=colors.HexColor("#666666"), spaceAfter=10),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontSize=12, spaceBefore=12,
                            spaceAfter=5),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=10, spaceBefore=8,
                             spaceAfter=3),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=8.6, leading=12,
                            alignment=TA_LEFT, spaceAfter=5),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=7.4, leading=10,
                                textColor=colors.HexColor("#444444")),
        "mono": ParagraphStyle("m", parent=base["Normal"], fontName="Courier",
                               fontSize=7.2, leading=9),
    }


def _kv(rows, st, widths=(38 * mm, 122 * mm)):
    data = [[Paragraph(f"<b>{k}</b>", st["small"]), Paragraph(str(v), st["small"])]
            for k, v in rows]
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


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

    tags = sorted({f.tag for r in results for f in r.findings if f.tag})
    body = ("This report leads with what was observed in the capture rather than with a "
            "model score. ")
    body += (f"The artifacts present are consistent with: {', '.join(tags)}. "
             if tags else "No indicator categories matched. ")
    if job.ood_count:
        body += (f"The model's own verdict is reported for reference only: {job.ood_count} "
                 "of its 55 inputs fall outside the range it was trained on.")
    return worst, body


def render(job, compress=True, generated_by=None):
    """-> PDF bytes. Rendered on demand from stored results; nothing is cached.

    `compress` only controls the page-stream encoding - the content is identical
    either way. The tests turn it off so they can assert that the mandatory
    limitation strings actually reached the page, without pulling in a PDF
    parsing library the project does not otherwise need.

    `generated_by` is the analyst who requested *this* rendering, not
    necessarily job.user - they are the same analyst today (every route that
    can reach here already enforces job ownership, CLAUDE.md 10), but the two
    are conceptually different facts, so callers pass it explicitly rather
    than this function assuming they're interchangeable. Falls back to the
    job's own owner for callers with no request/current_user available
    (scripts/verify_pipeline.py, the test suite).
    """
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

    # 1. Header / chain of custody
    flow.append(Paragraph("Malware Analysis Report", st["title"]))
    flow.append(Paragraph(
        f"{job.artifact or 'unknown'} artifact &middot; job {job.id} &middot; generated "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by {generated_by}",
        st["sub"]))

    flow.append(Paragraph("1. Chain of custody", st["h"]))
    custody = [
        ("Artifact", job.filename),
        ("SHA-256", f"<font face='Courier' size='7'>{job.sha256}</font>"),
        ("Size", f"{job.size_bytes:,} bytes"),
        ("Type", f"{job.artifact or 'undetermined'} — {job.detected_as or 'n/a'}"),
        ("Analyst", job.user.username),
    ]
    if job.case_reference:
        custody.append(("Case reference", job.case_reference))
    custody += [
        ("Uploaded", job.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Analysis duration", f"{job.duration / 60:.1f} minutes" if job.duration else "n/a"),
        ("Job ID", job.id),
        ("Report generated by", generated_by),
        ("Retention", "The uploaded artifact is retained indefinitely on the analysis "
                      f"host as <font face='Courier' size='7'>{job.stored_name}</font>, "
                      "so the SHA-256 above remains verifiable against it."),
    ]
    flow.append(_kv(custody, st))

    # 2. Executive summary
    flow.append(HRFlowable(width="100%", thickness=0.5, spaceBefore=10, spaceAfter=2,
                           color=colors.HexColor("#dddddd")))
    severity, summary = _summary(job, results)
    flow.append(Paragraph("2. Executive summary", st["h"]))
    # Never fall back to Low. An absent severity means it could not be computed,
    # and defaulting to the reassuring end of the scale is the wrong direction to
    # fail in - it reads as "nothing to worry about" on a report that in fact
    # scored nothing at all.
    flow.append(Paragraph(f"<b>Overall severity: {severity or 'not scored'}</b>", st["p"]))
    flow.append(Paragraph(summary, st["p"]))

    # 3. Verdict detail
    flow.append(HRFlowable(width="100%", thickness=0.5, spaceBefore=10, spaceAfter=2,
                           color=colors.HexColor("#dddddd")))
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
    else:
        flow.append(_kv([
            ("Model", "LightGBM, 150 of 2,381 EMBER features, disk pipeline"),
            ("Operating threshold",
             f"{results[0].threshold:.10f}" if results else "n/a"),
            ("Executables analysed", len(results)),
            ("Flagged", sum(1 for r in results if r.malicious)),
            ("Files examined", f"{job.files_scanned or 0:,}"),
        ], st))

    # 4/5. Findings, per file for disk
    flow.append(HRFlowable(width="100%", thickness=0.5, spaceBefore=10, spaceAfter=2,
                           color=colors.HexColor("#dddddd")))
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
            # Hard rule 16: a flagged file without path and hash is unactionable.
            block.append(Spacer(1, 3))
            block.append(_kv([
                ("SHA-256", f"<font face='Courier' size='6.5'>{r.file_sha256}</font>"),
                ("MD5", f"<font face='Courier' size='6.5'>{r.file_md5}</font>"),
                ("Size", f"{r.file_size:,} bytes" if r.file_size else "n/a"),
                ("MFT / inode", r.inode or "n/a"),
                ("Byte offset", r.data_offset if r.data_offset is not None
                 else "not exposed for this file"),
                ("Allocated", "yes" if r.allocated else "no (deleted)"),
                ("MACB", f"M {r.mtime or '-'} / A {r.atime or '-'} / "
                         f"C {r.ctime or '-'} / B {r.btime or '-'}"),
            ], st))
        if r.findings:
            data = [[Paragraph("<b>What was observed</b>", st["small"]),
                     Paragraph("<b>Indicator</b>", st["small"]),
                     Paragraph("<b>ATT&amp;CK</b>", st["small"])]]
            for f in sorted(r.findings, key=lambda f: f.rank or 99):
                data.append([
                    Paragraph(f.meaning or f.feature, st["small"]),
                    Paragraph(f"{f.tag or '—'}"
                              + (f" ({f.confidence})" if f.confidence else ""),
                              st["small"]),
                    Paragraph(f.mitre_id or "—", st["small"])])
            t = Table(data, colWidths=(96 * mm, 44 * mm, 20 * mm))
            t.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            block.append(Spacer(1, 3))
            block.append(t)
        flow.append(KeepTogether(block))
        flow.append(Spacer(1, 6))

    # Configuration counts, kept visually apart from the findings above so it is
    # never read as an indicator. It cannot reach severity by construction.
    volumetric = (job.volumetric or {}) if job.artifact == MEMORY else {}
    if volumetric.get("note"):
        flow.append(Paragraph("Configuration context", st["h3"]))
        flow.append(Paragraph(volumetric["note"], st["small"]))
        flow.append(Spacer(1, 6))

    # Section 5 is per-process evidence, but only for a memory job that has any -
    # so Scope and Appendix renumber accordingly rather than colliding on "5".
    sections = evidence_rows(job) if job.artifact == MEMORY else []
    scope_no = 6 if sections else 5

    if sections:
        flow.append(HRFlowable(width="100%", thickness=0.5, spaceBefore=10, spaceAfter=2,
                               color=colors.HexColor("#dddddd")))
        flow.append(Paragraph("5. Where these indicators were observed", st["h"]))
        flow.append(Paragraph(
            "These are the processes, addresses and modules behind the indicators "
            "above, so they can be examined directly in the capture.",
            st["p"]))
        for heading, columns, rows, total, shown in sections:
            head = f"{heading} — {total}"
            if shown < total:
                head += f", showing the first {shown}"
            flow.append(Paragraph(head, st["h3"]))
            data = [[Paragraph(f"<b>{c}</b>", st["small"]) for c in columns]]
            for row in rows:
                data.append([Paragraph(str(v), st["small"]) for v in row])
            # Evidence sections carry different column counts (Parent process
            # widened injected_regions/hidden_modules to six; unbacked_callbacks
            # has no PID/parent at all, so stays at four) - split the usable page
            # width evenly per section rather than a single hardcoded tuple.
            col_w = (160 * mm) / len(columns)
            t = Table(data, colWidths=[col_w] * len(columns))
            t.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            flow.append(t)
            flow.append(Spacer(1, 6))

    # Scope and limitations - mandatory, always rendered.
    flow.append(PageBreak())
    flow.append(Paragraph(f"{scope_no}. Scope and limitations", st["h"]))
    for heading, paragraphs in limitations(job):
        flow.append(Paragraph(heading, st["h3"]))
        for text in paragraphs:
            flow.append(Paragraph(text, st["small"]))
            flow.append(Spacer(1, 2))

    flow.append(HRFlowable(width="100%", thickness=0.5, spaceBefore=10, spaceAfter=2,
                           color=colors.HexColor("#dddddd")))
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

    doc.build(flow, canvasmaker=_canvas_maker(job.sha256))
    return buf.getvalue()


class _NumberedCanvas(Canvas):
    """Adds a running 'Page N of M' plus the artifact's SHA-256 to every page.

    ReportLab only knows the true page count once the whole flowable list has
    been laid out, so this is the standard two-pass recipe: save every page's
    drawing state as it goes past, then - once save() is actually called, and
    the true total is known - replay each saved state and draw the footer on
    it before it is really written out.
    """

    def __init__(self, *args, sha256="", **kwargs):
        Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []
        self._footer_sha256 = sha256

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            Canvas.showPage(self)
        Canvas.save(self)

    def _draw_footer(self, total):
        self.saveState()
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#888888"))
        width, _height = A4
        self.drawString(25 * mm, 12 * mm, f"SHA-256 {self._footer_sha256}")
        self.drawRightString(width - 25 * mm, 12 * mm,
                             f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _canvas_maker(sha256):
    def make(*args, **kwargs):
        return _NumberedCanvas(*args, sha256=sha256, **kwargs)
    return make