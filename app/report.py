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

from .models import DISK, MEMORY, SEVERITY_ORDER

INK_HEX = "#1b2430"
INK_SOFT_HEX = "#5c6b7a"
ACCENT_HEX = "#2c5a82"
RULE_HEX = "#b9c6d3"
PANEL_HEX = "#eef1f4"
LINE_HEX = "#d7dde3"
ZEBRA_HEX = "#f7f9fb"

INK = colors.HexColor(INK_HEX)
INK_SOFT = colors.HexColor(INK_SOFT_HEX)
ACCENT = colors.HexColor(ACCENT_HEX)
RULE = colors.HexColor(RULE_HEX)
PANEL = colors.HexColor(PANEL_HEX)
LINE = colors.HexColor(LINE_HEX)
ZEBRA = colors.HexColor(ZEBRA_HEX)

SEVERITY_HEX = {
    "Critical": "#b0273f", "High": "#b8650b", "Medium": "#1d7690", "Low": "#5c6b7a",
}


def _sev_hex(severity):
    return SEVERITY_HEX.get(severity, INK_HEX)


REQUIRED_ALWAYS = [
    "Scope and limitations",
]
REQUIRED_DISK = []
REQUIRED_MEMORY = []


def limitations(job):
    """-> [(heading, [paragraph, ...])], identical for the PDF and the dashboard.

    Trimmed to "Files not examined" only as of CLAUDE.md §18's seventh pass
    (2026-08-11): the memory-only "Extraction gaps" and "Baseline for the observed
    indicators" sections were removed from display. `job.extraction_gaps` is still
    populated by the extractor on every real run (app/extractors/memory.py) and
    `baseline.NOTE` still exists - this function just no longer surfaces either.
    """
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

    return out


def _parent_cell(d):
    """'python.exe, PID 4400' / 'unknown, PID 4400' / 'n/a'. Only ever called
    for the processes already named elsewhere in this evidence section - see
    extractors/memory.py:_parent(), which is where the actual lookup happens.

    Plain ASCII only, deliberately. ReportLab escapes literal '(' and ')'
    inside a PDF's text streams (a mandatory limitations string hit this trap
    first, back when the scope statement was still rendered - see CLAUDE.md
    §18), and - measured while building this function - it octal-escapes the
    em dash too (a non-WinAnsi-trivial byte). Both break any check that scans
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
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=21, leading=24, textColor=INK, spaceAfter=3),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9,
                              textColor=INK_SOFT, spaceAfter=4),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontName="Helvetica-Bold",
                            fontSize=13, leading=16, textColor=ACCENT,
                            spaceBefore=0, spaceAfter=7),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName="Helvetica-Bold",
                             fontSize=10.5, leading=13, textColor=INK,
                             spaceBefore=9, spaceAfter=4),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=9, leading=13,
                            textColor=INK, alignment=TA_LEFT, spaceAfter=6),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=7.6, leading=10.5,
                                textColor=INK),
        "label": ParagraphStyle("lb", parent=base["Normal"], fontSize=7.6, leading=10.5,
                                textColor=INK_SOFT),
    }


def _rule(flow):
    """One consistent divider ahead of every numbered section heading, so the document
    reads as a designed sequence of sections rather than headings dropped in at
    whatever spacing a paragraph style happens to leave."""
    flow.append(HRFlowable(width="100%", thickness=0.75, spaceBefore=14, spaceAfter=9,
                           color=RULE))


def _kv(rows, st, widths=(38 * mm, 122 * mm)):
    data = [[Paragraph(f"<b>{k}</b>", st["label"]), Paragraph(str(v), st["small"])]
            for k, v in rows]
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _table(data, col_widths, zebra=True):
    """Shared styling for the multi-row tables (findings, evidence): a tinted header
    row and light zebra striping so a long table stays readable at a glance rather than
    turning into a wall of undifferentiated grid lines."""
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

    flow.append(Paragraph("Malware Analysis Report", st["title"]))
    flow.append(Paragraph(
        f"{job.artifact or 'unknown'} artifact &middot; job {job.id} &middot; generated "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by {generated_by}",
        st["sub"]))

    _rule(flow)
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

    _rule(flow)
    severity, summary = _summary(job, results)
    flow.append(Paragraph("2. Executive summary", st["h"]))
    flow.append(Paragraph(
        f"<font color='{_sev_hex(severity)}'><b>Overall severity: "
        f"{severity or 'not scored'}</b></font>", st["p"]))
    flow.append(Paragraph(summary, st["p"]))

    _rule(flow)
    flow.append(Paragraph("3. Verdict detail", st["h"]))
    if job.artifact == MEMORY and results:
        r = results[0]
        flow.append(_kv([
            ("Model", "XGBoost, 55 features, memory pipeline"),
            ("Probability", f"{r.probability:.4f}"),
            ("Operating threshold", f"{r.threshold:.10f}"),
            ("Raw verdict", "malicious" if r.malicious else "benign"),
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

    _rule(flow)
    flow.append(Paragraph("4. Findings", st["h"]))
    if not results:
        flow.append(Paragraph("No results were recorded for this job.", st["p"]))
    for r in results:
        block = [Paragraph(
            f"<font color='{_sev_hex(r.severity)}'><b>{r.severity or 'Unrated'}</b></font>"
            f" &middot; probability {r.probability:.4f} &middot; "
            f"{r.path or 'whole memory dump'}", st["h3"])]
        if r.severity_note:
            block.append(Paragraph(r.severity_note, st["small"]))
        if r.file_sha256:
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
            block.append(Spacer(1, 3))
            block.append(_table(data, (96 * mm, 44 * mm, 20 * mm)))
        flow.append(KeepTogether(block))
        flow.append(Spacer(1, 6))

    sections = evidence_rows(job) if job.artifact == MEMORY else []
    scope_no = 6 if sections else 5

    if sections:
        _rule(flow)
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
            col_w = (160 * mm) / len(columns)
            flow.append(_table(data, [col_w] * len(columns)))
            flow.append(Spacer(1, 6))

    flow.append(PageBreak())
    flow.append(Paragraph(f"{scope_no}. Scope and limitations", st["h"]))
    for heading, paragraphs in limitations(job):
        flow.append(Paragraph(heading, st["h3"]))
        for text in paragraphs:
            flow.append(Paragraph(text, st["small"]))
            flow.append(Spacer(1, 2))

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
        width, _height = A4
        self.setStrokeColor(RULE)
        self.setLineWidth(0.5)
        self.line(25 * mm, 16 * mm, width - 25 * mm, 16 * mm)
        self.setFont("Helvetica", 7)
        self.setFillColor(INK_SOFT)
        self.drawString(25 * mm, 12 * mm, f"SHA-256 {self._footer_sha256}")
        self.drawRightString(width - 25 * mm, 12 * mm,
                             f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _canvas_maker(sha256):
    def make(*args, **kwargs):
        return _NumberedCanvas(*args, sha256=sha256, **kwargs)
    return make