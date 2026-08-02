import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from .forensics import baseline, mitre
from .models import DISK, MEMORY, SEVERITY_ORDER

# Strings that must survive into every report of the relevant kind. The test suite
# asserts each one, so removing a limitation from the renderer fails the build
# rather than quietly shipping a report that overstates its own confidence.
REQUIRED_ALWAYS = [
    "Scope and limitations",
    "narrows the scope of an investigation",
]
REQUIRED_DISK = [
    "lief",
    "0.9.0",
]
REQUIRED_MEMORY = [
    "out of the 55 features",
    "unusually high separability",
    "SMOTE",
    "controlled reference environment",
    "per-machine clean baseline",
]

LIEF_CAVEAT = (
    "Feature extraction uses lief 1.0.0, which differs from the 0.9.0 release EMBER's "
    "extractor was validated against. Feature values may differ slightly from the "
    "official EMBER benchmark. This was accepted during training and is disclosed "
    "rather than corrected.")

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

TRIAGE_NOTE = (
    "This system performs automated triage. It narrows the scope of an investigation to "
    "the artifacts most worth a human's attention; it does not produce conclusive "
    "findings. Every flagged item warrants manual verification.")


def limitations(job):
    """-> [(heading, [paragraph, ...])], identical for the PDF and the dashboard."""
    out = [("Nature of these results", [TRIAGE_NOTE])]

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

    if job.artifact == DISK:
        out.append(("Feature extraction environment", [LIEF_CAVEAT]))

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

    out.append(("MITRE ATT&CK mappings", [mitre.DISCLAIMER]))
    return out


EVIDENCE_SECTIONS = [
    ("injected_regions", "Injected executable memory",
     ("Process", "PID", "Region", "Size", "Protection"),
     lambda d: (d.get("process") or "?", d.get("pid"),
                f"{d.get('start') or '?'}–{d.get('end') or '?'}",
                f"{d['size']:,} B" if d.get("size") else "?",
                d.get("protection") or "?")),
    ("hidden_modules", "Modules absent from the PEB loader lists",
     ("Process", "PID", "Base", "Absent from", "Mapped path"),
     lambda d: (d.get("process") or "?", d.get("pid"), d.get("base") or "?",
                ", ".join(d.get("absent_from") or []), d.get("path") or "—")),
    ("hidden_processes", "Processes visible to some enumeration methods only",
     ("Name", "PID", "Missing from", "Exit time", ""),
     lambda d: (d.get("name") or "?", d.get("pid"),
                ", ".join(d.get("missing_from") or []),
                d.get("exit_time") or "still running", "")),
    ("unbacked_callbacks", "Kernel callbacks with no backing module",
     ("Type", "Callback", "Module", "Symbol", ""),
     lambda d: (d.get("type") or "?", d.get("callback") or "?",
                d.get("module") or "?", d.get("symbol") or "—", "")),
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


def render(job, compress=True):
    """-> PDF bytes. Rendered on demand from stored results; nothing is cached.

    `compress` only controls the page-stream encoding - the content is identical
    either way. The tests turn it off so they can assert that the mandatory
    limitation strings actually reached the page, without pulling in a PDF
    parsing library the project does not otherwise need.
    """
    st = _styles()
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
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", st["sub"]))

    flow.append(Paragraph("1. Chain of custody", st["h"]))
    flow.append(_kv([
        ("Artifact", job.filename),
        ("SHA-256", f"<font face='Courier' size='7'>{job.sha256}</font>"),
        ("Size", f"{job.size_bytes:,} bytes"),
        ("Type", f"{job.artifact or 'undetermined'} — {job.detected_as or 'n/a'}"),
        ("Analyst", job.user.username),
        ("Uploaded", job.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Analysis duration", f"{job.duration / 60:.1f} minutes" if job.duration else "n/a"),
        ("Job ID", job.id),
        ("Retention", "The uploaded artifact is retained indefinitely on the analysis "
                      f"host as <font face='Courier' size='7'>{job.stored_name}</font>, "
                      "so the SHA-256 above remains verifiable against it."),
    ], st))

    # 2. Executive summary
    severity, summary = _summary(job, results)
    flow.append(Paragraph("2. Executive summary", st["h"]))
    # Never fall back to Low. An absent severity means it could not be computed,
    # and defaulting to the reassuring end of the scale is the wrong direction to
    # fail in - it reads as "nothing to worry about" on a report that in fact
    # scored nothing at all.
    flow.append(Paragraph(f"<b>Overall severity: {severity or 'not scored'}</b>", st["p"]))
    flow.append(Paragraph(summary, st["p"]))

    # 3. Verdict detail
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

    # 5. Per-process locators - the memory counterpart to the disk per-file table.
    sections = evidence_rows(job) if job.artifact == MEMORY else []
    if sections:
        flow.append(Paragraph("5. Where these indicators were observed", st["h"]))
        flow.append(Paragraph(
            "Counts alone are not investigable. These are the processes, addresses "
            "and modules behind the indicators above, so they can be examined "
            "directly in the capture. Their presence is not by itself suspicious - "
            "read them against the baseline note in the limitations section.",
            st["p"]))
        for heading, columns, rows, total, shown in sections:
            head = f"{heading} — {total}"
            if shown < total:
                head += f", showing the first {shown}"
            flow.append(Paragraph(head, st["h3"]))
            data = [[Paragraph(f"<b>{c}</b>", st["small"]) for c in columns]]
            for row in rows:
                data.append([Paragraph(str(v), st["small"]) for v in row])
            t = Table(data, colWidths=(38 * mm, 15 * mm, 44 * mm, 24 * mm, 39 * mm))
            t.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            flow.append(t)
            flow.append(Spacer(1, 6))

    # 6. Scope and limitations - mandatory, always rendered
    flow.append(PageBreak())
    flow.append(Paragraph("5. Scope and limitations", st["h"]))
    for heading, paragraphs in limitations(job):
        flow.append(Paragraph(heading, st["h3"]))
        for text in paragraphs:
            flow.append(Paragraph(text, st["small"]))
            flow.append(Spacer(1, 2))

    # 7. Appendix
    flow.append(Paragraph("6. Appendix", st["h"]))
    if job.artifact == MEMORY and job.ood_fields:
        flow.append(Paragraph("Features outside the training range", st["h3"]))
        flow.append(Paragraph(", ".join(job.ood_fields), st["mono"]))
        flow.append(Spacer(1, 4))
    if baseline.info():
        flow.append(Paragraph("Clean-system baseline", st["h3"]))
        info = baseline.info()
        flow.append(_kv([(k.replace("_", " ").capitalize(), v)
                         for k, v in info.items() if not isinstance(v, dict)], st))
    flow.append(Paragraph("Environment", st["h3"]))
    flow.append(_kv(_versions(), st))

    doc.build(flow)
    return buf.getvalue()


def _versions():
    import lightgbm
    import lief
    import numpy
    import sklearn
    import volatility3.framework.constants as vc
    import xgboost
    return [("xgboost", xgboost.__version__), ("lightgbm", lightgbm.__version__),
            ("scikit-learn", sklearn.__version__), ("numpy", numpy.__version__),
            ("lief", lief.__version__), ("volatility3", vc.PACKAGE_VERSION)]