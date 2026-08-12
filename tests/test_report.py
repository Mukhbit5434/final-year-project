from datetime import datetime, timezone

import pytest

from app import report
from app.db import db
from app.models import (COMPLETED, CRITICAL, DISK, HIGH, LOW, MEMORY, Finding, Job,
                        Result)

DISK_THRESHOLD = 0.5010602922493019
MEM_THRESHOLD = 0.2336726188659668


def disk_job(db, analyst, flagged=True):
    job = Job(user=analyst, filename="case01.dd", stored_name=f"r1_{id(analyst)}_{db.session.query(Job).count()}.dd",
              sha256="a" * 64, size_bytes=4 * 1024 ** 3, artifact=DISK,
              status=COMPLETED, files_scanned=3817, files_flagged=1 if flagged else 0,
              started_at=datetime(2026, 7, 30, 9, tzinfo=timezone.utc),
              finished_at=datetime(2026, 7, 30, 9, 11, tzinfo=timezone.utc),
              skipped=[{"path": "/pagefile.sys", "reason": "exceeds 64 MB size cap"},
                       {"path": "/Windows/ehome", "reason": "deleted entry"}])
    r = Result(job=job, probability=0.94 if flagged else 0.03,
               threshold=DISK_THRESHOLD, malicious=flagged,
               severity=HIGH if flagged else LOW,
               severity_note="model confidence 0.94, 1 high-risk category matched",
               path="p6/Users/x/Desktop/packed.exe", partition="p6", inode="1001",
               file_sha256="b" * 64, file_md5="c" * 32, file_size=176408,
               allocated=True, data_offset=4096,
               mtime=datetime(2026, 3, 1, tzinfo=timezone.utc))
    if flagged:
        r.findings.append(Finding(
            feature="byte_entropy_247", weight=0.31, rank=1,
            meaning="Entropy measured over a sliding window.",
            tag="Obfuscated / Packed Files", mitre_id="T1027",
            mitre_name="Obfuscated Files or Information", confidence="moderate"))
    db.session.add(job)
    db.session.commit()
    return job


def memory_job(db, analyst):
    job = Job(user=analyst, filename="win10_memory.raw", stored_name=f"r2_{id(analyst)}_{db.session.query(Job).count()}.raw",
              sha256="d" * 64, size_bytes=2 * 1024 ** 3, artifact=MEMORY,
              status=COMPLETED, ood_count=21,
              ood_fields=["svcscan.nservices", "modules.nmodules"],
              started_at=datetime(2026, 7, 30, 9, tzinfo=timezone.utc),
              finished_at=datetime(2026, 7, 30, 9, 4, tzinfo=timezone.utc),
              extraction_gaps=[
                  {"field": "psxview.not_in_session", "plugin": "psxview",
                   "confidence": "missing",
                   "reason": "Volatility 3 psxview enumerates four ways"},
                  {"field": "malfind.protection", "plugin": "malfind",
                   "confidence": "inferred",
                   "reason": "summed Volatility 2 protection index"}])
    r = Result(job=job, probability=0.0084, threshold=MEM_THRESHOLD, malicious=False,
               severity=LOW,
               severity_note="0 high-risk indicator categories elevated against the "
                             "clean-system baseline")
    r.findings.append(Finding(
        feature="malfind.ninjections", rank=1,
        meaning="Private memory marked executable. 16 observed against a clean-system "
                "baseline of 16 - consistent with a healthy system.",
        tag="Process Injection", mitre_id="T1055", mitre_name="Process Injection",
        confidence="high"))
    db.session.add(job)
    db.session.commit()
    return job


def render(job):
    """Uncompressed so the page streams stay readable; identical content."""
    return report.render(job, compress=False)


def text_of(pdf):
    """Pull the literal strings out of the (uncompressed) PDF content streams."""
    import re

    body = b" ".join(re.findall(rb"\((?:[^()\\]|\\.)*\)", pdf))
    text = body.decode("latin-1", "replace")
    # ReportLab breaks lines mid-sentence, so collapse the string boundaries
    # before matching phrases that span them.
    return re.sub(r"\s+", " ", text.replace("(", "").replace(")", " "))


def test_a_disk_report_renders(db, analyst):
    pdf = render(disk_job(db, analyst))
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 3000


def test_all_five_sections_are_present(db, analyst):
    """There were six, including an Appendix, before CLAUDE.md §18's seventh pass
    removed it entirely - Scope and limitations is now the last section."""
    body = text_of(render(disk_job(db, analyst)))
    for heading in ("Chain of custody", "Executive summary", "Verdict detail",
                    "Findings", "Scope and limitations"):
        assert heading in body, heading
    assert "Appendix" not in body


def test_mandatory_limitation_strings_survive_into_a_disk_report(db, analyst):
    body = text_of(render(disk_job(db, analyst)))
    for required in report.REQUIRED_ALWAYS + report.REQUIRED_DISK:
        assert required in body, f"missing mandatory string: {required!r}"


def test_mandatory_limitation_strings_survive_into_a_memory_report(db, analyst):
    body = text_of(render(memory_job(db, analyst)))
    for required in report.REQUIRED_ALWAYS + report.REQUIRED_MEMORY:
        assert required in body, f"missing mandatory string: {required!r}"


def test_a_flagged_file_carries_its_path_and_hash(db, analyst):
    body = text_of(render(disk_job(db, analyst)))
    assert "packed.exe" in body, "hard rule 16"
    assert "b" * 64 in body, "hard rule 16"


def test_the_limitations_section_renders_when_nothing_was_skipped(db, analyst):
    job = disk_job(db, analyst)
    job.skipped = []
    db.session.commit()
    body = text_of(render(job))
    assert "Scope and limitations" in body
    assert "None recorded." in body


def test_a_memory_report_does_not_headline_the_probability(db, analyst):
    """Hard rule 22. The executive summary leads with observations; the score
    appears later, in verdict detail. The "secondary triage signal" sentence that
    used to carry this in words is gone as of CLAUDE.md §18's seventh pass - the
    ordering itself, not a sentence describing it, is what's actually asserted."""
    body = text_of(render(memory_job(db, analyst)))
    summary_at = body.index("Executive summary")
    verdict_at = body.index("Verdict detail")
    assert body.index("0.0084") > summary_at
    assert verdict_at < body.index("0.0084")
    assert "secondary triage signal" not in body


def test_extraction_gaps_are_stored_but_no_longer_displayed(db, analyst):
    """CLAUDE.md §18, seventh pass: the "Extraction gaps" limitations section was
    removed. `job.extraction_gaps` is still populated by the real extractor
    (app/extractors/memory.py) on every run regardless of what the report shows."""
    job = memory_job(db, analyst)
    assert job.extraction_gaps, "still recorded internally, independent of display"

    headings = [h for h, _ in report.limitations(job)]
    assert "Extraction gaps" not in headings
    assert "Baseline for the observed indicators" not in headings
    assert headings == ["Files not examined"]


def test_disk_reports_do_not_claim_memory_caveats(db, analyst):
    headings = [h for h, _ in report.limitations(disk_job(db, analyst))]
    assert "Extraction gaps" not in headings
    assert "Model applicability" not in headings


def test_the_ood_count_is_computed_but_no_longer_displayed(db, analyst):
    """Hard rule 17 requires the count be computed and stored on every memory job -
    it does not require the number, or any sentence about it, to appear in the
    report. CLAUDE.md §18's sixth pass removed the digit; the seventh pass removed
    the surrounding sentence entirely (it lived only in the executive summary by
    that point)."""
    job = memory_job(db, analyst)
    assert job.ood_count == 21, "hard rule 17: the gate still computes this internally"

    body = text_of(render(job))
    assert "21 of 55" not in body
    assert "of 55" not in body
    assert "falls outside the range it was trained on" not in body


def test_report_route_requires_ownership(client, signed_in, db, analyst):
    from app.models import User
    job = disk_job(db, analyst)

    other = User(username="stranger")
    other.set_password("x" * 12)
    db.session.add(other)
    db.session.commit()

    client.post("/logout")
    client.post("/login", data={"username": "stranger", "password": "x" * 12})
    assert client.get(f"/jobs/{job.id}/report.pdf").status_code == 404


def test_report_download_is_audited(client, signed_in, db, analyst):
    from app.models import AuditLog
    job = disk_job(db, analyst)
    r = client.get(f"/jobs/{job.id}/report.pdf")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert db.session.query(AuditLog).filter_by(action="report_download").count() == 1


def test_case_reference_appears_in_chain_of_custody_when_set(db, analyst):
    job = disk_job(db, analyst)
    job.case_reference = "CASE-2026-0142"
    db.session.commit()
    body = text_of(render(job))
    assert "Case reference" in body
    assert "CASE-2026-0142" in body


def test_case_reference_omitted_cleanly_when_not_set(db, analyst):
    job = disk_job(db, analyst)
    assert job.case_reference is None, "the fixture never sets one"
    body = text_of(render(job))
    assert "Case reference" not in body


def test_report_generated_by_line_names_the_requesting_analyst(db, analyst):
    job = disk_job(db, analyst)
    body = text_of(report.render(job, compress=False, generated_by="reviewer99"))
    assert "Report generated by" in body
    assert "reviewer99" in body


def test_generated_by_falls_back_to_the_jobs_owner_when_not_supplied(db, analyst):
    # scripts/verify_pipeline.py and the test suite itself render outside any
    # request, with no current_user to pass in - must still produce something
    # honest rather than a blank or a crash.
    job = disk_job(db, analyst)
    body = text_of(render(job))
    assert analyst.username in body


def test_pdf_carries_page_numbers_and_a_sha256_footer(db, analyst):
    job = disk_job(db, analyst)
    body = text_of(render(job))
    assert "Page 1 of" in body
    assert "SHA-256" in body
    assert "a" * 64 in body, "the footer repeats the artifact's own hash, not a fragment"


def test_csv_and_json_export(client, signed_in, db, analyst):
    job = disk_job(db, analyst)

    csv_out = client.get(f"/jobs/{job.id}/export.csv")
    assert csv_out.status_code == 200
    text = csv_out.get_data(as_text=True)
    assert "file_sha256" in text and "b" * 64 in text
    assert "packed.exe" in text

    json_out = client.get(f"/jobs/{job.id}/export.json").get_json()
    assert json_out["results"][0]["file_sha256"] == "b" * 64
    assert json_out["results"][0]["indicators"][0]["mitre_id"] == "T1027"
