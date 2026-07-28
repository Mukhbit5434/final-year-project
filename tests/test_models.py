from datetime import datetime, timedelta, timezone

from app.models import (COMPLETED, DISK, HIGH, MEMORY, AuditLog, Finding, Job,
                        Result, User)

MEM_THRESHOLD = 0.2336726188659668
DISK_THRESHOLD = 0.5010602922493019


def make_disk_job(db, user, n_files=3):
    job = Job(user=user, filename="case01.dd", stored_name="job1.dd",
              sha256="a" * 64, size_bytes=4 * 1024 ** 3, artifact=DISK,
              status=COMPLETED, files_scanned=412, files_flagged=n_files,
              skipped=[{"path": "/pagefile.sys", "reason": "size cap"}])
    db.session.add(job)
    for i in range(n_files):
        job.results.append(Result(
            probability=0.9 - i * 0.1, threshold=DISK_THRESHOLD, malicious=True,
            severity=HIGH, severity_note="model confidence 0.90, 3 high-risk categories",
            path=f"/Windows/System32/evil{i}.exe", partition="p1", inode=str(1000 + i),
            file_sha256=f"{i}" * 64, file_md5=f"{i}" * 32, file_size=90112,
            allocated=True, mtime=datetime(2025, 3, 1, tzinfo=timezone.utc)))
    db.session.commit()
    return job


def test_password_is_hashed_not_stored(db, analyst):
    assert analyst.pw_hash != "correct horse battery staple"
    assert analyst.check_password("correct horse battery staple")
    assert not analyst.check_password("wrong")


def test_username_is_unique(db, analyst):
    import sqlalchemy
    dupe = User(username="farooq", pw_hash="x")
    db.session.add(dupe)
    try:
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        db.session.rollback()
    else:
        raise AssertionError("duplicate username was accepted")


def test_disk_job_round_trips_with_files_and_findings(db, analyst):
    job = make_disk_job(db, analyst)
    for i, res in enumerate(job.results):
        res.findings.append(Finding(feature="imports_hash_1198", weight=0.31, rank=1,
                                    tag="Suspicious API Imports", mitre_id="T1106",
                                    mitre_name="Native API", confidence="moderate"))
        if i == 0:
            res.findings.append(Finding(feature="byte_entropy_247", weight=0.22, rank=2,
                                        tag="Obfuscated / Packed Files", mitre_id="T1027",
                                        mitre_name="Obfuscated Files or Information",
                                        confidence="moderate"))
    db.session.commit()

    fetched = db.session.get(Job, job.id)
    assert len(fetched.results) == 3
    assert sum(len(r.findings) for r in fetched.results) == 4
    assert fetched.skipped[0]["reason"] == "size cap"


def test_every_flagged_disk_result_carries_path_and_sha256(db, analyst):
    job = make_disk_job(db, analyst)
    for res in job.results:
        assert res.path and res.file_sha256, "hard rule 16"


def test_memory_job_uses_one_result_and_records_gaps(db, analyst):
    job = Job(user=analyst, filename="win10.vmem", stored_name="job2.vmem",
              sha256="b" * 64, size_bytes=2 * 1024 ** 3, artifact=MEMORY,
              status=COMPLETED, ood_count=38, ood_fields=["modules.nmodules"],
              extraction_gaps=[{"field": "psxview.not_in_deskthrd", "plugin": "psxview",
                                "reason": "no Volatility 3 equivalent", "confidence": "missing"}])
    job.results.append(Result(probability=0.81, threshold=MEM_THRESHOLD, malicious=True,
                              severity=HIGH))
    db.session.add(job)
    db.session.commit()

    fetched = db.session.get(Job, job.id)
    assert len(fetched.results) == 1
    assert fetched.results[0].path is None
    assert fetched.ood_count == 38
    assert fetched.extraction_gaps[0]["field"] == "psxview.not_in_deskthrd"


def test_thresholds_are_stored_not_defaulted(db, analyst):
    job = make_disk_job(db, analyst, n_files=1)
    assert job.results[0].threshold == DISK_THRESHOLD
    assert job.results[0].threshold != 0.5


def test_deleting_a_job_cascades_to_results_and_findings(db, analyst):
    job = make_disk_job(db, analyst)
    job.results[0].findings.append(Finding(feature="general_feat_7", weight=0.1))
    db.session.commit()

    db.session.delete(job)
    db.session.commit()
    assert db.session.query(Result).count() == 0
    assert db.session.query(Finding).count() == 0


def test_job_duration_needs_both_timestamps(db, analyst):
    job = make_disk_job(db, analyst, n_files=1)
    assert job.duration is None
    job.started_at = datetime.now(timezone.utc)
    job.finished_at = job.started_at + timedelta(minutes=22)
    assert job.duration == 22 * 60


def test_mitre_url_expands_sub_techniques(db, analyst):
    f = Finding(feature="malfind.ninjections", mitre_id="T1055.012")
    assert f.mitre_url == "https://attack.mitre.org/techniques/T1055/012/"
    assert Finding(feature="x", mitre_id="T1014").mitre_url.endswith("/T1014/")
    assert Finding(feature="x").mitre_url is None


def test_audit_row_survives_without_a_user(db):
    db.session.add(AuditLog(action="login_failed", detail="unknown user 'root'", ip="127.0.0.1"))
    db.session.commit()
    row = db.session.query(AuditLog).one()
    assert row.user_id is None and row.at is not None