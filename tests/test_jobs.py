import io
from datetime import datetime, timezone

import pytest

from app import jobs
from app.db import db
from app.models import (COMPLETED, DISK, FAILED, MEMORY, PENDING, RUNNING, Job,
                        Result)

MBR = b"\x33\xc0" + b"\x00" * 508 + b"\x55\xaa" + b"\x00" * 512

DISK_THRESHOLD = 0.5010602922493019
MEM_THRESHOLD = 0.2336726188659668


def fake_disk_scan(_path, _max_files, _max_bytes, _progress_file=None):
    return {
        "examined": 3817,
        "pe_found": 2,
        "volumes": ["p6:Basic data partition"],
        "skipped": [{"path": "/pagefile.sys", "reason": "exceeds 64 MB size cap"}],
        "files": [
            {"path": "p6/Windows/evil.exe", "partition": "p6", "inode": "1001",
             "file_sha256": "a" * 64, "file_md5": "b" * 32, "file_size": 90112,
             "allocated": True, "data_offset": 4096,
             "mtime": datetime(2025, 3, 1, tzinfo=timezone.utc),
             "atime": None, "ctime": None, "btime": None, "vec": [0.0] * 2381},
            {"path": "p6/Windows/ok.dll", "partition": "p6", "inode": "1002",
             "file_sha256": "c" * 64, "file_md5": "d" * 32, "file_size": 4096,
             "allocated": False, "data_offset": None,
             "mtime": None, "atime": None, "ctime": None, "btime": None,
             "vec": [0.0] * 2381},
        ],
    }


def fake_memory_extract(_path, names, _progress_file=None):
    return {
        "vec": [0.0] * len(names),
        "gaps": [{"field": "psxview.not_in_session", "plugin": "psxview",
                  "confidence": "missing", "reason": "no Volatility 3 equivalent"},
                 {"field": "malfind.protection", "plugin": "malfind",
                  "confidence": "inferred", "reason": "summed Vol2 protection index"}],
        "plugin_rows": {"pslist": 78},
        "bits": 64,
        "svcscan_raw_rows": 1311,
        "svcscan_duplicate_ratio": 2.207,
    }


class FakeFuture:
    def __init__(self, value):
        self._value = value

    def result(self, timeout=None):
        return self._value


class FakePool:
    """Stands in for the ProcessPoolExecutor so tests exercise the job body
    without spawning interpreters or touching a real artifact."""

    def __init__(self, fn):
        self.fn = fn
        self.calls = []

    def submit(self, target, *args):
        self.calls.append((target.__name__, args))
        return FakeFuture(self.fn(*args))


@pytest.fixture
def disk_job(db, analyst, app):
    job = Job(user=analyst, filename="case.dd", stored_name="j1.dd", sha256="a" * 64,
              size_bytes=1024, artifact=DISK, status=PENDING)
    db.session.add(job)
    db.session.commit()
    return job


@pytest.fixture
def memory_job(db, analyst):
    job = Job(user=analyst, filename="win.raw", stored_name="j2.raw", sha256="b" * 64,
              size_bytes=2048, artifact=MEMORY, status=PENDING)
    db.session.add(job)
    db.session.commit()
    return job


def load_models():
    from app.config import Config
    from app.inference import disk, memory
    disk.load(Config.MODELS_DIR, Config.REFERENCE_DIR)
    memory.load(Config.MODELS_DIR, Config.REFERENCE_DIR)


def run_job(app, job_id):
    """jobs.run commits inside its own app context - which is the point, since a
    worker thread has none - so the test's session is holding a pre-run copy
    until it is expired."""
    jobs.run(app, job_id)
    db.session.expire_all()
    return db.session.get(Job, job_id)


def test_disk_job_persists_one_result_per_file(app, disk_job, monkeypatch):
    load_models()
    monkeypatch.setattr(jobs, "pool", lambda: FakePool(fake_disk_scan))
    job = run_job(app, disk_job.id)
    assert job.status == COMPLETED
    assert len(job.results) == 2
    assert job.files_scanned == 3817
    assert job.skipped[0]["reason"].endswith("size cap")

    for r in job.results:
        assert r.path and r.file_sha256, "hard rule 16"
        assert r.threshold == DISK_THRESHOLD
        assert 0.0 <= r.probability <= 1.0


def test_disk_job_records_locators_and_timestamps(app, disk_job, monkeypatch):
    load_models()
    monkeypatch.setattr(jobs, "pool", lambda: FakePool(fake_disk_scan))
    evil = next(r for r in run_job(app, disk_job.id).results
                if r.path.endswith("evil.exe"))
    assert evil.inode == "1001"
    assert evil.file_md5 == "b" * 32
    assert evil.data_offset == 4096
    assert evil.allocated is True
    assert evil.mtime.year == 2025


def test_memory_job_uses_one_row_and_records_ood(app, memory_job, monkeypatch):
    load_models()
    monkeypatch.setattr(jobs, "pool", lambda: FakePool(fake_memory_extract))
    job = run_job(app, memory_job.id)
    assert job.status == COMPLETED
    assert len(job.results) == 1
    assert job.results[0].path is None
    assert job.results[0].threshold == MEM_THRESHOLD
    assert job.ood_count > 0, "hard rule 17"
    assert job.ood_fields


def test_memory_job_keeps_gaps_split_by_confidence(app, memory_job, monkeypatch):
    load_models()
    monkeypatch.setattr(jobs, "pool", lambda: FakePool(fake_memory_extract))
    gaps = run_job(app, memory_job.id).extraction_gaps
    assert {g["confidence"] for g in gaps} == {"missing", "inferred"}


def test_status_transitions_and_duration(app, disk_job, monkeypatch):
    load_models()
    monkeypatch.setattr(jobs, "pool", lambda: FakePool(fake_disk_scan))
    job = run_job(app, disk_job.id)
    assert job.started_at and job.finished_at
    assert job.duration is not None and job.duration >= 0


def test_a_failing_extractor_marks_the_job_failed_not_hung(app, disk_job, monkeypatch):
    def boom(*_a):
        raise RuntimeError("image is truncated")

    monkeypatch.setattr(jobs, "pool", lambda: FakePool(boom))
    job = run_job(app, disk_job.id)
    assert job.status == FAILED
    assert "truncated" in job.error
    assert job.finished_at is not None


def test_a_job_with_no_artifact_type_fails_cleanly(app, db, analyst, monkeypatch):
    job = Job(user=analyst, filename="x.raw", stored_name="j3.raw", sha256="c" * 64,
              size_bytes=1, artifact=None, status=PENDING)
    db.session.add(job)
    db.session.commit()

    assert run_job(app, job.id).status == FAILED


def test_orphaned_running_jobs_are_failed_at_boot(app, db, analyst):
    job = Job(user=analyst, filename="x.dd", stored_name="j4.dd", sha256="d" * 64,
              size_bytes=1, artifact=DISK, status=RUNNING)
    db.session.add(job)
    db.session.commit()

    assert jobs.recover_orphans(app) == 1
    refreshed = db.session.get(Job, job.id)
    assert refreshed.status == FAILED
    assert "interrupted" in refreshed.error
    assert jobs.recover_orphans(app) == 0


def test_status_endpoint_is_counts_only(client, signed_in):
    client.post("/upload", data={"artifact_file": (io.BytesIO(MBR), "img.dd"),
                                 "artifact": "auto"},
                content_type="multipart/form-data")
    job = db.session.query(Job).one()

    body = client.get(f"/jobs/{job.id}/status").get_json()
    assert set(body) == {"id", "status", "error", "done", "duration",
                         "stage", "progress_pct",
                         "files_scanned", "files_flagged", "ood_count", "results"}
    assert "path" not in str(body)


def test_upload_dispatches_the_job(client, signed_in, monkeypatch):
    started = []
    import app.routes as routes
    monkeypatch.setattr(routes.job_queue, "start",
                        lambda app, jid: started.append(jid))

    client.post("/upload", data={"artifact_file": (io.BytesIO(MBR), "img.dd"),
                                 "artifact": "auto"},
                content_type="multipart/form-data")
    assert started == [db.session.query(Job).one().id]


def test_confirming_an_ambiguous_type_dispatches_too(client, signed_in, monkeypatch):
    started = []
    import app.routes as routes
    monkeypatch.setattr(routes.job_queue, "start",
                        lambda app, jid: started.append(jid))

    client.post("/upload", data={"artifact_file": (io.BytesIO(bytes(range(256)) * 8),
                                                   "cap.raw"), "artifact": "auto"},
                content_type="multipart/form-data")
    job = db.session.query(Job).one()
    assert started == []

    client.post(f"/jobs/{job.id}/type", data={"artifact": MEMORY})
    assert started == [job.id]


def test_dispatch_is_disabled_under_test_config(app, disk_job):
    assert app.config["DISPATCH_JOBS"] is False
    jobs.start(app, disk_job.id)
    assert db.session.get(Job, disk_job.id).status == PENDING
