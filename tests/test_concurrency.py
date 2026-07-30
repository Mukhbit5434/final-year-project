import io
import threading

import pytest

from app import create_app, jobs
from app.config import TestConfig
from app.db import db
from app.models import COMPLETED, DISK, PENDING, Job, Result, User

from test_jobs import FakePool, fake_disk_scan, load_models

MBR = b"\x33\xc0" + b"\x00" * 508 + b"\x55\xaa" + b"\x00" * 512


@pytest.fixture
def file_app(tmp_path):
    """The concurrency tests need a file-backed database, not the in-memory one.

    Flask-SQLAlchemy hands every thread the same connection for `sqlite://`, so
    concurrent transactions collide there in a way they never do in production -
    which runs file-backed SQLite in WAL with a busy timeout. Testing the
    in-memory configuration would be testing something we do not ship.
    """
    class FileConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{(tmp_path / 'jobs.db').as_posix()}"

    app = create_app(FileConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()


@pytest.fixture
def file_analyst(file_app):
    u = User(username="farooq")
    u.set_password("correct horse battery staple")
    db.session.add(u)
    db.session.commit()
    return u


def make(db, analyst, n):
    out = []
    for i in range(n):
        job = Job(user=analyst, filename=f"c{i}.dd", stored_name=f"c{i}.dd",
                  sha256=f"{i:064d}", size_bytes=1024, artifact=DISK, status=PENDING)
        db.session.add(job)
        out.append(job)
    db.session.commit()
    return [j.id for j in out]


def test_the_test_database_is_file_backed(file_app):
    uri = file_app.config["SQLALCHEMY_DATABASE_URI"]
    assert uri.startswith("sqlite:///") and not uri.endswith("://")
    mode = db.session.execute(db.text("PRAGMA journal_mode")).scalar()
    assert mode == "wal", "concurrency depends on WAL; see app/db.py"


def test_concurrent_jobs_do_not_corrupt_each_others_state(file_app, file_analyst,
                                                          monkeypatch):
    app, analyst = file_app, file_analyst
    load_models()
    monkeypatch.setattr(jobs, "pool", lambda: FakePool(fake_disk_scan))
    ids = make(db, analyst, 6)

    errors = []

    def worker(job_id):
        try:
            jobs.run(app, job_id)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert errors == []
    db.session.expire_all()
    for job_id in ids:
        job = db.session.get(Job, job_id)
        assert job.status == COMPLETED, f"job {job_id} ended {job.status}: {job.error}"
        # Each job must own exactly its own results - two rows per fake scan.
        assert len(job.results) == 2
        assert all(r.job_id == job_id for r in job.results)

    assert db.session.query(Result).count() == 2 * len(ids)


def test_many_uploads_keep_distinct_stored_names(client, signed_in):
    # Names are generated, not taken from the client, so concurrent uploads of
    # identically named files must not collide on disk or in the unique index.
    for _ in range(8):
        client.post("/upload",
                    data={"artifact_file": (io.BytesIO(MBR), "same-name.dd"),
                          "artifact": "auto"},
                    content_type="multipart/form-data")
    jobs_ = db.session.query(Job).all()
    assert len(jobs_) == 8
    assert len({j.stored_name for j in jobs_}) == 8
    assert len({j.filename for j in jobs_}) == 1


def test_a_failing_job_does_not_affect_its_neighbours(file_app, file_analyst,
                                                      monkeypatch):
    app, analyst = file_app, file_analyst
    load_models()
    ids = make(db, analyst, 3)
    calls = {"n": 0}

    def flaky(*_a):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("image is truncated")
        return fake_disk_scan(None, None, None)

    monkeypatch.setattr(jobs, "pool", lambda: FakePool(flaky))
    for job_id in ids:
        jobs.run(app, job_id)

    db.session.expire_all()
    states = [db.session.get(Job, i).status for i in ids]
    assert states.count(COMPLETED) == 2
    assert states.count("FAILED") == 1