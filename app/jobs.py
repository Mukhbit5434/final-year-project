import json
import logging
from concurrent.futures import ProcessPoolExecutor

from .db import db
from .models import (COMPLETED, DISK, FAILED, MEMORY, RUNNING, Job, Result,
                     utcnow)

log = logging.getLogger(__name__)

_pool = None


def pool():
    """Extraction runs out of process, always.

    lief parses hostile PEs in native code and a segfault would take the web
    server with it, and volatility3 is CPU-bound Python that would otherwise hold
    the GIL for minutes at a time (hard rule 20). Created lazily so importing
    this module in a test or a CLI script does not spawn workers.
    """
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(max_workers=1)
    return _pool


def extract_disk(path, max_files, max_bytes):
    from .extractors import disk
    out = disk.scan(path, max_files=max_files, max_bytes=max_bytes, workers=2)
    # Vectors come back as float32 arrays; lists survive pickling between
    # interpreter versions more predictably and this is not a hot path.
    for rec in out["files"]:
        rec["vec"] = rec["vec"].tolist()
    return out


def extract_memory(path, feature_names):
    from .extractors import memory
    return memory.extract(path, feature_names)


def start(app, job_id):
    if not app.config.get("DISPATCH_JOBS", True):
        return
    from . import executor
    executor.submit(run, app, job_id)


def run(app, job_id):
    # Flask-Executor hands the task a bare thread with no application context.
    with app.app_context():
        job = db.session.get(Job, job_id)
        if job is None:
            return
        try:
            job.status = RUNNING
            job.started_at = utcnow()
            db.session.commit()

            path = app.config["UPLOAD_DIR"] / job.stored_name
            if job.artifact == DISK:
                _disk(app, job, path)
            elif job.artifact == MEMORY:
                _memory(app, job, path)
            else:
                raise ValueError(f"job {job.id} has no artifact type")

            job.status = COMPLETED
        except Exception as e:
            log.exception("job %s failed", job_id)
            job.status = FAILED
            job.error = f"{type(e).__name__}: {e}"[:2000]
        finally:
            job.finished_at = utcnow()
            db.session.commit()
            db.session.remove()


def _disk(app, job, path):
    from .inference import disk as model

    cfg = app.config
    out = pool().submit(extract_disk, str(path), cfg["MAX_PE_FILES"],
                        cfg["MAX_PE_BYTES"]).result()

    flagged = 0
    for rec in out["files"]:
        prob, malicious = model.predict(model.subset(rec["vec"]))
        flagged += malicious
        db.session.add(Result(
            job=job, probability=prob, threshold=model.threshold(),
            malicious=bool(malicious),
            path=rec["path"], partition=rec["partition"], inode=rec["inode"],
            file_sha256=rec["file_sha256"], file_md5=rec["file_md5"],
            file_size=rec["file_size"], allocated=rec["allocated"],
            data_offset=rec["data_offset"], mtime=rec["mtime"],
            atime=rec["atime"], ctime=rec["ctime"], btime=rec["btime"]))

    job.files_scanned = out["examined"]
    job.files_flagged = flagged
    job.skipped = out["skipped"]


def _memory(app, job, path):
    from .inference import memory as model

    names = model.names()
    out = pool().submit(extract_memory, str(path), names).result()
    vec = out["vec"]

    prob, malicious = model.predict(vec)
    count, fields = model.ood(vec)

    job.extraction_gaps = out["gaps"]
    job.ood_count = count
    job.ood_fields = fields
    # One row: the unit of analysis is the whole dump, not a file.
    db.session.add(Result(job=job, probability=prob, threshold=model.threshold(),
                          malicious=bool(malicious)))


def recover_orphans(app):
    """A job left RUNNING did not survive the last shutdown - nothing is going to
    finish it, so say so rather than leaving it spinning in the UI forever."""
    with app.app_context():
        stale = db.session.query(Job).filter_by(status=RUNNING).all()
        for job in stale:
            job.status = FAILED
            job.error = "interrupted: the server stopped while this job was running"
            job.finished_at = utcnow()
        if stale:
            log.warning("marked %d interrupted job(s) as failed", len(stale))
            db.session.commit()
        return len(stale)