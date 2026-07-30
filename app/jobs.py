import json
import logging
from concurrent.futures import ProcessPoolExecutor

from .db import db
from .models import (COMPLETED, DISK, FAILED, MEMORY, RUNNING, Finding, Job,
                     Result, utcnow)

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


def _findings(result, described, matched):
    """Attach the tag that claimed each feature, if any."""
    owner = {}
    for m in matched:
        for feature in m["features"]:
            owner.setdefault(feature, m)

    for item in described:
        m = owner.get(item["feature"])
        db.session.add(Finding(
            result=result, feature=item["feature"], weight=item.get("weight"),
            rank=item.get("rank"), meaning=item["why"],
            tag=m["tag"] if m else None,
            mitre_id=m["mitre_id"] if m else None,
            mitre_name=m["mitre_name"] if m else None,
            confidence=m["confidence"] if m else None))


def _disk(app, job, path):
    from . import explain
    from .forensics import mitre, severity
    from .inference import disk as model

    cfg = app.config
    out = pool().submit(extract_disk, str(path), cfg["MAX_PE_FILES"],
                        cfg["MAX_PE_BYTES"]).result()

    names = model.names()
    flagged = 0
    for rec in out["files"]:
        vec = model.subset(rec["vec"])
        prob, malicious = model.predict(vec)
        flagged += malicious

        result = Result(
            job=job, probability=prob, threshold=model.threshold(),
            malicious=bool(malicious),
            path=rec["path"], partition=rec["partition"], inode=rec["inode"],
            file_sha256=rec["file_sha256"], file_md5=rec["file_md5"],
            file_size=rec["file_size"], allocated=rec["allocated"],
            data_offset=rec["data_offset"], mtime=rec["mtime"],
            atime=rec["atime"], ctime=rec["ctime"], btime=rec["btime"])
        db.session.add(result)

        if not malicious:
            # Explaining a benign verdict wastes the expensive part of LIME.
            result.severity, result.severity_note = severity.for_disk(
                prob, [], model.threshold())
            continue

        described = explain.disk_findings(vec)
        values = dict(zip(names, (float(x) for x in vec)))
        matched = mitre.match([d["feature"] for d in described], "disk", values)
        result.severity, result.severity_note = severity.for_disk(
            prob, matched, model.threshold())
        _findings(result, described, matched)

    job.files_scanned = out["examined"]
    job.files_flagged = flagged
    job.skipped = out["skipped"]


def _memory(app, job, path):
    from . import explain
    from .forensics import baseline, meanings, mitre, severity
    from .inference import memory as model

    names = model.names()
    out = pool().submit(extract_memory, str(path), names).result()
    vec = out["vec"]

    prob, malicious = model.predict(vec)
    count, fields = model.ood(vec)
    # The score is only worth admitting when the four features the model actually
    # leans on are inside the range it was fitted on (CLAUDE.md 5.4a, 9.6).
    dominant = model.dominant_ood(vec)
    reliable = not dominant

    job.extraction_gaps = out["gaps"]
    job.ood_count = count
    job.ood_fields = fields

    # Evidence first. These are Volatility's measurements of this dump and hold
    # whatever the probability says, so they are collected regardless of verdict.
    observed = meanings.observed(vec, names)
    elevated = baseline.compare(observed)

    # Two matches on purpose. Findings are labelled from everything observed, so
    # the analyst sees what each measurement maps to. Severity counts only what
    # stands out against the clean baseline - matching on presence alone scored
    # the clean reference capture itself as Critical.
    matched = mitre.match(list(observed), "memory")
    standout = mitre.match([f for f, is_high in elevated.items() if is_high], "memory")
    sev, note = severity.for_memory(elevated, standout, prob, reliable,
                                    baselined=baseline.loaded())

    result = Result(job=job, probability=prob, threshold=model.threshold(),
                    malicious=bool(malicious), severity=sev, severity_note=note)
    db.session.add(result)

    described = []
    for feature, value in sorted(observed.items(), key=lambda kv: -kv[1]):
        d = meanings.describe(feature)
        if d is None:
            continue
        d["why"] = f"{d['why']} {baseline.phrase(feature, value)}."
        d["rank"] = len(described) + 1
        described.append(d)

    # LIME explains the model, so it only earns its runtime when the model both
    # flags and is worth listening to.
    if malicious and reliable:
        seen = {d["feature"] for d in described}
        for d in explain.memory_findings(vec):
            if d["feature"] not in seen:
                d["rank"] = len(described) + 1
                described.append(d)

    _findings(result, described, matched)


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