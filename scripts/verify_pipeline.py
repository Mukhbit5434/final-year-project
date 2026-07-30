"""End-to-end verification against real artifacts.

Runs whatever is present in sample/ through the full job pipeline - extraction in
the worker pool, prediction, findings, tags, severity, persistence - then renders
the reports and exercises every route. This is the check that caught six silent
bugs that unit tests could not; keep it runnable.

    scripts\\verify_pipeline.py [--keep]

Uses instance/verify.db so it never disturbs the development database.
"""
import argparse
import multiprocessing
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SAMPLES = [
    ("disk", ROOT / "sample" / "disk" / "2020JimmyWilson.E01"),
    ("memory", ROOT / "sample" / "memory" / "win10_memory.raw"),
    ("memory", ROOT / "sample" / "memory" / "Windows 10-32-f7257ea7.vmem"),
]

# What the artifacts above produced when last verified. Drifting from these is not
# automatically wrong - a different capture legitimately differs - but it is worth
# understanding before accepting.
EXPECTED = {
    "2020JimmyWilson.E01": "3,817 files examined, 13 results, 0 flagged, 60 skipped",
    "win10_memory.raw": "67 processes (ground truth 67), 21 of 55 out of distribution",
    "Windows 10-32-f7257ea7.vmem": "23 of 55 out of distribution, custom PAE layer",
}


def main():
    import logging
    logging.basicConfig(level=logging.WARNING)

    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="keep the verification database afterwards")
    args = ap.parse_args()

    from app import create_app, jobs, report
    from app.config import Config
    from app.db import db
    from app.forensics import baseline
    from app.models import PENDING, Finding, Job, Result, User

    class VerifyConfig(Config):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{(ROOT / 'instance' / 'verify.db').as_posix()}"
        WTF_CSRF_ENABLED = False

    (ROOT / "instance").mkdir(exist_ok=True)
    app = create_app(VerifyConfig)
    failures = []

    with app.app_context():
        db.create_all()
        print("baseline loaded:", baseline.loaded())

        user = db.session.query(User).filter_by(username="verify").first()
        if user is None:
            user = User(username="verify")
            user.set_password("verify-only-not-a-login")
            db.session.add(user)
            db.session.commit()

        for artifact, src in SAMPLES:
            if not src.exists():
                print(f"\n-- skipping {src.name}: not present")
                continue

            stored = f"verify_{src.name}"
            dest = app.config["UPLOAD_DIR"] / stored
            if not dest.exists():
                print(f"copying {src.name} into uploads/ ...", flush=True)
                import shutil
                shutil.copy2(src, dest)

            job = db.session.query(Job).filter_by(stored_name=stored).first()
            if job is None:
                job = Job(user_id=user.id, filename=src.name, stored_name=stored,
                          sha256="0" * 64, size_bytes=dest.stat().st_size,
                          artifact=artifact, status=PENDING)
                db.session.add(job)
            else:
                job.status, job.error = PENDING, None
                for r in list(job.results):
                    db.session.delete(r)
            db.session.commit()

            print(f"\n=== {src.name} ({artifact})")
            print(f"    last verified: {EXPECTED.get(src.name, 'n/a')}")
            jobs.run(app, job.id)
            db.session.expire_all()
            job = db.session.get(Job, job.id)

            print(f"    status  : {job.status}"
                  + (f" ({job.duration:.0f}s)" if job.duration else ""))
            if job.error:
                failures.append(f"{src.name}: {job.error}")
                print(f"    error   : {job.error}")
                continue
            print(f"    results : {len(job.results)}   "
                  f"findings: {sum(len(r.findings) for r in job.results)}")
            if job.files_scanned:
                print(f"    scanned : {job.files_scanned:,}   flagged: {job.files_flagged}"
                      f"   skipped: {len(job.skipped or [])}")
            if job.ood_count is not None:
                print(f"    ood     : {job.ood_count} of 55   "
                      f"gaps: {len(job.extraction_gaps or [])}")

            for r in sorted(job.results, key=lambda r: -r.probability)[:3]:
                print(f"      p={r.probability:.4f} {r.severity or '-':8s} "
                      f"{r.path or 'whole dump'}")
                if r.severity_note:
                    print(f"        {r.severity_note}")

            pdf = report.render(job)
            required = report.REQUIRED_ALWAYS + (
                report.REQUIRED_MEMORY if artifact == "memory" else report.REQUIRED_DISK)
            body = report.render(job, compress=False)
            for text in required:
                if text.encode("latin-1", "replace") not in body:
                    failures.append(f"{src.name}: report is missing {text!r}")
            print(f"    report  : {len(pdf):,} bytes, "
                  f"{len(required)} mandatory strings checked")

        job_ids = [j.id for j in db.session.query(Job).all()]

    with app.test_client() as c:
        c.post("/login", data={"username": "verify",
                               "password": "verify-only-not-a-login"})
        print("\n=== routes")
        for job_id in job_ids:
            for suffix in ("", "/status", "/export.csv", "/export.json", "/report.pdf"):
                r = c.get(f"/jobs/{job_id}{suffix}")
                flag = "" if r.status_code == 200 else "  <-- UNEXPECTED"
                if r.status_code != 200:
                    failures.append(f"GET /jobs/{job_id}{suffix} -> {r.status_code}")
                print(f"    GET /jobs/{job_id}{suffix:14s} {r.status_code} "
                      f"{len(r.data):>9,} bytes{flag}")

        with app.app_context():
            for job in db.session.query(Job).all():
                for path in (f"/static/{job.stored_name}", f"/uploads/{job.stored_name}"):
                    if c.get(path).status_code not in (404, 308):
                        failures.append(f"{path} is reachable over HTTP")
    print("\nuploaded artifacts unreachable over HTTP: "
          f"{'yes' if not any('reachable' in f for f in failures) else 'NO'}")

    if not args.keep:
        for suffix in ("", "-wal", "-shm"):
            (ROOT / "instance" / f"verify.db{suffix}").unlink(missing_ok=True)

    print("\n" + ("FAILURES:" if failures else "all checks passed"))
    for f in failures:
        print("  -", f)
    return 1 if failures else 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())