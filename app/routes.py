import csv
import io
import json
from collections import Counter
from datetime import datetime

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from . import artifacts, jobs as job_queue, limiter
from .audit import log
from .db import db
from .forms import ConfirmTypeForm, UploadForm
from .models import (DISK, MEMORY, NEEDS_TYPE, PENDING, SEVERITY_ORDER, Job)

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.jobs"))
    return redirect(url_for("auth.login"))


@bp.route("/jobs")
@login_required
def jobs():
    rows = (db.session.query(Job)
            .filter_by(user_id=current_user.id)
            .order_by(Job.created_at.desc())
            .all())
    return render_template("jobs.html", jobs=rows)


@bp.route("/jobs/<int:job_id>")
@login_required
def job_detail(job_id):
    from . import report
    from .forensics import baseline

    job = _owned(job_id)
    # Most severe first: an analyst reads the top of this table and stops.
    results = sorted(job.results,
                     key=lambda r: (-SEVERITY_ORDER.get(r.severity, 0), -r.probability))
    counts = Counter(r.severity or "Unrated" for r in results)
    return render_template("job_detail.html", job=job, results=results,
                           severity_counts=counts, baseline=baseline.info(),
                           limitations=report.limitations(job))


@bp.route("/jobs/<int:job_id>/report.pdf")
@login_required
def report(job_id):
    from . import report as renderer

    job = _owned(job_id)
    pdf = renderer.render(job)
    log("report_download", job=job, detail=f"{len(pdf)} bytes")
    db.session.commit()
    return current_app.response_class(
        pdf, mimetype="application/pdf",
        headers={"Content-Disposition":
                 f"inline; filename=forensic_report_job{job.id}.pdf"})


@bp.route("/jobs/<int:job_id>/export.<fmt>")
@login_required
def export(job_id, fmt):
    job = _owned(job_id)
    rows = sorted(job.results, key=lambda r: (-SEVERITY_ORDER.get(r.severity, 0),
                                              -r.probability))
    log("report_export", job=job, detail=fmt)
    db.session.commit()

    fields = ["path", "partition", "inode", "file_sha256", "file_md5", "file_size",
              "allocated", "data_offset", "mtime", "atime", "ctime", "btime",
              "probability", "threshold", "malicious", "severity"]

    if fmt == "json":
        payload = [{f: _plain(getattr(r, f)) for f in fields} |
                   {"indicators": [{"tag": x.tag, "mitre_id": x.mitre_id,
                                    "feature": x.feature} for x in r.findings]}
                   for r in rows]
        return current_app.response_class(
            json.dumps({"job": job.id, "artifact": job.artifact,
                        "sha256": job.sha256, "results": payload}, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=job{job.id}.json"})

    if fmt != "csv":
        abort(404)

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(fields + ["indicators"])
    for r in rows:
        writer.writerow([_plain(getattr(r, f)) for f in fields] +
                        ["; ".join(sorted({x.tag for x in r.findings if x.tag}))])
    return current_app.response_class(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=job{job.id}.csv"})


def _plain(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return value


@bp.route("/jobs/<int:job_id>/status")
@login_required
def job_status(job_id):
    job = _owned(job_id)
    # Counts only. The per-file table can run to hundreds of rows and the page
    # polls this every few seconds until the job settles.
    return {"id": job.id, "status": job.status, "error": job.error,
            "done": job.done, "duration": job.duration,
            "files_scanned": job.files_scanned, "files_flagged": job.files_flagged,
            "ood_count": job.ood_count, "results": len(job.results)}


@bp.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def upload():
    form = UploadForm()
    if not form.validate_on_submit():
        return render_template("upload.html", form=form,
                               max_gb=current_app.config["MAX_CONTENT_LENGTH"] // 1024 ** 3)

    fs = form.artifact_file.data
    ext = artifacts.ext_of(fs.filename)
    if ext not in current_app.config["ALLOWED_EXT"]:
        allowed = ", ".join(sorted(current_app.config["ALLOWED_EXT"]))
        flash(f"{ext or 'That file type'} is not accepted. Allowed: {allowed}", "danger")
        log("upload_rejected", detail=f"extension {ext!r}")
        db.session.commit()
        return redirect(url_for("main.upload"))

    name, sha, size = artifacts.store(fs.stream, current_app.config["UPLOAD_DIR"], ext)
    path = current_app.config["UPLOAD_DIR"] / name

    chosen = form.artifact.data
    if chosen == "auto":
        detected, why = artifacts.sniff(path)
    else:
        detected, why = chosen, "selected by analyst at upload"

    job = Job(user_id=current_user.id,
              filename=fs.filename or name,
              stored_name=name, sha256=sha, size_bytes=size,
              artifact=detected, detected_as=why,
              status=PENDING if detected else NEEDS_TYPE)
    db.session.add(job)
    db.session.flush()
    log("upload", job=job, detail=f"{size} bytes, sha256={sha}, type={detected or 'undetermined'}")
    db.session.commit()

    if not detected:
        flash("Could not identify this artifact from its contents. Please tell us what it is.",
              "warning")
        return redirect(url_for("main.confirm_type", job_id=job.id))

    job_queue.start(current_app._get_current_object(), job.id)
    flash(f"Uploaded and queued as a {detected} artifact. Analysis takes minutes, "
          "not seconds.", "success")
    return redirect(url_for("main.job_detail", job_id=job.id))


@bp.route("/jobs/<int:job_id>/type", methods=["GET", "POST"])
@login_required
def confirm_type(job_id):
    job = _owned(job_id)
    if job.status != NEEDS_TYPE:
        return redirect(url_for("main.job_detail", job_id=job.id))

    form = ConfirmTypeForm()
    if form.validate_on_submit():
        job.artifact = form.artifact.data
        job.detected_as = "confirmed by analyst after inconclusive detection"
        job.status = PENDING
        log("artifact_type_set", job=job, detail=job.artifact)
        db.session.commit()
        job_queue.start(current_app._get_current_object(), job.id)
        flash(f"Queued as a {job.artifact} artifact.", "success")
        return redirect(url_for("main.job_detail", job_id=job.id))

    return render_template("confirm_type.html", form=form, job=job)


def _owned(job_id):
    job = db.session.get(Job, job_id)
    # 404 rather than 403 on someone else's job - a 403 confirms the id exists.
    if job is None or job.user_id != current_user.id:
        abort(404)
    return job