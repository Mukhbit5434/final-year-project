from flask import has_request_context, request
from flask_login import current_user

from .db import db
from .models import AuditLog


def log(action, detail=None, job=None, user=None):
    if user is None and has_request_context() and current_user.is_authenticated:
        user = current_user

    ip = None
    if has_request_context():
        ip = request.remote_addr

    db.session.add(AuditLog(
        user_id=getattr(user, "id", None),
        job_id=getattr(job, "id", None) if job is not None else None,
        action=action, detail=detail, ip=ip))