from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .db import db

PENDING, RUNNING, COMPLETED, FAILED = "PENDING", "RUNNING", "COMPLETED", "FAILED"
DISK, MEMORY = "disk", "memory"

LOW, MEDIUM, HIGH, CRITICAL = "Low", "Medium", "High", "Critical"
SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1}


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255))
    pw_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    jobs = db.relationship("Job", back_populates="user")

    def set_password(self, pw):
        self.pw_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.pw_hash, pw)

    def __repr__(self):
        return f"<User {self.username}>"


class Job(db.Model):
    __tablename__ = "jobs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    filename = db.Column(db.String(512), nullable=False)
    stored_name = db.Column(db.String(128), unique=True, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    size_bytes = db.Column(db.BigInteger, nullable=False)
    artifact = db.Column(db.String(8), nullable=False)

    status = db.Column(db.String(16), default=PENDING, nullable=False, index=True)
    error = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)

    files_scanned = db.Column(db.Integer)
    files_flagged = db.Column(db.Integer)
    # [{path, reason}] - an analyst has to be able to tell "scanned and clean"
    # from "never examined", so skips are recorded, not dropped.
    skipped = db.Column(db.JSON)

    # Memory only. gaps are [{field, reason, plugin, confidence}] and cover both
    # missing fields and ones whose derivation is inferred (CLAUDE.md 5.5).
    extraction_gaps = db.Column(db.JSON)
    ood_count = db.Column(db.Integer)
    ood_fields = db.Column(db.JSON)

    user = db.relationship("User", back_populates="jobs")
    results = db.relationship("Result", back_populates="job",
                              cascade="all, delete-orphan", passive_deletes=True)

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def done(self):
        return self.status in (COMPLETED, FAILED)

    def __repr__(self):
        return f"<Job {self.id} {self.artifact} {self.status}>"


class Result(db.Model):
    __tablename__ = "results"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id", ondelete="CASCADE"),
                       nullable=False, index=True)

    probability = db.Column(db.Float, nullable=False)
    # Stored per row rather than looked up later: the operating thresholds are
    # 0.2337 and 0.5011, and a report has to show the one actually applied.
    threshold = db.Column(db.Float, nullable=False)
    malicious = db.Column(db.Boolean, nullable=False)
    severity = db.Column(db.String(16))
    severity_note = db.Column(db.String(255))

    # Everything below is disk-only and null on the single memory row, where the
    # unit of analysis is the whole dump. Hard rule 16: no flagged file ships
    # without path and file_sha256.
    path = db.Column(db.Text)
    partition = db.Column(db.String(64))
    inode = db.Column(db.String(64))
    file_sha256 = db.Column(db.String(64), index=True)
    file_md5 = db.Column(db.String(32))
    file_size = db.Column(db.BigInteger)
    allocated = db.Column(db.Boolean)
    # Omitted rather than guessed - TSK does not expose it for resident files.
    data_offset = db.Column(db.BigInteger)
    mtime = db.Column(db.DateTime)
    atime = db.Column(db.DateTime)
    ctime = db.Column(db.DateTime)
    btime = db.Column(db.DateTime)

    job = db.relationship("Job", back_populates="results")
    findings = db.relationship("Finding", back_populates="result",
                               cascade="all, delete-orphan", passive_deletes=True)

    @property
    def rank(self):
        return SEVERITY_ORDER.get(self.severity, 0), self.probability

    def __repr__(self):
        return f"<Result {self.id} p={self.probability:.4f} {self.path or 'dump'}>"


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey("results.id", ondelete="CASCADE"),
                          nullable=False, index=True)

    feature = db.Column(db.String(128), nullable=False)
    # LIME contribution. Kept for the report appendix; never rendered raw in the
    # findings themselves (CLAUDE.md 8).
    weight = db.Column(db.Float)
    rank = db.Column(db.Integer)

    meaning = db.Column(db.Text)
    tag = db.Column(db.String(64))
    mitre_id = db.Column(db.String(16))
    mitre_name = db.Column(db.String(128))
    confidence = db.Column(db.String(16))

    result = db.relationship("Result", back_populates="findings")

    @property
    def mitre_url(self):
        if not self.mitre_id:
            return None
        return "https://attack.mitre.org/techniques/{}/".format(
            self.mitre_id.replace(".", "/"))

    def __repr__(self):
        return f"<Finding {self.feature} {self.mitre_id or '-'}>"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    # Null for events with no authenticated user, e.g. a rejected login.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), index=True)

    action = db.Column(db.String(32), nullable=False)
    detail = db.Column(db.Text)
    ip = db.Column(db.String(45))
    at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<Audit {self.action} u={self.user_id} j={self.job_id}>"