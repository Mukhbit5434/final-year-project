import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _gb(name, default):
    return int(os.environ.get(name, default)) * 1024 ** 3


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-not-for-deployment")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{(ROOT / 'instance' / 'app.db').as_posix()}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", ROOT / "uploads"))
    MAX_CONTENT_LENGTH = _gb("MAX_UPLOAD_GB", 32)
    ALLOWED_EXT = {".dd", ".raw", ".img", ".e01", ".ex01", ".mem", ".dmp", ".vmem"}

    MODELS_DIR = ROOT / "models"
    REFERENCE_DIR = ROOT / "reference_data"
    BASELINE_FILE = Path(os.environ.get(
        "BASELINE_FILE", ROOT / "baselines" / "clean_win10_x64.json"))

    MAX_PE_FILES = int(os.environ.get("MAX_PE_FILES", 500))
    MAX_PE_BYTES = int(os.environ.get("MAX_PE_MB", 64)) * 1024 ** 2

    UPLOAD_RATE_LIMIT = os.environ.get("UPLOAD_RATE_LIMIT", "60 per hour")

    EXECUTOR_TYPE = "thread"
    EXECUTOR_MAX_WORKERS = int(os.environ.get("JOB_WORKERS", 2))
    EXECUTOR_PROPAGATE_EXCEPTIONS = False

    LOAD_MODELS = True
    RECOVER_ORPHANS = True

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = bool(os.environ.get("HTTPS"))
    WTF_CSRF_TIME_LIMIT = None


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test"
    UPLOAD_RATE_LIMIT = "10 per hour"
    LOAD_MODELS = False
    RECOVER_ORPHANS = False
    DISPATCH_JOBS = False
