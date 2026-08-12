from pathlib import Path

from flask import Flask, render_template
from flask_executor import Executor
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from .config import Config
from .db import db

executor = Executor()
login = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def create_app(config=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config.get("TESTING"):
        app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    executor.init_app(app)
    limiter.init_app(app)

    login.init_app(app)
    login.login_view = "auth.login"
    login.login_message_category = "warning"

    from . import models

    if app.config.get("LOAD_MODELS", True):
        from . import explain, inference
        from .forensics import baseline
        inference.init(app.config["MODELS_DIR"], app.config["REFERENCE_DIR"])
        explain.init(app.config["MODELS_DIR"], app.config["REFERENCE_DIR"])
        baseline.load(app.config["BASELINE_FILE"])

    @login.user_loader
    def load_user(uid):
        return db.session.get(models.User, int(uid))

    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    if app.config.get("RECOVER_ORPHANS", True):
        from . import jobs
        try:
            jobs.recover_orphans(app)
        except Exception:
            app.logger.debug("orphan recovery skipped", exc_info=True)

    @app.errorhandler(413)
    def too_large(_e):
        gb = app.config["MAX_CONTENT_LENGTH"] // 1024 ** 3
        return render_template("error.html", code=413,
                               message=f"That artifact is larger than the {gb} GB limit."), 413

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Not found."), 404

    @app.shell_context_processor
    def shell_ctx():
        return {"db": db, "m": models}

    return app