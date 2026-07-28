from pathlib import Path

from flask import Flask
from flask_executor import Executor
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from .config import Config
from .db import db

executor = Executor()
login = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()


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

    login.init_app(app)
    login.login_view = "auth.login"
    login.login_message_category = "warning"

    from . import models

    @login.user_loader
    def load_user(uid):
        return db.session.get(models.User, int(uid))

    @app.shell_context_processor
    def shell_ctx():
        return {"db": db, "m": models}

    return app