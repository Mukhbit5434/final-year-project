import pytest

from app import create_app, limiter
from app.config import TestConfig
from app.db import db as _db
from app.models import User


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
        # The limiter is a module-level singleton with in-memory storage, so its
        # counters would otherwise leak from one test into the next.
        limiter.reset()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def db(app):
    return _db


@pytest.fixture
def analyst(db):
    u = User(username="farooq", email="farooq@example.test")
    u.set_password("correct horse battery staple")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def client(app, tmp_path):
    app.config["UPLOAD_DIR"] = tmp_path / "uploads"
    return app.test_client()


@pytest.fixture
def signed_in(client, analyst):
    client.post("/login", data={"username": "farooq",
                                "password": "correct horse battery staple"})
    return analyst