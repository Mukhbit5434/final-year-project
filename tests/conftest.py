import pytest

from app import create_app
from app.config import TestConfig
from app.db import db as _db
from app.models import User


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
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