from app.db import db
from app.models import AuditLog, User


def register(client, username="mukhbit", password="a-long-enough-pass",
            email="mukhbit@example.com"):
    return client.post("/register", data={
        "username": username, "email": email, "password": password, "confirm": password,
    }, follow_redirects=True)


def login(client, username="farooq", password="correct horse battery staple"):
    return client.post("/login", data={"username": username, "password": password})


def test_register_then_sign_in(client):
    assert register(client).status_code == 200
    user = db.session.query(User).filter_by(username="mukhbit").one()
    assert user.pw_hash and user.pw_hash != "a-long-enough-pass"

    r = client.post("/login", data={"username": "mukhbit", "password": "a-long-enough-pass"})
    assert r.status_code == 302


def test_register_with_an_email_address(client):
    """A real address round-trips correctly - it once 500'd on the browser path."""
    r = client.post("/register", data={
        "username": "withmail", "email": "analyst@example.com",
        "password": "a-long-enough-pass", "confirm": "a-long-enough-pass",
    }, follow_redirects=True)
    assert r.status_code == 200
    user = db.session.query(User).filter_by(username="withmail").one()
    assert user.email == "analyst@example.com"


def test_registration_is_rejected_without_an_email(client):
    # Server-side, not just the browser's own required-field checking - the
    # form is posted directly, bypassing any client-side validation entirely.
    r = client.post("/register", data={"username": "noemail", "email": "",
                                       "password": "a-long-enough-pass",
                                       "confirm": "a-long-enough-pass"})
    assert r.status_code == 200
    assert db.session.query(User).filter_by(username="noemail").first() is None
    assert b"This field is required" in r.data


def test_registration_is_rejected_with_a_whitespace_only_email(client):
    r = client.post("/register", data={"username": "spacemail", "email": "   ",
                                       "password": "a-long-enough-pass",
                                       "confirm": "a-long-enough-pass"})
    assert r.status_code == 200
    assert db.session.query(User).filter_by(username="spacemail").first() is None


def test_short_password_is_rejected(client):
    r = client.post("/register", data={"username": "x", "email": "x@example.com",
                                       "password": "short", "confirm": "short"})
    assert r.status_code == 200
    assert db.session.query(User).filter_by(username="x").first() is None


def test_username_match_is_case_insensitive(client, analyst):
    assert client.post("/login", data={"username": "FarOOq",
                                       "password": "correct horse battery staple"}
                       ).status_code == 302


def test_bad_password_is_401_and_audited(client, analyst):
    r = login(client, password="nope")
    assert r.status_code == 401
    row = db.session.query(AuditLog).filter_by(action="login_failed").one()
    assert "farooq" in row.detail


def test_wrong_username_gives_the_same_message_as_wrong_password(client, analyst):
    # Unknown user and bad password must be indistinguishable, or the login page
    # becomes a user-enumeration oracle. The pages differ only by the username
    # the client itself submitted, which tells an attacker nothing.
    a = login(client, username="ghost", password="whatever")
    b = login(client, password="nope")
    assert a.status_code == b.status_code == 401
    assert b"Incorrect username or password." in a.data
    assert a.data.replace(b"ghost", b"farooq") == b.data


def test_disabled_account_cannot_sign_in(client, analyst):
    analyst.is_active = False
    db.session.commit()
    assert login(client).status_code == 403


def test_login_redirect_ignores_absolute_urls(client, analyst):
    r = client.post("/login?next=https://evil.example/steal",
                    data={"username": "farooq", "password": "correct horse battery staple"})
    assert r.headers["Location"] == "/jobs"


def test_login_redirect_honours_local_paths(client, analyst):
    r = client.post("/login?next=/upload",
                    data={"username": "farooq", "password": "correct horse battery staple"})
    assert r.headers["Location"] == "/upload"


def test_protected_pages_require_a_session(client):
    for path in ("/jobs", "/upload", "/jobs/1"):
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_logout_is_post_only(client, analyst):
    login(client)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 302
    assert db.session.query(AuditLog).filter_by(action="logout").count() == 1