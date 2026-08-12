from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func

from .audit import log
from .db import db
from .forms import LoginForm, RegisterForm
from .models import User

bp = Blueprint("auth", __name__)


def _by_name(username):
    return db.session.query(User).filter(
        func.lower(User.username) == username.strip().lower()).first()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.jobs"))

    form = LoginForm()
    if form.validate_on_submit():
        user = _by_name(form.username.data)
        if user is None or not user.check_password(form.password.data):
            log("login_failed", detail=f"username={form.username.data!r}")
            db.session.commit()
            flash("Incorrect username or password.", "danger")
            return render_template("auth/login.html", form=form), 401

        if not user.is_active:
            log("login_denied", detail="account disabled", user=user)
            db.session.commit()
            flash("That account is disabled.", "danger")
            return render_template("auth/login.html", form=form), 403

        login_user(user, remember=form.remember.data)
        log("login", user=user)
        db.session.commit()

        nxt = request.args.get("next", "")
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = url_for("main.jobs")
        return redirect(nxt)

    return render_template("auth/login.html", form=form)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.jobs"))

    form = RegisterForm()
    if form.validate_on_submit():
        if _by_name(form.username.data):
            flash("That username is taken.", "warning")
            return render_template("auth/register.html", form=form)

        user = User(username=form.username.data.strip(), email=form.email.data or None)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        log("register", user=user)
        db.session.commit()

        flash("Account created. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log("logout")
    db.session.commit()
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))