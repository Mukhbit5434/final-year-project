from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, PasswordField, RadioField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional

from .models import DISK, MEMORY


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Stay signed in")
    submit = SubmitField("Sign in")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 64)])
    email = StringField("Email", validators=[Optional(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12)])
    confirm = PasswordField("Confirm password",
                            validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create account")


class UploadForm(FlaskForm):
    artifact_file = FileField("Disk image or memory dump", validators=[FileRequired()])
    artifact = RadioField(
        "Artifact type",
        choices=[("auto", "Detect automatically"), (DISK, "Disk image"),
                 (MEMORY, "Memory dump")],
        default="auto")
    submit = SubmitField("Upload and queue")


class ConfirmTypeForm(FlaskForm):
    artifact = RadioField("This artifact is a",
                          choices=[(DISK, "Disk image"), (MEMORY, "Memory dump")],
                          validators=[DataRequired()])
    submit = SubmitField("Confirm")