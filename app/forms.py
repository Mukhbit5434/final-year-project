from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, PasswordField, RadioField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Optional

from .models import DISK, MEMORY


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Stay signed in")
    submit = SubmitField("Sign in")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 64)])
    # Mandatory as of 2026-08-10. Still no Email() format validator: wtforms'
    # raises a bare Exception unless the separate email_validator package is
    # installed, which would 500 the whole registration route - not worth a
    # dependency just for format checking. DataRequired() only checks presence.
    email = StringField("Email", validators=[DataRequired(), Length(max=255)])
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
    # Free text, entirely optional - an analyst who doesn't have a case number
    # yet, or is just trying the system, must still be able to upload normally.
    case_ref = StringField("Case / investigation reference (optional)",
                           validators=[Optional(), Length(max=128)])
    submit = SubmitField("Upload and queue")


class ConfirmTypeForm(FlaskForm):
    artifact = RadioField("This artifact is a",
                          choices=[(DISK, "Disk image"), (MEMORY, "Memory dump")],
                          validators=[DataRequired()])
    submit = SubmitField("Confirm")