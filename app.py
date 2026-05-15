from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import re
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

db = SQLAlchemy(app)


# ─────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    twofa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def validate_password(password):
    """Validate password strength."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "OK"


def validate_input(text):
    """Basic SQLi check — strip dangerous characters."""
    dangerous = ["'", '"', ";", "--", "/*", "*/", "xp_", "exec", "drop", "select", "insert", "delete"]
    lower = text.lower()
    for d in dangerous:
        if d in lower:
            return False
    return True


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Input validation
        if not validate_input(username) or not validate_input(email):
            flash("Invalid characters in input.", "danger")
            return redirect(url_for("register"))

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        valid, msg = validate_password(password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        # Check existing user
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        # Hash password using Argon2 (via werkzeug)
        hashed = generate_password_hash(password, method="pbkdf2:sha256:260000")

        new_user = User(username=username, email=email, password_hash=hashed)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_input(username):
            flash("Invalid input detected.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        if user.twofa_enabled:
            # Store temp user for 2FA verification
            session["temp_user_id"] = user.id
            return redirect(url_for("verify_2fa"))

        # Login successful
        session.permanent = True
        session["user_id"] = user.id
        session["username"] = user.username
        user.last_login = datetime.utcnow()
        db.session.commit()

        flash(f"Welcome back, {user.username}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "temp_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        user = User.query.get(session["temp_user_id"])

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            session.pop("temp_user_id")
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f"Welcome, {user.username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code.", "danger")

    return render_template("verify_2fa.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    return render_template("dashboard.html", user=user)


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            user.twofa_enabled = True
            db.session.commit()
            flash("2FA enabled successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code. Try again.", "danger")

    # Generate secret and QR code
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(user.email, issuer_name="SecureLogin")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("setup_2fa.html", qr_code=qr_b64, secret=user.totp_secret)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# Init DB and run
# ─────────────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
