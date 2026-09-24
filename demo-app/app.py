"""Local coursework login application with owner checks and user/admin roles."""

from datetime import timedelta
from functools import wraps
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


PASSWORD_METHOD = "scrypt:131072:8:1"
USERNAME = re.compile(r"[A-Za-z0-9_]{3,32}")
SESSION_SECONDS = 30 * 60
LIMIT_SECONDS = 15 * 60
# Real work for unknown usernames makes account lookup less distinguishable.
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32), method=PASSWORD_METHOD, salt_length=32)


def password_hash(password):
    return generate_password_hash(password, method=PASSWORD_METHOD, salt_length=32)


def supported_hash(record):
    if not isinstance(record, str) or len(record) > 200:
        return False
    parts = record.split("$")
    return (len(parts) == 3 and parts[0] == PASSWORD_METHOD
            and re.fullmatch(r"[A-Za-z0-9]{32}", parts[1]) is not None
            and re.fullmatch(r"[0-9a-f]{128}", parts[2]) is not None)


def valid_password(password):
    if not isinstance(password, str) or not 15 <= len(password) <= 128:
        return False
    try:
        password.encode("utf-8")
    except UnicodeError:
        return False
    return True


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_app(test_config=None):
    instance = Path(__file__).resolve().parent / "instance"
    app = Flask(__name__, instance_path=str(instance), instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.environ.get("DEMO_DATABASE", str(instance / "accounts.sqlite3")),
        SECRET_KEY=os.environ.get("DEMO_SECRET_KEY"),
        SESSION_COOKIE_NAME="access_lab_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("DEMO_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=SESSION_SECONDS),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=16 * 1024,
        TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"],
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        instance.mkdir(parents=True, exist_ok=True)
        key_path = instance / "secret.key"
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "w", encoding="ascii") as key_file:
                key_file.write(secrets.token_hex(32))
        app.config["SECRET_KEY"] = key_path.read_text(encoding="ascii").strip()
    if len(app.config["SECRET_KEY"]) < 32:
        raise ValueError("DEMO_SECRET_KEY must contain at least 32 random characters.")
    Path(app.config["DATABASE"]).resolve().parent.mkdir(parents=True, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], timeout=5, isolation_level=None)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def initialize_database():
        get_db().executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                bucket TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires_at);
        """)

    with app.app_context():
        initialize_database()

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def load_identity_and_check_csrf():
        g.user = None
        auth_token = session.get("auth_token")
        if isinstance(auth_token, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", auth_token):
            g.user = get_db().execute(
                "SELECT u.id, u.username, u.display_name, u.role FROM users u "
                "JOIN sessions s ON s.user_id = u.id "
                "WHERE s.token_hash = ? AND s.expires_at > ?",
                (token_digest(auth_token), time.time()),
            ).fetchone()
            if g.user is None:
                session.pop("auth_token", None)
        if request.method == "POST":
            expected = session.get("csrf_token")
            values = request.form.getlist("csrf_token")
            if (not isinstance(expected, str) or len(values) != 1
                    or len(values[0]) > 100
                    or not hmac.compare_digest(expected.encode(), values[0].encode())):
                abort(400, description="The form expired or its security token is invalid. Reload and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; "
            "script-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    def logged_in(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Sign in to continue.", "info")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def admit_attempt(limits):
        """Reserve attempts atomically before expensive hashing; fail closed."""
        now = time.time()
        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("DELETE FROM rate_limits WHERE expires_at <= ?", (now,))
            if db.execute("SELECT COUNT(*) FROM rate_limits").fetchone()[0] >= 10000:
                db.rollback()
                return False
            for bucket, maximum in limits:
                row = db.execute("SELECT attempts FROM rate_limits WHERE bucket = ?", (bucket,)).fetchone()
                if row is not None and row[0] >= maximum:
                    db.rollback()
                    return False
            for bucket, _ in limits:
                db.execute(
                    "INSERT INTO rate_limits(bucket, attempts, expires_at) VALUES (?, 1, ?) "
                    "ON CONFLICT(bucket) DO UPDATE SET attempts = attempts + 1",
                    (bucket, now + LIMIT_SECONDS),
                )
            db.commit()
            return True
        except BaseException:
            db.rollback()
            raise

    def client_bucket(action):
        # No trust in client-supplied forwarding headers.
        address = request.remote_addr or "unknown"
        return action + ":ip:" + hashlib.sha256(address.encode()).hexdigest()

    def revoke_current_session():
        token = session.get("auth_token")
        if isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))

    @app.get("/")
    def home():
        return render_template("home.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html", field_values={})
        username = request.form.get("username", "")
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        fields = {"username": username, "display_name": display_name}
        error = None
        if "role" in request.form:
            error = "Account roles cannot be chosen during registration."
        elif not USERNAME.fullmatch(username):
            error = "Use 3–32 letters, numbers, or underscores for your username."
        elif not 1 <= len(display_name) <= 80:
            error = "Enter a display name between 1 and 80 characters."
        elif not valid_password(password):
            error = "Use a password between 15 and 128 characters."
        elif password != request.form.get("confirm_password", ""):
            error = "Your passwords do not match."
        if error:
            return render_template("register.html", error=error, field_values=fields), 400
        if not admit_attempt([(client_bucket("register"), 10)]):
            abort(429)
        try:
            get_db().execute(
                "INSERT INTO users(username, display_name, password_hash, role, created_at) "
                "VALUES (?, ?, ?, 'user', ?)",
                (username.lower(), display_name, password_hash(password), time.time()),
            )
        except sqlite3.IntegrityError:
            return render_template("register.html", error="That username is unavailable.", field_values=fields), 400
        flash("Your account is ready. Sign in to continue.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        username = request.form.get("username", "").lower()
        password = request.form.get("password", "")
        generic_error = "Invalid username or password."
        if not USERNAME.fullmatch(username) or not valid_password(password):
            return render_template("login.html", error=generic_error), 401
        subject = "login:user:" + hashlib.sha256(username.encode()).hexdigest()
        if not admit_attempt([(subject, 5), (client_bucket("login"), 30)]):
            abort(429)
        user = get_db().execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        known = user is not None and supported_hash(user["password_hash"])
        candidate_hash = user["password_hash"] if known else DUMMY_HASH
        matched = check_password_hash(candidate_hash, password)
        if not known or not matched:
            return render_template("login.html", error=generic_error), 401
        revoke_current_session()
        session.clear()
        token = secrets.token_urlsafe(32)
        now = time.time()
        db = get_db()
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        db.execute("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                   (token_digest(token), user["id"], now + SESSION_SECONDS))
        session["auth_token"] = token
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("profile", user_id=user["id"]))

    @app.post("/logout")
    def logout():
        revoke_current_session()
        session.clear()
        flash("You have signed out.", "success")
        return redirect(url_for("login"))

    @app.get("/profile/<int:user_id>")
    @logged_in
    def profile(user_id):
        if user_id != g.user["id"]:
            abort(403)
        return render_template("profile.html", account=g.user)

    @app.get("/admin")
    @logged_in
    def admin():
        if g.user["role"] != "admin":
            abort(403)
        accounts = get_db().execute("SELECT id, username, display_name, role FROM users ORDER BY id").fetchall()
        return render_template("admin.html", accounts=accounts)

    error_messages = {
        400: ("Check your request", "The request could not be accepted. Reload the page and try again."),
        403: ("Access denied", "Your account does not have permission to open this page."),
        404: ("Page not found", "That page is not available."),
        405: ("Method not allowed", "Use the buttons and forms provided by this application."),
        413: ("Request too large", "The submitted form exceeds the allowed size."),
        429: ("Too many attempts", "Please wait 15 minutes before trying again."),
        500: ("Something went wrong", "The request could not be completed. Please try again later."),
    }

    def error_page(error):
        code = getattr(error, "code", 500) or 500
        title, message = error_messages.get(code, error_messages[500])
        return render_template("error.html", code=code, title=title, message=message), code

    for code in error_messages:
        app.register_error_handler(code, error_page)

    @app.cli.command("create-admin")
    @click.option("--username", required=True, help="3–32 letters, numbers, or underscores.")
    @click.option("--display-name", default="Administrator", show_default=True)
    def create_admin(username, display_name):
        """Create an admin locally, prompting for a password without echoing it."""
        if not USERNAME.fullmatch(username) or not 1 <= len(display_name.strip()) <= 80:
            raise click.ClickException("Enter a valid username and display name.")
        if get_db().execute("SELECT 1 FROM users WHERE username = ?", (username.lower(),)).fetchone():
            raise click.ClickException("That username already exists; no role was changed.")
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        if not valid_password(password):
            raise click.ClickException("Use a password between 15 and 128 characters.")
        get_db().execute(
            "INSERT INTO users(username, display_name, password_hash, role, created_at) "
            "VALUES (?, ?, ?, 'admin', ?)",
            (username.lower(), display_name.strip(), password_hash(password), time.time()),
        )
        click.echo("Administrator created. Sign in through the normal login page.")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
