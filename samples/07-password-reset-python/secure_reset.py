"""Password-reset core plus a Flask adapter with required application hooks.

No web server or email sender starts automatically. Real queue, mail, and shared
rate-limit implementations are injected by the host application.
"""

from contextlib import contextmanager
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from typing import Callable

from flask import Flask, jsonify, request, session

from password_hashing import hash_password


GENERIC_MESSAGE = "If the account is eligible, reset instructions will be sent."
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class ResetService:
    """Use a file-backed database so independent workers share atomic state."""

    def __init__(self, database: str, deliver: Callable[[str, str], None],
                 notify: Callable[[str], None], clock=time.time):
        if database == ":memory:":
            raise ValueError("Use a file-backed database.")
        if not callable(deliver) or not callable(notify):
            raise TypeError("Delivery and password-change notification are required.")
        self.database, self.deliver, self.notify, self.clock = database, deliver, notify, clock
        with self._connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    session_epoch INTEGER NOT NULL DEFAULT 0,
                    email_verified INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    digest TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS reset_token_user ON reset_tokens(user_id);
            """)

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    def add_verified_user(self, email: str, password: str) -> int:
        """Trusted provisioning adapter only; NOT exposed as an HTTP endpoint.

        The host must have verified ownership of this canonical email already.
        """
        record = hash_password(password)
        with self._connection() as connection:
            return connection.execute(
                "INSERT INTO users(email, password_hash, email_verified) VALUES (?, ?, 1)",
                (email.strip().lower(), record),
            ).lastrowid

    def issue_reset(self, email: str) -> None:
        """Queue worker entry point: send only to the account's verified address.

        Delivery receives a token for an HTTPS link using a configured trusted
        origin. It must never derive that origin from an incoming Host header.
        No token is returned to the requesting browser.
        """
        if not isinstance(email, str) or not 1 <= len(email) <= 254:
            return
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                user = connection.execute(
                    "SELECT id, email FROM users WHERE email = ? AND email_verified = 1",
                    (email.strip().lower(),),
                ).fetchone()
                if user is None:
                    connection.rollback()
                    return
                connection.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user[0],))
                connection.execute(
                    "INSERT INTO reset_tokens(digest, user_id, expires_at) VALUES (?, ?, ?)",
                    (digest, user[0], self.clock() + 15 * 60),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        # Only the registered, verified address receives the bearer secret.
        self.deliver(user[1], token)

    def reset_password(self, token: str, password: str, confirmation: str) -> bool:
        """Consume a valid token and update its bound user in one transaction."""
        if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
            return False
        if (not isinstance(password, str) or not isinstance(confirmation, str)
                or not 15 <= len(password) <= 128 or password != confirmation):
            return False
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        # Reject random tokens before allocating scrypt's 128 MiB working memory.
        with self._connection() as connection:
            found = connection.execute(
                "SELECT 1 FROM reset_tokens WHERE digest = ? AND expires_at > ?",
                (digest, self.clock()),
            ).fetchone()
        if found is None:
            return False
        try:
            record = hash_password(password)
        except (ValueError, UnicodeError):
            return False
        with self._connection() as connection:
            # SQLite serializes writers. The re-check below is inside the lock;
            # two workers cannot both spend the same token.
            connection.execute("BEGIN IMMEDIATE")
            try:
                user = connection.execute(
                    "SELECT u.id, u.email FROM reset_tokens t JOIN users u ON u.id = t.user_id "
                    "WHERE t.digest = ? AND t.expires_at > ? AND u.email_verified = 1",
                    (digest, self.clock()),
                ).fetchone()
                if user is None:
                    connection.rollback()
                    return False
                connection.execute(
                    "UPDATE users SET password_hash = ?, session_epoch = session_epoch + 1 "
                    "WHERE id = ?", (record, user[0]),
                )
                connection.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user[0],))
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        # Notification contains no password or reset token. A failure here does
        # not undo the committed reset; the host should retry its notification job.
        self.notify(user[1])
        return True

    def session_is_current(self, user_id: int, epoch: int) -> bool:
        """Host authentication middleware must call this on EVERY protected request.

        At login, put the account's current epoch in its server-validated session.
        Never accept user_id/epoch supplied in an unsigned client field.
        """
        if type(user_id) is not int or type(epoch) is not int:
            return False
        with self._connection() as connection:
            return connection.execute(
                "SELECT 1 FROM users WHERE id = ? AND session_epoch = ?", (user_id, epoch),
            ).fetchone() is not None


def create_app(service: ResetService, *, secret_key: bytes,
               enqueue_request: Callable[[str], None],
               allow_request: Callable[[str, str, str], bool]) -> Flask:
    """Required hooks: enqueue every email for an async worker; enforce rate limits.

    allow_request(action, client_ip, subject) must atomically enforce BOTH per-IP
    and per-subject quotas using storage shared by all web workers. Do not trust
    X-Forwarded-For unless the host has configured a trusted proxy correctly.
    """
    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("Supply at least 32 random secret-key bytes from secret storage.")
    if not callable(enqueue_request) or not callable(allow_request):
        raise TypeError("A real asynchronous queue and rate limiter are required.")
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secret_key, MAX_CONTENT_LENGTH=4096,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict")

    @app.after_request
    def prevent_secret_caching(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/reset-csrf")
    def reset_csrf():
        if "reset_csrf" not in session:
            session["reset_csrf"] = secrets.token_urlsafe(32)
        return jsonify(csrf_token=session["reset_csrf"])

    @app.before_request
    def csrf_protection():
        if request.method == "POST":
            expected = session.get("reset_csrf")
            supplied = request.headers.get("X-CSRF-Token", "")
            if (not isinstance(expected, str) or len(supplied) > 100
                    or not hmac.compare_digest(expected.encode(), supplied.encode())):
                return jsonify(error="Invalid CSRF token."), 403

    @app.post("/forgot-password")
    def forgot_password():
        email = request.form.get("email", "").strip().lower()
        if not 1 <= len(email) <= 254:
            return jsonify(error="Enter an email address."), 400
        if not allow_request("request", request.remote_addr or "unknown", email):
            return jsonify(error="Try again later."), 429
        # The HTTP thread never looks up whether the account exists. Production
        # must enqueue rather than execute the worker inline to avoid enumeration
        # through delivery/database timing differences.
        enqueue_request(email)
        return jsonify(message=GENERIC_MESSAGE), 202

    @app.post("/reset-password")
    def reset_password_route():
        token = request.form.get("token", "")
        # Pass a token digest to limiter storage; never log/store the raw token.
        subject = hashlib.sha256(token.encode()).hexdigest()
        if not allow_request("reset", request.remote_addr or "unknown", subject):
            return jsonify(error="Try again later."), 429
        if not service.reset_password(token, request.form.get("new_password", ""),
                                      request.form.get("confirm_password", "")):
            return jsonify(error="Invalid reset request or expired token."), 400
        session.clear()
        return jsonify(message="Password reset. Sign in through the normal login page.")

    return app
