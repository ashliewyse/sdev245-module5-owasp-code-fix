"""Functional checks for the login demo's real HTTP and SQLite boundaries.

Run from this directory with: python -m unittest -v
The test database and browser cookies are isolated for every test.
"""

from html.parser import HTMLParser
from pathlib import Path
import sqlite3
import tempfile
import unittest

from werkzeug.security import check_password_hash

from app import create_app


class _CsrfParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "csrf_token":
            self.token = attrs.get("value")


class LoginDemoTests(unittest.TestCase):
    PASSWORD = "A long demo password! 29"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database = str(Path(self.temp_dir.name) / "demo.sqlite3")
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "independent-test-secret-which-is-over-32-characters",
            "DATABASE": self.database,
            "SESSION_COOKIE_SECURE": False,
        })
        self.client = self.app.test_client()

    def sql(self, statement, args=()):
        db = sqlite3.connect(self.database)
        try:
            db.row_factory = sqlite3.Row
            rows = db.execute(statement, args).fetchall()
            db.commit()
            return rows
        finally:
            # SQLite's transaction context manager does not close the handle.
            # Close explicitly so Windows can remove each temporary database.
            db.close()

    def csrf(self, path="/login", client=None):
        client = client or self.client
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        parser = _CsrfParser()
        parser.feed(response.get_data(as_text=True))
        self.assertTrue(parser.token, f"No CSRF token on {path}")
        return parser.token

    def register(self, username="alice", display_name="Alice", password=None,
                 confirm_password=None, **extra):
        password = self.PASSWORD if password is None else password
        data = {
            "csrf_token": self.csrf("/register"),
            "username": username,
            "display_name": display_name,
            "password": password,
            "confirm_password": password if confirm_password is None else confirm_password,
        }
        data.update(extra)
        return self.client.post("/register", data=data)

    def login(self, username="alice", password=None, client=None, **extra):
        client = client or self.client
        data = {
            "csrf_token": self.csrf("/login", client=client),
            "username": username,
            "password": self.PASSWORD if password is None else password,
        }
        data.update(extra)
        return client.post("/login", data=data)

    def user(self, username="alice"):
        rows = self.sql("SELECT * FROM users WHERE username = ?", (username,))
        self.assertEqual(len(rows), 1)
        return rows[0]

    def seed_login(self, username="alice", display_name="Alice"):
        self.assertEqual(self.register(username, display_name).status_code, 302)
        self.assertEqual(self.login(username).status_code, 302)
        return self.user(username)

    def test_public_pages_and_registration_login_flow(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.register(username="ALICE", display_name="Alice Example")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login"))
        user = self.user()
        self.assertEqual(user["display_name"], "Alice Example")
        self.assertEqual(user["role"], "user")
        response = self.login(username="ALICE")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith(f"/profile/{user['id']}"))
        profile = self.client.get(response.headers["Location"])
        self.assertEqual(profile.status_code, 200)
        self.assertIn(b"Alice Example", profile.data)

    def test_password_is_salted_hash_and_never_rendered(self):
        self.assertEqual(self.register().status_code, 302)
        first_hash = self.user()["password_hash"]
        self.assertNotEqual(first_hash, self.PASSWORD)
        self.assertTrue(check_password_hash(first_hash, self.PASSWORD))
        self.assertFalse(check_password_hash(first_hash, "wrong password"))
        self.assertEqual(self.register("bob", "Bob").status_code, 302)
        self.assertNotEqual(first_hash, self.user("bob")["password_hash"])
        self.assertEqual(self.login().status_code, 302)
        profile = self.client.get(f"/profile/{self.user()['id']}")
        self.assertNotIn(first_hash.encode(), profile.data)
        self.assertNotIn(self.PASSWORD.encode(), profile.data)

    def test_registration_rejects_missing_and_foreign_csrf(self):
        other = self.app.test_client()
        foreign_token = self.csrf("/register", client=other)
        self.csrf("/register")
        for token in (None, "forged-token", foreign_token):
            with self.subTest(token=token):
                data = {"username": "alice", "display_name": "Alice",
                        "password": self.PASSWORD, "confirm_password": self.PASSWORD}
                if token is not None:
                    data["csrf_token"] = token
                self.assertEqual(self.client.post("/register", data=data).status_code, 400)
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_login_rejects_missing_or_invalid_csrf(self):
        self.assertEqual(self.register().status_code, 302)
        for token in (None, "forged-token"):
            with self.subTest(token=token):
                data = {"username": "alice", "password": self.PASSWORD}
                if token is not None:
                    data["csrf_token"] = token
                self.assertEqual(self.client.post("/login", data=data).status_code, 400)
        self.assertEqual(self.sql("SELECT token_hash FROM sessions"), [])

    def test_logout_requires_post_and_valid_csrf(self):
        user = self.seed_login()
        path = f"/profile/{user['id']}"
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout").status_code, 400)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": "forged"}).status_code, 400)
        self.assertEqual(self.client.get(path).status_code, 200)
        token = self.csrf(path)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": token}).status_code, 302)
        self.assertEqual(self.client.get(path).status_code, 302)

    def test_registration_cannot_choose_admin_role(self):
        self.assertEqual(self.register(role="admin").status_code, 400)
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_registration_username_validation_and_injection(self):
        for username in ("ab", "a" * 33, "alice smith", "alice@example", "álîce", "' OR 1=1--"):
            with self.subTest(username=username):
                self.assertEqual(self.register(username=username).status_code, 400)
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_registration_display_name_limits(self):
        for name in ("", "   ", "x" * 81):
            with self.subTest(length=len(name)):
                self.assertEqual(self.register(display_name=name).status_code, 400)
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_registration_password_limits_and_confirmation(self):
        for password in ("", "x" * 14, "x" * 129):
            with self.subTest(length=len(password)):
                self.assertEqual(self.register(password=password).status_code, 400)
        self.assertEqual(self.register(confirm_password="a different long password").status_code, 400)
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_duplicate_username_is_case_insensitive(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.register(username="ALICE").status_code, 400)
        self.assertEqual(len(self.sql("SELECT id FROM users")), 1)

    def test_anonymous_profile_and_admin_access_require_login(self):
        self.assertEqual(self.register().status_code, 302)
        for path in (f"/profile/{self.user()['id']}", "/admin"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])

    def test_owner_can_view_profile_but_not_another_user(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.register("bob", "Private Bob").status_code, 302)
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get(f"/profile/{self.user()['id']}").status_code, 200)
        denied = self.client.get(f"/profile/{self.user('bob')['id']}")
        self.assertEqual(denied.status_code, 403)
        self.assertNotIn(b"Private Bob", denied.data)
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_admin_can_view_admin_page_but_not_another_profile(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.register("bob", "Bob").status_code, 302)
        self.sql("UPDATE users SET role = 'admin' WHERE username = 'alice'")
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.assertEqual(self.client.get(f"/profile/{self.user()['id']}").status_code, 200)
        self.assertEqual(self.client.get(f"/profile/{self.user('bob')['id']}").status_code, 403)

    def test_role_changes_take_effect_without_trusting_cookie_role(self):
        self.seed_login()
        self.sql("UPDATE users SET role = 'admin' WHERE username = 'alice'")
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.sql("UPDATE users SET role = 'user' WHERE username = 'alice'")
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_display_name_is_escaped_on_profile(self):
        payload = '<script>alert("test")</script>'
        user = self.seed_login(display_name=payload)
        response = self.client.get(f"/profile/{user['id']}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(payload.encode(), response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_unknown_user_and_wrong_password_have_generic_error(self):
        self.assertEqual(self.register().status_code, 302)
        for username in ("alice", "missing_user"):
            with self.subTest(username=username):
                response = self.login(username=username, password="wrong but long password")
                self.assertEqual(response.status_code, 401)
                self.assertIn(b"Invalid username or password", response.data)
                self.assertNotIn(b"does not exist", response.data)
        self.assertEqual(self.sql("SELECT token_hash FROM sessions"), [])

    def test_login_sql_injection_does_not_authenticate(self):
        self.assertEqual(self.register().status_code, 302)
        response = self.login(username="' OR 1=1--")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.sql("SELECT token_hash FROM sessions"), [])

    def test_login_throttles_repeated_failure_for_username(self):
        self.assertEqual(self.register().status_code, 302)
        for _ in range(5):
            self.assertIn(self.login(password="wrong long password").status_code, (401, 429))
        response = self.login(password="wrong long password")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.sql("SELECT token_hash FROM sessions"), [])

    def test_login_throttles_password_spraying_from_one_ip(self):
        for attempt in range(30):
            response = self.login(username=f"unknown_{attempt}", password="wrong long password")
            self.assertIn(response.status_code, (401, 429))
        self.assertEqual(self.login(username="unknown_31").status_code, 429)

    def test_logged_out_cookie_cannot_be_replayed(self):
        user = self.seed_login()
        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        stolen_cookie = self.client.get_cookie(cookie_name).value
        replay_client = self.app.test_client()
        replay_client.set_cookie(cookie_name, stolen_cookie)
        profile_path = f"/profile/{user['id']}"
        self.assertEqual(replay_client.get(profile_path).status_code, 200)
        token = self.csrf(profile_path)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": token}).status_code, 302)
        self.assertEqual(replay_client.get(profile_path).status_code, 302)

    def test_expired_server_session_cannot_access_profile(self):
        user = self.seed_login()
        self.assertEqual(len(self.sql("SELECT token_hash FROM sessions")), 1)
        self.sql("UPDATE sessions SET expires_at = 0")
        self.assertEqual(self.client.get(f"/profile/{user['id']}").status_code, 302)

    def test_tampered_browser_cookie_cannot_access_profile(self):
        user = self.seed_login()
        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        cookie = self.client.get_cookie(cookie_name).value
        self.client.set_cookie(cookie_name, "tampered" + cookie)
        self.assertEqual(self.client.get(f"/profile/{user['id']}").status_code, 302)

    def test_security_headers_and_browser_cookie_flags(self):
        response = self.client.get("/login")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        cookies = response.headers.getlist("Set-Cookie")
        self.assertTrue(any("HttpOnly" in cookie and "SameSite=Lax" in cookie for cookie in cookies))

    def test_admin_cli_provisions_hashed_admin_with_prompt(self):
        result = self.app.test_cli_runner().invoke(
            args=["create-admin", "--username", "admin_user", "--display-name", "Admin User"],
            input=f"{self.PASSWORD}\n{self.PASSWORD}\n",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        user = self.user("admin_user")
        self.assertEqual(user["role"], "admin")
        self.assertTrue(check_password_hash(user["password_hash"], self.PASSWORD))
        self.assertEqual(self.login("admin_user").status_code, 302)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_admin_cli_cannot_overwrite_existing_user(self):
        self.assertEqual(self.register().status_code, 302)
        result = self.app.test_cli_runner().invoke(
            args=["create-admin", "--username", "alice", "--display-name", "Replacement"],
            input=f"{self.PASSWORD}\n{self.PASSWORD}\n",
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(self.user()["role"], "user")
        self.assertEqual(self.user()["display_name"], "Alice")

    def test_admin_cli_does_not_accept_password_argument(self):
        result = self.app.test_cli_runner().invoke(
            args=["create-admin", "--username", "admin_user", "--display-name", "Admin",
                  "--password", self.PASSWORD],
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(self.sql("SELECT id FROM users"), [])


if __name__ == "__main__":
    unittest.main()
