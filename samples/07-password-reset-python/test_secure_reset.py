from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
from pathlib import Path
import secrets
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from password_hashing import hash_password, verify_password
from secure_reset import GENERIC_MESSAGE, ResetService, create_app


OLD_PASSWORD = "Original long test passphrase"
NEW_PASSWORD = "Replacement long test passphrase"


class ResetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_hash = hash_password(OLD_PASSWORD)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "accounts.sqlite3")
        self.now = 1000.0
        self.deliveries, self.notifications, self.queued, self.limits = [], [], [], []
        self.permit = True
        self.service = ResetService(
            self.path, lambda email, token: self.deliveries.append((email, token)),
            self.notifications.append, lambda: self.now,
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.executemany(
                "INSERT INTO users(id,email,password_hash,email_verified) VALUES (?,?,?,?)",
                [(1, "alice@example.test", self.old_hash, 1),
                 (2, "bob@example.test", self.old_hash, 1),
                 (3, "unverified@example.test", self.old_hash, 0)],
            )
        self.app = create_app(self.service, secret_key=secrets.token_bytes(32),
                              enqueue_request=self.queued.append, allow_request=self.limiter)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf = self.client.get("/reset-csrf", base_url="https://localhost").json["csrf_token"]

    def limiter(self, action, address, subject):
        self.limits.append((action, address, subject))
        return self.permit

    def post(self, path, data, csrf=True):
        headers = {"X-CSRF-Token": self.csrf} if csrf else {}
        return self.client.post(path, data=data, headers=headers, base_url="https://localhost")

    def issue(self, email="alice@example.test"):
        self.service.issue_reset(email)
        return self.deliveries[-1][1]

    def rows(self, query, params=()):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            return connection.execute(query, params).fetchall()

    def test_unknown_and_unverified_users_receive_nothing(self):
        self.service.issue_reset("absent@example.test")
        self.service.issue_reset("unverified@example.test")
        self.assertEqual(self.deliveries, [])
        self.assertEqual(self.rows("SELECT * FROM reset_tokens"), [])

    def test_delivery_uses_only_verified_registered_email(self):
        token = self.issue("  ALICE@EXAMPLE.TEST  ")
        self.assertEqual(self.deliveries, [("alice@example.test", token)])
        self.assertEqual(len(token), 43)

    def test_token_storage_contains_only_digest_and_expiration(self):
        token = self.issue()
        self.assertEqual(self.rows("SELECT digest,user_id,expires_at FROM reset_tokens"),
                         [(hashlib.sha256(token.encode()).hexdigest(), 1, 1900.0)])
        self.assertNotIn(token.encode(), Path(self.path).read_bytes())

    def test_new_request_revokes_previous_token(self):
        first, second = self.issue(), self.issue()
        self.assertNotEqual(first, second)
        self.assertFalse(self.service.reset_password(first, NEW_PASSWORD, NEW_PASSWORD))
        self.assertTrue(self.service.reset_password(second, NEW_PASSWORD, NEW_PASSWORD))

    def test_success_changes_only_bound_user_and_invalidates_sessions(self):
        token = self.issue()
        self.assertTrue(self.service.session_is_current(1, 0))
        self.assertTrue(self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD))
        record = self.rows("SELECT password_hash FROM users WHERE id=1")[0][0]
        self.assertTrue(verify_password(NEW_PASSWORD, record))
        self.assertFalse(verify_password(OLD_PASSWORD, record))
        self.assertEqual(self.rows("SELECT password_hash FROM users WHERE id=2"), [(self.old_hash,)])
        self.assertFalse(self.service.session_is_current(1, 0))
        self.assertTrue(self.service.session_is_current(1, 1))
        self.assertTrue(self.service.session_is_current(2, 0))
        self.assertFalse(self.service.session_is_current(1, "1"))
        self.assertEqual(self.notifications, ["alice@example.test"])

    def test_token_expires_at_exact_deadline(self):
        token = self.issue()
        self.now = 1900.0
        self.assertFalse(self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD))
        self.assertEqual(self.rows("SELECT password_hash FROM users WHERE id=1"), [(self.old_hash,)])

    def test_successful_token_cannot_be_replayed(self):
        token = self.issue()
        self.assertTrue(self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD))
        self.assertFalse(self.service.reset_password(token, OLD_PASSWORD, OLD_PASSWORD))
        self.assertEqual(self.rows("SELECT * FROM reset_tokens"), [])
        self.assertEqual(len(self.notifications), 1)

    def test_two_concurrent_workers_can_consume_token_only_once(self):
        token = self.issue()
        barrier = threading.Barrier(2)
        def reset_in_worker():
            barrier.wait(timeout=10)
            return self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(reset_in_worker) for _ in range(2)]
            self.assertEqual(sorted(f.result(timeout=20) for f in futures), [False, True])
        self.assertEqual(self.rows("SELECT session_epoch FROM users WHERE id=1"), [(1,)])
        self.assertEqual(len(self.notifications), 1)

    def test_invalid_tokens_do_not_trigger_password_hashing(self):
        with patch("secure_reset.hash_password") as hasher:
            for token in (None, "", "email@example.test", secrets.token_urlsafe(32), "x" * 1000):
                self.assertFalse(self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD))
            hasher.assert_not_called()

    def test_policy_or_confirmation_failure_does_not_consume_token(self):
        token = self.issue()
        for password, confirmation in (("short", "short"), ("x" * 129, "x" * 129),
                                       (NEW_PASSWORD, "different confirmation")):
            self.assertFalse(self.service.reset_password(token, password, confirmation))
        self.assertTrue(self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD))

    def test_database_failure_rolls_back_password_and_token_consumption(self):
        token = self.issue()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""CREATE TRIGGER reject_token_delete BEFORE DELETE ON reset_tokens
                                  BEGIN SELECT RAISE(ABORT, 'test failure'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD)
        self.assertEqual(self.rows("SELECT password_hash,session_epoch FROM users WHERE id=1"),
                         [(self.old_hash, 0)])
        self.assertEqual(len(self.rows("SELECT * FROM reset_tokens")), 1)
        self.assertEqual(self.notifications, [])

    def test_expiry_is_rechecked_after_expensive_hashing(self):
        token = self.issue()
        def hash_and_advance(password):
            record = hash_password(password)
            self.now = 1901.0
            return record
        with patch("secure_reset.hash_password", side_effect=hash_and_advance):
            self.assertFalse(self.service.reset_password(token, NEW_PASSWORD, NEW_PASSWORD))
        self.assertEqual(self.rows("SELECT session_epoch FROM users WHERE id=1"), [(0,)])

    def test_known_and_unknown_requests_have_same_response_and_queue_path(self):
        known = self.post("/forgot-password", {"email": "alice@example.test"})
        unknown = self.post("/forgot-password", {"email": "absent@example.test"})
        self.assertEqual((known.status_code, known.json), (202, {"message": GENERIC_MESSAGE}))
        self.assertEqual((known.status_code, known.data), (unknown.status_code, unknown.data))
        self.assertEqual(self.queued, ["alice@example.test", "absent@example.test"])
        self.assertEqual(self.deliveries, [])
        self.assertEqual(self.rows("SELECT * FROM reset_tokens"), [])

    def test_email_without_token_cannot_change_password(self):
        response = self.post("/reset-password", {"email": "alice@example.test",
                             "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.rows("SELECT password_hash FROM users WHERE id=1"), [(self.old_hash,)])

    def test_both_post_routes_require_csrf(self):
        for path in ("/forgot-password", "/reset-password"):
            self.assertEqual(self.post(path, {}, csrf=False).status_code, 403)
        self.assertEqual(self.queued, [])

    def test_wrong_csrf_is_rejected(self):
        self.csrf = "incorrect"
        self.assertEqual(self.post("/forgot-password", {"email": "alice@example.test"}).status_code, 403)
        self.assertEqual(self.queued, [])

    def test_rate_limit_blocks_queue_and_reset_before_work(self):
        token = self.issue()
        self.permit = False
        self.assertEqual(self.post("/forgot-password", {"email": "alice@example.test"}).status_code, 429)
        response = self.post("/reset-password", {"token": token, "new_password": NEW_PASSWORD,
                                                  "confirm_password": NEW_PASSWORD})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.queued, [])
        self.assertEqual(self.rows("SELECT session_epoch FROM users WHERE id=1"), [(0,)])
        self.assertNotIn(token, repr(self.limits))

    def test_successful_http_reset_requires_fresh_login(self):
        token = self.issue()
        response = self.post("/reset-password", {"token": token, "email": "bob@example.test",
                             "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction(base_url="https://localhost") as current_session:
            self.assertEqual(dict(current_session), {})
        self.assertEqual(self.rows("SELECT session_epoch FROM users WHERE id=2"), [(0,)])

    def test_secure_cookie_cache_headers_and_body_limit(self):
        client = self.app.test_client()
        response = client.get("/reset-csrf", base_url="https://localhost")
        cookie = response.headers["Set-Cookie"]
        for expected in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(expected, cookie)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(self.post("/forgot-password", {"email": "x" * 5000}).status_code, 413)

    def test_application_requires_secret_and_integration_hooks(self):
        with self.assertRaises(ValueError):
            create_app(self.service, secret_key=b"weak", enqueue_request=self.queued.append,
                       allow_request=self.limiter)
        with self.assertRaises(TypeError):
            create_app(self.service, secret_key=secrets.token_bytes(32), enqueue_request=None,
                       allow_request=self.limiter)


if __name__ == "__main__":
    unittest.main()
