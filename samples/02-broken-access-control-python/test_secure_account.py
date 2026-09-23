"""Route tests with real Flask-Login sessions and an in-memory SQLite DB.

Sessions are established with Flask's test helper, not a production login API.
"""

import secrets
import unittest

from flask import Flask
from flask_login import LoginManager, UserMixin
from sqlalchemy import Column, Integer, String, create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

from secure_account import MAX_ACCOUNT_ID, create_account_blueprint


Base = declarative_base()


class Account(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    display_name = Column(String, nullable=False)
    email = Column(String)
    password_hash = Column(String)
    reset_token = Column(String)
    role = Column(String)


class TestPrincipal(UserMixin):
    def __init__(self, account_id, active=True):
        self.id = account_id
        self.active = active

    @property
    def is_active(self):
        return self.active


class AccountRouteTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        with self.Session.begin() as db:
            db.add_all([
                Account(id=1, username="alice", display_name="Alice Example",
                        email="alice@example.test", password_hash="private-hash",
                        reset_token="private-token", role="admin"),
                Account(id=2, username="bob", display_name="Bob Example"),
            ])

        self.queries = []
        event.listen(self.engine, "before_cursor_execute", self.record_query)
        self.principals = {
            "alice": TestPrincipal(1),
            "bob": TestPrincipal(2),
            "missing": TestPrincipal(999),
            "inactive": TestPrincipal(1, active=False),
        }
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY=secrets.token_hex(32))
        login_manager = LoginManager(self.app)

        @login_manager.user_loader
        def load_test_user(session_id):
            # Test-only identity store, independent of account lookup queries.
            return self.principals.get(session_id)

        self.app.register_blueprint(create_account_blueprint(self.Session, Account))
        self.client = self.app.test_client()

    def tearDown(self):
        self.engine.dispose()

    def record_query(self, connection, cursor, statement, parameters, context, many):
        self.queries.append(statement)

    def sign_in(self, session_id="alice"):
        # This helper bypasses credentials only inside the test harness.
        with self.client.session_transaction() as session:
            session.clear()
            session["_user_id"] = session_id
            session["_fresh"] = True

    def assert_response(self, response, status, body):
        self.assertEqual(response.status_code, status)
        self.assertEqual(response.get_json(), body)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_anonymous_request_is_denied_without_account_query(self):
        self.assert_response(self.client.get("/account/1"), 401,
                             {"error": "Authentication required."})
        self.assertEqual(self.queries, [])

    def test_owner_gets_only_allowed_fields(self):
        self.sign_in()
        response = self.client.get("/account/1")
        self.assert_response(response, 200, {
            "id": 1, "username": "alice", "display_name": "Alice Example",
        })
        self.assertEqual(len(self.queries), 1)
        self.assertNotIn("password_hash", self.queries[0])
        self.assertNotIn("reset_token", self.queries[0])

    def test_changing_to_another_or_unknown_account_is_denied_before_query(self):
        self.sign_in()
        for target in (2, 999):
            with self.subTest(target=target):
                self.assert_response(self.client.get(f"/account/{target}"), 403,
                                     {"error": "Access denied."})
        self.assertEqual(self.queries, [])

    def test_second_owner_can_read_own_account_but_not_first_owners(self):
        self.sign_in("bob")
        self.assert_response(self.client.get("/account/2"), 200, {
            "id": 2, "username": "bob", "display_name": "Bob Example",
        })
        self.queries.clear()
        self.assert_response(self.client.get("/account/1"), 403,
                             {"error": "Access denied."})
        self.assertEqual(self.queries, [])

    def test_untrusted_identity_inputs_do_not_grant_access(self):
        headers = {"X-User-Id": "2", "X-Role": "admin"}
        self.assert_response(self.client.get("/account/2", headers=headers), 401,
                             {"error": "Authentication required."})
        self.sign_in()
        self.assert_response(self.client.get(
            "/account/2?user_id=2&role=admin", headers=headers,
            json={"user_id": 2, "role": "admin"},
        ), 403, {"error": "Access denied."})
        self.assertEqual(self.queries, [])

    def test_malformed_url_ids_are_rejected_without_query(self):
        self.sign_in()
        for target in ("0", "-1", "01", "+1", "1.0", "abc", "1%20", "١",
                       str(MAX_ACCOUNT_ID + 1), "9" * 100):
            with self.subTest(target=target):
                self.assert_response(self.client.get(f"/account/{target}"), 400,
                                     {"error": "Invalid account ID."})
        self.assertEqual(self.queries, [])

    def test_malformed_authenticated_primary_keys_fail_closed(self):
        for account_id in (None, True, False, "1", 1.0, 0, -1, MAX_ACCOUNT_ID + 1):
            with self.subTest(account_id=account_id):
                self.principals["invalid"] = TestPrincipal(account_id)
                self.sign_in("invalid")
                self.assert_response(self.client.get("/account/1"), 401,
                                     {"error": "Authentication required."})
        self.assertEqual(self.queries, [])

    def test_inactive_account_is_denied(self):
        self.sign_in("inactive")
        self.assert_response(self.client.get("/account/1"), 401,
                             {"error": "Authentication required."})
        self.assertEqual(self.queries, [])

    def test_invalid_session_user_is_anonymous(self):
        self.sign_in("unknown-session-user")
        self.assert_response(self.client.get("/account/1"), 401,
                             {"error": "Authentication required."})
        self.assertEqual(self.queries, [])

    def test_missing_owned_account_returns_not_found(self):
        self.sign_in("missing")
        self.assert_response(self.client.get("/account/999"), 404,
                             {"error": "Account not found."})

    def test_database_failure_is_generic_and_later_requests_still_work(self):
        def fail_query(*args):
            raise SQLAlchemyError("private SQL and connection details")

        self.sign_in()
        event.listen(self.engine, "before_cursor_execute", fail_query)
        try:
            self.assert_response(self.client.get("/account/1"), 500,
                                 {"error": "Unable to load account."})
        finally:
            event.remove(self.engine, "before_cursor_execute", fail_query)
        self.assertEqual(self.client.get("/account/1").status_code, 200)


if __name__ == "__main__":
    unittest.main()
