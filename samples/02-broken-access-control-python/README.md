# Sample 2: Broken Access Control — Python account endpoint

**Status:** Corrected route, explanation, and 11 passing route tests.

## Original vulnerable code

```python
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

## Security flaw and real-world impact

The route selects whichever account ID appears in the URL without checking whether the caller owns it. Changing `/account/1` to `/account/2` could reveal another person's account. No authentication check is shown, so anonymous callers could also access records unless the surrounding application enforces login.

This is an insecure direct object reference (IDOR), under Broken Access Control. Depending on what `to_dict()` includes, it could disclose private account information, password hashes, or reset tokens. A missing record also causes an error when `to_dict()` is called on `None`. The demonstrated operation reads accounts; it does not itself grant editing or deletion.

ORM parameterization helps separate SQL from input, but it does not establish ownership. See [OWASP A01:2021 Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/) and [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).

## Corrected code and explanation

[secure_account.py](secure_account.py) supplies a Flask blueprint for the same URL.

1. Read the identity established by Flask-Login. Anonymous or inactive users receive JSON `401`.
2. Require the authenticated user's database primary key to be a positive integer. Reject invalid identities before an account query.
3. Accept a canonical positive decimal URL ID within the signed 64-bit range. Reject malformed IDs with `400`. This validation does not grant permission.
4. Compare the requested ID with the authenticated primary key on every request. A different ID receives `403` before an account lookup, whether or not that other account exists.
5. Query only the verified owner's key, projecting `id`, `username`, and `display_name`. Return an explicit JSON field list instead of serializing the entire model.
6. Return `404` for a missing owned account and a generic `500` for database errors. A session context closes the session and rolls back unfinished transactions.
7. Set `Cache-Control: no-store` on responses handled by this blueprint.

The policy permits only an owner to read their account, with no role-based exception. A claimed admin role or user ID in headers, query arguments, or JSON is ignored. These server-side ownership checks implement the least-privilege and per-request checks described by the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## Integration requirements

This sample assumes an existing Flask application, configured Flask-Login `LoginManager`, and SQLAlchemy model with an integer `id` plus string `username` and `display_name` fields. The ID contract is an explicit assumption because the assignment does not include a schema.

A real login flow must verify credentials before creating the session. The `user_loader` must load the legitimate user from that session and reject invalid or revoked identities. `current_user.id` must be the database primary key, not an untrusted request parameter. The handler deliberately does not use `get_id()`, because applications may use a separate session identifier there.

Replace the original route with this registration after configuring the application:

```python
from sqlalchemy.orm import sessionmaker
from secure_account import create_account_blueprint

# app, engine, and User belong to the existing application.
# Flask-Login must already be configured with a real user_loader.
Session = sessionmaker(bind=engine)
app.register_blueprint(create_account_blueprint(Session, User))
```

The blueprint performs its own authentication check to return JSON rather than redirect to a login page. Secure session configuration, credential verification, HTTPS, and monitoring belong to the host application. The test-only session helper must not become a production login endpoint.

Implementation references: [Flask-Login](https://flask-login.readthedocs.io/en/latest/), [SQLAlchemy session management](https://docs.sqlalchemy.org/en/20/orm/session_basics.html), and [Flask testing](https://flask.palletsprojects.com/en/stable/testing/).

## Run the tests

From the repository root, create an isolated environment:

```sh
python -m venv .venv
```

Activate it with `.venv\Scripts\Activate.ps1` in Windows PowerShell, or `source .venv/bin/activate` on macOS/Linux. Then run:

```sh
python -m pip install -r samples/02-broken-access-control-python/requirements.txt
python -m unittest discover -s samples/02-broken-access-control-python -p "test_*.py" -v
```

Alternatively, on Windows call `.venv\Scripts\python.exe` instead of `python` without activating the environment.

Verified with Python 3.14.6, Flask 3.1.3, Flask-Login 0.6.3, and SQLAlchemy 2.0.54: **11 tests passed**.

Tests cover anonymous access; owner success and field filtering; cross-user and unknown-account denial before queries; a second owner's access; spoofed identity inputs; malformed URL IDs; malformed authenticated primary keys; inactive users; invalid session users; missing owned records; and database errors with recovery.

The tests use the real Flask client, Flask-Login session loading, and a temporary in-memory SQLite database. They create authenticated sessions using Flask's test helper, so they do not validate passwords or a deployed authentication system. No production database is touched.
