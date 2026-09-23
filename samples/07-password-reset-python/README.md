# Sample 7 — Python password reset

**Category:** [A04:2021 — Insecure Design](https://owasp.org/Top10/2021/A04_2021-Insecure_Design/), matching the assignment's OWASP edition. The plaintext password assignment also creates a cryptographic-storage failure.

## Original vulnerable code

```python
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password
    db.session.commit()
    return 'Password reset'
```

## Flaw and possible harm

Knowing an email address is enough to replace that person's password: the route never proves the requester controls the account. An attacker can take over an account or lock its owner out. The password is also saved directly, exposing it to anyone who obtains database contents. This requires changing the recovery workflow, not just adding an input check. [OWASP Insecure Design](https://owasp.org/Top10/2021/A04_2021-Insecure_Design/), [OWASP Plaintext Password Storage](https://owasp.org/www-community/vulnerabilities/Password_Plaintext_Storage)

## Secure version and why it works

[secure_reset.py](secure_reset.py) separates requesting recovery from changing a password:

1. `POST /forgot-password` queues every valid email input and returns the same generic response. A worker sends a random 256-bit token only to the account's previously verified address.
2. The database stores a SHA-256 digest of that token, its user ID, and a 15-minute expiration. SHA-256 is appropriate here because the token is random and high entropy; human passwords use scrypt instead.
3. `POST /reset-password` requires the token and matching new-password fields. The token determines the account; a submitted email cannot choose a different target.
4. A SQLite write transaction rechecks expiration, stores the salted password hash, increments the session epoch, and deletes the user's reset tokens together. Replay and concurrent reuse fail.
5. The service sends a password-change notification and requires normal login afterward. [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

The included [password_hashing.py](password_hashing.py) is the independent copy of Sample 4's stdlib scrypt helper, using `N=2^17, r=8, p=1` and a random salt. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Both POST routes require a session-bound token in `X-CSRF-Token`, obtained from `GET /reset-csrf`. Cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`; responses disable caching and referrer disclosure. [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## Scope and required application integration

This is a tested Flask route/core example, not a deployed login website. Its dependencies are mandatory callbacks rather than silently permissive defaults:

- Supply a durable asynchronous `enqueue_request(email)`; a worker calls `service.issue_reset(email)`. Executing that worker inline would reintroduce account-dependent response timing. Queue error handling and operational timing measurements belong to the host application.
- Supply `allow_request(action, client_ip, subject)` backed by shared, atomic rate-limit storage. Enforce both per-IP and per-subject limits for request and reset actions. Tests inject controlled callbacks; they do not claim to test a production queue or limiter.
- Supply `deliver(verified_email, token)` and `notify(verified_email)` through a real email provider. Build reset links from a configured HTTPS origin, never the incoming Host header. Keep reset links, raw tokens, and passwords out of logs. The notification callback should enqueue a retriable job; notification failure does not roll back a completed reset.
- Supply at least 32 random secret-key bytes from secret storage. Serve over HTTPS with a production WSGI server. Configure trusted proxies before deriving client IPs.
- Connect the account table to trusted enrollment/email verification. `add_verified_user()` is a provisioning adapter, not a public registration endpoint. The sample treats emails case-insensitively; use the same canonicalization as the application's account system.
- At login, store the current `session_epoch` in the authenticated session. Authentication middleware must call `session_is_current(user_id, epoch)` on **every protected request**. The increment alone does not revoke a session if the surrounding application ignores it. [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- Apply the same password policy everywhere. This example accepts 15–128 characters, preserves whitespace/Unicode, and requires confirmation. Integrate compromised-password screening, account monitoring, and regular removal of expired token records in the host application.

All database values use parameters. Each operation opens and closes its own connection to a shared file-backed SQLite database. The writer transaction makes consumption atomic across workers using that database. Adapting to another database requires equivalent transactional guarantees.

## Verification

From this folder, with Python 3.10 or newer:

```text
python -m pip install -r requirements.txt
python -m unittest -v
```

Verified with **Python 3.14.6 and Flask 3.1.3: 20 tests passed** (`Ran 20 tests in 10.835s`, `OK`). Tests exercise verified delivery, digest-only token storage, expiration including expiry during hashing, replay, concurrent consumption, user binding, password hashing, session-epoch validation, transaction rollback, generic queued responses, CSRF, throttling hooks, secure response headers, body limits, and rejection of the original email-only reset. Tests use temporary SQLite databases and Flask's test client; no email is sent and no web service is started.
