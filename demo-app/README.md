# Access Lab — working login and role demo

A small Flask application for the assignment's authentication and role-based access requirement. It runs locally and includes registration, sign-in, sign-out, an owner-only profile page, and an administrator account directory.

## Start on Windows

From the repository root, with Python 3.14 installed:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r demo-app/requirements.txt
.\.venv\Scripts\python.exe demo-app/app.py
```

Open **http://127.0.0.1:5000**. Choose **Create account**, register, and sign in. Use a username with 3–32 ASCII letters, numbers, or underscores, and a password with 15–128 characters. Passwords preserve spaces and Unicode; no composition rules are imposed. Usernames are case-insensitive.

On macOS/Linux, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python` after creating the environment with `python3 -m venv .venv`.

The first run creates a SQLite database and random signing key in `demo-app/instance/`, which is ignored by Git. There are **no default accounts or passwords**. Keep the key and database private. The application binds to loopback only, with Flask debugging disabled. Stop it with Ctrl+C in its terminal.

## Create an administrator

Open a second terminal in the repository root:

```powershell
.\.venv\Scripts\python.exe -m flask --app demo-app/app.py create-admin --username course_admin --display-name "Course Admin"
```

Enter and confirm a new password when prompted; the input is hidden. Passwords are deliberately not accepted as command-line arguments. Sign in through the same web login form using that account. The **Admin** link appears for admins.

The command creates a new admin and refuses to overwrite an existing username. Public registration always creates a `user`, and submitting a `role` field is rejected. Access to the server's terminal/database is an administrative privilege; this command is not exposed through a web route.

## Demonstrate the requirements

1. Register a normal account, then sign in and open its profile.
2. Visit `/admin` while signed in as that user: access is denied.
3. Register another user, note their profile URL, then sign in as the first user and request the other profile: access is denied.
4. Sign in with the locally created admin: `/admin` lists account names and roles. Admins still cannot open someone else's private profile.
5. Sign out. A protected profile or admin URL now redirects to login.

These steps also work as a short optional recording outline. Registration and login alone are not enough: the server checks the requested profile owner or current database role on every protected request.

## Implemented controls

- **Password storage:** Werkzeug scrypt with explicit `N=131072, r=8, p=1` and independently random salts. Stored formats are bounded and checked before verification. Unknown users perform a real dummy verification. Registration does not store plaintext.
- **Authorization:** profile IDs must match the signed-in account; admin access checks the database role, not a submitted field or a role stored in the browser cookie.
- **Sessions:** each login rotates the signed-cookie state and creates a random server-side session token. Only its SHA-256 digest and expiration are stored in SQLite. Logout deletes it, so replaying the old cookie does not restore access. Sessions expire 30 minutes after login, without sliding renewal.
- **CSRF:** every POST checks a session-bound token; login and registration are protected too. Signing in rotates that token, and logout requires POST.
- **Throttling:** SQLite transactions reserve login attempts before password work: at most 5 per username and 30 per IP in 15 minutes, counting all well-formed attempts including successes. Registration allows 10 attempts per IP in that window. A fresh browser does not reset these database counters. The app does not trust forwarding headers.
- **Input/output:** bounded forms, parameterized SQL, Jinja autoescaping, explicit safe database fields, generic authentication failures, security response headers, and no-store caching.

## Tests

From the repository root, using the environment above:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s demo-app -p "test_*.py" -v
```

**26 tests passed** with Python 3.14.6 and Flask 3.1.3. The tests use real Flask requests/cookies, password verification, and temporary SQLite databases. They cover user/admin restrictions, registration-role tampering, login/logout CSRF, private profile isolation, escaped display names, salted hashes, attempt limits, expired/replayed/tampered sessions, and admin provisioning. No application accounts or personal data are used by these tests. The repository's `run_checks.py` also runs this suite.

A separate Chrome browser walkthrough confirmed registration, login, the owner's profile, rejection of another profile and the admin page for a regular user, admin directory access, and logout followed by a login requirement. It used a disposable local database with invented accounts.

## Scope

This is a runnable **local coursework demo**, not a public deployment. HTTPS is required before serving real users; set `DEMO_HTTPS=1` for Secure cookies under HTTPS, supply a secret through `DEMO_SECRET_KEY`, and use a production server and reviewed host/proxy configuration. The demo's trusted hosts are localhost/loopback only. SQLite throttle storage works across processes sharing the same database file, but a distributed deployment needs shared infrastructure and operational controls.

Password recovery is demonstrated independently in Sample 7; it is not connected to this app. MFA, email verification, breached-password screening, account-management UI, and production monitoring are outside this assignment demo. Password inputs are never logged, but users should still use invented coursework credentials rather than reuse a personal password. Generic errors and dummy hashing reduce account disclosure; they are not a formal constant-time guarantee.

## Official references

- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): adaptive password hashing and scrypt parameters.
- [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): password length, generic failures, and throttling.
- [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html): server-side ownership and permission checks.
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): protecting state-changing requests.
- [Flask security guidance](https://flask.palletsprojects.com/en/stable/web-security/): escaping, cookies, request limits, trusted hosts, and response headers.
