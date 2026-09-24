# Module 5: OWASP Top 10 Code Fix

**All ten code-fix samples and a working login application are implemented, documented, and tested.**

This repository follows the ten numbered snippets in the assignment, which repeat some categories and cover seven OWASP Top 10:2021 categories. Each sample folder uses the original snippet's language. The separate `demo-app/` folder provides a runnable local application demonstrating registration, authentication, owner-only profiles, and user/admin access.

Due: September 25, 2026 at 11:59 p.m. as displayed in Canvas.

## Working login application

[Access Lab in demo-app](demo-app/README.md) covers the assignment introduction's request for a working login system with role-based access. It includes registration with scrypt password storage, login/logout, owner-only profiles, a protected admin directory, CSRF protection, revocable sessions, and attempt limits.

Follow the [setup and administrator-creation instructions](demo-app/README.md). It runs locally at `http://127.0.0.1:5000`; no default accounts or passwords are supplied. The application is separate from the ten focused code-fix samples. Its 26 automated tests passed, and the registration/login/access/logout flow was also checked in Chrome.

## Deliverables

- [x] Runnable login application with user/admin roles
- [x] Corrected code for all ten supplied samples
- [x] Security-flaw explanations and real-world impact
- [x] Explanation of why each fix works
- [x] Official OWASP references for every sample
- [x] Readable code and reproducible tests
- [x] Repository is public and accessible to the instructor
- [ ] Optional: record a one-minute walkthrough

The repository is public. In Canvas, select **Web URL** and submit [this repository link](https://github.com/ashliewyse/sdev245-module5-owasp-code-fix). The code is ready for submission; changing repository visibility does not submit the assignment in Canvas.

## Samples and verification

| Sample | Topic | Main code | Passing tests |
| --- | --- | --- | ---: |
| 1 | Broken access control — JavaScript | [Profile handler](samples/01-broken-access-control-javascript/secure-profile.cjs) | 9 |
| 2 | Broken access control — Python | [Account route](samples/02-broken-access-control-python/secure_account.py) | 11 |
| 3 | MD5 password hashing — Java | [Password storage](samples/03-password-hashing-java/SecurePasswordStorage.java) | 14 |
| 4 | SHA-1 password hashing — Python | [Password hashing](samples/04-password-hashing-python/password_hashing.py) | 9 |
| 5 | SQL injection — Java | [User lookup](samples/05-sql-injection-java/UserLookup.java) | 10 |
| 6 | NoSQL injection — JavaScript | [User handler](samples/06-nosql-injection-javascript/secure-user.mjs) | 18 |
| 7 | Insecure password-reset design — Python | [Reset workflow](samples/07-password-reset-python/secure_reset.py) | 20 |
| 8 | Software/data integrity — HTML | [Pinned script example](samples/08-script-integrity-html/index.html) | 5 |
| 9 | SSRF — Python | [Restricted fetch helper](samples/09-ssrf-python/secure_fetch.py) | 11 |
| 10 | Authentication failures — Java | [Authentication service](samples/10-authentication-java/AuthenticationService.java) | 13 |
| Demo | Working login and role application | [Flask app](demo-app/app.py) | 26 |
| **Total** | | | **146** |

Every sample folder contains its original vulnerable snippet, corrected code, risk/fix explanations, references, and specific testing limits. See [VERIFICATION.md](VERIFICATION.md) for the combined results and scope.

## Run all checks

Prerequisites used for verification: **Python 3.14.6**, **Node.js 24.18.0**, and **JDK 17.0.19**. Both `java` and `javac` must be on PATH. Python password tests intentionally perform expensive KDF operations and need roughly 256 MiB or more available for concurrent hashing.

Windows PowerShell, from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_checks.py
```

macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run_checks.py
```

The runner stops on a failed command, compiles Java into a temporary directory, and runs each Python sample and the working login app separately. The checks use local fixtures, temporary databases, or test doubles. They send no email and make no external network requests.

## Sample explanations

### 1. JavaScript profile endpoint

Folder: [samples/01-broken-access-control-javascript](samples/01-broken-access-control-javascript/)

**Security flaw and real-world impact:** The original route retrieves whichever user ID appears in the URL without checking ownership. A caller can change that ID to read someone else's profile. Depending on the schema, returning the entire user record may disclose private fields. The snippet also returns internal database errors.

**Corrected code:** [secure-profile.cjs](samples/01-broken-access-control-javascript/secure-profile.cjs).

**Why the fix works:** The handler requires a verified authenticated ID, validates the requested ID, and allows only matching owner IDs before accessing the database. It returns an explicit field allowlist and generic errors. Real authentication middleware must establish the identity; see the [sample README](samples/01-broken-access-control-javascript/README.md) for the required integration contract.

**Verification:** Nine unit tests passed on Node.js v24.18.0. They cover anonymous access, malformed identity and URL input, owner success, cross-user denial, spoofed inputs, ID normalization, missing records, and safe database errors. Login and database integration are not tested.

**Official OWASP references:** [A01:2021 Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/), [IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), and [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). These explain object-level permissions and server-side authorization on each request.

### 2. Python account endpoint

Folder: [samples/02-broken-access-control-python](samples/02-broken-access-control-python/)

**Security flaw and real-world impact:** The original route trusts the account ID in the URL without checking ownership. A caller can request someone else's account, potentially exposing private fields included by `to_dict()`. ORM parameterization alone does not authorize the request.

**Corrected code:** [secure_account.py](samples/02-broken-access-control-python/secure_account.py).

**Why the fix works:** The route uses Flask-Login's authenticated user, validates the integer ID contract, and rejects another owner's ID before an account query. It selects and returns only approved fields, disables response caching, and handles missing records and database errors safely. See the [sample README](samples/02-broken-access-control-python/README.md) for the required authentication and model setup.

**Verification:** Eleven route tests passed with Flask, Flask-Login, SQLAlchemy, and an in-memory SQLite database on Python 3.14.6. They verify owner access, cross-user denial, identity/input validation, response filtering, and failure behavior. Test sessions bypass password verification; a production login system is outside this sample.

**Official OWASP references:** [A01:2021 Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/), [IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), and [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). These support object-level ownership checks and least privilege.

### 3. Java MD5 password hashing

**Flaw and impact:** Unsalted MD5 is fast to guess offline after a database leak and gives the same result for the same password.

**Corrected code and why it works:** [Sample 3](samples/03-password-hashing-java/README.md) uses a random salt, 600,000-iteration PBKDF2-HMAC-SHA256, bounded versioned records, and timing-safe derived-byte comparison. [Shared implementation](shared/java/PasswordHashes.java) is reused by Sample 10. This JDK-only teaching choice documents Argon2id as the preferred general-purpose option and does not claim FIPS validation.

**Verification:** 14 passing tests cover real KDF verification, independent salts, tampering, malformed records, and Unicode.

**OWASP reference:** [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### 4. Python SHA-1 password hashing

**Flaw and impact:** Unsalted SHA-1 allows inexpensive offline password guessing and identifies users who share a password.

**Corrected code and why it works:** [Sample 4](samples/04-password-hashing-python/README.md) replaces it with independently salted scrypt using `N=2^17, r=8, p=1`. Memory and CPU cost slow guessing; strict record parsing prevents an attacker-controlled cost parameter, and `compare_digest` verifies the derived value.

**Verification:** 9 passing tests exercise correct/wrong passwords, unique salts, tampering, malformed records, input limits, and Unicode preservation. Legacy hashes need a separate verified migration/reset workflow.

**OWASP reference:** [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### 5. Java SQL query

**Flaw and impact:** Concatenating a submitted username into SQL can let input change the query and retrieve unintended records.

**Corrected code and why it works:** [Sample 5](samples/05-sql-injection-java/README.md) binds the username through `PreparedStatement.setString`, keeping query syntax separate from data. It selects limited fields and closes owned statement/result resources on success and failure. The caller still enforces permissions.

**Verification:** 10 passing JDBC API-contract tests verify injection-like input remains a bound value and resources close correctly. They use JDBC test doubles, not a live database.

**OWASP reference:** [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

### 6. JavaScript NoSQL query

**Flaw and impact:** An unchecked query parameter may be parsed as an object containing MongoDB operators. Returning the whole matched document can disclose private data.

**Corrected code and why it works:** [Sample 6](samples/06-nosql-injection-javascript/README.md) accepts one bounded username string, constructs the query itself, binds it to the authenticated owner's immutable ID, and returns only approved fields. This independent sample documents a UUID-string `_id` schema. It also disables caching.

**Verification:** 18 passing handler tests cover operator objects, arrays, extra parameters, trailing newlines, unauthorized access, safe errors, and output filtering. The database is stubbed.

**OWASP references:** [NoSQL Security](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html) and [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

### 7. Python password reset

**Flaw and impact:** An email address alone lets a caller overwrite another person's password, causing account takeover. The original also stores the new password directly.

**Corrected code and why it works:** [Sample 7](samples/07-password-reset-python/README.md) uses verified-channel delivery of a random, expiring token. Only its digest is stored. A database transaction binds token consumption to the correct user's password update and session-epoch increment. Flask routes require CSRF checks and explicit queue/throttling integrations.

**Verification:** 20 passing tests include expiration, replay, concurrency, rollback, account binding, hashed storage, generic queued responses, CSRF, and session-epoch checks. Delivery, queue, shared throttling, and production authentication adapters are documented integration requirements.

**OWASP references:** [Insecure Design](https://owasp.org/Top10/2021/A04_2021-Insecure_Design/), [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html), and [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### 8. External script integrity

**Flaw and impact:** A mutable external script runs without verifying its approved contents; a supplier compromise can execute malicious code in the page.

**Corrected code and why it works:** [Sample 8](samples/08-script-integrity-html/README.md) includes a versioned harmless demo library and its actual SHA-384 Subresource Integrity digest, plus restrictive CSP. The assignment's illustrative CDN address is replaced with a runnable local example. The browser can reject changed bytes; review establishes whether those approved bytes are trustworthy.

**Verification:** 5 passing static/Node tests check the digest, tampering, markup, and harmless script behavior. Browser enforcement is not claimed as tested; manual browser steps are included.

**OWASP reference:** [Third Party JavaScript Management](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html#subresource-integrity).

### 9. Python URL fetching

**Flaw and impact:** Accepting an arbitrary URL can turn the server into a proxy to private services or cloud metadata.

**Corrected code and why it works:** [Sample 9](samples/09-ssrf-python/README.md) lets callers select a fixed approved resource instead of supplying a URL. It checks public IPv4 DNS results, pins the numeric connection, preserves TLS hostname verification, rejects redirects, and limits the response body. IPv6-only destinations are intentionally unsupported.

**Verification:** 11 passing offline tests cover destination restrictions, private/mixed DNS answers, address pinning, TLS settings, redirects, response limits, and safe errors. Live network behavior and deployed egress controls are outside the tests.

**OWASP references:** [A10:2021 SSRF](https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) and [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

### 10. Java password authentication

**Flaw and impact:** Comparing input directly to a stored password suggests plaintext storage and does not perform secure password-hash verification.

**Corrected code and why it works:** [Sample 10](samples/10-authentication-java/README.md) verifies the stored adaptive hash, performs dummy KDF work for missing/corrupt accounts, returns a generic failure, and applies bounded synchronized account/global attempt limits. Session creation and a shared multi-process limiter remain host-application responsibilities.

**Verification:** 13 passing tests cover real password verification, unknown users, input validation, limiter expiration/capacity, and concurrent attempts.

**OWASP references:** [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
