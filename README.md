# Module 5: OWASP Top 10 Code Fix

**Status: Samples 1–2 implemented and tested (9 JavaScript unit tests and 11 Python route tests). Samples 3–10 remain to be completed.**

## Assignment

Review and fix all ten numbered code samples provided in the assignment. The supplied samples cover seven vulnerability categories; numbering here matches the assignment.

Due: September 25, 2026 at 11:59 p.m. (as displayed in Canvas).

## Deliverables

- [ ] Corrected code for all ten samples
- [ ] Detailed explanation of each security flaw and its real-world impact
- [ ] Explanation of how each fix mitigates the vulnerability
- [ ] Official OWASP references for each sample
- [ ] Readable, consistently formatted code
- [ ] Verify instructor access to this repository before submitting its URL
- [ ] Optional: one-minute recording showing the changes

## Organization

Each numbered folder in `samples/` matches a supplied assignment sample. Samples 1–2 contain corrected JavaScript/Python routes, documentation, and executable tests. Samples 3–10 contain planning templates.

## Grading

| Criterion | Points |
| --- | ---: |
| Explanation of risk | 15 |
| Secure code fixes | 15 |
| Explanation of fixes | 15 |
| Code clarity and formatting | 5 |
| Total | 50 |

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

Folder: [samples/03-password-hashing-java](samples/03-password-hashing-java/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 4. Python SHA-1 password hashing

Folder: [samples/04-password-hashing-python](samples/04-password-hashing-python/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 5. Java SQL query

Folder: [samples/05-sql-injection-java](samples/05-sql-injection-java/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 6. JavaScript NoSQL query

Folder: [samples/06-nosql-injection-javascript](samples/06-nosql-injection-javascript/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 7. Python password reset

Folder: [samples/07-password-reset-python](samples/07-password-reset-python/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 8. External script integrity

Folder: [samples/08-script-integrity-html](samples/08-script-integrity-html/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 9. Python URL fetching

Folder: [samples/09-ssrf-python](samples/09-ssrf-python/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.

### 10. Java password authentication

Folder: [samples/10-authentication-java](samples/10-authentication-java/)

**Security flaw and real-world impact:** TODO.

**Corrected code:** TODO — add the source file and link it here.

**Why the fix works:** TODO.

**Verification:** TODO — describe relevant checks and actual results.

**Official OWASP reference:** TODO — add the specific page URL and explain its relevance.
