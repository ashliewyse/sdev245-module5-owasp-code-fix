# Sample 4 — Python password hashing

**Category:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/), matching the assignment's OWASP edition.

## Original vulnerable code

```python
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
```

## Flaw and possible harm

SHA-1 is a fast general-purpose hash. This code also omits a random salt, so identical passwords produce identical records. After stealing the database, an attacker can rapidly test guesses and reuse precomputed results across accounts. Recovering a password can enable account takeover and attacks against other sites where it was reused. The password-storage problem is fast guessing and missing salts; it does not require exploiting SHA-1 collisions. [OWASP A02 guidance](https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/)

## Secure version and why it works

See [password_hashing.py](password_hashing.py). `hash_password()` generates a fresh 16-byte salt and uses scrypt with `N=131072`, `r=8`, and `p=1`. The stored record includes the algorithm, cost settings, salt, and derived key. Salt separates accounts' results; scrypt raises the memory and computation needed per guess. These parameters match OWASP's scrypt option when Argon2id is unavailable. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

`verify_password()` parses only the supported record format, recomputes the key, and uses `hmac.compare_digest`. It refuses arbitrary cost settings rather than allowing a malformed database record to request excessive computation. Inputs are capped at 1,024 UTF-8 bytes and are never trimmed or silently truncated. [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#compare-password-hashes-using-safe-functions)

```python
from password_hashing import hash_password, verify_password

stored_record = hash_password("A long unique example passphrase")
assert verify_password("A long unique example passphrase", stored_record)
assert not verify_password("a different passphrase", stored_record)
```

## Scope and integration

This standalone storage helper uses Python's standard library; no third-party package is needed. The application must enforce its enrollment/password-strength policy and rate-limit login attempts. Each scrypt calculation needs about 128 MiB of working memory; measure concurrency limits on the deployment host. OpenSSL's memory ceiling is explicitly set to 256 MiB so the chosen configuration runs.

Existing SHA-1 records cannot be converted without the original password. Require a verified password reset, or implement a separate controlled migration after a successful legacy login. This helper deliberately rejects legacy records. Future work-factor changes require an explicit versioned verifier and rehash migration.

## Verification

From this folder:

```text
python -m unittest -v
```

Verified with **Python 3.14.6: 9 tests passed** (`Ran 9 tests in 8.172s`, `OK`). Tests cover correct and incorrect passwords, independent salts, Unicode/whitespace preservation, specified costs, malformed/legacy records, untrusted-cost rejection before hashing, input limits, and tampered digests. Timing is machine-dependent.
