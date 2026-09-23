# Sample 10: Password authentication in Java

## Original vulnerable code

```java
if (inputPassword.equals(user.getPassword())) {
    // Login success
}
```

## Flaw and potential harm

Comparing the submitted password directly to the stored value suggests that the application stores plaintext passwords. A credential-table leak would then reveal usable passwords immediately, including passwords reused elsewhere. If `getPassword()` instead returns a salted hash, this comparison does not perform the required password verification. The snippet also lacks protection against repeated guesses and does not show handling for missing users.

## Corrected code and why it works

[AuthenticationService.java](AuthenticationService.java) retrieves an encoded password hash and uses the [shared password verifier](../../shared/java/PasswordHashes.java) from Sample 3. Registration or password reset must store a value produced by `PasswordHashes.hash`, never the password itself. Verification runs PBKDF2 with the stored salt and compares derived bytes.

For an admitted request with an unknown username or corrupt hash, the service verifies against a randomly generated dummy hash of the same algorithm and cost. This avoids a cheap missing-user shortcut. An unknown account can never authenticate, even if its submitted password happens to match the dummy. Incorrect passwords, unknown accounts, unsupported hashes, invalid input, and throttled attempts all return `false`. The web adapter should map these results to the same message, such as `Unable to sign in.`, and the same response status/shape.

[AttemptLimiter.java](AttemptLimiter.java) runs before database lookup and KDF work. A long-lived service permits five admitted attempts per canonical username per minute and 100 total per process per minute. It counts successful attempts too, uses monotonic time, synchronizes updates, expires old counters, and limits tracked usernames to 10,000. If capacity is reached, it denies new entries instead of evicting active counters. Usernames are normalized to lowercase with `Locale.ROOT`, preventing case changes from creating separate account counters.

## Assumptions and limitations

- Create **one shared, long-lived** `AuthenticationService` for this application process. Creating one per request would reset limits and regenerate the dummy hash.
- `UserStore` is the integration boundary: supply a real, parameterized database lookup. Registration and the database must use the same lowercase, ASCII `[a-z0-9_.-]` username policy and enforce uniqueness. This deliberate example policy is not an email-username policy.
- The limiter is a bounded single-process demonstration. Its counters reset on restart, and separate servers have separate counters. A deployed service needs shared atomic rate limits and additional controls for distributed abuse. Fixed windows permit bursts near a boundary; targeted attempts can also temporarily block a legitimate user, so recovery and abuse policy require care.
- Dummy KDF work reduces one timing discrepancy; this is not a claim of constant-time HTTP responses. Database latency, network behavior, exceptions, and throttling still affect timing. Monitor failures without logging passwords or password hashes.
- The service returns a verification decision only. The surrounding application must provide HTTPS, password enrollment policy, MFA where appropriate, safe session creation/rotation, CSRF defenses, logout, verified reset, and generic internal-error handling.
- Malformed/legacy hashes fail closed. Use a verified reset or planned migration for old records. The shared KDF's password-input length limit is 1–1,024 UTF-16 code units without trimming or truncation; registration must enforce strength requirements separately.
- Clear the caller's password `char[]` after use. Follow the algorithm-selection and provider limitations described in [Sample 3](../03-password-hashing-java/README.md).

## Run the tests

Requires JDK 17 or newer. From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Force work/java10 | Out-Null
javac -encoding UTF-8 -Xlint:all -d work/java10 shared/java/PasswordHashes.java samples/10-authentication-java/AttemptLimiter.java samples/10-authentication-java/AuthenticationService.java samples/10-authentication-java/AuthenticationTest.java
java -cp work/java10 owasp.sample10.AuthenticationTest
```

Verified with `javac 17.0.19`: **13 tests passed**. Tests execute the real KDF for valid, incorrect, missing-user, and corrupt-record paths; they observe that missing users use the dummy hash. They also cover input validation, canonicalization, account/global limits, expiration, bounded capacity, 40 concurrent limiter calls, and the public service constructor. No timing-equality claim or live authentication/database/session integration test is made.

## Official OWASP references

- [Authentication Cheat Sheet — generic responses, throttling, transport, and MFA](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Password Storage Cheat Sheet — salted password verification and KDF selection](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

References reviewed September 23, 2026.
