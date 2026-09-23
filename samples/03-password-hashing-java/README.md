# Sample 3: Password hashing in Java

## Original vulnerable code

```java
public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest);
}
```

## Flaw and potential harm

The method uses fast, unsalted MD5 to store passwords. If the credential database leaks, an attacker can cheaply test many guesses offline and recognize accounts using the same password. MD5's collision weaknesses are another reason to retire it, but the immediate password-storage problem is cheap guessing and the missing per-password salt. Merely changing MD5 to a single SHA-256 digest would retain those problems.

## Corrected code and why it works

[SecurePasswordStorage.java](SecurePasswordStorage.java) replaces the method and delegates to [PasswordHashes.java](../../shared/java/PasswordHashes.java). The shared implementation generates a fresh 16-byte salt with `SecureRandom`, uses PBKDF2-HMAC-SHA256 with 600,000 iterations, and stores the algorithm, cost, salt, and 32-byte derived hash together. Verification derives the candidate hash with the saved salt and compares the fixed-length byte arrays using `MessageDigest.isEqual`. Different salts prevent reusable precomputed lookup results; the repeated KDF work increases the cost of each guess.

This example uses PBKDF2 because Java 17 provides it without extra dependencies. OWASP prefers Argon2id for new applications, then scrypt when Argon2id is unavailable. Its PBKDF2 guidance lists 600,000 iterations for HMAC-SHA256. An application able to manage a maintained password-hashing library should evaluate Argon2id first. This code does **not** claim that the installed Java provider is FIPS validated.

Malformed, truncated, legacy, and unsupported hash records fail closed. The parser accepts only this version's fixed work factor and bounded record size, so a malicious cost field cannot request arbitrary CPU work. Password input is limited to 1–1,024 UTF-16 code units without silent truncation. Spaces, Unicode, and embedded NUL characters are preserved. Temporary KDF password storage is cleared; the caller must also clear its own `char[]` when finished.

## Assumptions and limitations

- This is a storage component, not a registration or login application. Registration still needs an appropriate minimum length, breached-password checks, and other account policy; the 1-character lower bound is an API validity check, not a recommended password policy.
- Store the full encoded value in the password-hash column. Do not store or log the plaintext password. A salt is not a secret.
- Existing MD5 records are deliberately unsupported. Migrate affected users through a verified password reset or an explicitly designed legacy migration; do not relabel an MD5 value as a PBKDF2 record.
- Future cost upgrades require a versioned migration. Benchmark the KDF on the deployed server and rate-limit verification requests. Password hashing reduces offline guessing speed; it cannot guarantee that weak passwords remain unguessable.

## Run the tests

Requires JDK 17 or newer. From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Force work/java03 | Out-Null
javac -encoding UTF-8 -Xlint:all -d work/java03 shared/java/PasswordHashes.java samples/03-password-hashing-java/SecurePasswordStorage.java samples/03-password-hashing-java/PasswordStorageTest.java
java -cp work/java03 owasp.sample03.PasswordStorageTest
```

Verified with `javac 17.0.19`: **14 tests passed**. Tests exercise correct and incorrect passwords, independent salts, mismatched salt/hash records, malformed data, unsupported costs, input bounds, Unicode/NUL handling, and caller-array ownership. These tests execute the actual JDK KDF at the configured cost; they are not deployment performance measurements.

## Official OWASP references

- [Password Storage Cheat Sheet — password hashing algorithms, salts, work factors, and migration](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Authentication Cheat Sheet — password policy and throttling](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

References reviewed September 23, 2026.
