package owasp.sample10;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.function.BiPredicate;
import owasp.shared.PasswordHashes;

/** Password verification only: the web adapter must create/rotate sessions after success. */
public final class AuthenticationService {
    @FunctionalInterface
    public interface UserStore {
        /** Return a stored hash for a canonical username, or null if absent. */
        String findPasswordHash(String canonicalUsername);
    }

    private final UserStore users;
    private final AttemptLimiter limiter;
    private final BiPredicate<char[], String> verifier;
    private final String dummyHash;

    /** Create one long-lived service shared by all login requests in this process. */
    public AuthenticationService(UserStore users) {
        this(users, new AttemptLimiter(), PasswordHashes::verify, createDummyHash());
    }

    // Package-private dependency injection allows deterministic security behavior tests.
    AuthenticationService(UserStore users, AttemptLimiter limiter,
                          BiPredicate<char[], String> verifier, String dummyHash) {
        this.users = Objects.requireNonNull(users);
        this.limiter = Objects.requireNonNull(limiter);
        this.verifier = Objects.requireNonNull(verifier);
        if (!PasswordHashes.isSupportedHash(dummyHash)) {
            throw new IllegalArgumentException("Dummy hash must use the supported KDF");
        }
        this.dummyHash = dummyHash;
    }

    /** All ordinary failures return false; never return stored hashes or failure details. */
    public boolean authenticate(String username, char[] inputPassword) {
        if (username == null || username.length() > 64
                || !PasswordHashes.validPasswordInput(inputPassword)) return false;
        String canonical = username.toLowerCase(Locale.ROOT);
        if (!canonical.matches("[a-z0-9_.-]{1,64}") || !limiter.allow(canonical)) return false;

        String storedHash = users.findPasswordHash(canonical);
        boolean supportedAccount = PasswordHashes.isSupportedHash(storedHash);
        // Missing/corrupt records perform the same configured KDF work as a known account.
        boolean matches = verifier.test(inputPassword, supportedAccount ? storedHash : dummyHash);
        return supportedAccount && matches;
    }

    private static String createDummyHash() {
        SecureRandom random = new SecureRandom();
        char[] secret = new char[64];
        for (int i = 0; i < secret.length; i++) secret[i] = (char) ('!' + random.nextInt(94));
        try {
            return PasswordHashes.hash(secret);
        } finally {
            Arrays.fill(secret, '\0');
        }
    }
}
