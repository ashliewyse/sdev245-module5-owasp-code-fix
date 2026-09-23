package owasp.sample03;

import owasp.shared.PasswordHashes;

/** Replacement for the original MD5 hashPassword method. */
public final class SecurePasswordStorage {
    private SecurePasswordStorage() {}

    public static String hashPassword(char[] password) {
        return PasswordHashes.hash(password);
    }

    public static boolean verifyPassword(char[] inputPassword, String storedHash) {
        return PasswordHashes.verify(inputPassword, storedHash);
    }
}
