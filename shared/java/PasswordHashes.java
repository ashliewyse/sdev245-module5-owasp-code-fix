package owasp.shared;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A dependency-free Java 17 password-storage example. */
public final class PasswordHashes {
    public static final int ITERATIONS = 600_000;
    public static final int MAX_PASSWORD_CHARS = 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String PREFIX = "$pbkdf2-sha256$600000$";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;

    private PasswordHashes() {}

    public static boolean validPasswordInput(char[] password) {
        return password != null && password.length > 0
                && password.length <= MAX_PASSWORD_CHARS;
    }

    /** Caller remains responsible for clearing its own password array. */
    public static String hash(char[] password) {
        if (!validPasswordInput(password)) {
            throw new IllegalArgumentException("Password length must be 1..1024 characters");
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] derived = derive(password, salt);
        try {
            return PREFIX + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /** Malformed, legacy, or unsupported records fail closed. */
    public static boolean verify(char[] password, String encoded) {
        if (!validPasswordInput(password)) return false;
        Parsed record = parse(encoded);
        if (record == null) return false;
        byte[] actual = derive(password, record.salt());
        try {
            return MessageDigest.isEqual(record.hash(), actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
            Arrays.fill(record.hash(), (byte) 0);
        }
    }

    public static boolean isSupportedHash(String encoded) {
        return parse(encoded) != null;
    }

    private static Parsed parse(String encoded) {
        // Fixed-size records and one supported work factor prevent hostile cost fields.
        if (encoded == null || encoded.length() != PREFIX.length() + 24 + 1 + 44
                || !encoded.startsWith(PREFIX)) return null;
        String[] fields = encoded.split("\\$", -1);
        if (fields.length != 5) return null;
        try {
            byte[] salt = Base64.getDecoder().decode(fields[3]);
            byte[] hash = Base64.getDecoder().decode(fields[4]);
            if (salt.length != SALT_BYTES || hash.length != HASH_BYTES
                    || !Base64.getEncoder().encodeToString(salt).equals(fields[3])
                    || !Base64.getEncoder().encodeToString(hash).equals(fields[4])) return null;
            return new Parsed(salt, hash);
        } catch (IllegalArgumentException invalidBase64) {
            return null;
        }
    }

    private static byte[] derive(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("Required password KDF unavailable", unavailable);
        } finally {
            spec.clearPassword();
        }
    }

    private record Parsed(byte[] salt, byte[] hash) {}
}
