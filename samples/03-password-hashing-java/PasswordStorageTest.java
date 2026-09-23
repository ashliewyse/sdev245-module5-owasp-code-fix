package owasp.sample03;

import java.util.Arrays;
import owasp.shared.PasswordHashes;

public final class PasswordStorageTest {
    private static int passed;
    private static void check(String name, boolean condition) {
        if (!condition) throw new AssertionError(name);
        passed++;
        System.out.println("PASS " + name);
    }

    public static void main(String[] args) {
        char[] password = "A long test passphrase 42!".toCharArray();
        String first = SecurePasswordStorage.hashPassword(password);
        String second = SecurePasswordStorage.hashPassword(password);
        check("stored record identifies KDF and work factor", first.startsWith("$pbkdf2-sha256$600000$"));
        check("equal passwords receive different salts and records", !first.equals(second)
                && !first.split("\\$")[3].equals(second.split("\\$")[3]));
        check("correct password verifies", SecurePasswordStorage.verifyPassword(password, first));
        check("wrong password rejected", !SecurePasswordStorage.verifyPassword("wrong".toCharArray(), first));
        check("salt tampering rejected", !SecurePasswordStorage.verifyPassword(password,
                first.substring(0, first.lastIndexOf('$') + 1) + second.substring(second.lastIndexOf('$') + 1)));
        check("plaintext and MD5 records rejected", !SecurePasswordStorage.verifyPassword(password, "password")
                && !SecurePasswordStorage.verifyPassword(password, "5f4dcc3b5aa765d61d8327deb882cf99"));
        check("malformed and null records rejected", !SecurePasswordStorage.verifyPassword(password, null)
                && !SecurePasswordStorage.verifyPassword(password, first + "$extra")
                && !SecurePasswordStorage.verifyPassword(password, first.replace('$', '!')));
        check("weak or hostile iteration counts rejected", !SecurePasswordStorage.verifyPassword(password, first.replace("600000", "000001"))
                && !SecurePasswordStorage.verifyPassword(password, first.replace("600000", "999999")));
        check("invalid base64 rejected", !SecurePasswordStorage.verifyPassword(password,
                first.substring(0, first.length() - 1) + "!"));
        check("null empty oversized password inputs rejected", !SecurePasswordStorage.verifyPassword(null, first)
                && !SecurePasswordStorage.verifyPassword(new char[0], first)
                && !SecurePasswordStorage.verifyPassword(new char[1025], first));
        boolean rejected = false;
        try { SecurePasswordStorage.hashPassword(new char[0]); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check("hashing rejects empty password", rejected);
        char[] unicode = "Caf\u00e9 \ud83d\udd10 \u0000 trailing space ".toCharArray();
        String unicodeHash = SecurePasswordStorage.hashPassword(unicode);
        check("Unicode NUL and spaces survive round trip", SecurePasswordStorage.verifyPassword(unicode, unicodeHash)
                && !SecurePasswordStorage.verifyPassword("Caf\u00e9".toCharArray(), unicodeHash));
        check("supported format recognized", PasswordHashes.isSupportedHash(first)
                && !PasswordHashes.isSupportedHash("invalid"));
        check("caller array is not modified", Arrays.equals(password, "A long test passphrase 42!".toCharArray()));
        Arrays.fill(password, '\0');
        Arrays.fill(unicode, '\0');
        System.out.println(passed + " tests passed");
    }
}
