import unittest
from unittest.mock import patch

from password_hashing import hash_password, verify_password


class PasswordHashingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "A lengthy sample passphrase!"
        cls.record = hash_password(cls.password)

    def test_correct_password(self):
        self.assertTrue(verify_password(self.password, self.record))

    def test_wrong_password(self):
        self.assertFalse(verify_password("incorrect password", self.record))

    def test_each_hash_has_a_unique_salt(self):
        other = hash_password(self.password)
        self.assertNotEqual(self.record, other)
        self.assertNotEqual(self.record.split("$")[4], other.split("$")[4])
        self.assertTrue(verify_password(self.password, other))

    def test_unicode_and_whitespace_are_preserved(self):
        password = "  A long caf\u00e9 \U0001f512 passphrase  "
        record = hash_password(password)
        self.assertTrue(verify_password(password, record))
        self.assertFalse(verify_password(password.strip(), record))

    def test_records_use_documented_parameters_and_lengths(self):
        algorithm, n, r, p, salt, digest = self.record.split("$")
        self.assertEqual((algorithm, n, r, p), ("scrypt", "131072", "8", "1"))
        self.assertEqual(len(bytes.fromhex(salt)), 16)
        self.assertEqual(len(bytes.fromhex(digest)), 32)
        self.assertNotIn(self.password, self.record)

    def test_malformed_or_legacy_hashes_fail_closed(self):
        for record in (None, "", "a" * 40, self.record[:-1],
                       self.record.replace("$8$", "$9$"),
                       self.record[:-64] + "z" * 64):
            with self.subTest(record=record):
                self.assertFalse(verify_password(self.password, record))

    def test_untrusted_cost_cannot_trigger_expensive_work(self):
        with patch("password_hashing._derive") as derive:
            self.assertFalse(verify_password(self.password, self.record.replace("131072", "999999")))
            derive.assert_not_called()

    def test_invalid_passwords_are_rejected_before_hashing(self):
        for password in (None, b"bytes", "", "x" * 1025, "\ud800"):
            with self.subTest(password=repr(password)):
                with self.assertRaises((ValueError, UnicodeError)):
                    hash_password(password)
                self.assertFalse(verify_password(password, self.record))

    def test_digest_tampering_is_rejected(self):
        replacement = "0" if self.record[-1] != "0" else "1"
        self.assertFalse(verify_password(self.password, self.record[:-1] + replacement))


if __name__ == "__main__":
    unittest.main()
