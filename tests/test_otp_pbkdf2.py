"""Tests for cipher_forge One-Time Pad and PBKDF2 key derivation."""

import unittest
import hashlib
from cipher_forge.otp import OneTimePad
from cipher_forge.pbkdf2 import PBKDF2HMAC


class TestOTPAndPBKDF2(unittest.TestCase):
    def test_otp_roundtrip_bytes(self):
        msg = b"TOP SECRET MISSION 2026"
        ct, key = OneTimePad.encrypt_with_new_key(msg)
        self.assertNotEqual(ct, msg)
        self.assertEqual(len(ct), len(msg))
        
        pt = OneTimePad.decrypt(ct, key)
        self.assertEqual(pt, msg)

    def test_otp_roundtrip_str(self):
        msg = "Classical Vernam Cipher Test"
        key = OneTimePad.generate_key(len(msg.encode("utf-8")))
        ct = OneTimePad.encrypt(msg, key)
        pt = OneTimePad.decrypt(ct, key)
        self.assertEqual(pt.decode("utf-8"), msg)

    def test_otp_short_key_raises(self):
        with self.assertRaises(ValueError):
            OneTimePad.encrypt(b"long message", b"short")

    def test_pbkdf2_matches_stdlib(self):
        """Verify PBKDF2 output matches Python's hashlib.pbkdf2_hmac."""
        password = b"SuperStrongPassword2026!"
        salt = b"random_salt_1234"
        iterations = 500  # fast for test run
        key_len = 32

        expected = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=key_len)
        kdf = PBKDF2HMAC(password, salt, iterations=iterations, key_length=key_len)
        actual = kdf.derive()

        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 32)

    def test_pbkdf2_variable_lengths(self):
        password = "admin"
        salt = "salt"
        kdf48 = PBKDF2HMAC(password, salt, iterations=100, key_length=48)
        derived = kdf48.derive()
        self.assertEqual(len(derived), 48)


if __name__ == "__main__":
    unittest.main()
