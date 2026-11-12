"""Tests for cipher_forge.playfair and cipher_forge.hmac_forge."""

import unittest
import hmac as stdlib_hmac
import hashlib


class TestPlayfairCipher(unittest.TestCase):
    KEY = "PLAYFAIR EXAMPLE"

    def setUp(self):
        from cipher_forge.playfair import PlayfairCipher
        self.pf = PlayfairCipher()

    def test_encrypt_returns_string(self):
        ct = self.pf.encrypt("HELLO", self.KEY)
        self.assertIsInstance(ct, str)

    def test_encrypt_even_length(self):
        ct = self.pf.encrypt("HELLO", self.KEY)
        self.assertEqual(len(ct) % 2, 0)

    def test_known_encrypt(self):
        # Wikipedia example: "Hide the gold in the tree stump" / key "PLAYFAIR EXAMPLE"
        ct = self.pf.encrypt("Hide the gold in the tree stump", self.KEY)
        self.assertEqual(ct, "BMODZBXDNABEKUDMUIXMMOUVIF")

    def test_decrypt_matches_prepare(self):
        """Round-trip: decrypt(encrypt(msg)) starts with prepared msg."""
        msg = "ATTACK AT DAWN"
        ct = self.pf.encrypt(msg, self.KEY)
        pt = self.pf.decrypt(ct, self.KEY)
        # Prepared plaintext has X fillers; check prefix
        self.assertTrue(pt.startswith("AT"), pt)

    def test_different_keys_different_ciphertext(self):
        ct1 = self.pf.encrypt("ATTACKATDAWN", "SECRETKEYALPHA")
        ct2 = self.pf.encrypt("ATTACKATDAWN", "DIFFERENTKEYB")
        self.assertNotEqual(ct1, ct2)

    def test_show_square_is_string(self):
        square = self.pf.show_square(self.KEY)
        self.assertIsInstance(square, str)
        self.assertIn("\n", square)

    def test_j_treated_as_i(self):
        ct = self.pf.encrypt("JAB", self.KEY)
        ct2 = self.pf.encrypt("IAB", self.KEY)
        self.assertEqual(ct, ct2)

    def test_all_alpha_output(self):
        ct = self.pf.encrypt("Test Message 123!", self.KEY)
        self.assertTrue(ct.isalpha(), ct)


class TestHmacForge(unittest.TestCase):
    def test_returns_64_char_hex(self):
        from cipher_forge.hmac_forge import hmac_sha256
        tag = hmac_sha256(b"key", b"message")
        self.assertEqual(len(tag), 64)
        int(tag, 16)  # should not raise

    def test_matches_stdlib(self):
        """HMAC-SHA256 must match Python's stdlib hmac."""
        from cipher_forge.hmac_forge import hmac_sha256
        key = b"supersecretkey"
        message = b"authenticate this"
        expected = stdlib_hmac.new(key, message, hashlib.sha256).hexdigest()
        actual = hmac_sha256(key, message)
        self.assertEqual(actual, expected)

    def test_str_inputs(self):
        from cipher_forge.hmac_forge import hmac_sha256
        tag_str = hmac_sha256("key", "message")
        tag_bytes = hmac_sha256(b"key", b"message")
        self.assertEqual(tag_str, tag_bytes)

    def test_different_keys_different_tags(self):
        from cipher_forge.hmac_forge import hmac_sha256
        t1 = hmac_sha256("key1", "data")
        t2 = hmac_sha256("key2", "data")
        self.assertNotEqual(t1, t2)

    def test_different_messages_different_tags(self):
        from cipher_forge.hmac_forge import hmac_sha256
        t1 = hmac_sha256("key", "msg1")
        t2 = hmac_sha256("key", "msg2")
        self.assertNotEqual(t1, t2)

    def test_verify_correct(self):
        from cipher_forge.hmac_forge import hmac_sha256, verify_hmac
        tag = hmac_sha256("secret", "data")
        self.assertTrue(verify_hmac("secret", "data", tag))

    def test_verify_wrong_key(self):
        from cipher_forge.hmac_forge import hmac_sha256, verify_hmac
        tag = hmac_sha256("secret", "data")
        self.assertFalse(verify_hmac("wrongkey", "data", tag))

    def test_verify_wrong_message(self):
        from cipher_forge.hmac_forge import hmac_sha256, verify_hmac
        tag = hmac_sha256("secret", "data")
        self.assertFalse(verify_hmac("secret", "tampered", tag))

    def test_long_key_hashed(self):
        """Keys longer than 64 bytes should be hashed first (RFC 2104)."""
        from cipher_forge.hmac_forge import hmac_sha256
        long_key = b"k" * 100
        tag = hmac_sha256(long_key, b"msg")
        expected = stdlib_hmac.new(long_key, b"msg", hashlib.sha256).hexdigest()
        self.assertEqual(tag, expected)


if __name__ == "__main__":
    unittest.main()
