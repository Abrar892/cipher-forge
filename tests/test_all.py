"""Full test suite for cipher-forge."""
import unittest
from cipher_forge.classical import CaesarCipher, VigenereCipher
from cipher_forge.modern import AES128
from cipher_forge.hashing import SHA256
from cipher_forge.asymmetric import RSA, miller_rabin


class TestClassicalCiphers(unittest.TestCase):
    def setUp(self):
        self.caesar = CaesarCipher()
        self.vig = VigenereCipher()

    def test_caesar_roundtrip(self):
        text = "Hello, World! 123"
        enc = self.caesar.encrypt(text, 5)
        dec = self.caesar.decrypt(enc, 5)
        self.assertEqual(dec, text)

    def test_vigenere_roundtrip(self):
        text = "Confidential Message for Agent"
        key = "SECRETKEY"
        enc = self.vig.encrypt(text, key)
        dec = self.vig.decrypt(enc, key)
        self.assertEqual(dec, text)


class TestModernCrypto(unittest.TestCase):
    def test_aes_ecb_roundtrip(self):
        key = b"0123456789abcdef"
        aes = AES128(key)
        data = b"Testing pure Python AES-128 block cipher implementation with padding!"
        enc = aes.encrypt_ecb(data)
        dec = aes.decrypt_ecb(enc)
        self.assertEqual(dec, data)

    def test_aes_known_vector(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_cipher = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        aes = AES128(key)
        cipher = aes.encrypt_block(plain)
        self.assertEqual(cipher, expected_cipher)
        self.assertEqual(aes.decrypt_block(cipher), plain)


class TestHashing(unittest.TestCase):
    def test_sha256_known_vectors(self):
        self.assertEqual(
            SHA256.hash_str(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(
            SHA256.hash_str("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )


class TestRSA(unittest.TestCase):
    def test_miller_rabin(self):
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
        for p in primes:
            self.assertTrue(miller_rabin(p))
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25, 26, 27, 28]
        for c in composites:
            self.assertFalse(miller_rabin(c))

    def test_rsa_roundtrip(self):
        pub, priv = RSA.generate_keypair(bits=32)
        msg = "Safe RSA 2026"
        enc = RSA.encrypt_text(msg, pub)
        dec = RSA.decrypt_text(enc, priv)
        self.assertEqual(dec, msg)


if __name__ == "__main__":
    unittest.main()
