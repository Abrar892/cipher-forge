"""otp.py — Information-theoretically secure One-Time Pad (Vernam cipher) engine."""

from __future__ import annotations
import secrets
from typing import Tuple


class OneTimePad:
    """
    One-Time Pad implementation (Vernam cipher).
    Guarantees perfect secrecy (Shannon secrecy) when key is truly random,
    at least as long as the plaintext, and never reused.
    """

    @staticmethod
    def generate_key(length_bytes: int) -> bytes:
        """Generate cryptographically secure random key bytes."""
        if length_bytes <= 0:
            raise ValueError("Key length must be greater than zero")
        return secrets.token_bytes(length_bytes)

    @staticmethod
    def encrypt(plaintext: bytes | str, key: bytes) -> bytes:
        """Encrypt plaintext with key using bitwise XOR."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if len(key) < len(plaintext):
            raise ValueError(f"Key length ({len(key)}) must be at least plaintext length ({len(plaintext)})")
        return bytes(p ^ k for p, k in zip(plaintext, key))

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt ciphertext with key using bitwise XOR."""
        if len(key) < len(ciphertext):
            raise ValueError(f"Key length ({len(key)}) must be at least ciphertext length ({len(ciphertext)})")
        return bytes(c ^ k for c, k in zip(ciphertext, key))

    @classmethod
    def encrypt_with_new_key(cls, plaintext: bytes | str) -> Tuple[bytes, bytes]:
        """Convenience helper generating key and ciphertext together."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        key = cls.generate_key(len(plaintext))
        ciphertext = cls.encrypt(plaintext, key)
        return ciphertext, key
