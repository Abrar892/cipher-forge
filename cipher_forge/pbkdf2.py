"""pbkdf2.py — Pure-Python PBKDF2 key derivation using cipher-forge HMAC-SHA256."""

from __future__ import annotations
import struct
from cipher_forge.hmac_forge import hmac_sha256


class PBKDF2HMAC:
    """
    PBKDF2 (Password-Based Key Derivation Function 2) as specified in RFC 2898.
    Uses cipher-forge's HMAC-SHA256 as the pseudorandom function (PRF).
    """

    def __init__(self, password: bytes | str, salt: bytes | str, iterations: int = 10000, key_length: int = 32):
        if iterations <= 0:
            raise ValueError("Iterations must be positive")
        if key_length <= 0:
            raise ValueError("Key length must be positive")

        self.password = password.encode("utf-8") if isinstance(password, str) else password
        self.salt = salt.encode("utf-8") if isinstance(salt, str) else salt
        self.iterations = iterations
        self.key_length = key_length

    def _f(self, block_index: int) -> bytes:
        """Compute F(P, S, c, i) block."""
        # Initial U1 = PRF(P, S || INT_32_BE(i))
        msg = self.salt + struct.pack(">I", block_index)
        u_hex = hmac_sha256(self.password, msg)
        u_bytes = bytes.fromhex(u_hex)
        u_prev = u_bytes
        acc = bytearray(u_bytes)

        # U2 .. Uc
        for _ in range(1, self.iterations):
            u_hex = hmac_sha256(self.password, u_prev)
            u_prev = bytes.fromhex(u_hex)
            for j in range(len(acc)):
                acc[j] ^= u_prev[j]

        return bytes(acc)

    def derive(self) -> bytes:
        """Derive the cryptographic key bytes."""
        hlen = 32  # SHA-256 output length
        l = (self.key_length + hlen - 1) // hlen
        derived = bytearray()
        for i in range(1, l + 1):
            derived.extend(self._f(i))
        return bytes(derived[:self.key_length])
