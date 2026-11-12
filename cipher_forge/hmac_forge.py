"""hmac_forge.py — Pure-Python HMAC implementation built on cipher-forge's SHA-256.

Implements RFC 2104 HMAC using the existing sha256() function from hashing.py.

Usage::

    from cipher_forge.hmac_forge import hmac_sha256, verify_hmac
    tag = hmac_sha256(key=b"secret", message=b"data")
    ok  = verify_hmac(key=b"secret", message=b"data", tag=tag)
"""

from __future__ import annotations
from cipher_forge.hashing import SHA256


BLOCK_SIZE = 64   # SHA-256 block size in bytes
DIGEST_SIZE = 32  # SHA-256 output in bytes

IPAD = bytes([0x36] * BLOCK_SIZE)
OPAD = bytes([0x5C] * BLOCK_SIZE)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _sha256_bytes(data: bytes) -> bytes:
    """Return raw 32-byte SHA-256 digest of *data*."""
    hex_digest = SHA256().hash(data)
    return bytes(int(hex_digest[i:i+2], 16) for i in range(0, 64, 2))


def _prepare_key(key: bytes) -> bytes:
    """Normalize key to exactly BLOCK_SIZE bytes (hash if too long, pad if short)."""
    if len(key) > BLOCK_SIZE:
        key = _sha256_bytes(key)
    return key.ljust(BLOCK_SIZE, b"\x00")


def hmac_sha256(key: bytes | str, message: bytes | str) -> str:
    """
    Compute HMAC-SHA256 of *message* using *key*.

    Parameters
    ----------
    key:     Secret key (bytes or str; str encoded as UTF-8).
    message: Message to authenticate (bytes or str).

    Returns
    -------
    Lowercase hex string of 64 characters (32-byte MAC).
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")

    k = _prepare_key(key)
    inner = _sha256_bytes(_xor_bytes(k, IPAD) + message)
    outer = _sha256_bytes(_xor_bytes(k, OPAD) + inner)
    return outer.hex()


def verify_hmac(key: bytes | str, message: bytes | str, tag: str) -> bool:
    """
    Constant-time comparison of computed HMAC against *tag*.

    Returns True only if the tags match exactly.
    """
    computed = hmac_sha256(key, message)
    # Constant-time compare to avoid timing attacks
    if len(computed) != len(tag):
        return False
    result = 0
    for a, b in zip(computed, tag):
        result |= ord(a) ^ ord(b)
    return result == 0
