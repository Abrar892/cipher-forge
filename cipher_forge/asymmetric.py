"""Educational RSA implementation with Miller-Rabin primality test."""
import random
import math
from typing import Tuple, Dict, List


def miller_rabin(n: int, k: int = 20) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 64) -> int:
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if miller_rabin(p):
            return p


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi


class RSA:
    """Educational RSA cryptosystem."""

    @staticmethod
    def generate_keypair(bits: int = 64) -> Tuple[Dict[str, int], Dict[str, int]]:
        p = generate_prime(bits)
        q = generate_prime(bits)
        while q == p:
            q = generate_prime(bits)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if math.gcd(e, phi) != 1:
            e = 3
            while math.gcd(e, phi) != 1:
                e += 2

        d = mod_inverse(e, phi)
        public_key = {"n": n, "e": e}
        private_key = {"n": n, "d": d}
        return public_key, private_key

    @staticmethod
    def encrypt_int(m: int, public_key: Dict[str, int]) -> int:
        return pow(m, public_key["e"], public_key["n"])

    @staticmethod
    def decrypt_int(c: int, private_key: Dict[str, int]) -> int:
        return pow(c, private_key["d"], private_key["n"])

    @classmethod
    def encrypt_text(cls, text: str, public_key: Dict[str, int]) -> List[int]:
        return [cls.encrypt_int(b, public_key) for b in text.encode("utf-8")]

    @classmethod
    def decrypt_text(cls, cipher_ints: List[int], private_key: Dict[str, int]) -> str:
        dec_bytes = bytes([cls.decrypt_int(c, private_key) for c in cipher_ints])
        return dec_bytes.decode("utf-8")
