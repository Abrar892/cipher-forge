"""Pure Python implementation of SHA-256 hash algorithm."""
from typing import Union


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _shr(x: int, n: int) -> int:
    return (x >> n) & 0xFFFFFFFF


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _gamma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _gamma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
]


class SHA256:
    """Standard SHA-256 digest engine from scratch."""

    @staticmethod
    def hash(data: Union[bytes, str]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")

        # Initial hash values
        h0 = 0x6A09E667
        h1 = 0xBB67AE85
        h2 = 0x3C6EF372
        h3 = 0xA54FF53A
        h4 = 0x510E527F
        h5 = 0x9B05688C
        h6 = 0x1F83D9AB
        h7 = 0x5BE0CD19

        bit_len = len(data) * 8
        padded = bytearray(data)
        padded.append(0x80)
        while (len(padded) % 64) != 56:
            padded.append(0x00)
        padded.extend(bit_len.to_bytes(8, byteorder="big"))

        for i in range(0, len(padded), 64):
            chunk = padded[i : i + 64]
            w = [0] * 64
            for j in range(16):
                w[j] = int.from_bytes(chunk[j * 4 : (j + 1) * 4], "big")

            for j in range(16, 64):
                s0 = _gamma0(w[j - 15])
                s1 = _gamma1(w[j - 2])
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

            for j in range(64):
                t1 = (h + _sigma1(e) + _ch(e, f, g) + K[j] + w[j]) & 0xFFFFFFFF
                t2 = (_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF
                h = g
                g = f
                f = e
                e = (d + t1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (t1 + t2) & 0xFFFFFFFF

            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
            h5 = (h5 + f) & 0xFFFFFFFF
            h6 = (h6 + g) & 0xFFFFFFFF
            h7 = (h7 + h) & 0xFFFFFFFF

        return "".join(f"{x:08x}" for x in (h0, h1, h2, h3, h4, h5, h6, h7))

    @classmethod
    def hash_str(cls, text: str) -> str:
        return cls.hash(text.encode("utf-8"))
