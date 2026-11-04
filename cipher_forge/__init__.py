"""
Cipher Forge — Educational cryptography toolkit.

Implements classical and modern ciphers from scratch in pure Python.
No external cryptography libraries required.
"""

from cipher_forge.classical import CaesarCipher, VigenereCipher, RailFenceCipher, ColumnarTransposition
from cipher_forge.modern import AES128
from cipher_forge.hashing import SHA256
from cipher_forge.asymmetric import RSA
from cipher_forge.analysis import (
    letter_frequency,
    index_of_coincidence,
    crack_caesar,
    estimate_vigenere_key_length,
)

__version__ = "0.1.0"
__all__ = [
    "CaesarCipher",
    "VigenereCipher",
    "RailFenceCipher",
    "ColumnarTransposition",
    "AES128",
    "SHA256",
    "RSA",
    "letter_frequency",
    "index_of_coincidence",
    "crack_caesar",
    "estimate_vigenere_key_length",
]
