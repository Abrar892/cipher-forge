# 🔐 Cipher Forge

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Pure Python](https://img.shields.io/badge/pure-python-orange)
![Educational](https://img.shields.io/badge/purpose-educational-purple)

> An educational cryptography toolkit implementing classical and modern ciphers **entirely from scratch** in pure Python — zero external dependencies.

Cipher Forge is designed to demystify cryptography by providing readable, well-commented implementations of real-world algorithms. Each cipher is implemented following its original specification, making this an ideal companion for learning cryptographic concepts.

---

## 📚 Algorithms Implemented

### Classical Ciphers (`cipher_forge/classical.py`)
| Algorithm | Type | Key Space |
|-----------|------|-----------|
| Caesar Cipher | Substitution | Shift 0–25 |
| Vigenère Cipher | Polyalphabetic | Keyword |
| Rail-Fence Cipher | Transposition | Number of rails |
| Columnar Transposition | Transposition | Keyword |

### Modern Cryptography
| Algorithm | File | Notes |
|-----------|------|-------|
| AES-128 (ECB/CBC) | `modern.py` | Full FIPS 197 spec |
| SHA-256 | `hashing.py` | Full FIPS 180-4 spec |
| RSA | `asymmetric.py` | Miller-Rabin primality |

### Cryptanalysis (`cipher_forge/analysis.py`)
- Letter frequency analysis
- Index of Coincidence
- Caesar cipher breaker (frequency analysis)
- Vigenère key length estimation (Kasiski / IOC)

---

## 🚀 Installation

```bash
git clone https://github.com/Abrar892/cipher-forge.git
cd cipher-forge
pip install -e .
```

No external dependencies required — pure Python 3.10+ standard library only.

---

## 💻 Usage

### Python API

```python
from cipher_forge.classical import CaesarCipher, VigenereCipher
from cipher_forge.modern import AES128
from cipher_forge.hashing import SHA256
from cipher_forge.asymmetric import RSA

# Caesar Cipher
caesar = CaesarCipher()
encrypted = caesar.encrypt("Hello, World!", shift=13)
decrypted = caesar.decrypt(encrypted, shift=13)

# Vigenère Cipher
vigenere = VigenereCipher()
enc = vigenere.encrypt("attackatdawn", key="lemon")
dec = vigenere.decrypt(enc, key="lemon")

# AES-128 ECB
aes = AES128()
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
ciphertext = aes.encrypt_ecb(b"My secret message", key)
plaintext = aes.decrypt_ecb(ciphertext, key)

# SHA-256
sha = SHA256()
digest = sha.hash_str("hello")
# → "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# RSA
rsa = RSA()
pub, priv = rsa.generate_keypair(bits=512)
enc_ints = rsa.encrypt_text("Hello", pub)
plaintext = rsa.decrypt_text(enc_ints, priv)
```

### CLI

```bash
# Caesar cipher
cipher-forge caesar encrypt --text "hello" --shift 3
cipher-forge caesar decrypt --text "khoor" --shift 3

# Vigenère cipher
cipher-forge vigenere encrypt --text "hello" --key "key"
cipher-forge vigenere decrypt --text "rijvs" --key "key"

# SHA-256 hash
cipher-forge sha256 --text "hello"

# RSA demonstration
cipher-forge rsa demo

# Frequency analysis
cipher-forge analyze --text "KHOOR ZRUOG"
```

---

## 🎓 Educational Notes

### Why Pure Python?

External cryptography libraries (like `cryptography` or `PyCryptodome`) abstract away implementation details. By implementing everything from scratch, you can:

1. **Understand byte-level operations** — S-Box lookups, XOR mixing, Galois Field arithmetic
2. **See the math behind RSA** — modular exponentiation, Euler's totient, primality testing
3. **Follow SHA-256 step-by-step** — message scheduling, compression rounds, padding rules

### AES-128 Notes

The AES implementation follows FIPS 197:
- **SubBytes**: Non-linear byte substitution using the S-Box
- **ShiftRows**: Cyclic left-shift of rows
- **MixColumns**: Galois Field (GF(2⁸)) matrix multiplication
- **AddRoundKey**: XOR with round key (key schedule via Rijndael key expansion)

### SHA-256 Notes

SHA-256 follows FIPS 180-4:
- 512-bit block processing with 64 rounds
- 8 initial hash values (fractional parts of √prime)
- 64 round constants (fractional parts of ∛prime)
- Bitwise operations: Ch, Maj, Σ0, Σ1, σ0, σ1

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

Expected: **all tests pass**, including NIST AES-128 test vector and SHA-256 known-good hashes.

---

## 📋 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-cipher`
3. Implement your cipher with full docstrings and educational comments
4. Add tests with known test vectors
5. Submit a pull request

Please ensure all tests pass and no external dependencies are added.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for cryptography education. Not for production use.*
