"""CLI entry point for cipher-forge."""
import argparse
import sys
from cipher_forge.classical import CaesarCipher, VigenereCipher
from cipher_forge.modern import AES128
from cipher_forge.hashing import SHA256
from cipher_forge.asymmetric import RSA
from cipher_forge.analysis import FrequencyAnalyzer


def main():
    parser = argparse.ArgumentParser(description="CipherForge - Educational Cryptography Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Caesar
    caesar_p = subparsers.add_parser("caesar")
    caesar_p.add_argument("mode", choices=["encrypt", "decrypt", "crack"])
    caesar_p.add_argument("--text", required=True)
    caesar_p.add_argument("--shift", type=int, default=3)

    # Vigenere
    vig_p = subparsers.add_parser("vigenere")
    vig_p.add_argument("mode", choices=["encrypt", "decrypt"])
    vig_p.add_argument("--text", required=True)
    vig_p.add_argument("--key", required=True)

    # SHA256
    sha_p = subparsers.add_parser("sha256")
    sha_p.add_argument("--text", required=True)

    # RSA demo
    subparsers.add_parser("rsa-demo")

    args = parser.parse_args()

    if args.command == "caesar":
        c = CaesarCipher()
        if args.mode == "encrypt":
            print(c.encrypt(args.text, args.shift))
        elif args.mode == "decrypt":
            print(c.decrypt(args.text, args.shift))
        elif args.mode == "crack":
            shift, decrypted = c.crack(args.text)
            print(f"Detected shift: {shift}\nPlaintext: {decrypted}")

    elif args.command == "vigenere":
        v = VigenereCipher()
        if args.mode == "encrypt":
            print(v.encrypt(args.text, args.key))
        else:
            print(v.decrypt(args.text, args.key))

    elif args.command == "sha256":
        print(SHA256.hash_str(args.text))

    elif args.command == "rsa-demo":
        pub, priv = RSA.generate_keypair(bits=32)
        msg = "HELLO RSA"
        enc = RSA.encrypt_text(msg, pub)
        dec = RSA.decrypt_text(enc, priv)
        print(f"Public Key: {pub}\nOriginal: {msg}\nEncrypted: {enc}\nDecrypted: {dec}")


if __name__ == "__main__":
    main()
