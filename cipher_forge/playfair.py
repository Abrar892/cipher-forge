"""playfair.py — Playfair cipher implementation for cipher-forge.

The Playfair cipher is a digraph substitution cipher using a 5×5 key square.
It treats I and J as the same letter. Non-alpha characters are stripped before
encryption; decryption returns cleaned alpha text.

Reference: https://en.wikipedia.org/wiki/Playfair_cipher
"""

from __future__ import annotations
import re
from typing import List, Tuple


class PlayfairCipher:
    """
    Playfair cipher over a 5×5 key square (I=J substitution).

    Usage::

        pf = PlayfairCipher()
        ct = pf.encrypt("Hide the gold in the tree stump", "PLAYFAIR EXAMPLE")
        pt = pf.decrypt(ct, "PLAYFAIR EXAMPLE")
    """

    SIZE = 5

    # ------------------------------------------------------------------
    # Key-square construction
    # ------------------------------------------------------------------

    def _make_square(self, key: str) -> List[List[str]]:
        """Build a 5×5 Playfair key square from *key*."""
        seen: set[str] = set()
        sequence: List[str] = []

        for ch in (key + "ABCDEFGHIKLMNOPQRSTUVWXYZ"):
            ch = ch.upper()
            if ch == "J":
                ch = "I"
            if ch.isalpha() and ch not in seen:
                seen.add(ch)
                sequence.append(ch)

        square = [sequence[i * self.SIZE:(i + 1) * self.SIZE]
                  for i in range(self.SIZE)]
        return square

    def _index_map(self, square: List[List[str]]) -> dict[str, Tuple[int, int]]:
        return {square[r][c]: (r, c)
                for r in range(self.SIZE)
                for c in range(self.SIZE)}

    # ------------------------------------------------------------------
    # Text preparation
    # ------------------------------------------------------------------

    def _prepare(self, text: str) -> str:
        """Strip non-alpha, uppercase, replace J→I, insert X between doubles."""
        text = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
        result: List[str] = []
        i = 0
        while i < len(text):
            a = text[i]
            result.append(a)
            if i + 1 < len(text):
                b = text[i + 1]
                if a == b:
                    result.append("X")  # split double letters
                    i += 1
                    continue
            i += 1

        if len(result) % 2 != 0:
            result.append("X")  # pad to even length

        return "".join(result)

    def _make_pairs(self, text: str) -> List[Tuple[str, str]]:
        return [(text[i], text[i + 1]) for i in range(0, len(text), 2)]

    # ------------------------------------------------------------------
    # Core encryption / decryption
    # ------------------------------------------------------------------

    def _process_pair(
        self,
        a: str,
        b: str,
        square: List[List[str]],
        idx: dict[str, Tuple[int, int]],
        encrypt: bool,
    ) -> Tuple[str, str]:
        ra, ca = idx[a]
        rb, cb = idx[b]
        shift = 1 if encrypt else -1

        if ra == rb:
            # Same row → shift columns
            return (
                square[ra][(ca + shift) % self.SIZE],
                square[rb][(cb + shift) % self.SIZE],
            )
        elif ca == cb:
            # Same column → shift rows
            return (
                square[(ra + shift) % self.SIZE][ca],
                square[(rb + shift) % self.SIZE][cb],
            )
        else:
            # Rectangle → swap columns
            return square[ra][cb], square[rb][ca]

    def encrypt(self, plaintext: str, key: str) -> str:
        """Encrypt *plaintext* using Playfair with *key*. Returns uppercase ciphertext."""
        square = self._make_square(key)
        idx = self._index_map(square)
        prepared = self._prepare(plaintext)
        pairs = self._make_pairs(prepared)
        result = []
        for a, b in pairs:
            ca, cb = self._process_pair(a, b, square, idx, encrypt=True)
            result.extend([ca, cb])
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt *ciphertext* using Playfair with *key*. Returns uppercase plaintext."""
        square = self._make_square(key)
        idx = self._index_map(square)
        ciphertext = re.sub(r"[^A-Za-z]", "", ciphertext).upper().replace("J", "I")
        pairs = self._make_pairs(ciphertext)
        result = []
        for a, b in pairs:
            pa, pb = self._process_pair(a, b, square, idx, encrypt=False)
            result.extend([pa, pb])
        return "".join(result)

    def show_square(self, key: str) -> str:
        """Return a printable 5×5 key square string."""
        square = self._make_square(key)
        return "\n".join(" ".join(row) for row in square)
