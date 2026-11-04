"""
classical.py — Classical cipher implementations.

Implements:
  - CaesarCipher      : Simple shift cipher (monoalphabetic substitution)
  - VigenereCipher    : Polyalphabetic substitution using a repeating keyword
  - RailFenceCipher   : Zigzag transposition cipher
  - ColumnarTransposition : Columnar transposition cipher

All ciphers preserve non-alphabetic characters unchanged (unless noted).
"""


class CaesarCipher:
    """
    Caesar (shift) cipher.

    Each letter is shifted by a fixed amount in the alphabet.
    Uppercase and lowercase are preserved. Non-alpha chars are unchanged.

    Example:
        >>> c = CaesarCipher()
        >>> c.encrypt("hello", 3)
        'khoor'
        >>> c.decrypt("khoor", 3)
        'hello'
    """

    def encrypt(self, text: str, shift: int) -> str:
        """Encrypt *text* by shifting each letter forward by *shift* positions."""
        shift = shift % 26
        result = []
        for ch in text:
            if ch.isupper():
                result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            elif ch.islower():
                result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(ch)
        return ''.join(result)

    def decrypt(self, text: str, shift: int) -> str:
        """Decrypt *text* by shifting each letter backward by *shift* positions."""
        return self.encrypt(text, -shift)

    def brute_force(self, ciphertext: str) -> list[tuple[int, str]]:
        """
        Try all 26 possible shifts and return a list of (shift, decrypted_text) tuples.

        The list is ordered from shift 0 to shift 25.
        """
        return [(shift, self.decrypt(ciphertext, shift)) for shift in range(26)]


class VigenereCipher:
    """
    Vigenère cipher — polyalphabetic substitution.

    The keyword is repeated cyclically and each letter is shifted by the
    corresponding key letter's position in the alphabet (A=0, B=1, …, Z=25).
    Non-alphabetic characters in the plaintext are passed through unchanged;
    the key index only advances on alphabetic characters.

    Example:
        >>> v = VigenereCipher()
        >>> v.encrypt("attackatdawn", "lemon")
        'lxfopvefrnhr'
    """

    def _process(self, text: str, key: str, decrypt: bool = False) -> str:
        key = key.lower()
        key_len = len(key)
        result = []
        key_idx = 0

        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                key_shift = ord(key[key_idx % key_len]) - ord('a')
                if decrypt:
                    key_shift = -key_shift
                result.append(chr((ord(ch) - base + key_shift) % 26 + base))
                key_idx += 1
            else:
                result.append(ch)

        return ''.join(result)

    def encrypt(self, text: str, key: str) -> str:
        """Encrypt *text* using Vigenère cipher with *key*."""
        return self._process(text, key, decrypt=False)

    def decrypt(self, text: str, key: str) -> str:
        """Decrypt *text* using Vigenère cipher with *key*."""
        return self._process(text, key, decrypt=True)


class RailFenceCipher:
    """
    Rail-Fence (zigzag) transposition cipher.

    Characters are written diagonally across *rails* rows, then read off
    row by row to produce the ciphertext.

    Example (3 rails)::

        h . . . o . . . l .
        . e . l . . w . r . d
        . . l . . o . . . !

        → "holelwrdlo!"  (read row by row)

    Example:
        >>> r = RailFenceCipher()
        >>> r.encrypt("HELLO WORLD", 3)
        'HOLELWRDLO '  # spaces included
    """

    def _get_rail_pattern(self, length: int, rails: int) -> list[int]:
        """Return a list mapping each character position to its rail index."""
        pattern = []
        rail = 0
        direction = 1  # 1 = going down, -1 = going up

        for _ in range(length):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        return pattern

    def encrypt(self, text: str, rails: int) -> str:
        """Encrypt *text* with Rail-Fence cipher using *rails* rails."""
        if rails < 2:
            return text

        pattern = self._get_rail_pattern(len(text), rails)
        # Group characters by their rail
        fence = [[] for _ in range(rails)]
        for idx, ch in enumerate(text):
            fence[pattern[idx]].append(ch)

        return ''.join(''.join(row) for row in fence)

    def decrypt(self, text: str, rails: int) -> str:
        """Decrypt Rail-Fence ciphertext with *rails* rails."""
        if rails < 2:
            return text

        n = len(text)
        pattern = self._get_rail_pattern(n, rails)

        # Count characters per rail
        rail_lengths = [0] * rails
        for r in pattern:
            rail_lengths[r] += 1

        # Split ciphertext into rail segments
        fence = []
        idx = 0
        for length in rail_lengths:
            fence.append(list(text[idx:idx + length]))
            idx += length

        # Read off in original order
        rail_indices = [0] * rails
        result = []
        for r in pattern:
            result.append(fence[r][rail_indices[r]])
            rail_indices[r] += 1

        return ''.join(result)


class ColumnarTransposition:
    """
    Columnar Transposition cipher.

    The plaintext is written row-by-row into a grid whose width is
    determined by the length of *key_word*. Columns are then read out in
    alphabetical order of the keyword letters.

    Padding character: 'X' (added if the last row is incomplete).

    Example:
        >>> ct = ColumnarTransposition()
        >>> ct.encrypt("WEAREDISCOVEREDRUNATONCE", "ZEBRAS")
        'EVLNACDTESEAROFODEECWIREE'
    """

    def _get_column_order(self, key_word: str) -> list[int]:
        """
        Return the column read-out order based on alphabetical sort of *key_word*.

        E.g. key "KEY" → sorted chars are E(1), K(0), Y(2)
             so column order = [1, 0, 2]
        """
        indexed = sorted(enumerate(key_word.upper()), key=lambda x: x[1])
        return [i for i, _ in indexed]

    def encrypt(self, text: str, key_word: str) -> str:
        """Encrypt *text* with columnar transposition using *key_word*."""
        num_cols = len(key_word)
        # Pad text so it fills the grid completely
        pad_len = (num_cols - len(text) % num_cols) % num_cols
        padded = text + 'X' * pad_len

        num_rows = len(padded) // num_cols
        # Build grid
        grid = [list(padded[r * num_cols:(r + 1) * num_cols]) for r in range(num_rows)]

        order = self._get_column_order(key_word)
        result = []
        for col in order:
            for row in grid:
                result.append(row[col])

        return ''.join(result)

    def decrypt(self, text: str, key_word: str) -> str:
        """Decrypt columnar transposition ciphertext using *key_word*."""
        num_cols = len(key_word)
        num_rows = len(text) // num_cols

        order = self._get_column_order(key_word)

        # Build grid column by column in sorted order
        grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        idx = 0
        for col in order:
            for row in range(num_rows):
                grid[row][col] = text[idx]
                idx += 1

        return ''.join(''.join(row) for row in grid)
