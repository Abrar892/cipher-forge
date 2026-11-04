"""
modern.py — AES-128 implementation from scratch.

Implements AES-128 (Advanced Encryption Standard) following FIPS 197.
No external libraries. Uses ECB mode with PKCS#7 padding.

AES operates on a 4×4 matrix of bytes (the "state"). Each round applies:
  1. SubBytes   — Non-linear byte substitution via S-Box
  2. ShiftRows  — Cyclic left shift of each row
  3. MixColumns — Galois Field matrix multiplication (skipped in final round)
  4. AddRoundKey — XOR with round key derived from key schedule

AES-128 uses a 128-bit (16-byte) key and performs 10 rounds.
"""


class AES128:
    """
    AES-128 cipher implemented from scratch following FIPS 197.

    Supports:
      - Single block encrypt/decrypt (encrypt_block / decrypt_block)
      - ECB mode with PKCS#7 padding (encrypt_ecb / decrypt_ecb)

    Key must be exactly 16 bytes (128 bits).

    Example:
        >>> aes = AES128()
        >>> key = bytes(range(16))
        >>> ct = aes.encrypt_ecb(b"Hello, World!   ", key)
        >>> aes.decrypt_ecb(ct, key)
        b'Hello, World!   '
    """

    # ------------------------------------------------------------------ #
    #  AES S-Box (forward)
    # ------------------------------------------------------------------ #
    _SBOX = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]

    # ------------------------------------------------------------------ #
    #  AES Inverse S-Box
    # ------------------------------------------------------------------ #
    _INV_SBOX = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
        0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
        0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
        0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
        0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
        0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
        0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
        0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
        0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
        0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
        0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
        0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ]

    # Round constants for key expansion (Rcon), indices 1–10
    _RCON = [
        0x00,  # unused (index 0)
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36,
    ]

    # ------------------------------------------------------------------ #
    #  GF(2^8) arithmetic
    # ------------------------------------------------------------------ #

    @staticmethod
    def _xtime(b: int) -> int:
        """Multiply byte *b* by 2 in GF(2^8) with reduction polynomial x^8+x^4+x^3+x+1."""
        result = (b << 1) & 0xFF
        if b & 0x80:
            result ^= 0x1B
        return result

    @classmethod
    def _gmul(cls, a: int, b: int) -> int:
        """Multiply bytes *a* and *b* in GF(2^8)."""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit:
                a ^= 0x1B
            b >>= 1
        return result

    # ------------------------------------------------------------------ #
    #  State helpers (column-major 4x4 matrix)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _bytes_to_state(b: bytes) -> list[list[int]]:
        """Convert 16 bytes to a 4×4 column-major state matrix."""
        state = [[0] * 4 for _ in range(4)]
        for col in range(4):
            for row in range(4):
                state[row][col] = b[col * 4 + row]
        return state

    @staticmethod
    def _state_to_bytes(state: list[list[int]]) -> bytes:
        """Convert 4×4 column-major state matrix to 16 bytes."""
        result = []
        for col in range(4):
            for row in range(4):
                result.append(state[row][col])
        return bytes(result)

    # ------------------------------------------------------------------ #
    #  AES round operations
    # ------------------------------------------------------------------ #

    def _sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """Apply S-Box substitution to every byte in the state."""
        return [[self._SBOX[state[r][c]] for c in range(4)] for r in range(4)]

    def _inv_sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """Apply inverse S-Box substitution to every byte in the state."""
        return [[self._INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

    @staticmethod
    def _shift_rows(state: list[list[int]]) -> list[list[int]]:
        """
        Cyclically shift row i left by i positions (i = 0, 1, 2, 3).

        Row 0: no shift
        Row 1: shift left by 1
        Row 2: shift left by 2
        Row 3: shift left by 3
        """
        new_state = [row[:] for row in state]
        for r in range(1, 4):
            new_state[r] = state[r][r:] + state[r][:r]
        return new_state

    @staticmethod
    def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
        """Inverse ShiftRows: cyclically shift row i right by i positions."""
        new_state = [row[:] for row in state]
        for r in range(1, 4):
            new_state[r] = state[r][4 - r:] + state[r][:4 - r]
        return new_state

    def _mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """
        Mix each column using the AES MixColumns matrix multiplication in GF(2^8).

        MixColumns matrix:
            [2, 3, 1, 1]
            [1, 2, 3, 1]
            [1, 1, 2, 3]
            [3, 1, 1, 2]
        """
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            new_state[0][c] = self._gmul(col[0], 2) ^ self._gmul(col[1], 3) ^ col[2] ^ col[3]
            new_state[1][c] = col[0] ^ self._gmul(col[1], 2) ^ self._gmul(col[2], 3) ^ col[3]
            new_state[2][c] = col[0] ^ col[1] ^ self._gmul(col[2], 2) ^ self._gmul(col[3], 3)
            new_state[3][c] = self._gmul(col[0], 3) ^ col[1] ^ col[2] ^ self._gmul(col[3], 2)
        return new_state

    def _inv_mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """
        Inverse MixColumns using the inverse AES matrix in GF(2^8).

        Inverse matrix:
            [14, 11, 13,  9]
            [ 9, 14, 11, 13]
            [13,  9, 14, 11]
            [11, 13,  9, 14]
        """
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            new_state[0][c] = (self._gmul(col[0], 14) ^ self._gmul(col[1], 11) ^
                               self._gmul(col[2], 13) ^ self._gmul(col[3], 9))
            new_state[1][c] = (self._gmul(col[0], 9) ^ self._gmul(col[1], 14) ^
                               self._gmul(col[2], 11) ^ self._gmul(col[3], 13))
            new_state[2][c] = (self._gmul(col[0], 13) ^ self._gmul(col[1], 9) ^
                               self._gmul(col[2], 14) ^ self._gmul(col[3], 11))
            new_state[3][c] = (self._gmul(col[0], 11) ^ self._gmul(col[1], 13) ^
                               self._gmul(col[2], 9) ^ self._gmul(col[3], 14))
        return new_state

    @staticmethod
    def _add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
        """XOR the state with the round key."""
        return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

    # ------------------------------------------------------------------ #
    #  Key expansion (Rijndael key schedule for AES-128)
    # ------------------------------------------------------------------ #

    def _key_expansion(self, key_bytes: bytes) -> list[list[list[int]]]:
        """
        Expand a 16-byte (128-bit) key into 11 round key matrices.

        Returns a list of 11 elements, each a 4×4 column-major matrix
        (same layout as the state).
        """
        assert len(key_bytes) == 16, "Key must be exactly 16 bytes"

        # W is a list of 44 4-byte words
        W: list[list[int]] = []
        for i in range(4):
            W.append(list(key_bytes[4 * i:4 * i + 4]))

        for i in range(4, 44):
            temp = W[i - 1][:]
            if i % 4 == 0:
                # RotWord: rotate left by one byte
                temp = temp[1:] + temp[:1]
                # SubWord: apply S-Box
                temp = [self._SBOX[b] for b in temp]
                # XOR with Rcon
                temp[0] ^= self._RCON[i // 4]
            W.append([W[i - 4][j] ^ temp[j] for j in range(4)])

        # Build 11 round key matrices (each is a 4x4 column-major matrix)
        round_keys = []
        for rk in range(11):
            # Round key rk uses words W[4*rk .. 4*rk+3]
            matrix = [[0] * 4 for _ in range(4)]
            for col in range(4):
                for row in range(4):
                    matrix[row][col] = W[4 * rk + col][row]
            round_keys.append(matrix)

        return round_keys

    # ------------------------------------------------------------------ #
    #  Single-block encrypt / decrypt
    # ------------------------------------------------------------------ #

    def encrypt_block(self, plaintext_bytes: bytes, key_bytes: bytes) -> bytes:
        """
        Encrypt a single 16-byte block using AES-128.

        Args:
            plaintext_bytes: Exactly 16 bytes of plaintext.
            key_bytes:       Exactly 16 bytes key.

        Returns:
            16 bytes of ciphertext.
        """
        assert len(plaintext_bytes) == 16
        assert len(key_bytes) == 16

        round_keys = self._key_expansion(key_bytes)
        state = self._bytes_to_state(plaintext_bytes)

        # Initial round key addition
        state = self._add_round_key(state, round_keys[0])

        # Rounds 1–9
        for rnd in range(1, 10):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[rnd])

        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[10])

        return self._state_to_bytes(state)

    def decrypt_block(self, ciphertext_bytes: bytes, key_bytes: bytes) -> bytes:
        """
        Decrypt a single 16-byte block using AES-128.

        Args:
            ciphertext_bytes: Exactly 16 bytes of ciphertext.
            key_bytes:        Exactly 16 bytes key.

        Returns:
            16 bytes of plaintext.
        """
        assert len(ciphertext_bytes) == 16
        assert len(key_bytes) == 16

        round_keys = self._key_expansion(key_bytes)
        state = self._bytes_to_state(ciphertext_bytes)

        # Initial round key addition (reverse order)
        state = self._add_round_key(state, round_keys[10])

        # Rounds 9–1
        for rnd in range(9, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, round_keys[rnd])
            state = self._inv_mix_columns(state)

        # Final round
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, round_keys[0])

        return self._state_to_bytes(state)

    # ------------------------------------------------------------------ #
    #  PKCS#7 padding
    # ------------------------------------------------------------------ #

    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        """Add PKCS#7 padding to *data* to align to *block_size* bytes."""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        """Remove PKCS#7 padding from *data*."""
        if not data:
            raise ValueError("Empty data")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid PKCS#7 padding")
        return data[:-pad_len]

    # ------------------------------------------------------------------ #
    #  ECB mode
    # ------------------------------------------------------------------ #

    def encrypt_ecb(self, data_bytes: bytes, key_bytes: bytes) -> bytes:
        """
        Encrypt *data_bytes* in AES-128 ECB mode.

        Applies PKCS#7 padding then encrypts each 16-byte block independently.

        Args:
            data_bytes: Plaintext of arbitrary length.
            key_bytes:  16-byte AES key.

        Returns:
            Ciphertext bytes (length is a multiple of 16).
        """
        padded = self._pkcs7_pad(data_bytes)
        result = bytearray()
        for i in range(0, len(padded), 16):
            block = padded[i:i + 16]
            result.extend(self.encrypt_block(bytes(block), key_bytes))
        return bytes(result)

    def decrypt_ecb(self, data_bytes: bytes, key_bytes: bytes) -> bytes:
        """
        Decrypt *data_bytes* in AES-128 ECB mode.

        Decrypts each 16-byte block then removes PKCS#7 padding.

        Args:
            data_bytes: Ciphertext (must be a multiple of 16 bytes).
            key_bytes:  16-byte AES key.

        Returns:
            Original plaintext bytes.
        """
        if len(data_bytes) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16 bytes")
        result = bytearray()
        for i in range(0, len(data_bytes), 16):
            block = data_bytes[i:i + 16]
            result.extend(self.decrypt_block(bytes(block), key_bytes))
        return self._pkcs7_unpad(bytes(result))
