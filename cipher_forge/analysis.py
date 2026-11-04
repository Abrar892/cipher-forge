"""
analysis.py — Cryptanalysis helpers.

Implements:
  - letter_frequency           : Count letter occurrences in text
  - index_of_coincidence       : Statistical measure of letter distribution
  - crack_caesar               : Break Caesar cipher using frequency analysis
  - estimate_vigenere_key_length : Estimate Vigenère key length via IOC method
"""

# Standard English letter frequencies (percent), A–Z
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253,
    'e': 12.702, 'f': 2.228, 'g': 2.015, 'h': 6.094,
    'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929,
    'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074,
}


def letter_frequency(text: str) -> dict[str, int]:
    """
    Count letter occurrences in *text* (case-insensitive, letters only).

    Returns a dict mapping lowercase letters to their counts.
    Letters not present in *text* are omitted from the result.

    Example:
        >>> letter_frequency("Hello")
        {'h': 1, 'e': 1, 'l': 2, 'o': 1}
    """
    freq: dict[str, int] = {}
    for ch in text.lower():
        if ch.isalpha():
            freq[ch] = freq.get(ch, 0) + 1
    return freq


def index_of_coincidence(text: str) -> float:
    """
    Compute the Index of Coincidence (IOC) for *text*.

    IOC = Σ(f_i * (f_i - 1)) / (N * (N - 1))

    where f_i is the count of letter i and N is the total letter count.

    Random text → IOC ≈ 0.038; English text → IOC ≈ 0.065.

    Returns 0.0 if the text has fewer than 2 letters.
    """
    freq = letter_frequency(text)
    n = sum(freq.values())
    if n < 2:
        return 0.0

    numerator = sum(f * (f - 1) for f in freq.values())
    return numerator / (n * (n - 1))


def crack_caesar(ciphertext: str) -> tuple[int, str]:
    """
    Break a Caesar cipher using chi-squared frequency analysis.

    For each of the 26 possible shifts, compute the chi-squared statistic
    comparing the decrypted letter distribution to standard English
    frequencies. Return (best_shift, decrypted_text).

    Example:
        >>> crack_caesar("khoor")
        (3, 'hello')
    """
    from cipher_forge.classical import CaesarCipher

    caesar = CaesarCipher()
    letters_only = [ch.lower() for ch in ciphertext if ch.isalpha()]
    n = len(letters_only)

    if n == 0:
        return (0, ciphertext)

    best_shift = 0
    best_score = float('inf')

    for shift in range(26):
        decrypted = caesar.decrypt(ciphertext, shift)
        freq = letter_frequency(decrypted)

        # Chi-squared statistic: measures fit to English distribution
        chi_sq = 0.0
        for letter in 'abcdefghijklmnopqrstuvwxyz':
            observed = freq.get(letter, 0)
            expected = ENGLISH_FREQ[letter] / 100.0 * n
            if expected > 0:
                chi_sq += (observed - expected) ** 2 / expected

        if chi_sq < best_score:
            best_score = chi_sq
            best_shift = shift

    return (best_shift, caesar.decrypt(ciphertext, best_shift))


def estimate_vigenere_key_length(ciphertext: str, max_len: int = 20) -> int:
    """
    Estimate the key length of a Vigenère-encrypted ciphertext.

    Uses the Index of Coincidence method: for each candidate key length k,
    split the ciphertext into k subsequences (every k-th character) and
    compute the average IOC. The key length whose average IOC is closest
    to the English IOC (≈ 0.065) is returned.

    Returns the estimated key length (1 ≤ result ≤ max_len).
    """
    # Keep only alphabetic characters
    letters = [ch for ch in ciphertext.lower() if ch.isalpha()]
    n = len(letters)

    if n == 0:
        return 1

    ENGLISH_IOC = 0.065
    best_len = 1
    best_diff = float('inf')

    for key_len in range(1, min(max_len, n) + 1):
        # Split into key_len subsequences
        subsequences = [''.join(letters[i::key_len]) for i in range(key_len)]
        avg_ioc = sum(index_of_coincidence(seq) for seq in subsequences) / key_len

        diff = abs(avg_ioc - ENGLISH_IOC)
        if diff < best_diff:
            best_diff = diff
            best_len = key_len

    return best_len
