"""
entropy.py — password entropy auditor + HIBP k-anonymity breach check.

This module answers TWO independent questions about a password:

  1. "How strong is this password in the abstract?"  -> entropy_bits()
        Pure math. No network. Implemented in Stage 2 (this stage).

  2. "Has this exact password already leaked?"         -> hibp_pwned_count()
        A network lookup against Have I Been Pwned. Stage 3 (still a stub).

Both matter, and they're independent: "Tr0ub4dor&3" scores OK on (1) but is
famously in breach corpora, so (2) would still flag it. A real auditor needs
both signals.
"""

from __future__ import annotations

import hashlib
import math
import string


# ---------------------------------------------------------------------------
# 1. Entropy scoring  (Stage 2 — implemented)
# ---------------------------------------------------------------------------

def charset_pool_size(password: str) -> int:
    """Return the size of the character 'pool' the password draws from.

    The idea: an attacker brute-forcing doesn't know your password, but they
    can guess which *kinds* of characters you used. Each character CLASS you
    include enlarges the alphabet they must try per position:

        lowercase a-z            -> 26
        uppercase A-Z            -> 26
        digits 0-9               -> 10
        punctuation/symbols      -> 32   (an approximation of the common
                                          shifted-number + symbol keys)

    We detect which classes actually appear and sum only those. So "abc" draws
    from a 26-pool, while "Abc1!" draws from 26+26+10+32 = 94.

    Note: this is the *optimistic* model an attacker uses. It can't know that
    "Password1" is a predictable word+digit, so it overestimates real-world
    strength. That gap is exactly why we ALSO check HIBP in Stage 3.
    """
    pool = 0

    # `any(...)` walks the password once per class and stops early on the first
    # match — we only care whether the class is present at all, not how often.
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10

    # "symbol" = any printable character that isn't a letter, digit, or space.
    # string.punctuation has 32 chars, which is our approximation for the pool.
    symbols = set(string.punctuation)
    if any(c in symbols for c in password):
        pool += 32

    # Anything left over (spaces, accented/Unicode chars, emoji...) still adds
    # uncertainty for an attacker, so give it a small flat bump rather than 0.
    known = set(string.ascii_letters + string.digits) | symbols
    if any(c not in known for c in password):
        pool += 10

    return pool


def entropy_bits(password: str) -> float:
    """Estimate password entropy in BITS.

        bits = length * log2(pool_size)

    Intuition: each of the `length` positions can hold any of `pool_size`
    characters, so the total number of possible passwords is
    pool_size ** length. Entropy is just the log2 of that count — i.e. how
    many yes/no guesses (bits) it takes to cover the whole space.

    THIS is the math behind "length beats complexity":
      - Adding a character class grows `log2(pool)` only a little
        (log2(26)=4.7  ->  log2(94)=6.55, a modest bump).
      - Adding one more character multiplies the WHOLE space by `pool`,
        i.e. adds a full `log2(pool)` bits — every single time.
    So a long all-lowercase passphrase usually beats a short "complex" one.
    """
    if not password:
        return 0.0

    pool = charset_pool_size(password)
    # log2(pool) is the bits contributed per character; times length = total.
    return len(password) * math.log2(pool)


def strength_label(bits: float) -> str:
    """Map an entropy-bit score to a human-readable verdict.

    These thresholds are a common rule-of-thumb scale (documented so the
    judgement is transparent, not magic):

        < 28    very weak    (instantly crackable)
        28-35   weak         (online-guessing risk)
        36-59   reasonable   (ok for low-value accounts)
        60-127  strong       (resists offline cracking for now)
        128+    very strong  (overkill for almost everything)
    """
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 128:
        return "strong"
    return "very strong"


# ---------------------------------------------------------------------------
# 2. HIBP k-anonymity breach check  (Stage 3 — still a stub)
# ---------------------------------------------------------------------------

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def hibp_pwned_count(password: str, *, timeout: float = 5.0) -> int:
    """Return how many times `password` appears in HIBP breaches (0 = clean).

    Implemented in Stage 3. The k-anonymity flow will send ONLY the first 5
    hex chars of the SHA-1 — never the password or full hash.
    """
    raise NotImplementedError("hibp_pwned_count lands in Stage 3")


# ---------------------------------------------------------------------------
# 3. Top-level audit the CLI calls
# ---------------------------------------------------------------------------

def audit(password: str, *, check_hibp: bool = False) -> dict:
    """Run the full audit and return a plain dict for the CLI to format.

    Returning a dict (rather than printing here) keeps this module pure and
    testable: the logic lives here, the presentation lives in hashforge.py.
    That separation is why `identify`/`crack` can reuse the same pattern.
    """
    result = {
        "password_length": len(password),
        "pool_size": charset_pool_size(password),
        "entropy_bits": round(entropy_bits(password), 1),
        "strength": strength_label(entropy_bits(password)),
        # `None` (not 0) means "we didn't check", which the CLI prints
        # differently from "checked, found 0 breaches".
        "pwned_count": None,
    }

    if check_hibp:
        result["pwned_count"] = hibp_pwned_count(password)

    return result
