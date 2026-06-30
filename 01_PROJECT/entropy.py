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

    THE PRIVACY PROBLEM: we want to ask HIBP "is my password breached?"
    without telling HIBP (or any eavesdropper) what the password is — or even
    its full hash, since a full SHA-1 of a weak password is itself crackable.

    THE SOLUTION — k-anonymity (a.k.a. the "range" API):
      1. SHA-1 the password locally and uppercase the hex digest.
      2. Split it: the first 5 chars are the PREFIX, the rest is the SUFFIX.
      3. Send ONLY the 5-char prefix to HIBP.
      4. HIBP replies with EVERY breached suffix that shares that prefix
         (typically ~300-800 of them), each with a breach count.
      5. We search that list LOCALLY for our suffix.

    Because ~800 different passwords share any given 5-char prefix, HIBP can't
    tell which one is ours — we're hidden in a crowd of `k` look-alikes. The
    full hash never leaves the machine; the password certainly doesn't.
    This privacy guarantee is non-negotiable for hashforge (see CLAUDE.md).
    """
    # Lazy import: `requests` is only needed for this online check. Importing
    # it here (not at module top) means the offline entropy scoring still
    # works even if `requests` isn't installed.
    import requests

    # Step 1: SHA-1 of the UTF-8 bytes, as uppercase hex. HIBP's API speaks
    # uppercase hex, so we match that to compare strings directly.
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # Step 2: split into the part we send vs the part we keep.
    prefix, suffix = sha1[:5], sha1[5:]

    # Step 3: ask HIBP for everything under this prefix. Only `prefix` (5 hex
    # chars) is ever transmitted.
    resp = requests.get(HIBP_RANGE_URL.format(prefix=prefix), timeout=timeout)
    resp.raise_for_status()  # turn an HTTP 4xx/5xx into a clear exception

    # Step 4 + 5: the body is plain text, one "SUFFIX:COUNT" per line, e.g.
    #     0018A45C4D1DEF81644B54AB7F969B88D65:1
    #     00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
    # We scan locally for our suffix and return its count.
    for line in resp.text.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix == suffix:
            return int(count)

    # Our suffix wasn't in the list -> this password isn't in any HIBP breach.
    return 0


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
