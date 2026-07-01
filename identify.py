"""
identify.py — guess the algorithm behind an unknown hash string (like hashid).

THE CORE TENSION: a hash is just a string of characters. Nothing in
"5f4dcc3b5aa765d61d8327deb882cf99" *says* "I am MD5". We can only reason from
three observable signals:

    1. STRUCTURE / PREFIX  — some schemes self-label. Anything starting with
       "$2b$" is bcrypt; "$6$" is sha512crypt. These are nearly unambiguous.
    2. LENGTH              — a bare hex digest's length narrows the field
       (32 hex chars -> a 128-bit hash like MD5).
    3. CHARSET            — all hex? base64? contains "$" separators?

The catch: LENGTH ALONE IS AMBIGUOUS. MD5 and NTLM are *both* 32 hex chars and
indistinguishable by inspection — only context (a Windows SAM dump vs a web
app DB) tells them apart. So `identify()` returns a RANKED LIST of candidates
with confidence levels, never a single false-certain answer. That honesty is
the whole point of the tool.

Each candidate also carries the IDs you'll need in Stage 5 (cracking):
`hashcat_mode` (the -m number) and `john_format` (the --format= name).
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# 1. Structured ("self-labeling") hashes — matched by prefix.
# ---------------------------------------------------------------------------
# These use Modular Crypt Format: $id$params$salt$digest. The leading $id$
# identifies the scheme outright, so confidence is "high". Order doesn't
# matter here because prefixes are mutually exclusive.
#
# Each entry: (prefix it starts with, human name, hashcat -m mode, john format)
_PREFIX_SIGNATURES = [
    ("$2a$",       "bcrypt",          3200,  "bcrypt"),
    ("$2b$",       "bcrypt",          3200,  "bcrypt"),
    ("$2y$",       "bcrypt",          3200,  "bcrypt"),
    ("$argon2id$", "argon2id",        None,  "argon2"),   # hashcat support varies
    ("$argon2i$",  "argon2i",         None,  "argon2"),
    ("$argon2d$",  "argon2d",         None,  "argon2"),
    ("$6$",        "sha512crypt",     1800,  "sha512crypt"),
    ("$5$",        "sha256crypt",     7400,  "sha256crypt"),
    ("$1$",        "md5crypt",         500,  "md5crypt"),
    ("$y$",        "yescrypt",        None,  "crypt"),
    ("{SSHA}",     "LDAP SSHA",        111,  "ssha"),
]


# ---------------------------------------------------------------------------
# 2. Bare hex digests — matched by length (after confirming it's all hex).
# ---------------------------------------------------------------------------
# Keyed by character length. The VALUE is a list of candidates ranked best
# guess first. Where a length is ambiguous, we list every plausible scheme and
# lean on the confidence field to express the uncertainty.
#
# Each candidate: (name, confidence, hashcat -m mode, john format)
_HEX_LENGTH_CANDIDATES = {
    32: [
        ("MD5",  "high",   0,    "raw-md5"),
        ("NTLM", "medium", 1000, "nt"),       # same length as MD5 — context decides
        ("MD4",  "low",    900,  "raw-md4"),
    ],
    40: [
        ("SHA-1",      "high", 100,  "raw-sha1"),
        ("RIPEMD-160", "low",  6000, "ripemd-160"),
    ],
    56: [
        ("SHA-224", "high", 1300, "raw-sha224"),
    ],
    64: [
        ("SHA-256", "high",   1400, "raw-sha256"),
        ("SHA3-256","low",    17600,"raw-sha3-256"),
    ],
    96: [
        ("SHA-384", "high", 10800, "raw-sha384"),
    ],
    128: [
        ("SHA-512", "high", 1700,  "raw-sha512"),
        ("Whirlpool","low", 6100,  "whirlpool"),
    ],
}

# Pre-compiled test for "is this string nothing but hex digits?"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _candidate(name, confidence, hashcat_mode, john_format):
    """Tiny helper to keep the candidate dict shape consistent everywhere."""
    return {
        "name": name,
        "confidence": confidence,
        "hashcat_mode": hashcat_mode,
        "john_format": john_format,
    }


def identify(hash_string: str) -> list[dict]:
    """Return a ranked list of candidate algorithms for `hash_string`.

    Empty list = "I don't recognize this." Best guess is always first.
    """
    h = hash_string.strip()

    # --- Signal 1: structured prefixes win outright (high confidence). ------
    # We check these FIRST because a "$..." string is never a bare hex digest,
    # so a prefix match is decisive.
    for prefix, name, mode, jfmt in _PREFIX_SIGNATURES:
        if h.startswith(prefix):
            return [_candidate(name, "high", mode, jfmt)]

    # --- Signals 2 + 3: bare hex digest, classified by length. --------------
    # Only meaningful if the WHOLE string is hex (charset check), otherwise a
    # 32-char base64 blob would be misread as MD5.
    if _HEX_RE.match(h):
        candidates = _HEX_LENGTH_CANDIDATES.get(len(h))
        if candidates:
            return [_candidate(*c) for c in candidates]

    # --- Nothing matched. -----------------------------------------------------
    return []
