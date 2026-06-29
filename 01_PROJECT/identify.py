"""
identify.py — guess the algorithm behind an unknown hash string (like hashid).

STAGE 2 component — stub for now. We'll flesh this out after `entropy` works.

The detection strategy is pattern-matching on three signals:
  - prefix / format   ($2a$, $2b$ -> bcrypt; $argon2id$ -> argon2; $6$ -> sha512crypt)
  - length            (32 hex -> MD5 or NTLM; 40 hex -> SHA-1; 64 hex -> SHA-256)
  - charset           (all hex? base64? contains '$' separators?)

Length alone is ambiguous (MD5 vs NTLM are both 32 hex), so candidates are
returned as a ranked list, not a single answer.
"""

from __future__ import annotations


def identify(hash_string: str) -> list[dict]:
    """Return ranked candidate algorithms for `hash_string`.

    Suggested per-candidate shape:
        {"name": "MD5", "confidence": "high|medium|low", "hashcat_mode": 0, "john_format": "raw-md5"}

    TODO(stage 2): build this after the entropy auditor is done.
    """
    raise NotImplementedError
