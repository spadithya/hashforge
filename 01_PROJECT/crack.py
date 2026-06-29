"""
crack.py — thin, friendly wrapper around John the Ripper / Hashcat.

STAGE 3 component — stub for now. Build this last; it depends on `identify`
to pick the right mode/format, and it shells out to external crackers rather
than implementing any cracking itself.

Planned attack modes: dictionary, mask, rule-based.
Planned engines: john (CPU-friendly default), hashcat (GPU).

Safety: only ever run against hashes you own or are authorized to test.
Never auto-download wordlists into the repo (.gitignore blocks them anyway).
"""

from __future__ import annotations


def crack(hash_file: str, *, engine: str = "john", **opts) -> dict:
    """Drive an external cracker and return a summary of what was cracked.

    TODO(stage 3): assemble the argv for john/hashcat from opts (wordlist,
    rules, mask, mode), run it via subprocess, and parse cracked results from
    the potfile / `--show` output. Stream progress to the user.
    """
    raise NotImplementedError
