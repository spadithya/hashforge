"""
crack.py — a thin, friendly wrapper around John the Ripper / Hashcat.

hashforge does NOT crack anything itself. Cracking is just "hash a guess, see
if it matches" repeated billions of times — and john/hashcat already do that
superbly. Our job is purely ergonomic:

    * pick the right format/mode automatically (by reusing `identify`),
    * assemble the fiddly command line for you,
    * run it and report what cracked in a clean summary.

This is also why `crack` is the LAST stage: it leans on `identify` (Stage 4)
to translate a hash into the engine's format flag, and it depends on external
tools being installed.

SAFETY: only run this against hashes you own or are explicitly authorized to
test. Never point it at real breach dumps.
"""

from __future__ import annotations

import shutil
import subprocess

import identify


# Sensible defaults for a Kali box. The wrapper falls back to John's built-in
# list because it's always present (rockyou usually ships gzipped).
#DEFAULT_WORDLIST = "/usr/share/john/password.lst"
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

def _detect_format(hash_file: str) -> dict | None:
    """Peek at the first hash in the file and ask `identify` what it is.

    Returning the whole top candidate (not just a name) gives the caller both
    the john format AND the hashcat mode, so either engine can be configured
    from one detection. Returns None if the file is empty or unrecognized.
    """
    with open(hash_file, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                candidates = identify.identify(line)
                return candidates[0] if candidates else None
    return None


def _build_john_argv(hash_file, *, wordlist, rules, fmt):
    """Assemble the John command for a DICTIONARY attack.

        john --wordlist=<wl> [--rules=<r>] [--format=<f>] <hash_file>

    John can auto-detect many formats, but passing --format removes ambiguity
    (e.g. it won't guess MD5 when you meant raw-md5 vs NTLM).
    """
    argv = ["john", f"--wordlist={wordlist}"]
    if rules:
        argv.append(f"--rules={rules}")
    if fmt:
        argv.append(f"--format={fmt}")
    argv.append(hash_file)
    return argv


def _build_hashcat_argv(hash_file, *, wordlist, rules, mode, mask, hc_mode):
    """Assemble the Hashcat command.

    Hashcat is mode-driven and ALWAYS needs -m <number> (it never guesses):
        dictionary:  hashcat -m <hc_mode> -a 0 <hash_file> <wordlist> [-r <rules>]
        mask:        hashcat -m <hc_mode> -a 3 <hash_file> <mask>
    """
    if hc_mode is None:
        raise ValueError("hashcat needs a -m mode; couldn't determine one for this hash")

    # --force tells hashcat to run despite warnings about unsupported/virtual
    # hardware. It's normally discouraged, but on a GPU-less Kali VM hashcat
    # refuses to start without it. (This box is memory-constrained, so John is
    # the practical engine here — see the Stage 5 notes.)
    argv = ["hashcat", "-m", str(hc_mode), "--force"]
    if mode == "mask":
        if not mask:
            raise ValueError("mask mode needs --mask, e.g. ?u?l?l?l?d?d")
        argv += ["-a", "3", hash_file, mask]
    else:  # dictionary
        argv += ["-a", "0", hash_file, wordlist]
        if rules:
            argv += ["-r", rules]
    return argv


def _show_cracked(engine, hash_file, *, fmt, hc_mode):
    """Ask the engine which hashes are already cracked and parse the results.

    Both tools remember cracked hashes in a 'potfile', and both print them in
    `hash:password` form via a --show flag. We run that AFTER the attack so the
    report is the same whether we just cracked it now or in a previous run.
    """
    if engine == "john":
        argv = ["john", "--show"]
        if fmt:
            argv.append(f"--format={fmt}")
        argv.append(hash_file)
    else:
        argv = ["hashcat", "-m", str(hc_mode), "--show", hash_file]

    out = subprocess.run(argv, capture_output=True, text=True).stdout

    cracked = []
    for line in out.splitlines():
        line = line.strip()
        # Skip blanks and John's trailing summary line ("1 password hash cracked…").
        if not line or "password hash" in line:
            continue
        if ":" in line:
            target, _, password = line.partition(":")
            cracked.append({"hash": target, "password": password})
    return cracked


def crack(hash_file, *, engine="john", wordlist=None, rules=None,
          mode="dict", mask=None) -> dict:
    """Run an external cracker against `hash_file` and summarize what fell.

    Returns a dict:
        {"engine", "format", "attack", "cracked": [{hash, password}], "count"}
    """
    # Fail early with a clear message if the chosen tool isn't installed,
    # rather than letting subprocess raise a cryptic FileNotFoundError.
    if shutil.which(engine) is None:
        raise RuntimeError(f"{engine!r} is not installed or not on PATH")

    wordlist = wordlist or DEFAULT_WORDLIST

    # Reuse Stage 4 to translate the hash into engine-specific identifiers.
    detected = _detect_format(hash_file)
    fmt = detected["john_format"] if detected else None
    hc_mode = detected["hashcat_mode"] if detected else None

    if engine == "john":
        argv = _build_john_argv(hash_file, wordlist=wordlist, rules=rules, fmt=fmt)
    else:
        argv = _build_hashcat_argv(hash_file, wordlist=wordlist, rules=rules,
                                   mode=mode, mask=mask, hc_mode=hc_mode)

    # Stream the cracker's own progress straight to the terminal (no capture),
    # so you see it working in real time — exactly what the demo needs.
    print(f"[hashforge] {' '.join(argv)}\n")
    subprocess.run(argv)

    cracked = _show_cracked(engine, hash_file, fmt=fmt, hc_mode=hc_mode)
    return {
        "engine": engine,
        "format": fmt or (f"-m {hc_mode}" if hc_mode is not None else "unknown"),
        "attack": mode,
        "cracked": cracked,
        "count": len(cracked),
    }
