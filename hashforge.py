#!/usr/bin/env python3
"""
hashforge — password auditor + hash identifier + cracking harness.

    hashforge entropy  <password> [--hibp]
    hashforge identify <hash>
    hashforge crack    <hash_file> [options]

SCAFFOLD NOTE: the argparse plumbing below is wired up for you. The handler
bodies are yours to write (start with cmd_entropy). The real logic lives in
the sibling modules — keep this file thin: parse args, call the module,
print the result.
"""

from __future__ import annotations

import argparse
import sys

import entropy
import identify
import crack


# --- subcommand handlers ----------------------------------------------------

def cmd_entropy(args: argparse.Namespace) -> int:
    """Audit a password's strength and print a readable report.

    This handler stays THIN on purpose: it asks entropy.audit() for the facts
    (a dict) and is responsible only for turning that dict into nice output.
    Logic in the module, presentation here.
    """
    # Always compute the OFFLINE score first (this can't fail / needs no
    # network), so a flaky --hibp lookup never robs us of the entropy report.
    report = entropy.audit(args.password, check_hibp=False)

    # A small aligned key/value report. `:>13` right-pads the labels so the
    # values line up in a column regardless of label length.
    print(f"{'length':>13} : {report['password_length']}")
    print(f"{'char pool':>13} : {report['pool_size']}")
    print(f"{'entropy':>13} : {report['entropy_bits']} bits")
    print(f"{'strength':>13} : {report['strength']}")

    if not args.hibp:
        print(f"{'breached':>13} : (not checked — pass --hibp)")
        return 0

    # --hibp was requested: do the network lookup in isolation so we can show
    # a clean message if the request fails (offline, timeout, requests missing)
    # instead of dumping a stack trace at the user.
    try:
        count = entropy.hibp_pwned_count(args.password)
    except Exception as exc:  # noqa: BLE001 — any failure here is non-fatal
        print(f"{'breached':>13} : (check failed: {exc})")
        return 0

    if count == 0:
        print(f"{'breached':>13} : no — not found in HIBP")
    else:
        print(f"{'breached':>13} : YES — seen {count:,} times")

    return 0


def cmd_identify(args: argparse.Namespace) -> int:
    """Print ranked algorithm guesses for a hash string."""
    candidates = identify.identify(args.hash)

    if not candidates:
        print("no match — unrecognized hash format", file=sys.stderr)
        return 1

    # Header row, then one line per candidate. We show the cracking IDs too so
    # this output flows straight into Stage 5 (`crack`).
    print(f"{'algorithm':<14} {'confidence':<11} {'hashcat -m':<11} john --format")
    print("-" * 56)
    for c in candidates:
        mode = "-" if c["hashcat_mode"] is None else c["hashcat_mode"]
        print(f"{c['name']:<14} {c['confidence']:<11} {str(mode):<11} {c['john_format']}")

    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    """Drive John/Hashcat against a hash file and report what cracked."""
    try:
        result = crack.crack(
            args.hash_file,
            engine=args.engine,
            wordlist=args.wordlist,
            rules=args.rules,
            mode=args.mode,
            mask=args.mask,
        )
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"crack failed: {exc}", file=sys.stderr)
        return 1

    # Summary after the engine's own live output.
    print(f"\n[hashforge] engine={result['engine']}  format={result['format']}  "
          f"attack={result['attack']}")
    if result["count"] == 0:
        print("[hashforge] nothing cracked — try a bigger wordlist or rules")
        return 1

    print(f"[hashforge] cracked {result['count']}:")
    for item in result["cracked"]:
        print(f"    {item['hash']}  ->  {item['password']}")
    return 0


# --- argument parser --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashforge",
        description="Password auditor, hash identifier, and cracking harness!",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_entropy = sub.add_parser("entropy", help="audit a password's strength")
    p_entropy.add_argument("password", help="the password to audit")
    p_entropy.add_argument(
        "--hibp", action="store_true",
        help="also check Have I Been Pwned (k-anonymity: only 5 hash chars sent)",
    )
    p_entropy.set_defaults(func=cmd_entropy)

    p_identify = sub.add_parser("identify", help="guess a hash's algorithm")
    p_identify.add_argument("hash", help="the hash string to identify")
    p_identify.set_defaults(func=cmd_identify)

    p_crack = sub.add_parser("crack", help="drive John/Hashcat against a hash file")
    p_crack.add_argument("hash_file", help="file containing hashes to crack")
    p_crack.add_argument("--wordlist", help="path to a wordlist")
    p_crack.add_argument("--rules", help="rule preset (e.g. best64)")
    p_crack.add_argument("--mode", choices=["dict", "mask"], default="dict")
    p_crack.add_argument("--mask", help="mask pattern, e.g. ?u?l?l?l?d?d")
    p_crack.add_argument("--engine", choices=["john", "hashcat"], default="john")
    p_crack.set_defaults(func=cmd_crack)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
