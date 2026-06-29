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
    report = entropy.audit(args.password, check_hibp=args.hibp)

    # A small aligned key/value report. `:>13` right-pads the labels so the
    # values line up in a column regardless of label length.
    print(f"{'length':>13} : {report['password_length']}")
    print(f"{'char pool':>13} : {report['pool_size']}")
    print(f"{'entropy':>13} : {report['entropy_bits']} bits")
    print(f"{'strength':>13} : {report['strength']}")

    # pwned_count is None when --hibp wasn't passed (Stage 3 wires the real
    # lookup). We branch on the three meaningful states.
    if report["pwned_count"] is None:
        print(f"{'breached':>13} : (not checked — pass --hibp)")
    elif report["pwned_count"] == 0:
        print(f"{'breached':>13} : no — not found in HIBP")
    else:
        print(f"{'breached':>13} : YES — seen {report['pwned_count']:,} times")

    return 0


def cmd_identify(args: argparse.Namespace) -> int:
    # Stage 2 — leave until entropy works.
    print("identify: not built yet (stage 2)", file=sys.stderr)
    return 1


def cmd_crack(args: argparse.Namespace) -> int:
    # Stage 3 — leave until identify works.
    print("crack: not built yet (stage 3)", file=sys.stderr)
    return 1


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
