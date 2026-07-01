# 00 · Prime — Orientation Before Building

> Goal of this stage: get familiar with the topic landscape *before* writing code. What is it, why does it exist, where does it sit in the stack, what tools already do this? No hands-on yet — just orientation.

---

## Read / watch list

- [x] **Computerphile · Hashing Algorithms and Security** (~8 min, YouTube) — what a hash function IS and what it isn't.
- [x] **Computerphile · Password Cracking** (~20 min, YouTube) — Mike Pound on how the actual attacks work.
- [x] **"How NOT to store passwords"** — read any modern article comparing MD5/SHA → bcrypt → scrypt → argon2. Goal: understand *why* you'd pick one over another.
- [x] **Have I Been Pwned API docs** — read the section on the **k-anonymity model**. You should be able to explain how HIBP knows your password is breached without ever seeing it.
- [x] **Browse:** the top of the Hashcat `--help` output. Note the `-m` mode list. You don't need to memorize anything — just see the shape.
- [x] **Run once:** `echo -n "password" | md5sum` — eyeball what a hash looks like coming out of a real tool.

## Questions to keep in mind while reading

These don't need answers yet — they should be live in your head while you read so the right ideas stick.

1. What's the difference between a **hash function** (one-way) and **encryption** (reversible)? Why does it matter for passwords?
2. Why are MD5 and SHA-1 "dead for passwords" but still fine for file integrity checks?
3. What does **salting** actually protect against, and what does it NOT protect against?
4. How does HIBP's k-anonymity model let you check a password without uploading it?
5. Why is a GPU so much faster than a CPU at cracking — and why is bcrypt designed to resist that?

## Tool landscape (just be aware these exist)

| Tool | What it is |
|---|---|
| `john` (John the Ripper) | The classic password cracker. Flexible, scriptable, CPU-friendly. |
| `hashcat` | The modern GPU-accelerated cracker. Faster, more cryptic UX. |
| `hashid` / `hash-identifier` | Tells you what algorithm a hash string probably uses. |
| HIBP API | Lookup service for ~13 billion breached passwords (k-anonymity model). |
| `rockyou.txt` | The classic wordlist. Lives at `/usr/share/wordlists/rockyou.txt` on Kali. |
| `mkpasswd` / `openssl passwd` | Quickly generate test hashes in different algorithms. |
| `python -c "import bcrypt"` | Build your own test fixtures from inside the tool. |

## Concepts you'll meet again

- **Salt** — random per-password input that defeats rainbow tables.
- **Pepper** — server-side secret added to every hash; not in the DB.
- **Cost factor** (bcrypt `$2a$10$...`) — exponential slowdown knob.
- **Work factor** / **memory hardness** (argon2) — same idea, modernized.
- **Mask attack** — brute force constrained to a pattern (`?u?l?l?l?d?d`).
- **Rules** (John/Hashcat) — programmatic mutations of a wordlist (`password` → `Password1!`, `p@ssw0rd`, etc.).
- **Potfile** — the cracker's record of already-cracked hashes. Don't commit it.

## What you should NOT be doing yet

- Writing code
- Downloading wordlists into the repo
- Trying to crack real-world hash dumps

Done with this file when every checkbox is ticked and you can answer the 5 questions above out loud, in a sentence each.

