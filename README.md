# hashforge

> Password entropy auditor + hash identifier + cracking-wrapper, written in Python.

**Status:** Work in progress.
**Mission 2 of the [cybersecurity-journey](../cyberjournal/LEARNING_PLAN.txt) portfolio.**
**Region of the infrastructure map:** Cryptography, hashing, authentication.

---

## What it does (planned)

`hashforge` is three small tools behind one CLI, covering the password-handling lifecycle from "is this password any good?" to "what algorithm hashed it?" to "can we crack it?":

1. **Entropy auditor** — scores a password against entropy rules and checks it against the Have I Been Pwned API using the k-anonymity model (only the first 5 chars of the SHA-1 hash are sent).
2. **Hash identifier** — given an unknown hash string, guesses the algorithm (MD5, SHA-1, SHA-256, bcrypt, NTLM, etc.).
3. **Cracking wrapper** — a thin, friendly front-end that drives John the Ripper or Hashcat with the right flags for dictionary, mask, and rule-based attacks.

## Usage (planned)

```bash
# Entropy + HIBP check
hashforge entropy "correct horse battery staple"
hashforge entropy "Password123!" --hibp

# Hash identification
hashforge identify '$2a$10$N9qo8uLOickgx2ZMRZoMye...'
hashforge identify 5f4dcc3b5aa765d61d8327deb882cf99

# Cracking
hashforge crack hashes.txt --wordlist rockyou.txt --rules best64
hashforge crack hashes.txt --mode mask --mask '?u?l?l?l?l?d?d'
hashforge crack hashes.txt --engine hashcat --device gpu
```

## Mission folder layout

```
hashforge/
├── README.md            ← you are here
├── 00_PRIME.md          ← orientation reading, done BEFORE building
├── 01_PROJECT/          ← the actual code
├── 02_CTF_NOTES.md      ← matched TryHackMe / HTB rooms
└── 99_RECAP.md          ← what I learned, filled in AFTER shipping
```

## Done when

- [ ] Tool correctly identifies common hashes (MD5, SHA1, SHA256, bcrypt, NTLM)
- [ ] Entropy auditor matches HIBP results for a known-breached password
- [ ] Cracking wrapper successfully cracks a known-weak password list end-to-end with both John and Hashcat
- [ ] README has a cheat-sheet of common hash formats with examples
- [ ] Repo has a LICENSE, .gitignore, and clean commit history
- [ ] **~90-second asciinema demo** recorded, uploaded, and embedded in this README
- [ ] `99_RECAP.md` is filled in

## Demo

_Recorded with `asciinema rec` once the CLI works end to end. The cast will be embedded here and linked from the portfolio landing page._

```bash
# What the recording will show:
hashforge entropy "Password123!" --hibp
hashforge identify 5f4dcc3b5aa765d61d8327deb882cf99
hashforge crack samples/weak.txt --wordlist /usr/share/wordlists/rockyou.txt
```

## Hash format cheat-sheet (will be filled in as I go)

| Algorithm | Example | Notes |
|---|---|---|
| MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` | 32 hex chars. Deprecated for passwords. |
| SHA-1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | 40 hex chars. Deprecated. |
| SHA-256 | `5e88489...` | 64 hex chars. Fast → bad for passwords. |
| bcrypt | `$2a$10$N9qo8uLOick...` | Starts with `$2a$` / `$2b$`. Salted, slow, good. |
| NTLM | `8846f7eaee8fb117ad06bdd830b7586c` | 32 hex chars. Windows. Crack with Hashcat mode 1000. |
| argon2 | `$argon2id$v=19$m=65536,t=3,p=4$...` | Modern best practice. |

## Ethical use

Only crack hashes from systems you own or are explicitly authorized to test (your own VMs, CTF platforms, authorized engagements). Never paste hashes from production breaches into a public tool. The Have I Been Pwned k-anonymity model only sends the first 5 chars of the SHA-1, so the full password never leaves your machine — but the same care doesn't apply to other services. See [Section 6 of the parent plan](../cyberjournal/LEARNING_PLAN.txt) for the legal/ethical guardrails.

## License

TBD — likely MIT once the first version ships.
