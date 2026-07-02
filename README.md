# hashforge

> Password entropy auditor + hash identifier + cracking harness, written in Python.

**Status:** v1 — all three tools working; asciinema demo completed.
**Mission 2 of the [cybersecurity-journey] portfolio.**
**Region of the infrastructure map:** Cryptography, hashing, authentication.

---

## What it does

`hashforge` is three small tools behind one CLI, covering the password-handling
lifecycle from *"is this password any good?"* to *"what algorithm hashed it?"*
to *"can we crack it?"*:

1. **`entropy`** — scores a password's strength (bits of entropy) and, with
   `--hibp`, checks whether it has appeared in a breach — using Have I Been
   Pwned's **k-anonymity** model, so only the first 5 characters of the SHA-1
   ever leave your machine.
2. **`identify`** — given an unknown hash string, returns *ranked* guesses at
   the algorithm (MD5, SHA-1, SHA-256, bcrypt, NTLM, and more), reasoning from
   prefix, length, and charset — like `hashid`.
3. **`crack`** — a thin, friendly front-end that drives John the Ripper or
   Hashcat, auto-selecting the right format/mode by reusing `identify`.

It was built to *understand* password security from the inside, not to replace
`hashcat` — the interesting part is how little cracking code there is, because
identifying the hash is what makes cracking possible.

## Requirements

Python 3.8+. Standard library only, except the optional `--hibp` breach check,
which needs [`requests`](https://pypi.org/project/requests/):

```bash
pip install -r requirements.txt   # just `requests`, only needed for --hibp
```

`crack` shells out to [`john`](https://www.openwall.com/john/) and/or
[`hashcat`](https://hashcat.net/) — install whichever you want to use (both
ship with Kali).

## Usage

```bash
python3 hashforge.py entropy  <password> [--hibp]
python3 hashforge.py identify <hash>
python3 hashforge.py crack    <hash_file> [options]
```

| Command | Flag | Description |
|---|---|---|
| `entropy` | `<password>` | the password to audit |
| | `--hibp` | also check Have I Been Pwned (only 5 SHA-1 chars are sent) |
| `identify` | `<hash>` | the hash string to identify (**single-quote it** — `$` triggers shell expansion) |
| `crack` | `<hash_file>` | file of hashes, one per line |
| | `--engine` | `john` (default) or `hashcat` |
| | `--wordlist` | path to a wordlist (default: John's `password.lst`) |
| | `--rules` | rule preset / rule file to mutate the wordlist |
| | `--mode` | `dict` (default) or `mask` |
| | `--mask` | mask pattern for mask mode, e.g. `?u?l?l?l?d?d` |

### Real examples

**Entropy — length beats complexity** (the xkcd "correct horse" result, proven):

```console
$ python3 hashforge.py entropy "Tr0ub4dor&3"
       length : 11
    char pool : 94
      entropy : 72.1 bits
     strength : strong
     breached : (not checked — pass --hibp)

$ python3 hashforge.py entropy "correct horse battery staple"
       length : 28
    char pool : 36
      entropy : 144.8 bits
     strength : very strong
     breached : (not checked — pass --hibp)
```

**Entropy + HIBP — why entropy alone lies:**

```console
$ python3 hashforge.py entropy "password" --hibp
       length : 8
    char pool : 26
      entropy : 37.6 bits
     strength : reasonable
     breached : YES — seen 52,372,427 times
```

`"password"` looks "reasonable" by the math — but it's been breached 52 million
times. Only 5 characters of its SHA-1 (`5BAA6`) left the machine to learn that.

**Identify — ranked guesses, honest about ambiguity:**

```console
$ python3 hashforge.py identify 5f4dcc3b5aa765d61d8327deb882cf99
algorithm      confidence  hashcat -m  john --format
--------------------------------------------------------
MD5            high        0           raw-md5
NTLM           medium      1000        nt
MD4            low         900         raw-md4
```

MD5 and NTLM are byte-for-byte identical in form (both 32 hex chars), so the
tool ranks rather than pretends to be certain — only context breaks the tie.

**Crack — auto-detects the format, then drives John:**

```console
$ python3 hashforge.py crack samples/weak_md5.hash
[hashforge] john --wordlist=/usr/share/john/password.lst --format=raw-md5 samples/weak_md5.hash
...
[hashforge] engine=john  format=raw-md5  attack=dict
[hashforge] cracked 5:
    ?  ->  password
    ?  ->  123456
    ?  ->  letmein
    ?  ->  monkey
    ?  ->  superman
```

No `--format` was given — `crack` peeked at the first hash, asked `identify`,
and added `--format=raw-md5` automatically.

## Hash format cheat-sheet

The five mission-required formats, told apart by **prefix** or **length**:

| Algorithm | How to spot it | Example (of `password`) | Notes |
|---|---|---|---|
| **MD5** | 32 hex chars | `5f4dcc3b5aa765d61d8327deb882cf99` | 128-bit, fast → unsafe for passwords |
| **NTLM** | 32 hex chars | `8846f7eaee8fb117ad06bdd830b7586c` | Windows; identical shape to MD5, context decides |
| **SHA-1** | 40 hex chars | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | 160-bit, deprecated |
| **SHA-256** | 64 hex chars | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | 256-bit, fast → unsafe for passwords |
| **bcrypt** | starts `$2a$`/`$2b$`/`$2y$` | `$2b$12$GhvMmNVjRW29ulnudl.Lbu...` | salted, slow, tunable cost → good |

Rule of thumb: **hex length = output bits ÷ 4** (SHA-**256** → 64 hex chars).
Anything starting with `$` self-labels its algorithm. A full visual reference
covering every format `identify` detects (SHA-512, sha512crypt, argon2,
yescrypt, …) lives in [`docs/hash-format-reference.html`](docs/hash-format-reference.html).

## Repository layout

```
hashforge/
├── hashforge.py        ← CLI entrypoint (entropy | identify | crack)
├── entropy.py          ← entropy scoring + HIBP k-anonymity check
├── identify.py         ← hash-format detection (prefix / length / charset)
├── crack.py            ← John / Hashcat subprocess wrapper
├── requirements.txt    ← requests (only for --hibp)
├── README.md           ← you are here
├── LICENSE             ← MIT
├── samples/            ← demo fixtures (hashes of common words, safe to share)
│   ├── hash_zoo.txt    ← one example per algorithm, for testing `identify`
│   └── weak_md5.hash   ← the end-to-end cracking demo input
└── docs/               ← build journal (this was a learning project)
    ├── 00_PRIME.md              ← orientation notes, written before building
    ├── 02_CTF_NOTES.md          ← matched TryHackMe rooms
    ├── 99_RECAP.md              ← what I learned, written after shipping
    └── hash-format-reference.html ← visual reference for every detected format
```

If you just want to *use* the tool, you only need the `.py` files.

## Done when

- [x] Correctly identifies common hashes (MD5, SHA-1, SHA-256, bcrypt, NTLM)
- [x] Entropy auditor matches HIBP results for a known-breached password
- [x] Cracks a known-weak password list end-to-end **with John**
- [ ] Same, with **Hashcat** — code is correct, but needs a GPU-equipped host
      (this build VM is memory-constrained; see *Known limitations*)
- [x] README has a cheat-sheet of common hash formats
- [x] Repo has a LICENSE, .gitignore, and clean commit history
- [x] **~90-second asciinema demo** recorded and embedded
- [x] `99_RECAP.md` is filled in

## Known limitations

- **Hashcat needs real hardware.** `crack --engine hashcat` builds the correct
  command, but Hashcat won't run on this GPU-less, memory-constrained VM
  (`Not enough allocatable device memory`). John is the working engine here.
- **`identify` guesses form, never confirms.** A 32-hex string could be MD5 or
  NTLM; the tool ranks candidates and leaves the final call to context.
- **Entropy is the optimistic attacker model.** It can't know `"Password1"` is
  predictable — which is exactly why `--hibp` exists as the reality check.

## Demo

_A ~90-second asciinema walkthrough will be recorded and embedded here:_

[![asciicast](https://asciinema.org/a/4oIBON0aP3smOHOG.svg)](https://asciinema.org/a/4oIBON0aP3smOHOG)

## Ethical use

Only audit or crack hashes from systems you own or are explicitly authorized to
test (your own VMs, CTF platforms, authorized engagements). Never paste hashes
from real breaches into any tool. hashforge's HIBP integration is deliberately
k-anonymous — only the first 5 characters of the SHA-1 leave your machine — but
that care is on you for everything else.

## License

MIT — see [LICENSE](LICENSE).
