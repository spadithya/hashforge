# 99 · Recap — Things I Learned From hashforge

> Mission 2 of the cybersecurity-journey portfolio. Region of the map:
> cryptography, hashing, authentication.
>
> Date completed: 2026-07-01

---

## What I built

A single Python CLI, `hashforge`, with three subcommands that span the password
lifecycle: `entropy` (score a password's strength in bits, plus an optional
Have I Been Pwned breach check), `identify` (guess an unknown hash's algorithm
from its prefix/length/charset, like `hashid`), and `crack` (a thin wrapper
that drives John the Ripper / Hashcat). The most interesting part is how *small*
the cracking code is: `crack` doesn't hash anything itself — it reuses
`identify` to auto-pick the right format/mode, assembles the command line, and
lets the real cracker do the work. Identifying the hash is what makes cracking
possible, so most of the "cracking" tool is actually the identifier.

## Four questions to answer

### 1. Which hash schemes are weak for passwords, and why specifically?
The fast, unsalted digests: **MD5, SHA-1, SHA-256/512, and NTLM**. Their whole
design goal is *speed* — great for file checksums, fatal for passwords, because
a GPU can compute billions of guesses per second against them. MD5 and SHA-1
also have broken collision resistance. NTLM is just unsalted MD4, so identical
Windows passwords produce identical hashes. The safe schemes are deliberately
**slow and salted**: bcrypt (tunable cost factor), sha256/512crypt (thousands
of rounds), and argon2/yescrypt (memory-hard). Salting isn't optional — without
it, identical passwords collide and rainbow tables work.

### 2. When do you reach for Hashcat vs John?
**John** first for convenience: it auto-detects many formats, runs fine on a
CPU, and handles weird/rare hash types gracefully — it cracked my demo list
instantly. **Hashcat** when I have a GPU and a big job (large wordlist + rules,
or masks against fast hashes), because the GPU turns fast hashes into orders of
magnitude more guesses/sec. The catch I hit: Hashcat *always* needs the exact
`-m` mode number and refuses to run on a GPU-less VM without `--force` (and even
then, mine was too memory-constrained). So John is my reliable local engine;
Hashcat is the one I'd reach for on real hardware.

### 3. What is a "rule" in cracking, and why does it ~10x your dictionary?
A rule is a programmatic mutation applied to every word in the wordlist. One
rule like `$1` (append "1") turns `password` into `password1`; a ruleset like
Best64 stacks capitalization, leetspeak, and digit/symbol suffixes. So instead
of needing `password`, `Password`, `password1`, `p@ssw0rd!` etc. all sitting in
the wordlist, one word expands into dozens of realistic human variations — you
multiply coverage without multiplying the file. That's why `rockyou + Best64`
cracks far more than `rockyou` alone.

### 4. How does salting break rainbow tables but NOT brute force?
A rainbow table is a giant precomputed `digest → password` lookup. A salt is a
random per-password value hashed in alongside the password, so the same
password produces a *different* digest for every salt — an attacker would need
a separate rainbow table per salt value, which is infeasible. But the salt is
stored right next to the hash, so once an attacker targets *one* specific hash,
they just fold its salt into each guess: `hash(salt + "password123")`. Salting
raises the cost of attacking *everyone at once*; it does nothing to slow
attacking *one* hash. That's why you need salt **and** a slow hash.

---

## What surprised me

- **Entropy math lies.** `"password"` scores a "reasonable" 37.6 bits by the
  abstract charset model — yet it's been breached 52 million times. The math
  can't know a string is a famous password, which made the HIBP check feel
  essential rather than optional.
- **Length genuinely crushes complexity.** Seeing `correct horse battery staple`
  (144.8 bits) beat `Tr0ub4dor&3` (72.1 bits) *from my own tool* made the
  `bits = length × log2(pool)` formula click — adding characters is a multiplier;
  adding symbols is a small additive bump.
- **MD5 and NTLM are indistinguishable by inspection.** I assumed a hash "looks
  like" its algorithm; it doesn't. A 32-hex string is genuinely ambiguous, which
  is why honest tools rank candidates instead of asserting one.
- **k-anonymity is elegant.** Sending 5 characters and getting ~2,000 look-alike
  hashes back, then matching locally, means the server never learns what you
  asked — a lovely bit of privacy engineering.

## What I'd do differently next time

- Add a `--json` output mode (like portwalker) so results are machine-readable.
- Make `crack` drop `--force` automatically when a real GPU is detected, so the
  same command is clean on both a VM and a proper rig.
- Give `identify` a "no match" hint that suggests single-quoting `$…$` hashes —
  the shell-expansion gotcha cost me real confusion.
- Cache HIBP prefix responses locally to avoid repeat network calls.

## How this connects to earlier / later Missions

- **Earlier:**
  - `portwalker` (M1) — once you find an open service, the credential question
    is what comes next. hashforge is that next step.
- **Later:**
  - `glasshouse` (M3) — broken-auth and weak password storage show up directly
    in the vulnerable web app.
  - `tinyforest` (M5) — NTLM hashes are the currency of AD attacks
    (Kerberoasting, Pass-the-Hash); `identify` and `crack` apply directly.
  - `whisper-c2` (M10) — post-exploitation often means dumping and cracking creds.
  - `gauntlet` (M12) — credential access is one full stage of the kill chain.

## Lessons learned (one-liners, for the resume)

- Fast hashes are for integrity, slow salted hashes are for passwords — using
  one where the other belongs is the root of most password breaches.
- A hash reveals its *form*, not its *identity*; good tooling ranks guesses and
  admits ambiguity instead of faking certainty.
- The cheapest security win is often architectural (k-anonymity) rather than
  cryptographic — send less, and you don't have to trust the other end.
