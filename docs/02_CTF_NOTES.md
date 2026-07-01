# 02 · CTF Notes — Live-fire Reinforcement

> Matched rooms only. Don't grind random rooms — pick the ones that reinforce what `hashforge` is teaching you.

---

## Matched rooms

### TryHackMe · Crack the Hash
- URL: https://tryhackme.com/room/crackthehash
- Why this one: forces you to identify the algorithm AND choose the right tool/wordlist combo for each hash. Exactly the workflow `hashforge` automates.
- Notes:
  - [ ] Started
  - [ ] Completed

### TryHackMe · John the Ripper: The Basics
- URL: https://tryhackme.com/room/johntheripper0
- Why this one: walks through John's modes (single, wordlist, incremental) and rules — you'll need this vocabulary for the cracking wrapper.
- Notes:
  - [ ] Started
  - [ ] Completed

---

## Things to write down as you go

For each room:

1. **A hash you got stuck on, and what unstuck you.** One sentence.
2. **One command or technique you want to remember.** Paste the exact command.
3. **How it relates to hashforge.** Where would this idea show up in your CLI? (`identify`? `crack`? a new rule preset?)

---

## Optional stretch

- **TryHackMe · Hashing — Crypto 101** — fills in any gaps from the Prime stage.
- **Hashcat exercise:** run the same hash against John and Hashcat. Compare speed, output format, and which finds it faster. Note the gap.
- **Build your own hash zoo:** use `openssl passwd` and Python's `hashlib` / `bcrypt` to generate one example of each algorithm. This becomes the fixture set for `hashforge identify` unit tests.
