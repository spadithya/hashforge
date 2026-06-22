# 99 · Recap — Things I Learned From hashforge

> Fill this in AFTER shipping the project. Answer in your own words, in 1–3 sentences per question. This is the file your future self (and a recruiter) will read first.
>
> Date completed: _TBD_

---

## What I built

_One paragraph summary of the final tool — what it does, what it doesn't do, what's the most interesting part of the code._

## Four questions to answer

### 1. Which hash schemes are weak for passwords, and why specifically?
_Your answer here. Be specific about speed, salt support, and modern recommendations._

### 2. When do you reach for Hashcat vs John?
_Your answer here. Think about: GPU access, scripting needs, weird formats, output ergonomics._

### 3. What is a "rule" in cracking, and why does it ~10x your dictionary?
_Your answer here. Give one concrete rule and what it does to a wordlist entry._

### 4. How does salting break rainbow tables but NOT brute force?
_Your answer here. Use a 2-line example if it helps._

---

## What surprised me

_Things that were not what you expected. Counter-intuitive results. The "huh, weird" moments — e.g. how fast a GPU shreds unsalted MD5, or how hard NTLM still is in 2026._

## What I'd do differently next time

_With the benefit of hindsight, where would v2 start? Better hash detection heuristics? A proper rule engine? Caching the HIBP responses?_

## How this connects to earlier / later Missions

- **Earlier:**
  - `portwalker` (M1) — once you find an open service, the credential question is next.
- **Later:**
  - `glasshouse` (M3) — broken-auth and weak-hash storage will appear in the vulnerable web app.
  - `tinyforest` (M5) — NTLM hashes are the entire currency of AD attacks (Kerberoasting, Pass-the-Hash).
  - `whisper-c2` (M10) — post-exploitation often means dumping and cracking creds.
  - `gauntlet` (M12) — credential access is one full stage of the kill chain.

## Lessons learned (one-liners, for the resume)

- _A short, sharp lesson._
- _Another._
- _One more._
