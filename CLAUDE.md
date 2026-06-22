# Claude Onboarding — hashforge (Mission 2)

Before responding to anything in this folder, read:

- `/home/eel/Repositories/ctf/ONBOARDING.md` — full Mission lifecycle, file conventions, and what's expected of you across the two phases (learning + showcase).
- `/home/eel/Repositories/ctf/cyberjournal/LEARNING_PLAN.txt` — Section "M2 · hashforge" for this Mission's Prime/JIT/Build/CTF/Recap definitions.
- `/home/eel/Repositories/ctf/portwalker/` — the canonical example of what a finished Mission repo looks like. Match its showcase structure when this Mission's `docs/` reorg happens.

## Where I am in this Mission

- **Mission:** hashforge (Mission 2)
- **Region of the map:** Cryptography, hashing, authentication
- **Stage:** _ask me at the start of the session — Prime / Build / CTF / Recap / Showcase reorg_

## Universal deliverables I owe for this Mission

- A working CLI (`hashforge entropy | identify | crack`)
- A ~90-second asciinema demo embedded in the README
- All four done-when items from `LEARNING_PLAN.txt` checked
- The folder reorganized to mirror `portwalker/`'s final layout when shipped

## Conventions to honor here

- Don't paste-bomb code into `01_PROJECT/`. Scaffolds and templates are fine; the main CLI I type myself.
- Commit messages: `hashforge: <change>`, never "M2: ...".
- `.gitignore` already excludes wordlists, `.pot` potfiles, and unmarked hash files. Never commit real breached data or third-party hash dumps.
- The HIBP integration uses k-anonymity (only the first 5 chars of the SHA-1 leave the machine). Keep it that way.

Confirm where I am in the Mission with one short question, then take it from there.
