# Contributing

Thank you for looking under the hood. passforme keeps passwords, so it
moves carefully: small changes, each one explained, each one checked.

## Before you write code

- **A weakness in security is reported privately**, never in an issue:
  see [`SECURITY.md`](SECURITY.md).
- **Open an issue first** for anything beyond a small fix, so that the
  idea is agreed before the work is done. Say what problem it solves.
- **Read [`docs/design.md`](docs/design.md)**: how passforme works and
  why each decision was taken. Anything touching a secret also needs
  [`docs/threat-model.md`](docs/threat-model.md) and
  [`docs/cryptography.md`](docs/cryptography.md).
- **No home-made cryptography.** Only standard constructions from
  audited crates; a new combination of primitives is written down in
  `docs/cryptography.md` before it is implemented.

## The rules of the repository

[`AGENTS.md`](AGENTS.md) holds them in full, for people and their AI
agents alike. The short version:

- Everything is English: code, comments, docs, commit messages.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, …), one change per commit.
- Before every commit: `cargo fmt`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`,
  `cargo audit`. CI runs the same.
- Every user-visible change adds a line under `[Unreleased]` in
  [`CHANGELOG.md`](CHANGELOG.md), and a change to a design updates its
  document in the same commit.
- A change to a command or option is followed by an update of the
  guide in [passforme/website](https://github.com/passforme/website).

## Signing your work

passforme is licensed under the AGPL-3.0-only. By contributing you
certify the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change or have the right to submit it under this
license. Sign off every commit with `git commit -s`, which adds a
`Signed-off-by:` line with your name and email. No other paperwork.

## Pull requests

- One pull request per change, with the reason in the description.
- Tests for new behaviour, and the docs that describe it.
- Reviews look at the diff, not the description: expect questions.
