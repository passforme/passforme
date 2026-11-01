# passforme

A password manager in the spirit of 1Password and Bitwarden: a vault of
logins, codes and notes, a strong password generator, and sync between
devices through a small server the user runs themselves, which holds
only ciphertext. Linux, terminal first. Domain `passforme.com`, GitHub
org `passforme` (https://github.com/passforme), open source under
AGPL-3.0-only.

Started as the owner's personal tool for their homelab, it is becoming a
product. **What is true only of one person's machines and accounts**
(their server's address, Cloudflare and mail accounts, the programs on
their laptop) goes in `AGENTS.local.md`, ignored by Git, and never into a
tracked file. Anyone working on the project may keep one: read it when it
exists. (`CLAUDE.local.md`, also ignored, may contain `@AGENTS.local.md`
so that Claude Code loads it.)

## Read first

- [`docs/design.md`](docs/design.md): **how passforme works and why**,
  in full: every command and option, the session, the kinds of item,
  the unlock agent, sync and its merge, deployment, the roadmap, and
  each decision with its date and what was rejected. An agent that has
  read it knows the project; read it before changing behaviour.
- [`docs/threat-model.md`](docs/threat-model.md): what the design
  protects against (a stolen or malicious server, offline guessing,
  eavesdropping) and what it accepts (malware on an unlocked laptop, a
  server withholding data, losing both the password and the Secret Key).
- [`docs/cryptography.md`](docs/cryptography.md): Argon2id + HKDF key
  derivation with the Secret Key, XChaCha20-Poly1305 for the vault key
  and the items, padding, AADs, server authentication; the vectors each
  was checked against, and why.

The last two are **required reading before touching `crates/core`, the
handling of secrets in the CLI, or the server**. A change to a design
updates its document in the same commit; a decision taken while working
is written into `docs/design.md`, dated, with what it replaced.

## Rules for working here

- **Everything in this repository is English**: code, comments, CLI output,
  docs, commits. Whatever language the conversation is in, the code is not.
- **Commits** follow Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`,
  `refactor:`, `chore:`), are signed (`commit.gpgsign`), and carry **no AI
  attribution** — no `Co-Authored-By`, no "Generated with", no session links.
- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`
  (pedantic, must be clean) and `cargo test --workspace` before every
  commit; `cargo audit` clean too. CI (`.github/workflows/ci.yml`) runs
  the same on every push.
- **Every user-visible change adds a line under `[Unreleased]` in
  `CHANGELOG.md`** (Keep a Changelog). A release moves those lines under
  `## [X.Y.Z] - date`, bumps `version` in `Cargo.toml`, commits
  `chore(release): vX.Y.Z` and pushes the tag `vX.Y.Z`; `release.yml`
  builds x86_64 and aarch64 Linux tarballs with checksums and uses that
  section as the release notes. Linux only: the client needs `prctl`,
  `/proc` and `wl-copy`.
- License **AGPL-3.0-only** (chosen 2026-10-31): a modified sync server
  offered to others must publish its changes. The owner keeps the right
  to license an Enterprise edition separately, so outside contributions
  will need a CLA or DCO decision before they are merged.
- **Build on the developer's machine, never on the server.** A server only
  receives a binary (`bin/deploy`) or an image; releases are built on
  Ubuntu 22.04 runners so the binaries need only glibc 2.35.
- **No home-made cryptography.** Only standard constructions from audited
  crates (RustCrypto). New code may *combine* primitives, never invent them,
  and every combination is written down in `docs/cryptography.md`
  before it is implemented.
- **Secrets never reach a log, an error message, `Debug` output, a command
  line or this repository.** Secret types wrap `zeroize`/`secrecy` and have
  redacted `Debug`.
- Every change to the vault format bumps its version; old versions stay
  readable until explicitly dropped.
- **Two things keep the project's old name, `strongbox`, on purpose and
  must never be "fixed"**: the domain labels of the cryptography
  (`"strongbox v1 wrap"`, `"strongbox v1 item"` and the rest) and the
  `SB1-` prefix of the Secret Key. Both are inputs to key derivation or
  printed on Emergency Kits; changing either makes existing vaults and
  kits unreadable. The story is in `docs/design.md`, Name.

## Layout

A Cargo workspace inside this project; it depends on no other local
project.

| Crate | Binary | Role |
|---|---|---|
| `crates/core` (`passforme-core`) | — | `generator`, `kdf`, `seal`, `item` (the fields and their JSON), `kit` (Secret Key text), `vault` (file format, unlocked vault). **No I/O.** |
| `crates/cli` (`passforme`) | `passforme` | The client on the laptop. The only place where the vault is ever decrypted. |
| `crates/server` (`passforme-server`) | `passforme-server` | Sync server, on a machine of the user's. Stores ciphertext only; holds no key able to decrypt it. |

## Other files

| Path | What it is |
|---|---|
| `install.sh` | The README's one-line install: downloads the latest release for the machine, checks its `.sha256`, installs `passforme` and `pfm` into `~/.local/bin`. Depends on the archive names `release.yml` produces, so the two change together. |
| `bin/deploy`, `config/deploy.env.example` | Ships `passforme-server` to a machine of the user's over SSH (systemd unit in `contrib/`); settings in the ignored `config/deploy.env`. |
| `Dockerfile`, `contrib/compose.yml` | The `ghcr.io/passforme/passforme-server` image, packaged from the release binaries, never rebuilt. |
| `docs/self-hosting.md` | How anyone runs the sync server, systemd or Docker, Tailscale recommended. |
| `tools/*_reference.py` | Independent Python implementations the cryptography and TOTP tests are checked against. |
| `SECURITY.md` | How to report a vulnerability (`hello@passforme.com`); only the latest release gets fixes. |
| `CHANGELOG.md` | Keep a Changelog; every user-visible change adds a line under `[Unreleased]`, and the release workflow uses the version's section as the release notes. |

## Website

The home page, the command guide and the brand kit of `passforme.com`
live in their own repository since 2026-11-01:
[passforme/website](https://github.com/passforme/website), with its own
`AGENTS.md` (until then they were `site/` here). The rule that crosses
the two: **a change to a command or option is followed by the guide's
update there**, and noted in `CHANGELOG.md` here.

## Project plans (domain, accounts, release)

The domain `passforme.com` (registered 2026-10-17) and the GitHub org
`passforme` belong to the project, with their own Cloudflare and Zoho
Mail accounts (`hello@passforme.com`, also the address of
`SECURITY.md`), apart from the owner's personal ones. How those accounts
are operated, and what an agent may touch in them, is the owner's
business and lives in `AGENTS.local.md`. The one rule that concerns
everyone: an agent never holds an account's login, only a scoped token
handed to it by `passforme unlock`, and anything that costs money needs
the owner's approval.

Open source under AGPL-3.0-only since 2026-10-31, when the repository
was audited for publication (license, README, CHANGELOG, CI and release
workflows, `bin/deploy`, `docs/`, `install.sh`, `SECURITY.md`). An
Enterprise edition may follow, which is why outside contributions need
a CLA or DCO decision before the first one is merged.
