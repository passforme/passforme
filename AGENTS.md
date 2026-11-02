# passforme

A password manager in the spirit of 1Password and Bitwarden: a vault of
logins, codes and notes, a strong password generator, and sync between
devices through a small server the user runs themselves, which holds
only ciphertext. Linux, terminal first. Domain `passforme.com`, GitHub
org `passforme` (https://github.com/passforme), open source under
AGPL-3.0-only.

**What is true only of one person's machines and accounts**
(their server's address, Cloudflare and mail accounts, the programs on
their laptop) goes in `AGENTS.local.md`, ignored by Git, and never into a
tracked file. Anyone working on the project may keep one: read it when it
exists. (`CLAUDE.local.md`, also ignored, may contain `@AGENTS.local.md`
so that Claude Code loads it.)

## Commands

```
passforme init                      # vault + Secret Key, prints the Emergency Kit
passforme generate [--length 32] [--symbols] [--avoid-ambiguous] [--words 6 [--lang pt-br]] [--copy]
passforme add TITLE [--username USER] [--url URL]... [--generate [generator options]]
passforme add TITLE --kind KIND [--file PATH]   # card, pin, crypto-seed…: asks for each field
passforme kinds                     # the kinds and what each holds
passforme codes QUERY [--list]      # copy the next unused recovery code, mark it used
passforme add-many                  # label + secret, repeated; vault opened once, saved per item
passforme list                      # table: user, URL, AGENT, what else it holds (no secrets)
passforme show QUERY [--reveal]     # secrets masked unless --reveal
passforme get QUERY [--field FIELD] # clipboard, cleared after 30 s; FIELD: password (default),
                                    # username, url, totp, cvv, pin, number… or any field name
passforme get QUERY --attachment NAME [--output PATH]  # save an attached file (0600, never overwrites)
passforme rm QUERY                  # asks for the title to be typed back
passforme edit QUERY [--title T] [--username USER] [--url URL] [--rm-url URL]
                     [--password | --generate [generator options]] [--totp] [--notes]
                     [--set-field NAME] [--set-secret-field NAME] [--rm-field NAME]
                     [--codes] [--kind KIND] [--attach PATH] [--rm-attachment NAME]
passforme totp QUERY                # current code; `get --field totp` copies it
passforme passwd                    # new master password, vault key rotated
passforme unlock [--for 8h|forever] [ITEM…]  # marked items (all, or the ones named) to the agent
passforme get QUERY --stdout        # value alone on stdout, for programs
passforme lock                      # close the session and empty the agent now
passforme status                    # session, agent (locked / time left / no limit), sync link
passforme completions bash          # Tab completion script (sourced from ~/.bashrc)
```

`QUERY` is a title, case-insensitive: an exact title wins, otherwise it
must be part of exactly one title. Every option is long only. The first
command at a terminal asks for the master password and opens a session;
the next ones do not ask until the vault sits unused for 15 minutes, a
screen locker runs, or `passforme lock`. Programs without a terminal use
the unlock agent (`unlock`, then `get --stdout`), which holds only the
items marked `--agent`. The sync server is optional:

```
passforme register URL   # put this vault on an empty server (asks for the invite)
passforme login URL      # new device: Secret Key + master password
passforme sync           # exchange changes; add, edit and rm sync on their own
```

## Read first

- [`docs/design.md`](docs/design.md): **how passforme works and why**,
  in full: every command and option, the session, the kinds of item,
  the unlock agent, sync and its merge, deployment, and each decision
  with what was rejected. An agent that has read it knows the project;
  read it before changing behaviour.
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
  section as the release notes. Then `cargo publish --workspace` puts
  the three crates on crates.io, in dependency order, with the token
  the owner keeps in passforme (`crates.io passforme`), never in a file. Linux only: the client needs `prctl`,
  `/proc` and `wl-copy`.
- License **AGPL-3.0-only**: a modified sync server offered to others
  must publish its changes. Outside contributions are signed off
  under the DCO (`git commit -s`), as `CONTRIBUTING.md` says.
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
- **Two things carry the project's earlier name, `strongbox`, on purpose
  and must never be "fixed"**: the domain labels of the cryptography
  (`"strongbox v1 wrap"`, `"strongbox v1 item"` and the rest) and the
  `SB1-` prefix of the Secret Key. Both are inputs to key derivation or
  printed on Emergency Kits; changing either makes existing vaults and
  kits unreadable (`docs/design.md`, Name).

## Layout

A Cargo workspace inside this project; it depends on no other local
project.

| Crate | Binary | Role |
|---|---|---|
| `crates/core` (`passforme-core`) | — | `generator`, `kdf`, `seal`, `item` (the fields and their JSON), `kit` (Secret Key text), `vault` (file format, unlocked vault). **No I/O.** |
| `crates/cli` (`passforme`) | `passforme` | The client, on the user's computer. The only place where the vault is ever decrypted. |
| `crates/server` (`passforme-server`) | `passforme-server` | Sync server, on a machine of the user's. Stores ciphertext only; holds no key able to decrypt it. |

## Other files

| Path | What it is |
|---|---|
| `install.sh` | The README's one-line install: downloads the latest release for the machine, checks its `.sha256`, installs `passforme` and `pfm` into `~/.local/bin`. Depends on the archive names `release.yml` produces, so the two change together. |
| `bin/deploy`, `config/deploy.env.example` | Ships `passforme-server` to a machine of the user's over SSH (systemd unit in `contrib/`); settings in the ignored `config/deploy.env`. |
| `Dockerfile`, `contrib/compose.yml` | The `ghcr.io/passforme/passforme-server` image, packaged from the release binaries, never rebuilt. |
| `docs/self-hosting.md` | How anyone runs the sync server, systemd or Docker, Tailscale recommended. |
| `docs/brand/` | The two logos the README shows, copied from the brand kit in [passforme/website](https://github.com/passforme/website) (`site/brand/logo/`), where they are generated; when the kit changes, copy them again. |
| `tools/*_reference.py` | Independent Python implementations the cryptography and TOTP tests are checked against. |
| `CONTRIBUTING.md` | What a contributor reads first: issue before code, the rules in short, DCO sign-off. |
| `SECURITY.md` | How to report a vulnerability (`security@passforme.com`); only the latest release gets fixes. |
| `CHANGELOG.md` | Keep a Changelog; every user-visible change adds a line under `[Unreleased]`, and the release workflow uses the version's section as the release notes. |

## Website

The home page, the command guide and the brand kit of `passforme.com`
are in [passforme/website](https://github.com/passforme/website), with
its own `AGENTS.md`. **A change to a command or option here is followed
by the guide's update there.**
