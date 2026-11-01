<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/logo-gold-on-dark.svg">
    <img src="docs/brand/logo-brass-on-light.svg" alt="passforme" width="440">
  </picture>
  <br>
  <strong>A password vault only you can open.</strong>
  <br>
  <sub>Terminal first &middot; synced by a server you run &middot; the server sees only ciphertext</sub>
</p>

A password vault that only you can open, kept in sync between your devices
by a server you run yourself, which never sees anything but ciphertext.

It is for people who live in a terminal and want what 1Password or
Bitwarden give them, without handing the vault to someone else's cloud:
logins, 2FA codes, recovery codes, cards, bank accounts, API keys, SSH
keys, Wi-Fi passwords and a strong generator, all in one place. Opening
the vault takes your master password **and** a Secret Key that never
leaves your devices, so a copy stolen from the server, or from a backup,
cannot be guessed open.

What it deliberately does not do: fill browser forms, run on a phone
(yet), or offer a way back in if you lose both the master password and
the Secret Key. It has had no external security audit. Keep your
passwords where they are today as well, until it has.

> **Status:** in development. Linux only, with the clipboard on Wayland
> (`wl-copy`). The command guide, in English and Portuguese, is at
> [passforme.com/guide](https://passforme.com/guide)
> (source: [passforme/website](https://github.com/passforme/website)).

## Install

### One line

Downloads the latest [release](https://github.com/passforme/passforme/releases)
for your machine (x86_64 or aarch64 Linux), checks its checksum and puts
`passforme` and the short name `pfm` in `~/.local/bin`. Nothing runs as
root.

```sh
curl -fsSL https://raw.githubusercontent.com/passforme/passforme/main/install.sh | sh
```

Read [`install.sh`](install.sh) first if you prefer. `PASSFORME_VERSION`
pins a version and `PASSFORME_INSTALL_DIR` picks another directory.

### From a release, by hand

Every release ships `passforme-<version>-<target>.tar.gz` for
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, each with a
`.sha256`:

```sh
sha256sum -c passforme-*-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf passforme-*-x86_64-unknown-linux-gnu.tar.gz
install -m 755 passforme-*/passforme ~/.local/bin/
ln -s passforme ~/.local/bin/pfm
```

The archive also holds `passforme-server`, the optional sync server, and
its systemd unit.

### From source

Needs Rust 1.87 or later.

```sh
git clone https://github.com/passforme/passforme
cd passforme
cargo install --path crates/cli --locked     # puts passforme in ~/.cargo/bin
```

### Tab completion

```sh
echo 'source <(passforme completions bash)' >> ~/.bashrc    # also zsh, fish, elvish, powershell
```

### Sync server (optional)

Only needed to keep more than one device in sync; the vault works on its
own without it. On a machine of yours, from the release archive with
systemd, or with Docker:

```sh
docker run -d --name passforme --restart always -p 127.0.0.1:8090:8090 \
  -v passforme-data:/data ghcr.io/passforme/passforme-server
```

It needs HTTPS in front. We recommend `tailscale serve`, so only your own
devices can reach it. Everything else, including backups, is in
[`docs/self-hosting.md`](docs/self-hosting.md).

## Usage

```console
$ pfm init                                  # creates the vault; print the Emergency Kit it shows
$ pfm add github.com --username me@example.com --generate
$ pfm get github                            # password copied; the clipboard clears in 30 s
$ pfm totp github                           # current 2FA code
$ pfm add "Proton recovery codes" --kind recovery-codes
$ pfm codes proton                          # copies the next unused code and marks it used
$ pfm list
```

The first command at a terminal asks for the master password; the next
ones do not until the vault sits unused for 15 minutes, a screen locker
runs, or you type `pfm lock`. Programs get secrets without a terminal
through the unlock agent, which only ever holds the items you mark for
it:

```sh
pfm edit openrouter --agent              # mark the item
pfm unlock --for 8h                      # master password once
pfm get openrouter --stdout              # the value alone, for a script or a key_command
```

Sync is optional: `pfm register URL` puts the vault on your own
`passforme-server`, and `pfm login URL` sets up another device from it.
Every change made at the terminal is uploaded at once; conflicts keep
both versions.

Write the master password and the Secret Key on paper and keep them away
from the computer. Without both there is no recovery, by design.

## Configuration

| Where | What | Default |
|---|---|---|
| `~/.config/passforme/config` | `session = 15m` (or `1h`, `30s`, `off`): how long a terminal stays unlocked after each use | `15m` |
| `PASSFORME_DIR` | the directory of the vault and the Secret Key | `~/.local/share/passforme` |
| `LANG` / `LC_ALL` | the language of generated passphrases (`pt…` means Brazilian Portuguese; `--lang` overrides it) | English |

## Security

Everything the design protects against, and what it knowingly does not,
is in [`docs/threat-model.md`](docs/threat-model.md); every key, nonce
and primitive, and how each was verified, in
[`docs/cryptography.md`](docs/cryptography.md). Found a problem? Please
report it privately as [`SECURITY.md`](SECURITY.md) asks.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Read the two documents above before changing anything that touches a
secret. How everything else works, and why each decision was taken, is
in [`docs/design.md`](docs/design.md), written for people and their
agents alike; the rules the code follows are in [`AGENTS.md`](AGENTS.md),
and [`CONTRIBUTING.md`](CONTRIBUTING.md) is where a contribution starts.
Changes to a command are followed by an update of the guide in
[passforme/website](https://github.com/passforme/website).

## License

[AGPL-3.0](LICENSE). Running a modified `passforme-server` for others
means publishing your changes.
