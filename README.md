# passforme

A password vault that only you can open, kept in sync between your devices
by a server you run yourself, which never sees anything but ciphertext.

Reach for it when you want what 1Password or Bitwarden give you (logins,
2FA codes, recovery codes, cards, API keys, a strong generator) without
handing the vault to someone else's cloud, and you live in a terminal.
Opening the vault takes your master password **and** a Secret Key that
never leaves your devices, so a stolen server copy cannot be guessed open.
It deliberately does not fill browser forms, and it has had no external
security audit yet: keep your passwords where they are today as well, until
it has.

> **Status:** in development. Linux only for now (the clipboard goes through
> Wayland's `wl-copy`). The command guide is at
> [passforme.com/guide.html](https://passforme.com/guide.html), in
> English and Portuguese.

## Install

### From a release

Every [release](https://github.com/passforme/passforme/releases) ships
`passforme-<version>-<target>.tar.gz` for `x86_64` and `aarch64` Linux,
each with a `.sha256`:

```sh
sha256sum -c passforme-*-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf passforme-*-x86_64-unknown-linux-gnu.tar.gz
install -m 755 passforme-*/passforme ~/.local/bin/
ln -s passforme ~/.local/bin/pfm        # the short name used in the guide
```

The archive also holds `passforme-server`, the optional sync server.

### From source

Needs Rust 1.87 or later.

```sh
git clone https://github.com/passforme/passforme
cd passforme
cargo build --release -p passforme
install -m 755 target/release/passforme ~/.local/bin/
```

Tab completion, in `~/.bashrc`: `source <(passforme completions bash)`.

### Sync server (optional)

On a machine of yours, with systemd from the release archive, or with
Docker:

```sh
docker run -d --name passforme --restart always -p 127.0.0.1:8090:8090 \
  -v passforme-data:/data ghcr.io/passforme/passforme-server
```

It needs HTTPS in front; we recommend `tailscale serve`, so only your own
devices reach it. Everything else is in
[`docs/self-hosting.md`](docs/self-hosting.md).

## Usage

```console
$ pfm init                              # vault, Secret Key, Emergency Kit to print
$ pfm add github.com --username me@example.com --generate
$ pfm get github                        # copied; the clipboard clears in 30 s
$ pfm totp github                       # current 2FA code
$ pfm add "Proton recovery codes" --kind recovery-codes
$ pfm codes proton                      # next unused code, marked as used
$ pfm list
```

Write the master password and the Secret Key on paper and keep them away
from the laptop. Without both there is no recovery, by design.

Sync is optional: `pfm register URL` puts the vault on your own
`passforme-server` ([self-hosting](docs/self-hosting.md)), and
`pfm login URL` sets up another device from it.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Before changing anything that touches a secret, read
[`docs/threat-model.md`](docs/threat-model.md) and
[`docs/cryptography.md`](docs/cryptography.md). The reasons behind the
rest of the design are in [`AGENTS.md`](AGENTS.md); the website is in
[`site/`](site/).

## License

[AGPL-3.0](LICENSE). Running a modified `passforme-server` for others
means publishing your changes.
