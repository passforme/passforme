# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-01

### Added

- Vault encrypted on the device with XChaCha20-Poly1305; opening it takes
  the master password (Argon2id) and a 128-bit Secret Key, printed once as
  the Emergency Kit.
- Password and passphrase generator, in English or Brazilian Portuguese,
  reporting the exact entropy.
- Kinds of item: login, note, recovery codes and phrases, security
  questions, PIN, API key, crypto seed, SSH key, card, bank, Wi-Fi,
  license and document, each asking for its own fields.
- Recovery codes used one at a time with `codes`, TOTP codes with `totp`,
  small encrypted attachments with `edit --attach`.
- Clipboard copies cleared after 30 seconds, and only if still unchanged.
- A terminal session that stops asking for the master password while the
  vault is in use, closed by a screen locker or `lock`.
- An unlock agent that hands only the items marked for programs to
  `get --stdout`.
- `passforme-server`, an optional sync server that stores ciphertext
  only, with a three-way merge and rollback protection on the client.
- `ghcr.io/passforme/passforme-server` Docker image for amd64 and arm64,
  with a hardened `contrib/compose.yml`, and a self-hosting guide
  (`docs/self-hosting.md`) recommending Tailscale.
- Tab completion for bash, zsh, fish, elvish and PowerShell.
- `install.sh`, the README's one-line install: downloads the latest
  release for the machine, checks its checksum and installs `passforme`
  and `pfm` into `~/.local/bin`.

[Unreleased]: https://github.com/passforme/passforme/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/passforme/passforme/releases/tag/v0.1.0
