# passforme-server

The optional sync server of [passforme](https://github.com/passforme/passforme),
a password vault only you can open. It stores each vault as ciphertext
and holds no key able to decrypt it: a stolen server, or a malicious
one, yields nothing that can be guessed open. Clients authenticate with
a key derived from their Secret Key, exchange changes with a three-way
merge, and refuse a server that tries to roll a vault back.

Install it with `cargo install passforme-server --locked`, or run the
`ghcr.io/passforme/passforme-server` image. How to run it, with systemd
or Docker and Tailscale in front, is in the project's
[`docs/self-hosting.md`](https://github.com/passforme/passforme/blob/main/docs/self-hosting.md).

Licensed under the AGPL-3.0-only: a modified server offered to others
must publish its changes.
