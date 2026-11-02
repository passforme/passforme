# passforme-core

The heart of [passforme](https://github.com/passforme/passforme), a
password vault only you can open: the vault file format, the
cryptography (Argon2id and HKDF key derivation with a Secret Key,
XChaCha20-Poly1305 for the vault key and every item), the kinds of item
and their fields, the Emergency Kit text and the password generator.
No network, no disk: the crate only transforms bytes, and the client and
the server decide where they go.

It exists to be shared by the `passforme` client and `passforme-server`,
and is published so that the two can be installed from crates.io. It is
not a general-purpose library and its API follows the needs of those
two; anyone building on it should read the project's
[`docs/cryptography.md`](https://github.com/passforme/passforme/blob/main/docs/cryptography.md)
and [`docs/threat-model.md`](https://github.com/passforme/passforme/blob/main/docs/threat-model.md)
first.

Licensed under the AGPL-3.0-only.
