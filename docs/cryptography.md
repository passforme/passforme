# Cryptographic design (v1)

What every key, nonce and AAD is, which audited crate provides each
primitive, how it was verified, and why each choice was made. Read it
before changing anything in `crates/core`.

Crates: `argon2`, `hkdf` + `sha2`, `chacha20poly1305` (XChaCha20-Poly1305),
`rand_core` (traits only) with `getrandom`'s `SysRng` (the kernel's
`getrandom(2)`) in the binaries, `zeroize`, `secrecy`. `core` takes the RNG
as a `CryptoRng` argument and never opens it itself.

1. **Account creation** (client): random 16-byte `salt`, random 16-byte
   `secret_key` (shown once as the Emergency Kit, stored on each device at
   `0600`), random 32-byte `vault_key`, random 16-byte `account_id`.
   The Secret Key's text form (`kit.rs`) is `SB1-` and six groups of five
   Crockford base32 digits: 26 for the key, 4 for a 20-bit checksum
   (`SHA-256("strongbox v1 kit" ‖ key)`), so a key typed back from paper is
   either right or refused (every single-digit typo is caught in the tests).
   Reading accepts any case, O for 0, I/L for 1, with or without hyphens.
2. **Master key** (`crates/core/src/kdf.rs`, **done**):
   `pw_key = Argon2id(NFKC(master_password), salt, m = 256 MiB, t = 3, p = 1, 32 bytes)`
   (about 0.6 s on the laptop), then
   `master_key = HKDF-Extract-SHA256(salt = account_id, ikm = pw_key ‖ secret_key)`.
   The Argon2 parameters are stored with the account so they can be raised,
   and `KdfParams::new` only accepts 64 MiB..=4 GiB, 2..=64 passes and
   1..=16 lanes: a server handing back parameters can neither weaken the
   derivation nor exhaust the client's memory.
3. **Two independent subkeys** from `master_key` with HKDF-Expand:
   `wrap_key` (info `"strongbox v1 wrap"`) and `auth_key` (info
   `"strongbox v1 auth"`). The server may learn `auth_key`; that reveals
   nothing about `wrap_key`.

   Verified three ways: the RFC 9106 Argon2id vector, the RFC 5869 HKDF
   vector, and our whole derivation (fast and real parameters, and a Unicode
   password) against `tools/kdf_reference.py`, an independent Python
   implementation over the Argon2 reference C code. Decisions and why:

   - **NFKC** so the same password typed on another device (composed `é` or
     `e` + combining accent, ligatures) gives the same key. The normalized
     length is measured first so the string is allocated once.
   - **The Argon2 memory is ours**, in a `Zeroizing<Vec<Block>>` passed to
     `hash_password_into_with_memory`. With `argon2` 0.6 the crate's own
     allocation is freed **without being wiped** even with its `zeroize`
     feature, and those 256 MiB determine the output (the last blocks are
     XORed and hashed). The crate's `alloc` feature is off, so the
     non-wiping path does not even compile.
   - **`Hkdf::new` discards the PRK (our master key) unwiped**, so `extract`
     is used and the returned PRK zeroized; `sha2` has `zeroize` on so the
     HMAC states are wiped on drop.
   - Keys live in `Box<[u8; 32]>` (a move copies only the pointer), are
     wiped on drop and print as `[REDACTED]`. Stack copies made inside
     dependencies cannot be reached; wiping is best effort, as with any Rust
     code.
4. **Vault key wrapping** (`crates/core/src/seal.rs`, **done**): `vault_key`
   encrypted with XChaCha20-Poly1305 under `wrap_key`, random 24-byte nonce,
   AAD = `"strongbox v1 vault-key" ‖ account_id`.

   **Changing the master password rotates the vault key** (`change_password`,
   `passforme passwd`): new salt, new vault key, every item re-sealed at the
   next revision; account id and Secret Key stay. Re-wrapping the old vault
   key alone would change the password, but an older copy of the file (a
   backup, `.bak`, the server) would still open with the old password and give
   the key protecting everything written afterwards — exactly wrong when the
   password is changed because it leaked. With rotation an old password opens
   old copies only, as they were. The CLI also deletes `vault.json.bak` after
   the change, since it would open with the old password.
5. **Items** (**done**): padded, encrypted with XChaCha20-Poly1305 under
   `vault_key`, fresh random nonce per write, AAD =
   `"strongbox v1 item" ‖ account_id ‖ item_id ‖ revision (u64 BE)`. Random
   192-bit nonces make reuse negligible without any counter state. Items are
   at most 1 MiB.

   Wire format of both: `version (1) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`.
   The AAD is authenticated, not stored: a domain string and then only
   fixed-length fields, so it is unambiguous, and a ciphertext opens only as
   what it was sealed as — another account's item, another item, another
   revision, or the wrapped vault key presented as an item all fail.

   Verified: the XChaCha20-Poly1305 draft vector (draft-irtf-cfrg-xchacha-03
   A.3.1), both formats byte for byte against `tools/seal_reference.py`
   (libsodium through PyNaCl), every single-bit flip of a sealed item
   rejected, every wrong context rejected. Decisions and why:

   - **Padding to a power of two, at least 256 bytes** (ISO/IEC 7816-4:
     `0x80` then zeros). Every password and short note lands in the same
     256-byte bucket, so ciphertext length reveals nothing about them; long
     notes leak only their size class. It is stripped only after the tag
     checks, so there is no padding oracle.
   - **One opaque error (`Rejected`)** for every authentication failure: the
     caller cannot tell a wrong key from tampering, and neither can anyone
     watching it.
   - **Encryption in place** in a buffer allocated once at its final size
     (the detached AEAD API, no `alloc` feature), so no plaintext copy is
     left; decryption output is `Zeroizing`. `chacha20poly1305` has
     `zeroize` on, wiping its key copy on drop.
   - **The revision in the AAD** stops a server from passing an old version
     of an item off as the current one under the current revision number.
     Serving an old revision *with* its old number is the whole-vault
     rollback in the threat model, handled at sync level.

6. **Authentication to the server** (**done**, decided 2026-09-29): the client
   sends `auth_key` as `Authorization: Bearer` over HTTPS and the server stores
   only `SHA-256("strongbox v1 auth-hash" ‖ auth_key)`, compared in constant
   time. A fast hash is enough because the key is 256 bits derived from the
   master password *and* the Secret Key: nothing about it can be guessed, and
   the hash only keeps a leaked server copy from being replayed as a login.
   A PAKE (OPAQUE) would hide even `auth_key` from the server; not worth its
   complexity while `auth_key` opens nothing.
