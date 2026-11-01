# How passforme works, and why

Everything about passforme that is not in the code: what each part is
for, every command, and the reasoning behind each decision, including
what was rejected. Written so that a person, or the agent they hand it
to, gets the whole picture from this one file.
[`AGENTS.md`](../AGENTS.md) holds the rules and the layout and points
here; [`threat-model.md`](threat-model.md) and
[`cryptography.md`](cryptography.md) hold the security design and are
required reading before touching anything that handles a secret.

## Name

The project began as `strongbox` and was renamed because another
password manager already used that name. Two things keep the earlier
name **on purpose** and must never be "fixed": the
domain labels of the cryptography (`"strongbox v1 wrap"`, `"strongbox v1
item"` and the rest, listed in `cryptography.md`), which are inputs to key derivation and
encryption, and the `SB1-` prefix of the Secret Key, printed on every
Emergency Kit. Changing either would make existing vaults and kits
unreadable.

## Password generator

`crates/core/src/generator.rs`. Two modes, each reporting its exact entropy
(`log2` of the number of equally likely outputs):

- **Random characters:** length 4..=1024, classes lowercase, uppercase,
  digits and the 32 ASCII symbols. **Default: 29 letters and digits, no
  symbols (172.6 bits)**, in the style of `DOz8kNqus39NRlzgUDAgQyKnMXf2B`:
  stronger than 24 characters with symbols (157.2 bits), and nothing that breaks in a
  form, a shell or a URL, or stops a double-click from selecting it.
  `--symbols` adds them for sites that demand one. Optionally without
  ambiguous characters (`Il1|O0o'"` and backtick).
  At least one character of each enabled class, by **rejection sampling** of
  the whole string, so the output is uniform over exactly the valid strings;
  the entropy is counted by inclusion-exclusion, checked against brute force.
- **Passphrases:** 3..=64 words (default 6, separator `-`: 77.5 bits) from
  the EFF large wordlist, embedded verbatim and pinned by SHA-256
  (`addd3553…b903e`, the file from eff.org and an independent mirror were
  byte-identical). Four words contain a hyphen; none has both halves in the
  list, so `-` never makes two passphrases equal (a test keeps it so).
- **Passphrases in Brazilian Portuguese** (a scene is easier to picture
  and remember in one's own language): the
  BIP-39 Portuguese wordlist, the one Bitcoin wallets use for recovery
  phrases, embedded verbatim and pinned by SHA-256 (`2685e9c1…7d79cd3f`;
  `bitcoin/bips` and Trezor's `python-mnemonic` were byte-identical). 2048
  words, only `a`-`z` (no accents to type), each fixed by its first four
  letters: 11 bits a word, so 7 Portuguese words ≈ 6 English ones. Chosen
  over a home-made list because it is curated, widely reviewed and stable.
  `--lang en|pt-br`; without it the CLI follows the locale (`LC_ALL`,
  `LC_MESSAGES`, `LANG`; `pt…` means Portuguese).

Decisions and why:

- **Own rejection sampling instead of `rand`'s ranges.** `rand` 0.10
  documents that its uniform integer sampling "may have a small bias" unless
  the `unbiased` feature is on. The bias is negligible (about 2^-96 per draw),
  but a password generator should be exactly uniform by construction, not by a
  feature flag; `uniform_index` is five reviewable lines. That also drops
  `rand` for the much smaller `rand_core`.
- **No stray copies.** Candidates live in `Zeroizing` buffers, and the final
  `String` is allocated with its exact length: `SecretString::from(String)`
  calls `into_boxed_str`, which would otherwise reallocate and leave an
  unwiped copy behind.

## The CLI (`passforme`)

Install from a checkout: `cargo install --path crates/cli --locked`.
Everyone else: `install.sh` at the root (the README's one line), which downloads the latest release for the machine, checks its
`.sha256` and installs `passforme` and `pfm` into `~/.local/bin`; it
depends on the archive names that `release.yml` produces, so the two
change together.

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

**Long options only** (`-u` beside `--url`, and a short form for `--kind`
in one command but not another, make options hard to remember). Every
option is spelled out (`--username`, `--generate`, `--symbols`); only
`-h` stays. Short forms typed from habit (`-u -g -k -s -l -w -f`), and
`--field`/`--secret-field` in `edit` (where the names are
`--set-field`/`--set-secret-field`, since `--field` in `get` means "which
field to copy"), are answered with the right name and exit 2, before
clap parses anything. The typing is paid back by Tab completion
(`clap_complete`): `completions bash` prints the script for both
`passforme` and `pfm`, kinds included (`--kind` takes the names from
`Kind::ALL`, so a wrong kind also gets the list). Sourcing it from
`~/.bashrc` (0.15 s for an interactive bash) keeps it matching the
installed binary; the `bash-completion` package is not needed.

**No option is ignored** (`add X --symbols` without `--generate` must
not silently ask for a password). Generator options in `add`
and `edit` need `--generate`; character options (`--length`, `--symbols`,
`--no-*`, `--avoid-ambiguous`) conflict with `--words`, and `--lang` and
`--separator` require it (clap rules, so they are refused before any
prompt; `length` and `separator` are `Option`s rather than clap defaults so
that an explicit default counts as given). `add --kind` refuses
`--username`, `--url` and `--file` for kinds without that slot, and
`--generate` except for `login`, `wifi` and `bank`, whose secret is a
password; `edit --generate` refuses the same kinds.

`QUERY` is a title, case-insensitive; an exact title wins, otherwise it must
be part of exactly one title. Commands that read the vault ask for the
master password, unless a **session** is open (below).

**Session** (`crates/cli/src/keeper.rs`; typing a long phrase for every
lookup is too much). Like `sudo`, the
master password typed at a terminal opens a session, and the next commands
at a terminal do not ask again until the vault sits unused for 15 minutes
(each use starts the time again), a screen locker runs, or `passforme lock`.
Configurable in `~/.config/passforme/config`:

```
session = 15m    # or 1h, 30s…; `off` asks every time
```

Decisions and why:

- **A separate process from the unlock agent**, with its own socket
  (`session.sock`): the session holds the master password, so the whole
  vault, while the agent holds only the items marked for programs. Locking
  or refreshing one never moves secrets into the other.
- **Terminal only.** A command whose stdin is not a terminal neither uses
  nor opens a session, so programs (`get --stdout` from a script or a `key_command`)
  stay limited to the agent's marked items. This is a policy, not a wall:
  same-user malware can talk to the socket, as with every password manager
  that stays unlocked for a while; the idle time bounds that window.
- **It keeps the password, not a derived key.** Each command still spends
  ~0.6 s on Argon2, but sync, which may need to open the server's copy,
  works exactly as with a typed password. For this vault the password and
  its keys are worth the same to a thief, and the phrase is used nowhere
  else.
- **Locks on a screen locker**: a watcher looks every 2 s for `hyprlock`
  (or `swaylock`, `gtklock`, `waylock`, `i3lock`) of this user in `/proc`.
  `hypridle` is usually set to run `loginctl lock-session` before a
  suspend, so suspending locks it too; the idle time is wall-clock, so a
  longer suspend would expire it anyway. Watching `/proc` instead of
  logind's D-Bus signals keeps a D-Bus library out, and asks nothing of
  the user's idle daemon configuration.
- **Only a password that opened the vault opens a session**; a wrong one
  never does. If the kept password stops opening the vault (changed on
  another device), the session is closed and the password asked. `passwd`
  closes it; a password changed elsewhere and typed during sync replaces it.
- A broken config file is reported and means no session, never a silent
  default: a typo (`sesion = 1h`) is an error.

Tested in a pty with throwaway dirs: typed once → next command
asks nothing; piped command and `get --stdout` without a terminal ignore
it; `lock` removes it; wrong password opens none; `session = 3s` expires,
and each use renews it; a process named `hyprlock` closes it within 2 s;
`off` and a typo open none. Socket paths must fit in 108 bytes (`SUN_LEN`):
a test with a long `XDG_RUNTIME_DIR` failed to open a session, harmlessly.

**Kinds of item** (`crates/core/src/kind.rs`, `crates/cli/src/kinds.rs`;
every kind of password and security code should fit). An item has a `kind`; each kind is a template —
which slots to ask for, in which order, under which labels — over the same
`Item`: the common slots (`username`, `password`, `urls`, `totp`, `notes`)
relabelled ("PIN", "Key", "Words", "Number"), plus named extra fields.

| Kind | Asks for |
|---|---|
| `login` (default) | secret typed twice, username and URLs from the command line |
| `note` | text |
| `recovery-codes` | account, URL, codes (one per line, may contain spaces) |
| `recovery-phrase` | account, URL, words (BIP-39 checked when its length fits; kept as typed otherwise) |
| `security-questions` | account, URL, question → concealed answer pairs |
| `pin` | PIN |
| `api-key` | account, key name (as the provider lists it), key, URL, expiry |
| `crypto-seed` | words (BIP-39 checked), passphrase, wallet, network |
| `ssh-key` | user, private key (`--file`), public key, key passphrase, URL |
| `card` | cardholder, number (Luhn checked), expiry (MM/YY checked), CVV, PIN |
| `bank` | bank, branch, account, login, app password, transaction password, Pix key, URL |
| `wifi` | network, password |
| `license` | registered to, license key, URL |
| `document` | number, issued, expires, issuer |

Decisions and why:

- **A template, not a schema.** Any item still takes any extra field, and
  `edit --kind` relabels an item without touching its data (e.g. one added
  with `add-many` that is really a PIN). Nothing is lost if a template
  changes: `show` lists the template's slots in order, then everything else.
- **No format bump.** `kind` and `codes` are optional JSON members: an
  item without them reads as `login` with no codes, and a client that
  does not know them lists the item ignoring its kind (tested both ways).
  Such a client *editing* the item would drop those members, which is
  acceptable while every device runs the current client. A kind from a
  newer version reads as `other` and shows like a login.
- **Recovery codes have storage of their own** (`codes: [{code, used}]`):
  `passforme codes X` copies the next unused one, marks it used, saves and
  syncs, and warns when two or fewer are left. Copying comes first, so a
  clipboard failure never burns a code.
- **Checks catch typos while the paper is at hand, and ask** ("save it
  anyway?") rather than refuse: the BIP-39 checksum of a recovery phrase
  (`crates/core/src/bip39.rs`; English and Portuguese lists pinned by
  SHA-256 and checked against the reference vectors; a wrong or swapped
  word fails with probability 15/16 at 12 words, 255/256 at 24), the Luhn
  digit of a card number, the MM/YY of an expiry. Errors name the
  position of a bad word, never the word.
- **`get` copies the main secret** (`password`, under whatever label), or
  for kinds without one (`document`) the first field; `--field` takes any name,
  case-insensitive, and an unknown one lists what the item has.
- **A private key comes from its file** (`--file`), byte for byte (tested:
  the copied key equals the file): pasting a multi-line key into a hidden
  prompt is unreliable.
- **`recovery-phrase`** (a service's recovery phrase, Proton's for one,
  fits `crypto-seed` only with "Wallet" and "Network" left empty). A
  service's phrase may or may not be BIP-39: it is checked only when its
  word count is one BIP-39 uses, a failure asks before saving (some
  services use the same lengths without BIP-39), and any other phrase is
  kept exactly as typed — only a phrase that checks is normalized.
- **Attachments** (for a service's recovery file, Proton's for one): `edit --attach`
  keeps small files inside the item (`attachments: [{name, data}]`, data
  in standard base64), sealed with it like every other field; `get
  --attachment NAME [--output PATH]` writes one back with `create_new` and
  mode 0600, so nothing is ever overwritten and the file is private from
  its first byte. At most **512 KiB per item**, raw: base64 makes it 683
  KiB, inside the 1 MiB an item may be, and the whole vault is uploaded on
  every change and kept 30 times in the server's history (a 64 MB
  `MemoryMax` there), so a vault is no place for big files. The agent
  never receives attachments: programs read values, not files. No format
  bump, as with kinds: an optional JSON member that older clients skip.
- Rejected: passkeys. They live in the browser or the phone's platform
  authenticator and cannot be used from a CLI.

**Files** (`crates/cli/src/store.rs`): `$PASSFORME_DIR`, or
`$XDG_DATA_HOME/passforme`, or `~/.local/share/passforme`, mode 0700, with
`vault.json` (0600, ciphertext only; the previous version kept as
`vault.json.bak`) and `secret-key` (0600, the Secret Key in Emergency Kit
text, refused if group or others can read it, as ssh does). The vault is
replaced atomically: temporary file, `fsync`, copy to `.bak`, `rename`,
`fsync` of the directory.

Decisions and why:

- **No secret on the command line or in the environment**, where `ps` and
  `/proc/*/environ` show them: master and item passwords are prompted without
  echo on `/dev/tty`. When stdin is not a terminal, each prompt reads one line
  from it instead (like `sudo -S`), which is how scripts and tests drive it.
- **`harden()` at start**: `RLIMIT_CORE` 0 and `PR_SET_DUMPABLE` 0, so a
  crash never writes the decrypted vault to a core file, and no other process
  of the same user can `ptrace` it or read its `/proc/<pid>/mem`.
- **Clipboard via `wl-copy`/`wl-paste`** (Wayland),
  the secret written to `wl-copy`'s stdin. Clearing after 30 s is done by a
  detached child of the binary (`passforme __clear-clipboard`, own process
  group so Ctrl-C does not kill it), which receives the SHA-256 of the secret
  on stdin and clears the clipboard **only if it still holds that secret**:
  anything the user copied since is left alone. The hash never goes on a
  command line (a hash of a weak password can be brute-forced).
- **Clipboard history managers defeat the 30 s clearing**: `cliphist`,
  `clipman` and the like store every copy on disk, passwords included.
  Check before installing one, and exclude `passforme` copies from it.
- **Minimum 12 characters** for the master password: the Secret Key makes a
  stolen *server* copy unguessable, but a stolen *laptop* has the Secret Key
  file next to the vault, and then only the master password and Argon2 stand
  in the way.
- **`edit` never takes a secret as an argument**: `--password`, `--totp` and
  `--set-secret-field` prompt without echo, `--set-field` prompts visibly, `--notes`
  reads lines until Ctrl-D (always the last prompt). Notes never touch a
  temporary file, so no editor swap file can leave them on disk.
- **TOTP** (`crates/core/src/totp.rs`): the item keeps what the service gave
  (base32 secret or `otpauth://` URI with algorithm, digits and period),
  validated when saved; codes checked against every RFC 6238 appendix B
  vector (SHA-1/256/512) and `tools/totp_reference.py`. Keeping the TOTP
  secret in the same vault as the password makes it one factor for whoever
  opens the vault; the convenience was chosen knowingly, as in 1Password.
- Items are only decrypted after the master password opens the vault key, and
  one item failing authentication aborts the listing: a tampered vault is
  reported, not partially shown.

## Unlock agent (for programs that need a secret)

Exists so that a program can read its API keys through a `key_command`,
which runs without a terminal and with an empty stdin.
Code in `crates/cli/src/agent.rs`.

```toml
# a program's config
[provider.openrouter]
key_command = ["passforme", "get", "openrouter", "--stdout"]
```

```
passforme edit openrouter --agent    # mark (or `add … --agent`); --no-agent unmarks
passforme unlock --for 8h            # master password once, at a terminal
passforme unlock --for forever       # no time limit: until lock, reboot or logout
passforme unlock --for 8h gemini     # only these (each must be marked)
passforme status                     # is it unlocked, and for how long
passforme lock                       # or wait for the time to run out
```

- **Scoped, the decision that matters:** the agent receives only the items
  marked `agent` (a field of the item, `false` by default), never the vault
  key. While it runs, any process of this user can read those items and
  nothing else; the bank password is simply not in it. Same-user malware
  can still take the marked items — no design prevents a program of yours
  from reading a secret another program of yours must use — but it cannot
  reach the rest of the vault.
- The agent is this binary (`passforme __agent SECS`), hardened like every
  command, detached in its own process group; items arrive as JSON on stdin.
  Socket `$XDG_RUNTIME_DIR/passforme/agent.sock` (directory 0700 and owned by
  the user, socket 0600), peer uid checked with `SO_PEERCRED`. On `lock`,
  when its time is up (1 s to 7 d, default 8 h), or when its socket is gone
  or replaced it wipes the items and exits; a watcher checks every 30 s.
- **`--for forever`** (a program must not stop working every 8 h): no time limit, so the marked items stay readable by this user's
  programs until `lock`, a reboot or a logout — the same exposure as the
  timed mode, for longer, and still never on disk. A reboot always needs a
  new `unlock` with the master password; avoiding that would mean storing
  it. The socket watcher exists for this mode: logind removes
  `/run/user/<uid>` when the session ends, and without it the agent would
  outlive its socket holding keys that nobody could lock anymore (tested: it
  exits 31 s after the socket vanishes).
- `get --stdout` prints the value alone, without a newline. Without an agent
  it asks for the master password on a terminal and **fails at once
  elsewhere**, so a program is never left waiting on a prompt. The agent and
  the CLI resolve a query with the same function (`pick_index`).
- **Selection:** `unlock ITEM…` hands over only the named items, and each
  must already be marked: two separate decisions, so a typo or a broad
  query (`unlock ban…` matching "Bank") can never expose an unmarked secret.
  The agent keeps the selection as item ids (renaming does not break it);
  without names it holds "every marked item".
- **Refresh:** `add`, `edit` and `rm` rebuild a running agent from the vault
  right after saving (and syncing), with the same selection and the time it
  had left: in "every marked item" mode a newly marked item joins; with a
  selection it stays out; an emptied selection locks the agent. The agent
  itself accepts no new values from anyone — only a command that has just
  opened the vault with the master password starts a new one. An agent
  whose status carries no selection is treated as "every marked item";
  tested.
- `unlock` syncs first when linked. `status` lists what the agent holds and
  for how long.
- Rejected: implementing the freedesktop Secret Service (D-Bus). Any program
  of the session could ask it for anything, and it is far more code.

Tested, called the way a `key_command` is (`setsid -w env -i … </dev/null`):
locked → fails in 3 ms; unlocked → exact value, no newline; unmarked item
refused while unlocked; socket 0600 in a 0700 directory; agent's
`/proc/<pid>/environ` unreadable; 3.7 MB; `lock` and the time limit both
remove it; a startup failure reaches `unlock` with its reason. **Not tested:**
a connection from another uid (needs a second account); the 0600 socket in a
0700 directory already stops it before `SO_PEERCRED`.

## Sync server (`passforme-server`) and sync

**Server** (`crates/server`): one account per server, `axum` on
`127.0.0.1:8090`, meant to sit behind `tailscale serve` (HTTPS). API in
`crates/core/src/api.rs`: `GET /api/v1/prelogin` (public: account id, salt,
Argon2 parameters — what a new device needs), `POST /api/v1/register`,
`GET`/`PUT /api/v1/vault` (bearer auth key; `PUT` carries `base_revision` and
gets `409` when stale). Data dir (`--data`, default `/var/lib/passforme`):
`state.json` (revision, account id, auth hash), `vault.json` exactly as
uploaded, `history/<rev>.json` (last 30 versions, ciphertext, for recovery
from a bad sync), `invite.json`. Every write atomic. Registration needs a
single-use invite valid for one hour (`passforme-server invite`, over SSH), so
nobody else on the tailnet can claim an empty server. It refuses uploads of
another account, and a new salt without a new auth key (or the reverse),
which would lock the client out. Failed auth and invites are logged, never
their values.

**Client** (`crates/cli/src/{remote,session,sync}.rs`, `ureq` with rustls
and the Mozilla roots; plain HTTP only for localhost):

```
passforme register URL   # put this vault on an empty server (asks for the invite)
passforme login URL      # new device: Secret Key + master password
passforme sync           # exchange changes
```

`add`, `edit` and `rm` sync right after saving when the vault is linked; if
the server is unreachable the change stays saved here, with a warning, and
goes up with the next `sync`. Reading commands stay local.

**Merge** (`crates/core/src/sync.rs`): three-way, per item, against
`sync-base.json` (the vault at the last sync), built on the server's copy so
its keys win. Nothing typed is lost: an item edited on both sides keeps the
server's version and the local one as `"<title> (conflict)"`; a deletion
against an edit keeps the edit. **Rollback defence:** the client remembers
the highest revision seen (`sync.json`) and refuses a lower one, and refuses
the same revision with different content. **Password changed elsewhere:**
the server refuses this device's auth key; the client asks for the current
password, and from then on uses it. **Password changed here** while linked:
`passwd` syncs first, rotates, and uploads with the old auth key plus the
new one; nothing is saved locally unless the server accepted it.

Tested end to end with a local server and two devices: register
(wrong invite refused, invite single-use), login (wrong password refused),
changes both ways, conflict copy, rollback and silent tampering refused,
password change carried to the other device, offline change pushed later, and
no plaintext anywhere in the server's data directory.

## Deployment

The server runs as a systemd service (unit in `contrib/`) on a small Linux
machine of the user's, a VM with 1 vCPU and 512 MB being plenty, reached
over HTTPS through `tailscale serve`. Only the server binary goes there,
with **`bin/deploy`**: it builds `passforme-server` here, copies it and
the unit to `DEPLOY_HOST`, installs both with `sudo`, restarts the service
and checks that `DEPLOY_URL` answers `/api/v1/prelogin`. Host, ssh options
and URL live in `config/deploy.env` (ignored by Git;
`config/deploy.env.example` documents it). Systemd rather than Docker
Compose: one static binary in a small VM gains nothing from a daemon and
a registry, and would lose the unit's confinement. **For others, both**:
every release also publishes `ghcr.io/passforme/passforme-server`
(amd64, arm64) from the same binaries, never rebuilt (`Dockerfile`,
`contrib/compose.yml`, non-root, read-only, no capabilities). How to
self-host, with Tailscale as the recommended setup:
`docs/self-hosting.md`.

First install also needs `useradd --system --no-create-home --home-dir
/var/lib/passforme --shell /usr/sbin/nologin passforme` and `tailscale serve
--bg --https=443 http://127.0.0.1:8090`. The unit confines the process to
loopback (`IPAddressDeny=any`, `IPAddressAllow=localhost`), 64 MB, no
capabilities: `systemd-analyze security` 1.1. Invite, on the server:
`sudo -u passforme passforme-server --data /var/lib/passforme invite`.

## Next

**A web client served by the sync server**, for the phone and
emergencies; the computer keeps the CLI. It decrypts in the browser
(`core` compiled to WASM), so whoever serves the page could serve one
that steals the master password: the weakness of every web vault
(Bitwarden's included), accepted for the convenience. The disk
encryption of the server does not help here: it covers physical access
to a powered-off machine, while this risk is a remote compromise of a
running one. Mitigations, all part of the plan:

- the server reachable only through `tailscale serve`, nothing on the LAN;
- the machine runs only `passforme-server`; the page is embedded in that
  binary, built elsewhere, with no third-party code and a strict CSP;
- the computer that builds it never uses the web client, so it never
  trusts code from the server;
- a watcher on that computer fetches the served page periodically,
  compares it byte for byte with the build, and alerts if it differs;
- the server still holds only ciphertext.

Rejected for now: a native phone app (Android sideloading is doable,
iPhone needs a paid developer account) and a browser extension
(autofill; maybe later). Rule regardless of client: **no code that
decrypts is delivered by the server without a signature made off the
server**, except this web client, by the decision above.
