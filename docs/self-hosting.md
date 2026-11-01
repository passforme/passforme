# Running your own sync server

`passforme` works without a server: the vault lives on the device. A
server is only needed to keep several devices in sync, and it is yours:
`passforme-server` stores the vault exactly as the client encrypted it,
holds no key able to decrypt it, and serves a single account.

## What the server needs

- A small Linux machine that stays on. It uses a few MB of memory: the
  author's runs in a VM with 1 vCPU and 512 MB on a home server.
- **HTTPS.** The client talks plain HTTP only to `localhost`; the server
  itself speaks plain HTTP on `127.0.0.1:8090`, so something in front of
  it terminates TLS.
- **A private network, preferably.** Nothing in the vault can be read or
  guessed from the server, but a server nobody else can reach is one less
  thing to defend. The setup we recommend, and run ourselves, is
  [Tailscale](https://tailscale.com): `tailscale serve` gives the machine
  an HTTPS address with a valid certificate that only your own devices can
  reach, and nothing is opened to the internet or the LAN.

```sh
tailscale serve --bg --https=443 http://127.0.0.1:8090
```

A public reverse proxy (Caddy, nginx) works too; then the server is
reachable by anyone, and its defences are the ones in
[`threat-model.md`](threat-model.md): a 256-bit authentication key and
single-use invites for registration.

## Option A: systemd (what the author runs)

From the [release](https://github.com/passforme/passforme/releases)
archive, which holds `passforme-server` and `passforme-server.service`:

```sh
sudo useradd --system --no-create-home --home-dir /var/lib/passforme \
  --shell /usr/sbin/nologin passforme
sudo install -m 755 passforme-server /usr/local/bin/
sudo install -m 644 passforme-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now passforme-server
```

The unit confines the process: loopback only, no capabilities, a
read-only system, 64 MB of memory (`systemd-analyze security
passforme-server` rates it 1.1). Data goes to `/var/lib/passforme`.

To update, install the new binary and `sudo systemctl restart
passforme-server`. Contributors deploy from a checkout with `bin/deploy`
(settings in `config/deploy.env`, see `config/deploy.env.example`).

## Option B: Docker

Every release publishes `ghcr.io/passforme/passforme-server` for amd64
and arm64, built from the same binary as the archive. With
[`contrib/compose.yml`](../contrib/compose.yml):

```sh
docker compose up -d
```

It runs as a non-root user with a read-only filesystem, no capabilities,
64 MB of memory, the vault in the `passforme-data` volume and the port
published on `127.0.0.1:8090` only. To update, `docker compose pull &&
docker compose up -d`.

## Linking the first device

The server accepts one account, registered with a single-use invite
valid for one hour, so nobody else can claim it first. On the server:

```sh
sudo -u passforme passforme-server --data /var/lib/passforme invite              # systemd
docker compose exec passforme passforme-server --data /data invite              # Docker
```

Then, on the device that holds the vault:

```sh
pfm register https://pfm.example.com     # asks for the invite
```

Every other device joins with `pfm login https://pfm.example.com`, which
asks for the Secret Key and the master password.

## Backups

The data directory (`/var/lib/passforme`, or the Docker volume) holds
only ciphertext: the vault, its last 30 versions in `history/`, and the
hash of the authentication key. Copy it anywhere; it is useless without
the master password **and** the Secret Key. Every linked device also
keeps a full copy of the vault.
