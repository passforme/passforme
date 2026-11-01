#!/bin/sh
# Install the latest passforme release on Linux, from the GitHub Release:
#
#   curl -fsSL https://raw.githubusercontent.com/passforme/passforme/main/install.sh | sh
#
# Downloads passforme-<version>-<target>.tar.gz and its .sha256 for this
# machine, checks the checksum, and installs `passforme` and the short name
# `pfm` into ~/.local/bin. Nothing runs as root; nothing else is touched.
#
#   PASSFORME_VERSION=0.1.0        install that version instead of the latest
#   PASSFORME_INSTALL_DIR=/opt/bin install there instead of ~/.local/bin
#
# The archive also holds passforme-server and its systemd unit; this script
# leaves them in place, see docs/self-hosting.md for the server.
set -eu

repo="passforme/passforme"
name="passforme"
dir="${PASSFORME_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

for tool in curl tar sha256sum install; do
    command -v "$tool" >/dev/null 2>&1 || fail "needs $tool"
done

[ "$(uname -s)" = Linux ] || fail "passforme runs on Linux only (it needs prctl, /proc and wl-copy)"
case "$(uname -m)" in
    x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
    aarch64 | arm64) target="aarch64-unknown-linux-gnu" ;;
    *) fail "no release for $(uname -m); build from source: cargo install --path crates/cli" ;;
esac

version="${PASSFORME_VERSION:-}"
if [ -z "$version" ]; then
    # The /releases/latest page redirects to /releases/tag/vX.Y.Z; no API
    # call, so no rate limit.
    response="$(curl -sLI -o /dev/null -w '%{http_code} %{url_effective}' "https://github.com/$repo/releases/latest")" ||
        fail "could not reach github.com"
    code="${response%% *}"
    location="${response#* }"
    [ "$code" = 200 ] || fail "no release found at https://github.com/$repo/releases (HTTP $code)"
    version="${location##*/tag/v}"
    [ "$version" != "$location" ] && [ -n "$version" ] ||
        fail "unexpected release page $location"
fi

base="$name-$version-$target"
url="https://github.com/$repo/releases/download/v$version/$base.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "downloading $base.tar.gz"
curl -fsSL -o "$tmp/$base.tar.gz" "$url" ||
    fail "no archive at $url (is $version a released version?)"
curl -fsSL -o "$tmp/$base.tar.gz.sha256" "$url.sha256" ||
    fail "no checksum at $url.sha256"
(cd "$tmp" && sha256sum -c --quiet "$base.tar.gz.sha256") ||
    fail "checksum mismatch: the download is corrupt or has been tampered with"

tar -xzf "$tmp/$base.tar.gz" -C "$tmp"
mkdir -p "$dir"
install -m 755 "$tmp/$base/$name" "$dir/$name"
if [ ! -e "$dir/pfm" ] || [ -L "$dir/pfm" ]; then
    ln -sfn "$name" "$dir/pfm"
else
    echo "note: $dir/pfm exists and is not a link; left as is" >&2
fi

echo "installed $("$dir/$name" --version) to $dir"
case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "note: $dir is not on your PATH; add it to your shell's startup file" >&2 ;;
esac
echo "next: $name init   (tab completion: source <($name completions bash) in ~/.bashrc)"
