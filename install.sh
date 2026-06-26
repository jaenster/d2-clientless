#!/bin/sh
# Install the latest clientless release binary for this OS/arch.
#   curl -fsSL https://raw.githubusercontent.com/jaenster/d2-clientless/main/install.sh | sh
set -eu

REPO="jaenster/d2-clientless"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
    Linux)   OS=linux ;;
    Darwin)  OS=macos ;;
    FreeBSD) OS=freebsd ;;
    *) echo "clientless: unsupported OS '$os' — build from source"; exit 1 ;;
esac
case "$arch" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    armv7l|armv7)  ARCH=armv7 ;;
    riscv64)       ARCH=riscv64 ;;
    *) echo "clientless: unsupported arch '$arch' — build from source"; exit 1 ;;
esac

asset="clientless-${OS}-${ARCH}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

fetch() { # fetch <url> <out>
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
    elif command -v fetch >/dev/null 2>&1; then fetch -qo "$2" "$1"
    else echo "clientless: need curl, wget, or fetch"; exit 1; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "clientless: downloading ${asset} ..."
fetch "$url" "$tmp/c.tar.gz" || { echo "clientless: no prebuilt binary for ${OS}-${ARCH}"; exit 1; }
tar -xzf "$tmp/c.tar.gz" -C "$tmp"
bin=$(find "$tmp" -type f -name clientless | head -n 1)
[ -n "$bin" ] || { echo "clientless: binary not found in archive"; exit 1; }

dir=/usr/local/bin
SUDO=
if [ -w "$dir" ] || [ ! -e "$dir" -a -w "$(dirname "$dir")" ]; then
    :
elif command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
else
    dir="$HOME/.local/bin"
    mkdir -p "$dir"
fi

$SUDO install -m 0755 "$bin" "$dir/clientless"
echo "clientless: installed -> $dir/clientless"
case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "clientless: add '$dir' to your PATH" ;;
esac
echo "clientless: run 'clientless' for help"
