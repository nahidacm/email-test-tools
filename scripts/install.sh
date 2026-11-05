#!/bin/sh
# Email Test Tools installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/nahidacm/email-test-tools/main/scripts/install.sh | sh
#
# Options (environment variables):
#   VERSION=v0.1.0     install a specific release (default: latest)
#   INSTALL_DIR=/path  where to put the binary (default: /usr/local/bin if writable, else ~/.local/bin)
set -eu

REPO="nahidacm/email-test-tools"
BIN="email-test-tools"

say()  { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not installed."; }

need uname; need tar
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
  fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  fetch_stdout() { wget -qO- "$1"; }
else
  fail "curl or wget is required."
fi

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) fail "Unsupported system $(uname -s). On Windows, use the setup.exe from the releases page." ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) fail "Unsupported CPU $(uname -m)." ;;
esac

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  say "Finding the latest release…"
  VERSION=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || fail "Could not determine the latest version. Set VERSION=vX.Y.Z and retry."
fi
NUM="${VERSION#v}"
FILE="${BIN}_${NUM}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading $FILE ($VERSION)…"
fetch "$URL/$FILE" "$TMP/$FILE" || fail "Download failed: $URL/$FILE"
fetch "$URL/checksums.txt" "$TMP/checksums.txt" || fail "Could not download checksums."

say "Verifying checksum…"
EXPECTED=$(grep " $FILE\$" "$TMP/checksums.txt" | awk '{print $1}')
[ -n "$EXPECTED" ] || fail "No checksum listed for $FILE."
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP/$FILE" | awk '{print $1}')
else
  ACTUAL=$(shasum -a 256 "$TMP/$FILE" | awk '{print $1}')
fi
[ "$EXPECTED" = "$ACTUAL" ] || fail "Checksum mismatch. The download may be corrupted."

tar -xzf "$TMP/$FILE" -C "$TMP" "$BIN"

if [ -z "${INSTALL_DIR:-}" ]; then
  if [ -w /usr/local/bin ]; then INSTALL_DIR=/usr/local/bin
  elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then INSTALL_DIR=/usr/local/bin; USE_SUDO=1
  else INSTALL_DIR="$HOME/.local/bin"
  fi
fi
mkdir -p "$INSTALL_DIR" 2>/dev/null || true

say "Installing to $INSTALL_DIR/$BIN"
if [ "${USE_SUDO:-0}" = 1 ]; then
  sudo install -m 0755 "$TMP/$BIN" "$INSTALL_DIR/$BIN"
else
  install -m 0755 "$TMP/$BIN" "$INSTALL_DIR/$BIN"
fi

# macOS: remove the download quarantine flag so Gatekeeper doesn't block the unsigned binary.
if [ "$OS" = darwin ]; then
  xattr -d com.apple.quarantine "$INSTALL_DIR/$BIN" 2>/dev/null || true
fi

# shellcheck disable=SC2016  # $PATH is meant literally in the printed hint
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf '\n  Note: %s is not in your PATH. Add this line to your shell profile:\n    export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR" ;;
esac

printf '\n  \033[1;32m✓ Email Test Tools %s installed.\033[0m\n  Run:  %s\n  It opens in your browser at http://127.0.0.1:8587\n\n' "$VERSION" "$BIN"
