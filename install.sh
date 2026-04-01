#!/bin/sh
# Numa installer — detects OS/arch and downloads the latest release
# Usage: curl -sSL https://raw.githubusercontent.com/razvandimescu/numa/main/install.sh | sh
set -e

REPO="razvandimescu/numa"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Darwin) OS_NAME="macos" ;;
  Linux)  OS_NAME="linux" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH_NAME="x86_64" ;;
  arm64|aarch64) ARCH_NAME="aarch64" ;;
  *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET="numa-${OS_NAME}-${ARCH_NAME}.tar.gz"

echo ""
echo "  \033[1;38;2;192;98;58mNuma\033[0m installer"
echo ""
echo "  OS:   $OS_NAME"
echo "  Arch: $ARCH_NAME"
echo ""

# Get latest release tag
echo "  Fetching latest release..."
TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$TAG" ]; then
  echo "  Error: could not find latest release."
  echo "  Check https://github.com/${REPO}/releases"
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
echo "  Downloading ${TAG}..."

# Download and extract
TMP=$(mktemp -d)
curl -sSL "$URL" -o "$TMP/$ASSET"
tar xzf "$TMP/$ASSET" -C "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/numa" "$INSTALL_DIR/numa"
else
  echo "  Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "$TMP/numa" "$INSTALL_DIR/numa"
fi

chmod +x "$INSTALL_DIR/numa"

# macOS: ad-hoc codesign (required or the binary gets killed)
if [ "$OS_NAME" = "macos" ]; then
  codesign -f -s - "$INSTALL_DIR/numa" 2>/dev/null || true
fi

rm -rf "$TMP"

echo ""
echo "  \033[38;2;107;124;78mInstalled:\033[0m $INSTALL_DIR/numa ($TAG)"
echo ""
echo "  Get started:"
echo "    sudo numa install            # install service + set as system DNS"
echo "    open http://localhost:5380   # dashboard"
echo ""
echo "  Other commands:"
echo "    sudo numa                    # run in foreground (no service)"
echo "    sudo numa uninstall          # restore original DNS"
echo ""
