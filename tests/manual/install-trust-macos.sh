#!/usr/bin/env bash
#
# Manual macOS CA trust contract test.
#
# Mirrors src/system_dns.rs::trust_ca_macos / untrust_ca_macos by running
# the same `security` shell commands against a fixture cert with a unique
# CN. Designed to coexist with a running production numa: refuses to run
# if a real "Numa Local CA" cert is already present in System.keychain,
# and uses by-hash deletion (so it cannot accidentally touch a production
# CA even in the unlikely event the bail-out check is bypassed).
#
# Mutates the System keychain (briefly). Cleans up on success or interrupt.
# Requires sudo for `security add-trusted-cert` and `delete-certificate`.
#
# Usage: ./tests/manual/install-trust-macos.sh

set -euo pipefail

if [[ "$OSTYPE" != darwin* ]]; then
    echo "This test is macOS-only." >&2
    exit 1
fi

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

# Production constant from src/tls.rs::CA_COMMON_NAME — keep in sync.
PROD_CN="Numa Local CA"
KEYCHAIN="/Library/Keychains/System.keychain"

# Refuse to run if a real Numa CA is installed. The test cert has a unique
# CN that can never collide, but failing closed protects a dogfood install.
if security find-certificate -c "$PROD_CN" "$KEYCHAIN" >/dev/null 2>&1; then
    printf "${RED}refuse:${RESET} a '%s' cert is already in %s.\n" "$PROD_CN" "$KEYCHAIN"
    echo "  This is your production numa CA. To avoid any chance of touching it,"
    echo "  this test refuses to run. Either:"
    echo "    sudo numa uninstall   # then rerun this test, then reinstall"
    echo "  or accept that the macOS path is covered by manual smoke instead."
    exit 1
fi

# Unique CN ensures the test cert can never collide with production.
TEST_CN="Numa Local CA Test $$-$(date +%s)"
FIXTURE_DIR=$(mktemp -d)

cleanup() {
    # Best-effort: remove any test certs by hash if still present.
    if security find-certificate -c "$TEST_CN" "$KEYCHAIN" >/dev/null 2>&1; then
        echo "  cleanup: removing leftover test cert"
        security find-certificate -c "$TEST_CN" -a -Z "$KEYCHAIN" 2>/dev/null \
            | awk '/^SHA-1 hash:/ {print $NF}' \
            | while read -r hash; do
                sudo security delete-certificate -Z "$hash" "$KEYCHAIN" >/dev/null 2>&1 || true
            done
    fi
    rm -rf "$FIXTURE_DIR"
}
trap cleanup EXIT

echo "── generating fixture CA ──"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$FIXTURE_DIR/ca.key" \
    -out    "$FIXTURE_DIR/ca.pem" \
    -subj   "/CN=$TEST_CN" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
echo "  CN: $TEST_CN"
echo

echo "── trust step (mirrors trust_ca_macos) ──"
sudo security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$FIXTURE_DIR/ca.pem"
if security find-certificate -c "$TEST_CN" "$KEYCHAIN" >/dev/null 2>&1; then
    printf "  ${GREEN}✓${RESET} test cert found in keychain\n"
else
    printf "  ${RED}✗${RESET} test cert NOT found after add-trusted-cert\n"
    exit 1
fi
echo

echo "── untrust step (mirrors untrust_ca_macos) ──"
security find-certificate -c "$TEST_CN" -a -Z "$KEYCHAIN" 2>/dev/null \
    | awk '/^SHA-1 hash:/ {print $NF}' \
    | while read -r hash; do
        sudo security delete-certificate -Z "$hash" "$KEYCHAIN" >/dev/null
    done
if security find-certificate -c "$TEST_CN" "$KEYCHAIN" >/dev/null 2>&1; then
    printf "  ${RED}✗${RESET} test cert STILL present after delete (regression)\n"
    exit 1
fi
printf "  ${GREEN}✓${RESET} test cert removed from keychain\n"
echo

printf "${GREEN}all checks passed${RESET}\n"
