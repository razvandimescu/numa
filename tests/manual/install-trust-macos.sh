#!/usr/bin/env bash
#
# Manual macOS CA trust contract test.
#
# Mirrors src/system_dns.rs::trust_ca_macos / untrust_ca_macos by running
# the same `security` shell commands against a fixture cert with a unique
# CN. Safe to run alongside a production numa install:
#
#   - Test cert CN = "Numa Local CA Test <pid-ts>", always strictly longer
#     than the production CN "Numa Local CA". `security find-certificate -c`
#     does substring matching, so the test's search for $TEST_CN can never
#     match the production cert (the search term is longer than the prod CN).
#   - All deletes use `delete-certificate -Z <hash>`, which only touches the
#     cert with that exact hash. Production and test certs have different
#     hashes by construction (different key material), so the delete cannot
#     reach the production cert even if a CN search somehow returned both.
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

# Notice if production numa is already installed. We proceed regardless —
# see header for why coexistence is safe (unique CN + by-hash deletion).
if security find-certificate -c "$PROD_CN" "$KEYCHAIN" >/dev/null 2>&1; then
    echo "  note: production '$PROD_CN' detected — proceeding alongside (test cert can't touch it)"
    echo
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
