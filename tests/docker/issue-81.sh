#!/usr/bin/env bash
#
# End-to-end validation of the issue #81 fix (config path advisory).
#
# Builds numa from two source trees — the buggy baseline and the fix
# candidate — inside one debian:bookworm container, then runs four
# scenarios to prove:
#
#   1. replication/main  — reporter's sequence, bug confirmed
#   2. replication/fix   — reporter's sequence, bug is gone
#   3. existing/main     — pre-installed config at FHS data dir still loads
#   4. existing/fix      — same, unchanged by the fix (no regression)
#
# Scenarios 3 and 4 guard against the fear that the fix might change
# candidate order and break existing daemon installs (including the
# macOS Homebrew-prefix layout at /usr/local/var/numa/).
#
# Usage:
#   MAIN_SRC=/path/to/main-checkout FIX_SRC=/path/to/fix-worktree \
#     ./tests/docker/issue-81.sh
#
# Defaults: MAIN_SRC = $(git rev-parse --show-toplevel), FIX_SRC = same.

set -euo pipefail

MAIN_SRC="${MAIN_SRC:-$(git rev-parse --show-toplevel)}"
FIX_SRC="${FIX_SRC:-$MAIN_SRC}"

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

echo "── issue #81 validation ──"
echo "  main: $MAIN_SRC"
echo "  fix:  $FIX_SRC"
echo

docker run --rm \
    --platform linux/amd64 \
    -v "$MAIN_SRC:/main:ro" \
    -v "$FIX_SRC:/fix:ro" \
    -v "$(dirname "$0")/hold53.py:/tmp/hold53.py:ro" \
    -v numa-port53-cargo:/root/.cargo \
    -v numa-port53-target:/work/target \
    debian:bookworm bash -c '
set -euo pipefail

# Paths and ports used by all scenarios — keep in one place so the
# heredocs and the verdict greps cannot drift.
XDG_CONFIG="/root/.config/numa/numa.toml"
FHS_CONFIG="/var/lib/numa/numa.toml"
TEST_PORT="5354"
TEST_API_PORT="5380"

apt-get update -qq && apt-get install -y -qq curl build-essential python3 2>&1 | tail -1
if ! command -v cargo &>/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"

build_from() {
    local label="$1"; local src="$2"
    mkdir -p "/work/$label"
    tar -C "$src" --exclude=./target --exclude=./.git -cf - . | tar -C "/work/$label" -xf -
    (cd "/work/$label" && cargo build --release --locked 2>&1 | tail -1)
    cp "/work/$label/target/release/numa" "/work/numa-$label"
}

build_from main /main
build_from fix /fix

holder=0
stop_holder() {
    if [ "$holder" -ne 0 ]; then
        kill "$holder" 2>/dev/null || true
        wait "$holder" 2>/dev/null || true
        holder=0
    fi
}
trap stop_holder EXIT

start_holder() {
    python3 /tmp/hold53.py &
    holder=$!
    sleep 0.3
}

write_test_config() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<EOF
[server]
bind_addr = "127.0.0.1:$TEST_PORT"
api_port = $TEST_API_PORT
EOF
}

verdict() {
    local label="$1"; local expected="$2"; local file="$3"
    # "cannot bind to" is printed by the advisory when numa fails to start.
    # Its absence is a reliable proxy for "numa bound successfully" because
    # the banner-only log we capture contains no other failure surface.
    if grep -q "cannot bind to" "$file"; then
        echo "  [$label] did not bind $TEST_PORT — numa ignored the XDG config"
        [ "$expected" = "ignored" ] && return 0 || return 1
    else
        echo "  [$label] bound $TEST_PORT — config loaded"
        [ "$expected" = "bound" ] && return 0 || return 1
    fi
}

scenario_replication() {
    local label="$1"; local bin="/work/numa-$label"; local expected="$2"
    echo
    echo "════════ REPLICATION / $label ════════"
    rm -rf /root/.config/numa /var/lib/numa
    mkdir -p "$(dirname "$XDG_CONFIG")"

    start_holder
    set +e
    timeout 5 "$bin" > /tmp/run1.txt 2>&1
    set -e
    echo "── step 1: advisory printed by $label ──"
    grep -E "Create .* with:" /tmp/run1.txt | sed "s/^/  /" || echo "  <no advisory line>"

    write_test_config "$XDG_CONFIG"
    echo "── step 2: wrote config at $XDG_CONFIG ──"

    set +e
    timeout 3 "$bin" > /tmp/run2.txt 2>&1
    set -e
    stop_holder

    verdict "$label" "$expected" /tmp/run2.txt
}

scenario_existing_install() {
    local label="$1"; local bin="/work/numa-$label"
    echo
    echo "════════ EXISTING INSTALL / $label ════════"
    rm -rf /root/.config/numa /var/lib/numa
    write_test_config "$FHS_CONFIG"

    start_holder
    set +e
    timeout 3 "$bin" > /tmp/run.txt 2>&1
    set -e
    stop_holder

    verdict "$label" "bound" /tmp/run.txt
}

RC=0
scenario_replication main ignored || RC=1
scenario_replication fix bound || RC=1
scenario_existing_install main || RC=1
scenario_existing_install fix || RC=1

echo
if [ "$RC" -eq 0 ]; then
    echo "── all scenarios matched expectations ──"
else
    echo "── FAILURE: one or more scenarios diverged ──"
fi
exit $RC
'
