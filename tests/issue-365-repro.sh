#!/usr/bin/env bash
# Client-side half of issue #365: "ODoH relay returned 404 Not Found".
#
# The old message named the relay for a status the relay may only have
# proxied, so three unrelated misconfigurations rendered one line and none
# of them said which hop to fix:
#
#   A  correct relay + correct target        → NOERROR (control)
#   B  relay path typo (trailing slash)      → 404, never reached the target
#   C  target path typo, crypto.sx           → 404 from the target, empty body
#   D  target path typo, cloudflare          → 404 from the target, HTML body
#
# After the fix B names the relay URL and upstream.relay, while C and D name
# the target URL — the reporter would have read their own answer off the log.
# Attribution comes from the response media type: a relay that forwarded
# returns the target's answer as application/oblivious-dns-message (RFC 9230
# §4.3); its own rejections, and a front proxy 404ing a mistyped path before
# the relay sees it, do not.
#
# The relay half of the fix is tests/docker/odoh-relay-routing.sh.
#
# Live network required: hits the public relay and two public ODoH targets.
# Read-only — four DNS queries and two header probes.
#
# Usage:
#   tests/issue-365-repro.sh
#   RELAY=https://my-relay.example/relay tests/issue-365-repro.sh
#   NUMA_BIN=./target/release/numa tests/issue-365-repro.sh

set -euo pipefail

NUMA_BIN="${NUMA_BIN:-./target/debug/numa}"
RELAY="${RELAY:-https://odoh-relay.numa.rs/relay}"
WORKDIR="$(mktemp -d)"
NUMA_PID=""
NUMA_PORT=15353
NUMA_API_PORT=15380

GREEN=$'\033[32m'
RED=$'\033[31m'
DIM=$'\033[90m'
RESET=$'\033[0m'

cleanup() {
    stop_numa
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

stop_numa() {
    if [ -n "$NUMA_PID" ]; then
        kill "$NUMA_PID" 2>/dev/null || true
        wait "$NUMA_PID" 2>/dev/null || true
        NUMA_PID=""
    fi
}

if [ ! -x "$NUMA_BIN" ]; then
    echo "${RED}✗${RESET} numa binary not found at $NUMA_BIN — run 'cargo build' first"
    exit 2
fi

# Run one ODoH config through numa and print the rcode plus the upstream
# error line, which is what the reporter pasted into the issue.
run_case() {
    local relay="$1" target="$2"

    cat > "$WORKDIR/numa.toml" <<EOF
[server]
bind_addr = "127.0.0.1:${NUMA_PORT}"
api_port = ${NUMA_API_PORT}
data_dir = "${WORKDIR}"

[upstream]
mode = "odoh"
relay = "${relay}"
target = "${target}"

[blocking]
enabled = false
EOF

    "$NUMA_BIN" "$WORKDIR/numa.toml" --no-system-dns >"$WORKDIR/numa.log" 2>&1 &
    NUMA_PID=$!
    sleep 3

    local rcode err
    rcode=$(dig @127.0.0.1 -p "$NUMA_PORT" example.com A +time=6 +tries=1 2>/dev/null |
        awk '/status:/{print $6}' | tr -d ',' || true)
    err=$(grep -oE 'UPSTREAM ERROR \| .*$' "$WORKDIR/numa.log" | tail -1 || true)
    stop_numa

    echo "  ${DIM}relay ${relay}${RESET}"
    echo "  ${DIM}target${RESET} ${target}"
    if [ -n "$err" ]; then
        echo "  ${RED}${rcode:-no answer}${RESET} — ${err}"
    else
        echo "  ${GREEN}${rcode:-no answer}${RESET}"
    fi
    echo
}

echo "── A. control: correct relay, correct target ───────────────────────"
run_case "$RELAY" "https://odoh.crypto.sx/dns-query"

echo "── B. relay path typo — the relay never sees the request ───────────"
run_case "${RELAY}/" "https://odoh.crypto.sx/dns-query"

echo "── C. target path typo — 404 from the target, empty body ───────────"
echo "   ${DIM}relay is spelled correctly; pre-fix this read identically to B${RESET}"
run_case "$RELAY" "https://odoh.crypto.sx/dns-query/"

echo "── D. target path typo, cloudflare — 404 with an HTML body ─────────"
echo "   ${DIM}cloudflare 301s a bad path; a relay that follows redirects launders${RESET}"
echo "   ${DIM}that into a 404 from a host the client never named${RESET}"
run_case "$RELAY" "https://odoh.cloudflare-dns.com/dns-query/"

# Which hop answered is visible in the response headers, but numa discards
# them: Caddy's own 404 carries `server: Caddy`, anything proxied from the
# numa binary behind it carries `via: 1.1 Caddy` instead.
echo "── header provenance of the two 404s ───────────────────────────────"
for path in "/relay?targethost=odoh.crypto.sx&targetpath=/dns-query" "/relay/"; do
    printf '  %-52s ' "POST ${path}"
    curl -s -D- -o /dev/null --max-time 8 -X POST \
        -H 'content-type: application/oblivious-dns-message' \
        --data-binary 'probe' "${RELAY%/relay}${path}" |
        tr -d '\r' | grep -Ei '^(HTTP|via|server):?' | tr '\n' ' '
    echo
done
