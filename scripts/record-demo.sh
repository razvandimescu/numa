#!/bin/bash
# record-demo.sh — Records a hero GIF of the Numa dashboard.
#
# Prerequisites: ffmpeg, gifsicle (optional), numa running, python3
# Usage: ./scripts/record-demo.sh [output.gif]
#
# The script:
#   1. Opens the dashboard in Chrome --app mode (clean, no address bar)
#   2. Generates DNS traffic (forward, cache hit, blocked)
#   3. Types "peekm" / "6419" into the Local Services form on camera
#   4. Opens peekm.numa to show the proxy working
#   5. Records via ffmpeg and converts to optimized GIF

set -euo pipefail

# --------------- Configuration ---------------
OUTPUT="${1:-assets/hero-demo.gif}"
PORT=5380
RECORD_SECONDS=20
VIEWPORT_W=1800
VIEWPORT_H=1100
FPS=12
GIF_WIDTH=800
MAX_GIF_SIZE_MB=5
CDP_PORT=9223

# --------------- State ---------------
FFMPEG_PID=""
CHROME_PID=""
MOV_FILE=""
CHROME_DATA_DIR=""
CDP_HELPER=""

# --------------- Helpers ---------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
log()  { echo -e "${GREEN}[demo]${NC} $1"; }
warn() { echo -e "${YELLOW}[demo]${NC} $1"; }
err()  { echo -e "${RED}[demo]${NC} $1" >&2; }

cleanup() {
    log "Cleaning up..."
    [ -n "$FFMPEG_PID" ] && kill "$FFMPEG_PID" 2>/dev/null || true
    [ -n "$CHROME_PID" ] && kill "$CHROME_PID" 2>/dev/null && wait "$CHROME_PID" 2>/dev/null || true
    [ -n "$MOV_FILE" ] && [ -f "$MOV_FILE" ] && rm -f "$MOV_FILE"
    [ -n "$CDP_HELPER" ] && rm -f "$CDP_HELPER"
    [ -n "$CHROME_DATA_DIR" ] && sleep 0.5 && rm -rf "$CHROME_DATA_DIR"
    log "Done."
}
trap cleanup EXIT

# --------------- CDP helper (Chrome DevTools Protocol) ---------------
CDP_HELPER=$(mktemp /tmp/numa-cdp-XXXXXX.py)
cat > "$CDP_HELPER" << 'PYTHON'
import json, socket, struct, os, sys, http.client, urllib.parse

def cdp_eval(port, js):
    conn = http.client.HTTPConnection('localhost', port, timeout=2)
    conn.request('GET', '/json')
    targets = json.loads(conn.getresponse().read())
    conn.close()
    page = next((t for t in targets if t.get('type') == 'page'), None)
    if not page:
        return
    ws_url = page.get('webSocketDebuggerUrl')
    if not ws_url:
        return
    parsed = urllib.parse.urlparse(ws_url)
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
    key = 'dGhlIHNhbXBsZSBub25jZQ=='
    handshake = (
        f"GET {parsed.path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(handshake.encode())
    sock.recv(4096)
    msg = json.dumps({"id": 1, "method": "Runtime.evaluate",
                       "params": {"expression": js}}).encode()
    mask = os.urandom(4)
    frame = bytearray([0x81])
    if len(msg) < 126:
        frame.append(0x80 | len(msg))
    elif len(msg) < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack('>H', len(msg)))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack('>Q', len(msg)))
    frame.extend(mask)
    frame.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(msg)))
    sock.sendall(bytes(frame))
    sock.recv(4096)
    sock.close()

if __name__ == '__main__':
    try:
        cdp_eval(int(sys.argv[1]), sys.argv[2])
    except Exception:
        pass
PYTHON

run_js() {
    python3 "$CDP_HELPER" "$CDP_PORT" "$1" 2>/dev/null || true
}

# Simulate typing into an input field character by character
type_into() {
    local selector="$1"
    local text="$2"
    local delay="${3:-0.08}"

    # Focus the field
    run_js "document.querySelector('$selector').focus();"
    sleep 0.2

    # Type each character
    for (( i=0; i<${#text}; i++ )); do
        local char="${text:$i:1}"
        run_js "
            var el = document.querySelector('$selector');
            el.value += '$char';
            el.dispatchEvent(new Event('input', {bubbles: true}));
        "
        sleep "$delay"
    done
}

# --------------- Dependency checks ---------------
for cmd in ffmpeg dig curl python3; do
    if ! command -v "$cmd" &>/dev/null; then
        err "$cmd is required but not found"
        exit 1
    fi
done

# Check numa is running
if ! dig @127.0.0.1 google.com +short +time=1 > /dev/null 2>&1; then
    err "Numa is not running. Start it with: sudo numa"
    exit 1
fi
log "Numa is running."

# Clean slate: remove peekm service if it exists from a previous run
curl -s -X DELETE "http://localhost:$PORT/services/peekm" > /dev/null 2>&1 || true

# Pre-populate traffic so dashboard looks alive from frame 1
log "Pre-populating DNS traffic..."
for domain in github.com google.com stackoverflow.com reddit.com cloudflare.com \
    fonts.googleapis.com api.github.com www.google.com cdn.jsdelivr.net; do
    dig @127.0.0.1 "$domain" +short > /dev/null 2>&1
done
# Blocked traffic
for domain in ads.doubleclick.net tracking.google.com ad.doubleclick.net \
    pixel.facebook.com analytics.google.com; do
    dig @127.0.0.1 "$domain" +short > /dev/null 2>&1
done
# Cache hits
for domain in github.com google.com stackoverflow.com; do
    dig @127.0.0.1 "$domain" +short > /dev/null 2>&1
done

# --------------- Step 1: Open Chrome in --app mode ---------------
log "Opening dashboard in Chrome app mode (${VIEWPORT_W}x${VIEWPORT_H})..."
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CHROME_DATA_DIR=$(mktemp -d /tmp/numa-demo-chrome-XXXXXX)

"$CHROME" \
    --app="http://localhost:$PORT" \
    --window-size=${VIEWPORT_W},${VIEWPORT_H} \
    --window-position=100,100 \
    --user-data-dir="$CHROME_DATA_DIR" \
    --remote-debugging-port=${CDP_PORT} \
    --no-first-run \
    --disable-extensions \
    --disable-infobars 2>/dev/null &
CHROME_PID=$!

log "Waiting for page load..."
sleep 3

# Bring Chrome to front
osascript -e "tell application \"System Events\" to set frontmost of (first process whose unix id is $CHROME_PID) to true" 2>/dev/null || true
sleep 0.5

# --------------- Step 2: Start screen recording ---------------
MOV_FILE=$(mktemp /tmp/numa-demo-XXXXXX.mov)

SCREEN_LOGICAL_W=$(osascript -l JavaScript -e 'ObjC.import("AppKit"); $.NSScreen.mainScreen.frame.size.width')
SCREEN_LOGICAL_H=$(osascript -l JavaScript -e 'ObjC.import("AppKit"); $.NSScreen.mainScreen.frame.size.height')
log "Screen: ${SCREEN_LOGICAL_W}x${SCREEN_LOGICAL_H}"

SCREEN_INDEX=$(ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
    | grep "Capture screen" | head -1 | sed 's/.*\[\([0-9]*\)\].*/\1/' || true)

if [ -z "$SCREEN_INDEX" ]; then
    err "No screen capture device found."
    exit 1
fi

log "Recording ${RECORD_SECONDS}s..."
ffmpeg -y -loglevel warning \
    -f avfoundation -framerate 24 -capture_cursor 0 \
    -pixel_format uyvy422 \
    -probesize 50M \
    -i "${SCREEN_INDEX}:none" \
    -t "$RECORD_SECONDS" \
    -r 24 \
    -c:v libx264 -preset ultrafast -crf 18 \
    "$MOV_FILE" &
FFMPEG_PID=$!

sleep 1

# Bring Chrome to front again
osascript -e "tell application \"System Events\" to set frontmost of (first process whose unix id is $CHROME_PID) to true" 2>/dev/null || true
sleep 0.5

# --------------- Scene 1: Dashboard alive (0-3s) ---------------
# Dashboard is already showing pre-populated traffic from frame 1
log "Scene 1: Dashboard with live traffic (3s)..."
# Trickle a few more queries for movement
dig @127.0.0.1 github.com +short > /dev/null 2>&1
dig @127.0.0.1 ad.doubleclick.net +short > /dev/null 2>&1
sleep 3

# --------------- Scene 2: Check Domain blocker (3-6s) ---------------
log "Scene 2: Check Domain — blocked tracker..."
type_into "#checkDomainInput" "ads.doubleclick.net" 0.04
sleep 0.3
# Click Check button
run_js "document.querySelector('#checkDomainInput').closest('form').querySelector('.btn').click();"
sleep 2

# --------------- Scene 3: Add peekm service via UI (6-10s) ---------------
log "Scene 3: Adding peekm.numa service..."

# Scroll to Local Services form
run_js "
    var svcPanel = document.getElementById('serviceForm');
    if (svcPanel) svcPanel.scrollIntoView({behavior: 'smooth', block: 'center'});
"
sleep 0.5

type_into "#svcName" "peekm" 0.06
sleep 0.2
type_into "#svcPort" "6419" 0.1
sleep 0.3

# Click "Add Service"
run_js "document.querySelector('#serviceForm .btn-add').click();"
sleep 1.5

# --------------- Scene 4: Open peekm.numa (10-14s) ---------------
log "Scene 4: Opening peekm.numa in browser..."
open "http://peekm.numa/view/peekm/README.md" 2>/dev/null || true
sleep 4

# --------------- Scene 5: Back to dashboard (14-17s) ---------------
log "Scene 5: Back to dashboard — LOCAL queries visible..."
osascript -e "tell application \"System Events\" to set frontmost of (first process whose unix id is $CHROME_PID) to true" 2>/dev/null || true
sleep 3

# --------------- Scene 6: Terminal-style dig overlay (17-20s) ---------------
log "Scene 6: dig proof overlay..."
DIG_RESULT=$(dig @127.0.0.1 peekm.numa +short 2>/dev/null | head -1)
run_js "
    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;bottom:32px;left:50%;transform:translateX(-50%);background:#1a1814;color:#e8e0d4;padding:16px 28px;border-radius:10px;font-family:var(--font-mono);font-size:14px;z-index:99999;box-shadow:0 8px 32px rgba(0,0,0,0.3);border:1px solid rgba(192,98,58,0.3);white-space:pre;line-height:1.6;';
    overlay.innerHTML = '<span style=\"color:#8baa6e\">\$</span> <span style=\"color:#d48a5a\">dig</span> <span style=\"color:#8b9fbb\">@127.0.0.1</span> peekm.numa +short\n<span style=\"color:#8baa6e\">${DIG_RESULT}</span>';
    document.body.appendChild(overlay);
"
sleep 3

# --------------- Step 6: Stop recording and convert ---------------
log "Stopping recording..."
kill "$FFMPEG_PID" 2>/dev/null || true
wait "$FFMPEG_PID" 2>/dev/null || true
FFMPEG_PID=""

if [ ! -f "$MOV_FILE" ] || [ ! -s "$MOV_FILE" ]; then
    err "Recording failed — no video captured."
    err "Tip: grant Screen Recording permission to Terminal in System Settings > Privacy & Security"
    exit 1
fi

# Compute crop region
CAPTURE_W=$(ffprobe -v error -select_streams v:0 -show_entries stream=width -of csv=p=0 "$MOV_FILE")
CAPTURE_H=$(ffprobe -v error -select_streams v:0 -show_entries stream=height -of csv=p=0 "$MOV_FILE")

read -r CROP_W CROP_H CROP_X CROP_Y <<< "$(awk -v cw="$CAPTURE_W" -v ch="$CAPTURE_H" \
    -v sw="$SCREEN_LOGICAL_W" -v sh="$SCREEN_LOGICAL_H" \
    -v ww="$VIEWPORT_W" -v wh="$VIEWPORT_H" \
    'BEGIN {
        sx = cw / sw; sy = ch / sh
        printf "%d %d %d %d", int(ww*sx), int(wh*sy), int(100*sx), int(100*sy)
    }')"

log "Capture: ${CAPTURE_W}x${CAPTURE_H}, crop: ${CROP_W}x${CROP_H}+${CROP_X}+${CROP_Y}"

mkdir -p "$(dirname "$OUTPUT")"

log "Converting to GIF (${GIF_WIDTH}px, ${FPS}fps)..."
ffmpeg -y -loglevel error \
    -i "$MOV_FILE" \
    -vf "crop=${CROP_W}:${CROP_H}:${CROP_X}:${CROP_Y},fps=${FPS},scale=${GIF_WIDTH}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
    -loop 0 \
    "$OUTPUT"

# Optimize with gifsicle if available
if command -v gifsicle &>/dev/null; then
    log "Optimizing with gifsicle..."
    gifsicle -O3 --lossy=60 --colors 128 "$OUTPUT" -o "$OUTPUT"
fi

SIZE_BYTES=$(stat -f%z "$OUTPUT")
SIZE_MB=$(awk "BEGIN { printf \"%.1f\", $SIZE_BYTES / 1048576 }")
log "Hero GIF saved to $OUTPUT (${SIZE_MB}MB)"

if awk "BEGIN { exit ($SIZE_MB > $MAX_GIF_SIZE_MB) ? 0 : 1 }"; then
    warn "GIF is over ${MAX_GIF_SIZE_MB}MB. Consider reducing RECORD_SECONDS, FPS, or GIF_WIDTH."
fi

# Clean up demo data
log "Cleaning up demo services..."
curl -s -X DELETE "http://localhost:$PORT/services/peekm" > /dev/null 2>&1 || true

log ""
log "Add to README.md:"
log '  ![Numa dashboard](assets/hero-demo.gif)'
