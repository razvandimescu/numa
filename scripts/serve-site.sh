#!/usr/bin/env bash
# Dev server for site/: regenerates drafts on each MD change, reloads the
# browser on each rendered HTML/CSS/JS change. Port is the first numeric arg
# (default 9000); any other args are ignored for back-compat.
#
# First run downloads chokidar-cli + browser-sync into the npm cache — slow
# once, instant after that.

set -euo pipefail

PORT=9000
for arg in "$@"; do
  if [[ "$arg" =~ ^[0-9]+$ ]]; then
    PORT="$arg"
    break
  fi
done

command -v npx >/dev/null || { echo "npx not found. Install Node.js: https://nodejs.org" >&2; exit 1; }
command -v pandoc >/dev/null || { echo "pandoc not found (required by 'make blog-drafts')." >&2; exit 1; }

# Initial render so the first page load has everything.
make blog-drafts

echo "Serving site at http://localhost:$PORT (drafts included, live reload)"

# Kill child processes on exit so re-runs don't leave orphaned watchers.
trap 'kill $(jobs -p) 2>/dev/null' EXIT INT TERM

# Regenerate HTML when MD sources or the blog template change.
npx --yes chokidar-cli \
  "drafts/*.md" "blog/*.md" "site/blog-template.html" \
  -c "make blog-drafts" &

# Serve + reload on rendered-asset changes.
cd site && exec npx --yes browser-sync start \
  --server . \
  --port "$PORT" \
  --files "**/*.html,**/*.css,**/*.js" \
  --no-open \
  --no-notify
