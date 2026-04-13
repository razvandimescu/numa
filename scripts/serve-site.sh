#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-9000}"

if [[ "${1:-}" == "--drafts" ]] || [[ "${2:-}" == "--drafts" ]]; then
  PORT="${PORT//--drafts/9000}"  # default port if --drafts was first arg
  make blog-drafts
else
  make blog
fi

echo "Serving site at http://localhost:$PORT"
cd site && python3 -m http.server "$PORT"
