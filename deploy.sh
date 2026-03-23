#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "Usage: ./deploy.sh v0.5.1"
    exit 1
fi

# Strip leading 'v' for Cargo.toml (accepts both "v0.5.1" and "0.5.1")
SEMVER="${VERSION#v}"
TAG="v${SEMVER}"

# Validate semver format
if ! [[ "$SEMVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: '$SEMVER' is not a valid semver (expected: X.Y.Z)"
    exit 1
fi

# Check we're on main
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "Error: must be on main branch (currently on '$BRANCH')"
    exit 1
fi

# Check working tree is clean
if [ -n "$(git status --porcelain -- ':!deploy.sh' ':!Cargo.toml' ':!Cargo.lock')" ]; then
    echo "Error: working tree has uncommitted changes"
    git status --short
    exit 1
fi

# Check tag doesn't already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Error: tag '$TAG' already exists"
    exit 1
fi

CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "Bumping $CURRENT → $SEMVER"

# Update Cargo.toml version
sed -i '' "s/^version = \"$CURRENT\"/version = \"$SEMVER\"/" Cargo.toml

# Update Cargo.lock
cargo check --quiet 2>/dev/null

# Commit, tag, push
git add Cargo.toml Cargo.lock
git commit -m "bump version to $SEMVER"
git tag "$TAG"
git push
git push origin "$TAG"

echo ""
echo "✓ Tagged $TAG and pushed"
echo "  → GitHub Actions: release binaries + crates.io publish"
echo "  → Watch: gh run list --limit 1"
