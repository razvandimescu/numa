#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>  (e.g. 0.7.0)" >&2
  exit 1
fi

VERSION="$1"
TAG="v$VERSION"

# Sanity checks
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: working tree is dirty — commit or stash first" >&2
  exit 1
fi

if [ "$(git branch --show-current)" != "main" ]; then
  echo "ERROR: must be on main branch" >&2
  exit 1
fi

if git tag -l "$TAG" | grep -q .; then
  echo "ERROR: tag $TAG already exists" >&2
  exit 1
fi

CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "Bumping $CURRENT -> $VERSION"

# Bump version
sed -i.bak "s/^version = \"$CURRENT\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak
cargo update --workspace

# Commit, tag, push
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to $VERSION"
git tag "$TAG"
git push origin main --tags

echo
echo "Released $TAG — GitHub Actions will build, publish to crates.io, and create the release."
