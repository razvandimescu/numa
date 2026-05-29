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

# Refresh the Nix vendor hash. cargo update shifts the vendored crate set, so a
# stale flake.nix cargoHash fails the nix-build CI job (deps are fetched via
# cargoHash, not the lockfile — see #252). Recompute via the fake-hash dance.
if command -v nix >/dev/null 2>&1; then
  echo "Refreshing flake.nix cargoHash"
  FAKE="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  sed -i.bak "s|cargoHash = \"sha256-[^\"]*\";|cargoHash = \"$FAKE\";|" flake.nix
  rm -f flake.nix.bak
  NEW_HASH=$(nix build .#numa --no-link 2>&1 \
    | sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' | tail -1 || true)
  if [ -z "$NEW_HASH" ]; then
    echo "ERROR: could not compute cargoHash from nix build" >&2
    git checkout -- flake.nix
    exit 1
  fi
  sed -i.bak "s|cargoHash = \"$FAKE\";|cargoHash = \"$NEW_HASH\";|" flake.nix
  rm -f flake.nix.bak
  echo "  cargoHash -> $NEW_HASH"
else
  echo "WARNING: nix not found — flake.nix cargoHash NOT refreshed; nix-build CI will fail until it is updated by hand." >&2
fi

# Commit, tag, push
git add Cargo.toml Cargo.lock flake.nix
git commit -m "chore: bump version to $VERSION"
git tag "$TAG"
git push origin main "$TAG"

echo
echo "Released $TAG — GitHub Actions will build, publish to crates.io, and create the release."
