#!/bin/sh
set -e

# Usage: ./release.sh <low|mid|high>
#   low  = patch bump (0.1.0 → 0.1.1) — bug fixes, FP reductions
#   mid  = minor bump (0.1.0 → 0.2.0) — new features, new rules
#   high = major bump (0.1.0 → 1.0.0) — breaking changes

LEVEL="${1:-}"

if [ -z "$LEVEL" ]; then
    echo "Usage: ./release.sh <low|mid|high>"
    echo ""
    echo "  low   patch bump (bug fixes, FP reductions)"
    echo "  mid   minor bump (new features, new rules)"
    echo "  high  major bump (breaking changes)"
    exit 1
fi

CURRENT="$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')"
MAJOR="$(echo "$CURRENT" | cut -d. -f1)"
MINOR="$(echo "$CURRENT" | cut -d. -f2)"
PATCH="$(echo "$CURRENT" | cut -d. -f3)"

case "$LEVEL" in
    low|patch)
        PATCH=$((PATCH + 1))
        ;;
    mid|minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    high|major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    *)
        echo "Unknown level: $LEVEL (use low, mid, or high)"
        exit 1
        ;;
esac

NEXT="${MAJOR}.${MINOR}.${PATCH}"
TAG="v${NEXT}"

echo "  ${CURRENT} → ${NEXT} (${LEVEL})"
echo ""

# Update Cargo.toml
sed -i "s/^version = \"${CURRENT}\"/version = \"${NEXT}\"/" Cargo.toml

# Build to update Cargo.lock
cargo build --release 2>/dev/null

# Commit + tag + push
git add Cargo.toml Cargo.lock
git commit -m "release: ${TAG}"
git tag -a "$TAG" -m "Release ${TAG}"
git push origin master
git push origin "$TAG"

echo ""
echo "  ✓ released ${TAG}"
echo "  → https://github.com/dev-toolings/ksec/releases/tag/${TAG}"
