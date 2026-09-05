#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/SaFo-Lab/A2ASecBench"
REF="e02109ebdcce3fe926884fbacbc935eef44e4aa3"
DEST="vendor/A2ASecBench"
EXPECTED_SHA="5726ad3ff42f53d6853ad790e65b2f44f32664b3c6b4f123ba3dadbddcaf0697"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [ ! -d "$DEST/.git" ]; then
  rm -rf "$DEST"
  git clone "$REPO" "$DEST"
fi
git -C "$DEST" fetch --depth 1 origin "$REF"
git -C "$DEST" checkout "$REF"

actual="$(find "$DEST/attacks/fixtures/as" -name '*.json' ! -name meta.json | sort | xargs cat | shasum -a 256 | cut -d' ' -f1)"
[ "$actual" = "$EXPECTED_SHA" ] || { echo "AS corpus checksum drift: $actual != $EXPECTED_SHA" >&2; exit 1; }
