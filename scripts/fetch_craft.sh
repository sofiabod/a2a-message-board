#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/csu-signal/CRAFT"
REF="f174fa5ae80c20ce5ccc7bb7cbf4aeab69efe430"
DEST="vendor/CRAFT"
DATASET="data/structures_dataset_20.json"
EXPECTED_SHA="c7a57048ec0d2e92c25bde8aa7936c911919accdcdcedc078e9ccf1e0a2c9e3a"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [ ! -d "$DEST/.git" ]; then
  rm -rf "$DEST"
  git clone "$REPO" "$DEST"
fi
git -C "$DEST" fetch --depth 1 origin "$REF"
git -C "$DEST" checkout "$REF"

actual="$(shasum -a 256 "$DEST/$DATASET" | cut -d' ' -f1)"
[ "$actual" = "$EXPECTED_SHA" ] || { echo "CRAFT corpus checksum drift: $actual != $EXPECTED_SHA" >&2; exit 1; }

PYTHONPATH="$root" python coordination/fetch_craft.py "$DEST/$DATASET" eval/data/craft/craft.jsonl
PYTHONPATH="$root" python coordination/fetch_craft.py "$DEST/$DATASET" tests/fixtures/craft/craft.jsonl --sample 2
