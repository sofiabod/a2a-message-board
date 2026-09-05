#!/usr/bin/env bash
# Reproduce the ablation. Default: hermetic mock (bit-for-bit, no spend).
# --real reproduces the full claim (5 CRAFT seeds, 5 A2A seeds, CRAFT+A2A pass^k,
# aggregate, verify every sealed run, render). --real spends tokens.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=.

REAL=""
[ "${1:-}" = "--real" ] && REAL="--real"

echo "== tests =="
python -m pytest -q

if [ -z "$REAL" ]; then
  echo "== mock: A2ASecBench (spoofing + injection) =="
  python -m eval.experiments.pilot1 --mock | tail -3

  echo "== mock: CRAFT whiteboard (B/C/D/E, one seed) =="
  CRAFT=$(python -m eval.coordination.run_wb --seed 0 | python -c "import sys,json;print(json.load(sys.stdin)['root'])")
  echo "craft run: $CRAFT"

  echo "== mock: verify sealed evidence =="
  python -m eval.evidence.verify "$CRAFT"

  echo "== mock: render results + traces =="
  python scripts/results_page.py "craft=$CRAFT"
  python scripts/trace_site.py "$(dirname "$CRAFT")"
  echo "done (mock). open site/results.html and site/traces.html"
  exit 0
fi

# --- real path: full claim reproduction ---
test -z "$(git status --porcelain)" || { echo "git tree dirty; real runs refuse to seal. commit first."; exit 1; }
: "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY for a real run}"
export MODEL_ID="${MODEL_ID:-openai/gpt-5.6-sol}"

echo "== real: 5 CRAFT seeds (B/C/D/E, model-driven) =="
for s in 0 1 2 3 4; do
  echo "-- craft seed $s --"
  python -m eval.experiments.run_paired --bench craft --craft eval/data/craft/craft.jsonl --real --seed "$s" | tail -3
done

echo "== real: 5 A2A seeds (AgentCard spoofing + benign control) =="
for s in 0 1 2 3 4; do
  echo "-- as seed $s --"
  python -m eval.experiments.run_paired --bench as --real --seed "$s" | tail -3
done

echo "== real: CRAFT pass^k (k=8) =="
python scripts/passk_craft.py k=8 mock=0 | tail -3

echo "== real: A2A pass^k (k=8, n=100 -> 800 calls) =="
python scripts/passk_local.py k=8 total=100 mock=0 | tail -3

echo "== real: verify every sealed run =="
for d in evidence/runs/*/; do
  [ -f "$d/manifest.json" ] || continue
  python -m eval.evidence.verify "$d"
done

echo "== real: aggregate across all runs =="
python scripts/aggregate.py evidence/runs

echo "== real: render traces =="
python scripts/trace_site.py evidence/runs
echo "done (real). open site/results.html and site/traces.html"
