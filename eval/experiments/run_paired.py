import argparse
import json
import os

from eval.evidence.verify import verify_run


def _craft_report(mock: bool, seed: int, craft_path: str | None) -> dict:
    from eval.coordination.craft import CraftCoordinationBenchmark
    from eval.coordination.run_wb import run_whiteboard
    from eval.harness.model_openrouter import MODEL_ID

    if not mock:
        assert os.environ["MODEL_ID"] == MODEL_ID, os.environ["MODEL_ID"]
    path = craft_path or "tests/fixtures/craft/craft.jsonl"
    bench = CraftCoordinationBenchmark(path)
    r = run_whiteboard(bench, seed=seed, mock=mock)
    root = r.root

    trials = [json.loads(l) for l in open(os.path.join(root, "trials.jsonl")) if l.strip()]
    by_cond = {}
    for t in trials:
        by_cond.setdefault(t["condition"], []).append(t)
    util = {c: sum(t["metric"] for t in v) / len(v) for c, v in by_cond.items()}
    atk = {c: sum(t["security_success"] for t in v) / len(v) for c, v in by_cond.items()}

    with open(os.path.join(root, "manifest.json")) as f:
        model_id = json.load(f)["model_id"]
    return {
        "benchmark": "craft",
        "raw": {"utility": util["B"]},
        "governed": {"utility": util["C"]},
        "attack": {"raw_D": atk.get("D", 0.0), "governed_E": atk.get("E", 0.0)},
        "coordination_delta": {"metric": "utility_C_minus_B", "value": util["C"] - util["B"]},
        "security_delta": {"metric": "attack_success_E_minus_D",
                           "value": atk.get("E", 0.0) - atk.get("D", 0.0)},
        "causal_drop_confirms": r.attack.get("causal_drop_confirms", False),
        "evidence": root,
        "model_id": model_id,
    }


def _as_report(mock: bool, seed: int, limit: int | None = None) -> dict:
    import eval.experiments.pilot1 as p
    from eval.harness.agents import ScriptedSelector
    from eval.harness.benchmarks import load_as_cases, load_benign_cases
    from eval.harness.model_openrouter import MODEL_ID
    from eval.evidence import open_run, write_aggregates, seal

    selector = ScriptedSelector({}) if mock else p._real_selector()
    cases = load_as_cases(sample=mock)
    if limit:
        cases = cases[:limit]
    args = argparse.Namespace(real=not mock, seed=seed)
    rd = open_run(p._build_manifest(cases, args))
    attack = p.run_slice(cases, selector=selector, seed=seed, out_dir=os.path.join(rd.root, "transcripts"), rd=rd)
    benign_cases = load_benign_cases(sample=mock)
    if limit:
        benign_cases = benign_cases[:limit]
    benign = p.run_benign_control(benign_cases, selector=selector, seed=seed, rd=rd)
    report = p._report(attack, benign, seed=seed)
    trials = [json.loads(l) for l in open(os.path.join(rd.root, "trials.jsonl")) if l.strip()]
    write_aggregates(rd, trials)
    seal(rd)

    b, c = report["B"], report["C"]
    ci = report["_paired_ci"]
    return {
        "benchmark": "as",
        "raw": {"security": b["attack_success"]},
        "governed": {"security": c["attack_success"]},
        "guardrail_delta": {"metric": "attack_success_B_minus_C",
                            "value": b["attack_success"] - c["attack_success"],
                            "ci95": [-ci["ci95"][1], -ci["ci95"][0]]},
        "benign_overblock": c["benign_overblock"],
        "evidence": rd.root,
        "model_id": MODEL_ID if not mock else "mock:scripted",
    }


def run_paired(bench_name: str, mock: bool = True, seed: int = 0,
               craft_path: str | None = None, limit: int | None = None) -> dict:
    report = _craft_report(mock, seed, craft_path) if bench_name == "craft" else _as_report(mock, seed, limit)
    verify_run(report["evidence"])
    return report


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", choices=("craft", "as"), required=True)
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--real", action="store_true")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--craft", default=None)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    if args.mock == args.real:
        raise SystemExit("choose exactly one: --mock (no spend) or --real (OpenRouter, spends tokens)")
    report = run_paired(args.bench, mock=args.mock, seed=args.seed, craft_path=args.craft, limit=args.limit)
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
