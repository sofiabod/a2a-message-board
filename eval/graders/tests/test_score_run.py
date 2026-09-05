import json
import os

from eval.experiments.pilot1 import run_slice, run_benign_control, _build_manifest, CONDITIONS
from eval.harness.agents import ScriptedSelector
from eval.harness.benchmarks import load_as_cases, load_benign_cases
from eval.evidence import open_run, seal, write_aggregates
from eval.evidence.verify import verify_run


class _Args:
    real = False


def _load(root, name):
    return [json.loads(l) for l in open(os.path.join(root, name)) if l.strip()]


def _emit(tmp_path):
    cases = load_as_cases(sample=True)[:2]
    benign = load_benign_cases(sample=True)[:2]
    rd = open_run(_build_manifest(cases, _Args()), out_root=str(tmp_path / "runs"))
    run_slice(cases, selector=ScriptedSelector({}), out_dir=str(tmp_path / "t"), rd=rd)
    run_benign_control(benign, selector=ScriptedSelector({}), rd=rd)
    write_aggregates(rd, _load(rd.root, "trials.jsonl"))
    seal(rd)
    return rd.root


def test_as_run_writes_per_dimension_scores_and_verifies(tmp_path):
    root = _emit(tmp_path)
    verify_run(root)
    scores = _load(root, "scores.jsonl")
    assert scores, "no per-dimension scores written"
    attack = [s for s in scores if ":benign" not in s["condition"]]
    assert all(set(s["scores"]) == {"security_spoofing", "overblock", "utility"} for s in attack)
    benign = [s for s in scores if ":benign" in s["condition"]]
    assert benign and all("overblock" in s["scores"] for s in benign)


def test_scores_call_the_registry_graders_not_a_copy(tmp_path):
    root = _emit(tmp_path)
    scores = {(s["case_id"], s["condition"]): s["scores"] for s in _load(root, "scores.jsonl")}
    trials = {(t["case_id"], t["condition"]): t for t in _load(root, "trials.jsonl")}
    spoofed = [k for k, t in trials.items() if t["spoof_success"]]
    assert spoofed
    for k in spoofed:
        assert scores[k]["security_spoofing"]["score"] == 1.0
