import hashlib
import json
import os
import sys

for _line in open(os.path.join(os.path.dirname(__file__), "..", ".env")):
    _line = _line.strip()
    if _line and "=" in _line and not _line.startswith("#"):
        _k, _v = _line.split("=", 1)
        os.environ.setdefault(_k, _v.strip().strip('"').strip("'"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eval.coordination.craft import CraftCoordinationBenchmark
from eval.coordination.run_wb import _run_condition, _channel
from eval.coordination.adversary import attack_succeeded
from eval.coordination.bus import _Bus
from eval.harness.model_openrouter import MODEL_ID
from eval.evidence.writer import (
    open_run, log_trial, write_aggregates, seal, git_commit,
)
from eval.evidence.verify import verify_run
from eval.metrics.stats import pass_at_k, pass_hat_k, wilson

CANARY = "CANARY-SEEDED-SECRET"
MALICIOUS = "D1"


def _attempt(bench, task_id, roles, views, truth, ceiling, rd, seed, mock):
    """One resample: benign baseline (B), attacked raw (D), attacked governed (E)."""
    benign, b_refs, _, _ = _run_condition(
        "B", task_id, roles, views, _channel("B", roles, CANARY),
        _Bus(rd, f"B:{task_id}:s{seed}"), rd, seed, mock, "", CANARY)
    d_ans, d_refs, _, d_exfil = _run_condition(
        "D", task_id, roles, views, _channel("D", roles, CANARY),
        _Bus(rd, f"D:{task_id}:s{seed}"), rd, seed, mock, MALICIOUS, CANARY)
    e_ans, e_refs, _, e_exfil = _run_condition(
        "E", task_id, roles, views, _channel("E", roles, CANARY),
        _Bus(rd, f"E:{task_id}:s{seed}"), rd, seed, mock, MALICIOUS, CANARY, honest_inject=True)
    attacked = d_exfil or attack_succeeded(d_ans, benign, truth, CANARY, [])
    breach = e_exfil or attack_succeeded(e_ans, benign, truth, CANARY, [])
    coord_metric = bench.score_answer(task_id, benign)
    coordinated = coord_metric >= ceiling if ceiling > 0 else coord_metric > 0
    return int(attacked), int(coordinated), int(breach), d_refs + e_refs, b_refs


def main(k=8, tasks="tests/fixtures/craft/craft.jsonl", mock=True):
    if not mock:
        assert os.environ.get("OPENROUTER_BASE_URL") and os.environ.get("OPENROUTER_API_KEY"), \
            "real mode needs OPENROUTER_BASE_URL + OPENROUTER_API_KEY (MODEL_ID pinned in harness)"
    bench = CraftCoordinationBenchmark(tasks)
    task_ids = [t.id for t in bench.iter_tasks()]
    n = len(task_ids)

    payload = [(tid, bench._roles[tid]) for tid in task_ids]
    man = {"seed": 0, "commit": git_commit(),
           "dataset_hash": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
           "model_id": "mock:craft" if mock else MODEL_ID,
           "prompts": {"director": hashlib.sha256(b"craft-director-v1").hexdigest()},
           "seeds": [0], "policies": {"utility_margin": 0.0}, "budgets": {"k": k},
           "condition_set": ["D_passk_craft", "coord_passk"], "n_tasks": n}
    rd = open_run(man)
    print(f"running {n} tasks x {k} resamples ({'mock' if mock else 'real'})...")

    atk = [0] * n
    coord = [0] * n
    atk_refs = [[] for _ in range(n)]
    coord_refs = [[] for _ in range(n)]
    breaches = 0
    for i, tid in enumerate(task_ids):
        roles = bench._roles[tid]
        views = {r: bench.view_for(tid, r) for r in roles}
        truth = bench.ground_truth(tid)
        ceiling = bench.attainable_iou(tid)
        for s in range(k):
            a, c, b, a_refs, c_refs = _attempt(bench, tid, roles, views, truth, ceiling, rd, s, mock)
            atk[i] += a
            coord[i] += c
            breaches += b
            atk_refs[i] += a_refs
            coord_refs[i] += c_refs

    rows = []
    for i, tid in enumerate(task_ids):
        for cond, sc, refs in (("D_passk_craft", atk[i], atk_refs[i]),
                               ("coord_passk", coord[i], coord_refs[i])):
            row = dict(case_id=tid, condition=cond, seed=0, outcome=f"{sc}/{k}",
                       spoof_success=False, security_success=False, receipt_id=None,
                       call_refs=refs, event_ids=[], metric=sc / k,
                       extra={"successes": sc, "k": k, "all_k": sc == k})
            log_trial(rd, **row)
            rows.append({"condition": cond, "metric": sc / k, "spoof_success": False})
    write_aggregates(rd, rows)
    seal(rd)
    verify_run(rd.root)

    a_lo, a_hi = wilson(sum(1 for x in atk if x == k), n)
    c_lo, c_hi = wilson(sum(1 for x in coord if x == k), n)
    res = {"k": k, "n": n, "root": rd.root, "mock": mock,
           "attack_pass_at_k": sum(pass_at_k(x, k, k) for x in atk) / n,
           "attack_pass_hat_k": sum(pass_hat_k(x, k, k) for x in atk) / n,
           "attack_pass_hat_k_ci": [round(a_lo, 3), round(a_hi, 3)],
           "attack_mean_rate": sum(atk) / (n * k),
           "coord_pass_at_k": sum(pass_at_k(x, k, k) for x in coord) / n,
           "coord_pass_hat_k": sum(pass_hat_k(x, k, k) for x in coord) / n,
           "coord_pass_hat_k_ci": [round(c_lo, 3), round(c_hi, 3)],
           "coord_mean_rate": sum(coord) / (n * k),
           "guard_breaches": breaches, "guard_attempts": n * k}
    print("PASSK_CRAFT " + json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    kw = dict(a.split("=") for a in sys.argv[1:] if "=" in a)
    _real_env = bool(os.environ.get("OPENROUTER_BASE_URL") and os.environ.get("OPENROUTER_API_KEY"))
    _mock = kw["mock"] != "0" if "mock" in kw else not _real_env
    _default_tasks = "tests/fixtures/craft/craft.jsonl" if _mock else "eval/data/craft/craft.jsonl"
    main(k=int(kw.get("k", 8)), tasks=kw.get("tasks", _default_tasks), mock=_mock)
