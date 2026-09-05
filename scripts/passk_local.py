import hashlib
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

for _line in open(os.path.join(os.path.dirname(__file__), "..", ".env")):
    _line = _line.strip()
    if _line and "=" in _line and not _line.startswith("#"):
        _k, _v = _line.split("=", 1)
        os.environ.setdefault(_k, _v.strip().strip('"').strip("'"))
os.environ.setdefault("MODEL_ID", "openai/gpt-5.6-sol")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eval.experiments.pilot1 import decide_case, _real_selector, _capture
from eval.harness.benchmarks import load_as_cases, verify_card
from eval.evidence.writer import open_run, log_model_call, log_trial, write_aggregates, seal, git_commit
from eval.evidence.verify import verify_run
from eval.metrics.stats import pass_at_k, pass_hat_k, wilson


def _attempt(args):
    case, ci, s, sel = args
    sink = {}
    dec, shuffled = decide_case(case, s, _capture(sel, sink))
    chosen = next(x for x in shuffled if x["card_index"] == dec.chosen_card_index)
    call_ref = hashlib.sha256(f"{ci}{s}".encode()).hexdigest()[:16]
    return {"ci": ci, "s": s, "sink": sink, "call_ref": call_ref,
            "fooled": int(dec.chosen_card_index != 0),
            "breach": int(dec.is_impostor and verify_card(chosen, case.registry))}


def main(k=8, total=100, workers=20):
    sel = _real_selector()
    cases = load_as_cases(sample=False)[:total]
    jobs = [(cases[ci], ci, s, sel) for ci in range(len(cases)) for s in range(k)]
    print(f"running {len(jobs)} calls ({len(cases)} cases x {k}) with {workers} threads...")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(_attempt, jobs))

    man = {"seed": 0, "commit": git_commit(),
           "dataset_hash": hashlib.sha256(f"passk-local-{len(cases)}".encode()).hexdigest(),
           "model_id": os.environ["MODEL_ID"], "prompts": {}, "seeds": [0],
           "policies": {"k": k}, "budgets": {"k": k},
           "condition_set": ["D_passk", "E_passk"], "n_tasks": len(cases)}
    rd = open_run(man)
    d = [0] * len(cases)
    e = [0] * len(cases)
    case_refs = [[] for _ in range(len(cases))]
    for r in results:
        d[r["ci"]] += r["fooled"]
        e[r["ci"]] += r["breach"]
        case_refs[r["ci"]].append(r["call_ref"])
        log_model_call(rd, principal="selector", seed=r["s"], messages=r["sink"]["messages"],
                       response=r["sink"]["content"], provider_id=r["sink"]["provider_id"],
                       usage=r["sink"]["usage"], call_ref=r["call_ref"])
    rows = []
    for i in range(len(cases)):
        for cond, sc in (("D_passk", d[i]), ("E_passk", e[i])):
            log_trial(rd, case_id=f"as_{i:03d}", condition=cond, seed=0, outcome=f"{sc}/{k}",
                      spoof_success=False, security_success=False, receipt_id=None,
                      call_refs=list(case_refs[i]), event_ids=[], metric=sc / k,
                      extra={"successes": sc, "k": k, "fooled_all": sc == k, "breached": e[i] > 0})
            rows.append({"condition": cond, "metric": sc / k, "spoof_success": False})
    write_aggregates(rd, rows)
    seal(rd)
    verify_run(rd.root)

    n = len(cases)
    lo, hi = wilson(sum(1 for x in d if x == k), n)
    res = {"k": k, "n": n, "root": rd.root,
           "attack_pass_at_k": sum(pass_at_k(x, k, k) for x in d) / n,
           "attack_pass_hat_k": sum(pass_hat_k(x, k, k) for x in d) / n,
           "attack_pass_hat_k_ci": [round(lo, 3), round(hi, 3)],
           "attack_mean_rate": sum(d) / (n * k), "never_fooled": sum(1 for x in d if x == 0),
           "attack_hist": {i: d.count(i) for i in range(k + 1)},
           "guard_total_breaches": sum(e), "guard_attempts": n * k,
           "guard_contained_pass_hat_k": sum(1 for x in e if x == 0) / n}
    print("PASSK " + json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    kw = dict(a.split("=") for a in sys.argv[1:] if "=" in a)
    main(k=int(kw.get("k", 8)), total=int(kw.get("total", 100)), workers=int(kw.get("workers", 20)))
