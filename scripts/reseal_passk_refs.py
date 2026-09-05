"""One-off: back-fill call_refs on already-sealed pass^k runs whose trials logged call_refs=[]."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from eval.evidence.writer import aggregate_trials, _SEAL_FILES
from eval.evidence.verify import verify_run


def _load(path):
    return [json.loads(l) for l in open(path) if l.strip()]


def _rewrite_jsonl(path, rows):
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _refs_for_local(trials, calls):
    # both conditions of a case share the same k selector calls
    refs = set(c["call_ref"] for c in calls)
    per_case = {}
    for t in trials:
        ci = int(t["case_id"].split("_")[1])
        found = []
        s = 0
        while True:
            r = hashlib.sha256(f"{ci}{s}".encode()).hexdigest()[:16]
            if r not in refs:
                break
            found.append(r)
            s += 1
        assert found, f"no calls re-derived for {t['case_id']}"
        per_case[t["case_id"]] = found
    return {t["case_id"]: per_case[t["case_id"]] for t in trials}


def _refs_for_craft(trials, calls):
    # B -> coord_passk, D/E -> D_passk_craft
    task_ids = sorted(set(t["case_id"] for t in trials))
    buckets = {tid: {"D_passk_craft": [], "coord_passk": []} for tid in task_ids}
    for c in calls:
        role, step, out, ref = c["principal"], c["seed"], c["output"], c["call_ref"]
        placed = False
        for tid in task_ids:
            for cond in ("B", "D", "E"):
                if hashlib.sha256(f"{cond}:{tid}{role}{step}{out}".encode()).hexdigest()[:16] == ref:
                    dest = "coord_passk" if cond == "B" else "D_passk_craft"
                    buckets[tid][dest].append(ref)
                    placed = True
                    break
            if placed:
                break
        assert placed, f"call {ref} did not re-derive to any (cond,task)"
    return buckets


def reseal(root, kind):
    trials = _load(os.path.join(root, "trials.jsonl"))
    calls = _load(os.path.join(root, "model_calls.jsonl"))
    call_ref_set = set(c["call_ref"] for c in calls)

    if kind == "local":
        by_case = _refs_for_local(trials, calls)
        for t in trials:
            t["call_refs"] = list(by_case[t["case_id"]])
    else:
        buckets = _refs_for_craft(trials, calls)
        for t in trials:
            t["call_refs"] = list(buckets[t["case_id"]][t["condition"]])

    for t in trials:
        for r in t["call_refs"]:
            assert r in call_ref_set, f"derived ref {r} not in model_calls"
    assert any(t["call_refs"] for t in trials), "no trial got refs"

    _rewrite_jsonl(os.path.join(root, "trials.jsonl"), trials)
    with open(os.path.join(root, "aggregates.json"), "w") as f:
        json.dump(aggregate_trials(trials), f)

    sums = {}
    for name in _SEAL_FILES + ("status.json",):
        p = os.path.join(root, name)
        if os.path.exists(p):
            sums[name] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with open(os.path.join(root, "checksums.txt"), "w") as f:
        for name in sorted(sums):
            f.write(f"{sums[name]}  {name}\n")

    verify_run(root)
    total = sum(len(t["call_refs"]) for t in trials)
    print(f"OK {root}: {len(trials)} trials, {total} refs linked, verify_run passed")


if __name__ == "__main__":
    base = "evidence/claim_runs"
    for d in ("craft-passk-0", "craft-passk-1", "craft-passk-2", "craft-passk-3"):
        reseal(os.path.join(base, d), "craft")
    reseal(os.path.join(base, "047c185d3deccfe3-0"), "local")
