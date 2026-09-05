import hashlib
import json
import os
import sys
from collections import defaultdict


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _sha_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _load(path: str) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _by_id(events: list[dict], event_id: str) -> dict:
    return next(e for e in events if e["event_id"] == event_id)


def seq(events: list[dict]):
    return {e["event_id"]: i for i, e in enumerate(events)}


def nonce_lineage(events: list[dict], nonce: str, answer_event_id: str) -> str:
    sends = [e for e in events if e["kind"] == "send"
             and e["sender"] == "agent1" and nonce in e["payload"]["text"]]
    assert sends, "nonce never left agent1"
    parents = {s["event_id"] for s in sends}
    reads = [e for e in events if e["kind"] == "read"
             and e["recipient"] == "agent2" and e["causal_parent"] in parents
             and nonce in e["payload"]["text"]]
    assert reads, "agent2 never read the nonce-bearing message"
    s = seq(events)
    ans = _by_id(events, answer_event_id)
    assert any(s[r["event_id"]] < s[ans["event_id"]] for r in reads), "answer predates the read"
    return reads[0]["causal_parent"]


SCHEMA_VERSION = "2"


def verify_run(root: str) -> None:
    for name in ("status.json", "checksums.txt", "manifest.json", "trials.jsonl",
                 "model_calls.jsonl", "events.jsonl", "receipts.jsonl", "aggregates.json"):
        assert os.path.exists(os.path.join(root, name)), f"incomplete run: missing {name}"
    with open(os.path.join(root, "status.json")) as f:
        status = json.load(f)
    assert status["schema_version"] == SCHEMA_VERSION, f"status schema {status['schema_version']!r} != {SCHEMA_VERSION}"
    assert status["status"] == "passed", f"run status is {status['status']!r}"
    verify_checksums(root)
    trials = _load(os.path.join(root, "trials.jsonl"))
    model_calls = _load(os.path.join(root, "model_calls.jsonl"))
    events = _load(os.path.join(root, "events.jsonl"))
    receipts = _load(os.path.join(root, "receipts.jsonl"))
    with open(os.path.join(root, "manifest.json")) as f:
        manifest = json.load(f)
    assert manifest["schema_version"] == SCHEMA_VERSION, f"manifest schema {manifest.get('schema_version')!r} != {SCHEMA_VERSION}"
    assert manifest.get("source_tree_hash"), "manifest missing source_tree_hash"
    mock_manifest = manifest["model_id"].startswith(("mock:", "scripted:"))
    if not mock_manifest:
        assert manifest.get("dirty") is False, "real run sealed from a dirty tree"
    for kind, rows in (("model_calls", model_calls), ("events", events),
                       ("receipts", receipts), ("trials", trials)):
        for r in rows:
            assert r.get("schema_version") == SCHEMA_VERSION, f"{kind} row schema {r.get('schema_version')!r} != {SCHEMA_VERSION}"

    call_refs = [m["call_ref"] for m in model_calls]
    assert len(call_refs) == len(set(call_refs)), "duplicate call_ref within run"
    event_ids = [e["event_id"] for e in events]
    assert len(event_ids) == len(set(event_ids)), "duplicate event_id within run"
    seeds = set(manifest["seeds"])
    for t in trials:
        assert t["seed"] in seeds, f"trial seed {t['seed']} not in manifest seeds {sorted(seeds)}"




    scores = _load(os.path.join(root, "scores.jsonl"))
    trial_cases = {t["case_id"] for t in trials}
    for srow in scores:
        assert srow["case_id"] in trial_cases, f"score row case {srow['case_id']!r} not in run trials"
        assert srow["seed"] in seeds, f"score row seed {srow['seed']} not in manifest seeds"
        assert isinstance(srow.get("scores"), dict) and srow["scores"], f"score row {srow['case_id']!r} has no scores"

    if not manifest["model_id"].startswith(("mock:", "scripted:")):
        assert model_calls, "real-model manifest with zero model_calls"
        real_calls = [m for m in model_calls if not m["provider_id"].startswith(("mock:", "scripted:"))]
        assert real_calls, "real-model manifest with zero real model_calls"
        for m in model_calls:
            assert (not m["provider_id"].startswith(("mock:", "scripted:"))
                    or m["provider_id"] == "scripted:adversary"), \
                "real-model manifest: only scripted:adversary may be non-real"
    M = {r["call_ref"]: r for r in model_calls}
    E = {r["event_id"]: r for r in events}
    R = {r["receipt_id"]: r for r in receipts}
    R_rows = defaultdict(list)
    for r in receipts:
        R_rows[r["receipt_id"]].append(r)


    from eval.evidence.writer import aggregate_trials
    with open(os.path.join(root, "aggregates.json")) as f:
        assert aggregate_trials(trials) == json.load(f)


    for t in trials:
        for ref in t["call_refs"]:
            assert ref in M
    for ev in events:
        if ev["kind"] == "send" and ev["payload"].get("call_ref"):
            assert ev["payload"]["call_ref"] in M
            m = M[ev["payload"]["call_ref"]]
            assert m["output_sha"] == _sha(m["output"])


    s = seq(events)
    for i, ev in enumerate(events):
        if ev["kind"] != "read":
            continue
        p = ev["causal_parent"]
        assert p is not None and p in E
        assert s[p] < i
        assert E[p]["kind"] == "send"
        assert E[p]["outcome"] == "ALLOW"
        assert E[p]["channel"] == ev["channel"]














    for t in trials:
        if not t["security_success"]:
            continue
        rid = t["receipt_id"]
        assert rid is not None and rid in R
        own = {eid for eid in t["event_ids"]
               if eid in E and E[eid]["kind"] == "send" and E[eid]["outcome"] == "ALLOW"}
        assert own, f"receipt {rid} win lists no own ALLOW send in event_ids"
        backing = [row for row in R_rows[rid]
                   if row["event_id"] in own and row["kind"] != "decision"
                   and row["outcome"] in ("SENT", "EXECUTED", "DELIVERED")
                   and (row["exit_code"] in (0, None) or row["kind"] == "delivery")
                   and row["detail"].get("external") is True]
        assert backing, f"receipt {rid} for security win has no external ALLOW-send-bound receipt"



























    def source_consumed(t):
        return sorted(_sha(json.dumps(M[r]["messages"])) for r in t["call_refs"] if M[r]["seed"] == 0)
    by_case = defaultdict(dict)
    for t in trials:
        by_case[(t["case_id"], t["seed"])][t["condition"]] = t
    for lo, hi in (("B", "C"), ("D", "E")):
        for m in by_case.values():
            if lo not in m or hi not in m:
                continue
            x, y = m[lo], m[hi]
            assert x["condition"] != y["condition"]
            assert all(r in M for r in x["call_refs"] + y["call_refs"])
            assert source_consumed(x) == source_consumed(y), "paired arms diverge at the source (step-0) input"


def verify_checksums(root: str) -> None:
    from eval.evidence.writer import _SEAL_FILES
    listed = set()
    with open(os.path.join(root, "checksums.txt")) as f:
        for line in f:
            digest, name = line.split()
            assert _sha_file(os.path.join(root, name)) == digest, f"checksum mismatch: {name}"
            listed.add(name)
    for name in _SEAL_FILES:
        assert name in listed, f"checksums.txt missing required sealed file: {name}"


if __name__ == "__main__":
    root = sys.argv[1]
    verify_run(root)
    print("ok", root)
