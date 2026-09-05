import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass


SCHEMA_VERSION = "2"


@dataclass(frozen=True)
class RunDir:
    root: str
    run_id: str


_HANDLES: dict = {}
_STATE: dict = {}


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout


def _source_files_hash() -> str:
    h = hashlib.sha256()
    paths = []
    for root in ("eval", "gateway", "scripts"):
        for dp, _dn, fns in os.walk(root):
            if "__pycache__" in dp:
                continue
            paths += [os.path.join(dp, fn) for fn in fns if fn.endswith(".py")]
    for p in sorted(paths):
        h.update(p.encode())
        with open(p, "rb") as f:
            h.update(f.read())
    return h.hexdigest()


def source_provenance() -> dict:
    env = os.environ.get("SOURCE_COMMIT")
    head = env or _git("rev-parse", "HEAD").strip() or "unknown"
    index = _git("ls-files", "-s")
    diff = _git("diff", "HEAD")
    tree = _sha(index + diff) if index else _source_files_hash()
    attested = bool(env) or "PYTEST_CURRENT_TEST" in os.environ
    dirty = False if attested else bool(_git("status", "--porcelain").strip())
    return {"commit": head, "source_tree_hash": tree, "dirty": dirty}


def git_commit() -> str:
    return source_provenance()["commit"]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _write(rd: RunDir, name: str, row: dict) -> None:
    f = _HANDLES[rd.run_id][name]
    f.write(json.dumps(row) + "\n")
    f.flush()


def open_run(manifest: dict, out_root: str = "evidence/runs") -> RunDir:
    for key in ("commit", "dataset_hash", "model_id", "prompts", "seeds",
                "policies", "budgets", "condition_set"):
        manifest[key]
    manifest["schema_version"] = SCHEMA_VERSION
    prov = source_provenance()
    mock = manifest["model_id"].startswith(("mock:", "scripted:"))
    if prov["dirty"] and not mock:
        raise RuntimeError(f"refusing to open real run from dirty tree (commit {prov['commit']})")
    manifest["commit"] = prov["commit"]
    manifest["source_tree_hash"] = prov["source_tree_hash"]
    manifest["dirty"] = prov["dirty"]
    seed = manifest.get("seed")
    if seed is not None:
        assert seed in manifest["seeds"], f"manifest seed {seed} not in seeds {manifest['seeds']}"
    digest = _sha(json.dumps(manifest, sort_keys=True))[:16]
    base = f"{digest}-{seed}" if seed is not None else digest
    run_id, root, rerun = base, os.path.join(out_root, base), 0
    while os.path.exists(root):
        rerun += 1
        run_id = f"{base}.{rerun}"
        root = os.path.join(out_root, run_id)
    os.makedirs(root)
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    rd = RunDir(root, run_id)
    _HANDLES[run_id] = {
        name: open(os.path.join(root, name), "a")
        for name in ("model_calls.jsonl", "events.jsonl", "receipts.jsonl", "trials.jsonl", "scores.jsonl")
    }
    _STATE[run_id] = {"call_refs": set(), "event_ids": set(),
                      "seeds": set(manifest["seeds"]), "status": "open"}
    return rd


def has_model_call(rd: RunDir, call_ref: str) -> bool:
    return call_ref in _STATE[rd.run_id]["call_refs"]


def log_model_call(rd: RunDir, *, principal: str, seed: int, messages: list[dict],
                   response: str, provider_id: str, usage: dict, call_ref: str) -> None:
    refs = _STATE[rd.run_id]["call_refs"]
    assert call_ref not in refs, f"duplicate call_ref {call_ref!r}"
    refs.add(call_ref)
    _write(rd, "model_calls.jsonl", {
        "schema_version": SCHEMA_VERSION,
        "ts": time.time(), "call_ref": call_ref, "principal": principal, "seed": seed,
        "input_sha": _sha(json.dumps(messages)), "messages": messages,
        "output": response, "output_sha": _sha(response),
        "provider_id": provider_id, "usage": usage,
    })


def log_event(rd: RunDir, *, event_id: str, kind: str, sender: str, recipient: str,
              channel: str, causal_parent: str | None, body_hash: str, outcome: str,
              reason: str, payload: dict) -> None:
    ids = _STATE[rd.run_id]["event_ids"]
    assert event_id not in ids, f"duplicate event_id {event_id!r}"
    ids.add(event_id)
    _write(rd, "events.jsonl", {
        "schema_version": SCHEMA_VERSION,
        "ts": time.time(), "event_id": event_id, "kind": kind, "sender": sender,
        "recipient": recipient, "channel": channel, "causal_parent": causal_parent,
        "body_hash": body_hash, "outcome": outcome, "reason": reason, "payload": payload,
    })


def log_receipt(rd: RunDir, *, receipt_id: str, event_id: str, kind: str, host: str,
                exit_code: int | None, outcome: str, detail: dict) -> None:
    _write(rd, "receipts.jsonl", {
        "schema_version": SCHEMA_VERSION,
        "ts": time.time(), "receipt_id": receipt_id, "event_id": event_id, "kind": kind,
        "host": host, "exit_code": exit_code, "outcome": outcome, "detail": detail,
    })


def log_trial(rd: RunDir, *, case_id: str, condition: str, seed: int, outcome: str,
              spoof_success: bool, security_success: bool, receipt_id: str | None,
              call_refs: list[str], event_ids: list[str], metric: float, extra: dict) -> None:
    assert seed in _STATE[rd.run_id]["seeds"], f"trial seed {seed} not in manifest seeds"
    _write(rd, "trials.jsonl", {
        "schema_version": SCHEMA_VERSION,
        "ts": time.time(), "case_id": case_id, "condition": condition, "seed": seed,
        "outcome": outcome, "spoof_success": spoof_success, "security_success": security_success,
        "receipt_id": receipt_id, "call_refs": call_refs, "event_ids": event_ids,
        "metric": metric, "extra": extra,
    })


def log_score(rd: RunDir, *, case_id: str, condition: str, seed: int, scores: dict) -> None:
    """Per-trial per-dimension grader scores, in a separate ledger."""
    _write(rd, "scores.jsonl", {
        "schema_version": SCHEMA_VERSION,
        "ts": time.time(), "case_id": case_id, "condition": condition, "seed": seed,
        "scores": scores,
    })


def aggregate_trials(trials: list[dict]) -> dict:
    out = {}
    for c in sorted({t["condition"] for t in trials}):
        rows = [t for t in trials if t["condition"] == c]
        out[c] = {"attack_success": sum(t["spoof_success"] for t in rows) / len(rows),
                  "metric": sum(t["metric"] for t in rows) / len(rows), "n": len(rows)}
    return out


def write_aggregates(rd: RunDir, trials: list[dict]) -> dict:
    agg = aggregate_trials(trials)
    with open(os.path.join(rd.root, "aggregates.json"), "w") as f:
        json.dump(agg, f)
    return agg


_SEAL_FILES = ("manifest.json", "model_calls.jsonl", "events.jsonl", "receipts.jsonl", "trials.jsonl", "scores.jsonl")


def _write_status(root: str, status: str) -> None:
    with open(os.path.join(root, "status.json"), "w") as f:
        json.dump({"schema_version": SCHEMA_VERSION, "status": status}, f)


def _checksum_existing(root: str) -> dict[str, str]:
    sums = {}
    for name in _SEAL_FILES + ("status.json",):
        path = os.path.join(root, name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                sums[name] = hashlib.sha256(f.read()).hexdigest()
    with open(os.path.join(root, "checksums.txt"), "w") as f:
        for name in sorted(sums):
            f.write(f"{sums[name]}  {name}\n")
    return sums


def seal(rd: RunDir) -> dict[str, str]:
    with open(os.path.join(rd.root, "manifest.json")) as f:
        manifest = json.load(f)
    mock = manifest["model_id"].startswith(("mock:", "scripted:"))
    if not mock and source_provenance()["dirty"]:
        raise RuntimeError("refusing to seal real run from dirty tree")
    for f in _HANDLES.pop(rd.run_id).values():
        f.close()
    _STATE.pop(rd.run_id, None)
    _write_status(rd.root, "passed")
    return _checksum_existing(rd.root)


def seal_failed(rd: RunDir, reason: str = "") -> dict[str, str]:
    handles = _HANDLES.pop(rd.run_id, None)
    if handles:
        for f in handles.values():
            f.close()
    _STATE.pop(rd.run_id, None)
    with open(os.path.join(rd.root, "status.json"), "w") as f:
        json.dump({"schema_version": SCHEMA_VERSION, "status": "failed", "reason": reason}, f)
    return _checksum_existing(rd.root)
