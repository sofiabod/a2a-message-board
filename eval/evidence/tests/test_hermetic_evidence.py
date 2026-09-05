import hashlib
import json
import os
import random

import pytest

from eval.experiments.pilot1 import run_slice, CONDITIONS, _build_manifest
from eval.harness.agents import ScriptedSelector
from eval.harness.benchmarks import load_as_cases, sign_card
from eval.evidence import open_run, seal, seal_failed, write_aggregates, log_trial, SCHEMA_VERSION
from eval.evidence.writer import aggregate_trials
from eval.evidence.verify import verify_run, verify_checksums

EVIDENCE_FILES = ("aggregates.json", "events.jsonl", "manifest.json",
                  "model_calls.jsonl", "receipts.jsonl", "trials.jsonl")


class _Args:
    real = False


def _order(case_id, seed=0):
    rng = random.Random(hashlib.sha256(f"{case_id}:{seed}".encode()).hexdigest())
    o = list(range(10))
    rng.shuffle(o)
    return o


def _signed_impostor_case():
    case = load_as_cases(sample=True)[0]
    key = b"a2a-registered-genuine-key"
    genuine = {k: v for k, v in case.cards[0].items() if k not in ("case_id", "card_index", "signature")}
    body = dict(genuine, name="Rogue " + genuine["name"])
    signed = dict(body, signature=sign_card(body, key))
    replaced = case.__class__(case.case_id, case.task_prompt,
                              (case.cards[0], signed) + case.cards[2:],
                              case.benign_choice, case.registry)
    pos = _order(case.case_id).index(1) + 1
    return replaced, pos


def _bind_win_sends(root):
    """Give each governed-verified win a real ALLOW send, event_id, and receipt, since the pilot1 producer records none for a verified governed win."""
    trials = _load(root, "trials.jsonl")
    events = _load(root, "events.jsonl")
    receipts = _load(root, "receipts.jsonl")
    from eval.experiments.pilot1 import CHANNELS
    for t in trials:
        if not t["security_success"]:
            continue
        eid = hashlib.sha256(f"win{t['condition']}{t['case_id']}{t['seed']}".encode()).hexdigest()
        events.append({"schema_version": SCHEMA_VERSION, "ts": 0.0, "event_id": eid,
                       "kind": "send", "sender": "selector", "recipient": "registry",
                       "channel": CHANNELS[t["condition"]], "causal_parent": None,
                       "body_hash": "0" * 64, "outcome": "ALLOW", "reason": "invoked",
                       "payload": {}})
        t["event_ids"] = [eid] + t["event_ids"]
        receipts.append({"schema_version": SCHEMA_VERSION, "ts": 0.0,
                         "receipt_id": t["receipt_id"], "event_id": eid, "kind": "delivery",
                         "host": "ext", "exit_code": None, "outcome": "DELIVERED",
                         "detail": {"external": True}})
    _rewrite(root, "trials.jsonl", trials)
    _rewrite(root, "events.jsonl", events)
    _rewrite(root, "receipts.jsonl", receipts)


def _emit_run(tmp_path):
    case, pos = _signed_impostor_case()
    rd = open_run(_build_manifest([case], _Args()), out_root=str(tmp_path / "runs"))
    run_slice([case], selector=ScriptedSelector({case.case_id: pos}),
              out_dir=str(tmp_path / "t"), rd=rd)
    seal(rd)
    _bind_win_sends(rd.root)
    write_aggregates(_RD(rd.root), _load(rd.root, "trials.jsonl"))
    _reseal(rd.root)
    return rd.root


def _reseal(root):
    with open(os.path.join(root, "checksums.txt")) as f:
        names = [line.split()[1] for line in f]
    with open(os.path.join(root, "checksums.txt"), "w") as f:
        for name in names:
            with open(os.path.join(root, name), "rb") as g:
                f.write(hashlib.sha256(g.read()).hexdigest() + "  " + name + "\n")


def _rewrite(root, name, rows):
    with open(os.path.join(root, name), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _load(root, name):
    with open(os.path.join(root, name)) as f:
        return [json.loads(line) for line in f if line.strip()]


def test_a_run_emits_six_files_and_verify_passes(tmp_path):
    root = _emit_run(tmp_path)
    for name in EVIDENCE_FILES:
        assert os.path.exists(os.path.join(root, name))
    assert os.path.exists(os.path.join(root, "checksums.txt"))
    verify_checksums(root)
    verify_run(root)
    trials = _load(root, "trials.jsonl")
    assert any(t["security_success"] for t in trials)


def test_as_paired_arms_share_call_refs_and_input_digest(tmp_path):


    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    by_cond = {t["condition"]: t for t in trials if ":" not in t["condition"]}
    for lo, hi in (("B", "C"), ("D", "E")):
        if lo in by_cond and hi in by_cond:
            assert by_cond[lo]["call_refs"] == by_cond[hi]["call_refs"]
            assert by_cond[lo]["extra"]["input_digest"] == by_cond[hi]["extra"]["input_digest"]
    verify_run(root)


def test_input_digest_is_not_the_check5_signal(tmp_path):



    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    next(t for t in trials if t["condition"] == "C")["extra"]["input_digest"] = "tampered"
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    verify_run(root)


def test_b6_cheater_divergent_input_arm_fails_check5(tmp_path):



    root = _emit_run(tmp_path)
    calls = _load(root, "model_calls.jsonl")
    cheat_ref = "cheater" * 8
    calls.append({"schema_version": SCHEMA_VERSION, "ts": 0.0, "call_ref": cheat_ref,
                  "principal": "selector", "seed": 0,
                  "input_sha": hashlib.sha256(b'["cheat"]').hexdigest(),
                  "messages": [{"role": "user", "content": "cheat"}],
                  "output": "different", "output_sha": hashlib.sha256(b"different").hexdigest(),
                  "provider_id": "mock:x", "usage": {}})
    _rewrite(root, "model_calls.jsonl", calls)
    trials = _load(root, "trials.jsonl")
    next(t for t in trials if t["condition"] == "C")["call_refs"] = [cheat_ref]
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_extra_keys_cannot_pick_weak_check5_branch(tmp_path):



    root = _emit_run(tmp_path)
    calls = _load(root, "model_calls.jsonl")
    cheat_ref = "weakbranch" * 5 + "aa"
    calls.append({"schema_version": SCHEMA_VERSION, "ts": 0.0, "call_ref": cheat_ref,
                  "principal": "selector", "seed": 0,
                  "input_sha": hashlib.sha256(b'["cheat"]').hexdigest(),
                  "messages": [{"role": "user", "content": "cheat"}],
                  "output": "different", "output_sha": hashlib.sha256(b"different").hexdigest(),
                  "provider_id": "mock:x", "usage": {}})
    _rewrite(root, "model_calls.jsonl", calls)
    trials = _load(root, "trials.jsonl")
    c = next(t for t in trials if t["condition"] == "C")
    c["call_refs"] = [cheat_ref]
    c["extra"] = {"input_digest": c["extra"]["input_digest"], "attainable_iou": 0.9}
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_receipt_backed_by_unrelated_arm_send_fails_check4(tmp_path):



    root = _emit_run(tmp_path)
    events = _load(root, "events.jsonl")
    trials = _load(root, "trials.jsonl")
    receipts = _load(root, "receipts.jsonl")
    win = next(t for t in trials if t["security_success"])
    other = next(e["event_id"] for e in events
                 if e["kind"] == "send" and e["outcome"] == "ALLOW"
                 and e["event_id"] not in win["event_ids"])
    for r in receipts:
        if r["receipt_id"] == win["receipt_id"]:
            r["event_id"] = other
    win["event_ids"] = win["event_ids"][1:]
    _rewrite(root, "receipts.jsonl", receipts)
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_m1_forged_receipt_unlinked_event_fails_check4(tmp_path):



    root = _emit_run(tmp_path)
    receipts = _load(root, "receipts.jsonl")
    forged_rid = "f0" * 32
    receipts.append({"schema_version": SCHEMA_VERSION, "ts": 0.0, "receipt_id": forged_rid,
                     "event_id": "bogus" * 12 + "beef", "kind": "delivery", "host": "ext",
                     "exit_code": None, "outcome": "DELIVERED", "detail": {"external": True}})
    _rewrite(root, "receipts.jsonl", receipts)
    trials = _load(root, "trials.jsonl")
    victim = next(t for t in trials if not t["security_success"])
    victim["security_success"] = True
    victim["receipt_id"] = forged_rid
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_commproof_divergent_consumed_input_fails_check5(tmp_path):


    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    calls = _load(root, "model_calls.jsonl")
    dig = "same" * 16
    refB, refC = "bref" * 8, "cref" * 8
    for ref, msg in ((refB, "hello"), (refC, "goodbye")):
        calls.append({"schema_version": SCHEMA_VERSION, "ts": 0.0, "call_ref": ref,
                      "principal": "agent1", "seed": 0,
                      "input_sha": hashlib.sha256(msg.encode()).hexdigest(),
                      "messages": [{"role": "user", "content": msg}], "output": "o",
                      "output_sha": hashlib.sha256(b"o").hexdigest(),
                      "provider_id": "openrouter", "usage": {}})
    keep = [t for t in trials if t["condition"] in ("A", "O")]
    for cond, ref in (("B", refB), ("C", refC)):
        keep.append({"schema_version": SCHEMA_VERSION, "ts": 0.0, "case_id": "keyassembly",
                     "condition": cond, "seed": 0, "outcome": "failed", "spoof_success": False,
                     "security_success": False, "receipt_id": None, "call_refs": [ref],
                     "event_ids": [], "metric": 0.0, "extra": {"input_digest": dig}})
    _rewrite(root, "trials.jsonl", keep)
    _rewrite(root, "model_calls.jsonl", calls)
    write_aggregates(_RD(root), keep)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


class _RD:
    def __init__(self, root):
        self.root = root


def test_b_mutate_trial_row_fails_check1(tmp_path):
    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    victim = next(t for t in trials if t["spoof_success"] is False)
    victim["spoof_success"] = True
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_b_delete_model_call_response_fails_check2(tmp_path):
    root = _emit_run(tmp_path)
    calls = _load(root, "model_calls.jsonl")
    refs = {c for t in _load(root, "trials.jsonl") for c in t["call_refs"]}
    kept = [c for c in calls if c["call_ref"] not in refs]
    assert len(kept) < len(calls)
    _rewrite(root, "model_calls.jsonl", kept)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_b_forge_read_without_send_fails_check3(tmp_path):
    root = _emit_run(tmp_path)
    events = _load(root, "events.jsonl")
    forged = {"ts": 0.0, "event_id": "f" * 64, "kind": "read", "sender": "ghost",
              "recipient": "selector", "channel": "raw", "causal_parent": "0" * 64,
              "body_hash": "0" * 64, "outcome": "ALLOW", "reason": "delivered",
              "payload": {}}
    events.append(forged)
    _rewrite(root, "events.jsonl", events)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_b_security_success_without_receipt_fails_check4(tmp_path):
    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    victim = next(t for t in trials if not t["security_success"])
    victim["security_success"] = True
    victim["receipt_id"] = None
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_b_security_success_with_bare_decision_receipt_fails_check4(tmp_path):
    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    receipts = _load(root, "receipts.jsonl")
    victim = next(t for t in trials if not t["security_success"])
    forged_rid = "d" * 64
    receipts.append({"ts": 0.0, "receipt_id": forged_rid, "event_id": "e" * 64,
                     "kind": "decision", "host": "", "exit_code": None, "outcome": "ALLOW",
                     "detail": {}})
    victim["security_success"] = True
    victim["receipt_id"] = forged_rid
    _rewrite(root, "trials.jsonl", trials)
    _rewrite(root, "receipts.jsonl", receipts)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_manifest_and_rows_carry_schema_version_2(tmp_path):
    root = _emit_run(tmp_path)
    with open(os.path.join(root, "manifest.json")) as f:
        assert json.load(f)["schema_version"] == "2"
    for name in ("model_calls.jsonl", "events.jsonl", "receipts.jsonl", "trials.jsonl"):
        rows = _load(root, name)
        assert rows and all(r["schema_version"] == "2" for r in rows)


def test_schema_drift_is_detected(tmp_path):
    root = _emit_run(tmp_path)
    trials = _load(root, "trials.jsonl")
    trials[0]["schema_version"] = "1"
    _rewrite(root, "trials.jsonl", trials)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError):
        verify_run(root)


def test_call_refs_and_event_ids_are_unique(tmp_path):
    root = _emit_run(tmp_path)
    refs = [c["call_ref"] for c in _load(root, "model_calls.jsonl")]
    eids = [e["event_id"] for e in _load(root, "events.jsonl")]
    assert refs and len(refs) == len(set(refs))
    assert eids and len(eids) == len(set(eids))


def test_same_channel_conditions_get_distinct_event_ids(tmp_path):


    root = _emit_run(tmp_path)
    eids = [e["event_id"] for e in _load(root, "events.jsonl")]
    assert len(eids) == len(set(eids))


def test_duplicate_call_ref_crashes_loudly(tmp_path):
    from eval.evidence import log_model_call
    man = {"commit": "x", "dataset_hash": "d", "model_id": "mock:x", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path / "r"))
    log_model_call(rd, principal="p", seed=0, messages=[], response="o",
                   provider_id="mock:x", usage={}, call_ref="dup")
    with pytest.raises(AssertionError):
        log_model_call(rd, principal="p", seed=0, messages=[], response="o2",
                       provider_id="mock:x", usage={}, call_ref="dup")


def test_trial_seed_not_in_manifest_crashes(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": "mock:x", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path / "r"))
    with pytest.raises(AssertionError):
        log_trial(rd, case_id="c", condition="A", seed=99, outcome="x",
                  spoof_success=False, security_success=False, receipt_id=None,
                  call_refs=[], event_ids=[], metric=0.0, extra={})


def test_run_id_is_seed_deterministic(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": "mock:x", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    rd = open_run(dict(man), out_root=str(tmp_path / "r"))
    assert rd.run_id.endswith("-0")


def test_run_id_incorporates_seed(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": "mock:x", "prompts": {},
           "seeds": [0, 1], "policies": {}, "budgets": {}, "condition_set": ["A"]}
    r0 = open_run(dict(man, seed=0), out_root=str(tmp_path / "r"))
    r1 = open_run(dict(man, seed=1), out_root=str(tmp_path / "r"))
    r0_again = open_run(dict(man, seed=0), out_root=str(tmp_path / "r"))
    base = lambda rid: rid.rsplit(".", 1)[0]
    assert base(r0.run_id) != base(r1.run_id)
    assert base(r0_again.run_id) == r0.run_id


def test_failed_run_seals_atomically_and_verify_fails(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": "mock:x", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path / "r"))
    log_trial(rd, case_id="c", condition="A", seed=0, outcome="x",
              spoof_success=False, security_success=False, receipt_id=None,
              call_refs=[], event_ids=[], metric=0.0, extra={})
    seal_failed(rd, reason="boom")
    with open(os.path.join(rd.root, "status.json")) as f:
        assert json.load(f)["status"] == "failed"
    verify_checksums(rd.root)
    with pytest.raises(AssertionError):
        verify_run(rd.root)


def test_dirty_tree_blocks_open_run_for_real_manifest(tmp_path, monkeypatch):
    import eval.evidence.writer as w
    monkeypatch.setattr(w, "source_provenance",
                        lambda: {"commit": "abc", "source_tree_hash": "h", "dirty": True})
    man = {"commit": "abc", "dataset_hash": "d", "model_id": "openai/gpt-5.6-sol", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    with pytest.raises(RuntimeError, match="dirty tree"):
        open_run(man, out_root=str(tmp_path / "r"))


def test_dirty_tree_blocks_seal_for_real_manifest(tmp_path, monkeypatch):
    import eval.evidence.writer as w
    clean = {"commit": "abc", "source_tree_hash": "h", "dirty": False}
    monkeypatch.setattr(w, "source_provenance", lambda: clean)
    man = {"commit": "abc", "dataset_hash": "d", "model_id": "openai/gpt-5.6-sol", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path / "r"))
    write_aggregates(rd, [])
    monkeypatch.setattr(w, "source_provenance",
                        lambda: {"commit": "abc", "source_tree_hash": "h", "dirty": True})
    with pytest.raises(RuntimeError, match="dirty tree"):
        seal(rd)


def test_clean_mock_run_records_provenance_and_verifies(tmp_path, monkeypatch):
    import eval.evidence.writer as w
    monkeypatch.setattr(w, "source_provenance",
                        lambda: {"commit": "cafe", "source_tree_hash": "treehash", "dirty": False})
    root = _emit_run(tmp_path)
    with open(os.path.join(root, "manifest.json")) as f:
        m = json.load(f)
    assert m["commit"] == "cafe"
    assert m["source_tree_hash"] == "treehash"
    assert m["dirty"] is False
    verify_run(root)


def test_verify_fails_when_manifest_missing_source_tree_hash(tmp_path):
    root = _emit_run(tmp_path)
    with open(os.path.join(root, "manifest.json")) as f:
        m = json.load(f)
    del m["source_tree_hash"]
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump(m, f, indent=2, sort_keys=True)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError, match="source_tree_hash"):
        verify_run(root)


def test_verify_fails_when_real_run_marked_dirty(tmp_path):
    root = _emit_run(tmp_path)
    with open(os.path.join(root, "manifest.json")) as f:
        m = json.load(f)
    m["model_id"] = "openai/gpt-5.6-sol"
    m["dirty"] = True
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump(m, f, indent=2, sort_keys=True)
    _reseal(root)
    verify_checksums(root)
    with pytest.raises(AssertionError, match="dirty tree"):
        verify_run(root)


def test_partial_unsealed_run_fails_verify(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": "mock:x", "prompts": {},
           "seeds": [0], "seed": 0, "policies": {}, "budgets": {}, "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path / "r"))

    with pytest.raises(AssertionError):
        verify_run(rd.root)
