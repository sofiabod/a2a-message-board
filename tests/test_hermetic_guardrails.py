import json
import os
import socket

import httpx
import pytest

import eval.experiments.pilot1 as pilot1
from eval.evidence import open_run, seal, write_aggregates
from eval.evidence.verify import verify_run
from eval.harness import model_openrouter as mo
from eval.harness import RawChannel, GovernedChannel, InMemoryRecorder
from eval.harness.benchmarks import load_as_cases, load_benign_cases
from gateway.allowlists import EffectivePolicy
from gateway.screening import Decision, ALLOW

PROVIDER_ID = "prov-sol-abc123"


def _boom(*a, **k):
    raise AssertionError("network in hermetic test")


class _Resp:
    def __init__(self, content):
        self._body = {"id": PROVIDER_ID, "usage": {"total_tokens": 7},
                      "choices": [{"message": {"content": content}}]}

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


@pytest.fixture
def sol_http(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    monkeypatch.setenv("MODEL_ID", mo.MODEL_ID)
    monkeypatch.setattr(socket, "socket", _boom)
    seen = []

    def fake_post(url, **kw):
        seen.append(PROVIDER_ID)
        return _Resp("2")

    monkeypatch.setattr(httpx, "post", fake_post)
    return seen


def _load(root, name):
    with open(os.path.join(root, name)) as f:
        return [json.loads(l) for l in f if l.strip()]


def _run_as_real(root_dir, cases):
    class _Args:
        real = True
    man = pilot1._build_manifest(cases, _Args())
    rd = open_run(man, out_root=root_dir)
    out_dir = os.path.join(root_dir, "transcripts")
    pilot1.run_slice(cases, selector=mo.openrouter_selector, out_dir=out_dir, rd=rd)
    pilot1.run_benign_control(load_benign_cases(sample=True), selector=mo.openrouter_selector, rd=rd)
    write_aggregates(rd, _load(rd.root, "trials.jsonl"))
    seal(rd)
    return rd.root


def test_a_paired_as_one_call_shared_ref_check5_holds(tmp_path, sol_http):
    cases = load_as_cases(sample=True)[:1]
    root = _run_as_real(str(tmp_path), cases)

    calls = _load(root, "model_calls.jsonl")
    attack_calls = [c for c in calls if c["principal"] == "selector"]
    assert len(attack_calls) == 1
    assert attack_calls[0]["provider_id"] == PROVIDER_ID

    trials = _load(root, "trials.jsonl")
    by_cond = {t["condition"]: t for t in trials if t["case_id"] == cases[0].case_id
               and not t["condition"].endswith(":benign")}
    assert by_cond["B"]["call_refs"] == by_cond["C"]["call_refs"]
    assert by_cond["B"]["call_refs"] == [attack_calls[0]["call_ref"]]

    verify_run(root)


def test_b_real_manifest_zero_model_calls_fails(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": mo.MODEL_ID,
           "prompts": {}, "seeds": [0], "seed": 0, "policies": {}, "budgets": {},
           "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path))
    write_aggregates(rd, [])
    seal(rd)
    with pytest.raises(AssertionError, match="zero model_calls"):
        verify_run(rd.root)


def test_b2_real_manifest_mock_provider_fails(tmp_path):
    from eval.evidence import log_model_call
    man = {"commit": "x", "dataset_hash": "d", "model_id": mo.MODEL_ID,
           "prompts": {}, "seeds": [0], "seed": 0, "policies": {}, "budgets": {},
           "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path))
    log_model_call(rd, principal="selector", seed=0, messages=[{"role": "user", "content": "x"}],
                   response="1", provider_id="mock:scripted", usage={}, call_ref="r1")
    write_aggregates(rd, [])
    seal(rd)
    with pytest.raises(AssertionError, match="zero real model_calls"):
        verify_run(rd.root)


def test_d_benign_sealed_and_referenced(tmp_path, sol_http):
    cases = load_as_cases(sample=True)[:1]
    root = _run_as_real(str(tmp_path), cases)

    calls = _load(root, "model_calls.jsonl")
    assert any(c["principal"] == "selector-benign" for c in calls)
    refs = {c["call_ref"] for c in calls}
    for t in _load(root, "trials.jsonl"):
        if t["condition"].endswith(":benign"):
            assert t["call_refs"] and all(r in refs for r in t["call_refs"])
    verify_run(root)


def test_e_governed_records_policy_decision_raw_does_not(sol_http):
    case = load_as_cases(sample=True)[0]
    decision, shuffled = pilot1.decide_case(case, 0, mo.openrouter_selector)

    raw = pilot1.apply_policy("B", decision, shuffled, case, pilot1.scoped_key("B", case))
    governed = pilot1.apply_policy("C", decision, shuffled, case, pilot1.scoped_key("C", case))

    assert raw["choice"] == governed["choice"]
    assert not raw["records"]
    assert governed["records"] and governed["records"][0]["guardrail"] == "provenance"

    policy = EffectivePolicy(peer_allowlist=("agent0",), tool_allowlist=("*",),
                             mode_map=(("message", "ALWAYS_ALLOW"),),
                             lane_bindings=(("agent0", "coord"),))
    rec = InMemoryRecorder()
    gov = GovernedChannel(policy, rec, lambda m, t: Decision(ALLOW, []), lane="coord")
    payload = {"type": "message", "text": "held-constant output"}
    rawch = RawChannel()

    assert rawch.post("agent0", "coord", payload).outcome == "ALLOW"
    assert not rawch._store.get("__records__")
    gov.post("agent0", "coord", payload)
    assert len(rec.all()) == 1 and rec.all()[0].outcome == "ALLOW"
