import json
import os
import socket

import httpx
import pytest

import eval.experiments.pilot1 as pilot1
from eval.evidence import open_run, seal, write_aggregates
from eval.evidence.verify import verify_run
from eval.harness.agents import ScriptedSelector
from eval.harness.benchmarks import load_as_cases, load_benign_cases
from eval.harness.benchmarks.a2a_as import as_task
from eval.harness import model_openrouter as mo

AS_TRUTH = {"A": 0.0, "B": 0.8, "O": 0.8, "C": 0.0, "D": 0.8, "E": 0.0}


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network in hermetic test")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(httpx, "post", boom)


def _load_trials(root):
    with open(os.path.join(root, "trials.jsonl")) as f:
        return [json.loads(l) for l in f if l.strip()]


def _recompute_aggregates(root):
    trials = _load_trials(root)
    conditions = sorted({t["condition"] for t in trials})
    out = {}
    for c in conditions:
        rows = [t for t in trials if t["condition"] == c]
        out[c] = {"attack_success": sum(t["spoof_success"] for t in rows) / len(rows),
                  "metric": sum(t["metric"] for t in rows) / len(rows), "n": len(rows)}
    return out


def _run_as_mock(root_dir):
    sel = ScriptedSelector({})
    cases = load_as_cases(sample=True)

    class _Args:
        real = False

    man = pilot1._build_manifest(cases, _Args())
    rd = open_run(man, out_root=root_dir)
    out_dir = os.path.join(root_dir, "transcripts")
    pilot1.run_slice(cases, selector=sel, out_dir=out_dir, rd=rd)
    pilot1.run_benign_control(load_benign_cases(sample=True), selector=sel, rd=rd)
    write_aggregates(rd, _load_trials(rd.root))
    seal(rd)
    return rd.root


def test_a_as_mock_run_seals_and_verifies_six_checks(tmp_path, no_network):
    root = _run_as_mock(str(tmp_path))
    for name in ("manifest.json", "model_calls.jsonl", "events.jsonl", "receipts.jsonl",
                 "trials.jsonl", "aggregates.json", "checksums.txt"):
        assert os.path.exists(os.path.join(root, name))
    verify_run(root)


def test_a_benign_path_model_calls_present_and_referenced(tmp_path, no_network):
    root = _run_as_mock(str(tmp_path))
    with open(os.path.join(root, "model_calls.jsonl")) as f:
        calls = [json.loads(l) for l in f if l.strip()]
    principals = {c["principal"] for c in calls}
    assert "selector-benign" in principals
    refs = {c["call_ref"] for c in calls}
    for t in _load_trials(root):
        if t["condition"].endswith(":benign"):
            assert t["call_refs"] and all(r in refs for r in t["call_refs"])


_MALFORMED = [
    {},
    {"choices": []},
    {"choices": None},
    {"choices": [{}]},
    {"choices": [{"message": {}}]},
    {"choices": [{"message": {"content": None}}]},
    {"choices": [{"message": {"content": ""}}]},
    {"error": {"message": "rate limited"}},
    {"choices": [{"message": {"content": "no integer here"}}]},
    {"choices": [{"message": {"content": "not json at all"}}]},
    {"choices": [{"message": {"content": '{"text": broken'}}]},
    {"choices": [{"message": {"content": "```json\n{\"text\":\"x\"}\n```"}}]},
]


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


@pytest.fixture
def sol(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    monkeypatch.setenv("MODEL_ID", mo.MODEL_ID)
    holder = {}
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(holder["body"]))
    return holder


def test_b_every_real_parser_survives_malformed_without_faking_success(sol):
    cards = [{"name": "a", "case_id": "c", "card_index": 0}, {"name": "b", "case_id": "c", "card_index": 1}]
    victim = mo.openrouter_victim("s3cr3t", "ops")
    attacker = mo.openrouter_attacker([{"text": "a"}, {"text": "b"}], "ops")
    obs = [{"payload": {"text": "hi"}}]
    for body in _MALFORMED:
        sol["body"] = body

        choice, pid, usage, content = mo.openrouter_selector("t", cards, 0)
        assert isinstance(choice, int) and isinstance(content, str) and isinstance(usage, dict)

        v = victim("victim", obs, 0)
        assert set(v) == {"channel", "type", "text"} and isinstance(v["text"], str)
        assert "s3cr3t" not in v["text"]

        a = attacker("attacker", obs, 0)
        assert a["channel"] == "ops" and isinstance(a["text"], str)


def test_c_selector_tuple_contract_mock_vs_real(sol):
    cards = pilot1._shuffle(load_as_cases(sample=True)[0].cards, "c", 0)

    sol["body"] = {"choices": [{"message": {"content": "1"}}], "id": "prov-1", "usage": {"total_tokens": 3}}
    real = mo.openrouter_selector("t", cards, 0)
    assert isinstance(real, tuple) and len(real) == 4
    assert isinstance(real[0], int) and isinstance(real[1], str) and isinstance(real[2], dict) and isinstance(real[3], str)

    mock = ScriptedSelector({}, default=1)("t", cards, 0)
    assert isinstance(mock, int)

    sol["body"] = {"choices": [{"message": {"content": "3"}}], "id": "p", "usage": {}}
    case = load_as_cases(sample=True)[0]
    d_real, _ = pilot1.decide_case(case, 0, mo.openrouter_selector)
    d_mock, _ = pilot1.decide_case(case, 0, ScriptedSelector({}, default=3))
    assert d_real.choice == d_mock.choice == 3


def test_e_aggregates_recompute_from_trials_as(tmp_path, no_network):
    root = _run_as_mock(str(tmp_path))
    with open(os.path.join(root, "aggregates.json")) as f:
        sealed = json.load(f)
    assert _recompute_aggregates(root) == sealed
    for cond, expected in AS_TRUTH.items():
        assert sealed[cond]["attack_success"] == expected
        assert sealed[cond + ":benign"]["attack_success"] == 0.0


def test_f_non_mock_zero_model_calls_fails(tmp_path):
    man = {"commit": "x", "dataset_hash": "d", "model_id": "openrouter/real",
           "prompts": {}, "seeds": [0], "seed": 0, "policies": {}, "budgets": {},
           "condition_set": ["A"]}
    rd = open_run(man, out_root=str(tmp_path))
    write_aggregates(rd, [])
    seal(rd)
    with pytest.raises(AssertionError, match="zero model_calls"):
        verify_run(rd.root)
