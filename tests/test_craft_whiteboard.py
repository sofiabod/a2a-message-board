import json
import os
import socket

import httpx
import pytest

from eval.coordination.craft import CraftCoordinationBenchmark
from eval.coordination.run_wb import run_whiteboard
from eval.evidence.verify import verify_run

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "craft", "craft.jsonl")


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network in hermetic test")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(httpx, "post", boom)


@pytest.fixture
def bench():
    return CraftCoordinationBenchmark(FIX)


def _read_jsonl(root, name):
    with open(os.path.join(root, name)) as f:
        return [json.loads(l) for l in f if l.strip()]


def _trials(root):
    return _read_jsonl(root, "trials.jsonl")


def _rate(root, cond):
    rows = [t for t in _trials(root) if t["condition"] == cond]
    return sum(bool(t["security_success"]) for t in rows) / len(rows)


def _metric(root, cond):
    rows = [t for t in _trials(root) if t["condition"] == cond]
    return sum(t["metric"] for t in rows) / len(rows)


def _assembler_answer(root):
    ans = [e for e in _read_jsonl(root, "events.jsonl") if e.get("reason") == "answer"]
    for e in ans:
        payload = e["payload"]["text"]
        obj = json.loads(payload) if isinstance(payload, str) else payload
        if isinstance(obj, dict) and any(k.startswith("(") for k in obj):
            return obj
    raise AssertionError("no assembler answer event found")


def test_run_seals_and_verifies(no_network, bench):
    r = run_whiteboard(bench, mock=True)
    for name in ("manifest.json", "model_calls.jsonl", "events.jsonl", "receipts.jsonl",
                 "trials.jsonl", "aggregates.json", "checksums.txt"):
        assert os.path.exists(os.path.join(r.root, name))
    verify_run(r.root)


def test_utility_b_positive_and_agents_authored(no_network, bench):
    r = run_whiteboard(bench, mock=True)
    assert _metric(r.root, "B") > 0
    assert _read_jsonl(r.root, "model_calls.jsonl")


def test_causal_answer_contains_peer_only_block(no_network, bench):
    r = run_whiteboard(bench, mock=True)
    task = bench.iter_tasks()[0]
    roles = bench._roles[task.id]
    assembler = roles[-1]
    own = {b for coord, b in _view_blocks(bench, task.id, assembler)}
    peers = set()
    for role in roles[:-1]:
        peers |= {b for coord, b in _view_blocks(bench, task.id, role)}
    peer_only = peers - own
    assert peer_only, "fixture assumption: peers hold blocks the assembler doesn't"

    answer = _assembler_answer(r.root)
    seen = {b for blocks in answer.values() for b in blocks}
    assert seen & peer_only, "assembler answer shows no peer-only block -> no causal read"


def test_security_e_lt_d(no_network, bench):
    r = run_whiteboard(bench, mock=True)
    assert _rate(r.root, "E") < _rate(r.root, "D")


def test_coordination_preserved_c_approx_b(no_network, bench):
    r = run_whiteboard(bench, mock=True)
    assert abs(_metric(r.root, "C") - _metric(r.root, "B")) <= 0.05


def test_causal_drop_confirms_for_d(no_network, bench):
    r = run_whiteboard(bench, mock=True)
    assert any(v is True for v in _flatten(r.attack)), "attack must expose causal_drop_confirms True"


def _view_blocks(bench, task_id, role):
    from eval.coordination.craft import _cells
    return list(_cells(bench.view_for(task_id, role)).items())


def _flatten(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _flatten(v)
    else:
        yield obj
