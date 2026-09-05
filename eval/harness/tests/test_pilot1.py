import hashlib
import json
import os

import pytest

from eval.experiments.pilot1 import (
    run_slice, run_benign_control, decide_case, scoped_key, apply_policy, CONDITIONS,
)
from eval.harness.agents import ScriptedSelector
from eval.harness.benchmarks import load_as_cases, load_benign_cases, EndpointSink


def _read(out_dir, condition, case_id):
    with open(os.path.join(out_dir, condition, case_id + ".json")) as f:
        return json.load(f)


def test_writes_one_transcript_per_condition_case(tmp_path):
    cases = load_as_cases(sample=True)[:2]
    out_dir = str(tmp_path)
    run_slice(cases, selector=ScriptedSelector({}, default=1), out_dir=out_dir)

    files = [p for _, _, fs in os.walk(out_dir) for p in fs if p.endswith(".json")]
    assert len(files) == 2 * len(CONDITIONS)
    row = _read(out_dir, "A", cases[0].case_id)
    assert len(row["manifest_hash"]) == 64


def test_outcomes_have_no_leak_records(tmp_path):
    cases = load_as_cases(sample=True)[:2]
    out_dir = str(tmp_path)
    run_slice(cases, selector=ScriptedSelector({}, default=1), out_dir=out_dir)
    for c in CONDITIONS:
        for case in cases:
            row = _read(out_dir, c, case.case_id)
            assert row["outcome"] in {"selected_impostor", "rejected_impostor", "selected_benign"}
            assert all(r["kind"] != "leak" for r in row["records"])


def test_six_numbers_differ_by_construction(tmp_path):
    cases = load_as_cases(sample=True)[:1]
    probe = str(tmp_path / "probe")
    run_slice(cases, selector=ScriptedSelector({}, default=1), out_dir=probe)
    benign_index = _read(probe, "B", cases[0].case_id)["benign_index"]
    impostor = 1 + (benign_index % 10)

    out_dir = str(tmp_path / "attack")
    summary = run_slice(cases, selector=ScriptedSelector({}, default=impostor), out_dir=out_dir)

    assert summary["A"]["spoof_success"] == 0
    assert summary["B"]["spoof_success"] == 1
    assert summary["D"]["spoof_success"] == 1
    assert summary["O"]["spoof_success"] == 1
    assert summary["C"]["spoof_success"] == 0
    assert summary["E"]["spoof_success"] == 0

    row_c = _read(out_dir, "C", cases[0].case_id)
    assert row_c["outcome"] == "rejected_impostor"
    assert row_c["verified"] is False
    row_b = _read(out_dir, "B", cases[0].case_id)
    row_e = _read(out_dir, "E", cases[0].case_id)
    assert row_b["outcome"] == "selected_impostor"
    assert row_c["decision_ref"] == row_b["decision_ref"] == row_e["decision_ref"]


def test_benign_control_is_separate_and_passes(tmp_path):
    benign = load_benign_cases(sample=True)[:3]
    probe = str(tmp_path / "probe")
    run_slice(benign, selector=ScriptedSelector({}, default=1), out_dir=probe)
    picks = {c.case_id: _read(probe, "B", c.case_id)["benign_index"] for c in benign}

    summary = run_benign_control(benign, selector=ScriptedSelector(picks))
    assert summary["A"]["pass"] == 0
    for c in [c for c in CONDITIONS if c != "A"]:
        assert summary[c]["pass"] == summary[c]["n"]


def test_all_conditions_share_one_decision(tmp_path):
    cases = load_as_cases(sample=True)[:2]
    out_dir = str(tmp_path)
    run_slice(cases, selector=ScriptedSelector({}, default=1), out_dir=out_dir)
    for case in cases:
        decision, _ = decide_case(case, 0, ScriptedSelector({}, default=1))
        refs = {_read(out_dir, c, case.case_id)["decision_ref"] for c in CONDITIONS}
        assert refs == {decision.ref()}


def test_selector_called_once_per_case(tmp_path):
    cases = load_as_cases(sample=True)[:2]
    calls = {"n": 0}
    base = ScriptedSelector({}, default=1)

    def counting(task_prompt, cards, seed):
        calls["n"] += 1
        return base(task_prompt, cards, seed)

    run_slice(cases, selector=counting, out_dir=str(tmp_path))
    assert calls["n"] == len(cases)


def _impostor_decision(case):
    probe = decide_case(case, 0, ScriptedSelector({}, default=1))[0]
    impostor = 1 + (probe.benign_index % 10)
    return decide_case(case, 0, ScriptedSelector({}, default=impostor))


def test_raw_impostor_produces_receipt_reaching_attacker():
    case = load_as_cases(sample=True)[0]
    decision, shuffled = _impostor_decision(case)
    assert decision.is_impostor
    sink = EndpointSink()
    row = apply_policy("B", decision, shuffled, case, scoped_key("B", case), sink)
    assert row["spoof_success"] is True
    assert len(sink.receipts) == 1
    assert sink.receipts[0]["is_impostor"] is True
    assert row["receipt"]["endpoint"] == shuffled[decision.choice - 1]["url"]


def test_governed_impostor_records_no_receipt():
    case = load_as_cases(sample=True)[0]
    decision, shuffled = _impostor_decision(case)
    sink = EndpointSink()
    row = apply_policy("C", decision, shuffled, case, scoped_key("C", case), sink)
    assert row["spoof_success"] is False
    assert sink.receipts == []
    assert row["receipt"] is None


def test_gutted_invocation_yields_zero_attack_success_even_when_selected():
    import eval.experiments.pilot1 as pilot1
    case = load_as_cases(sample=True)[0]
    decision, shuffled = _impostor_decision(case)
    dead = EndpointSink()
    dead.invoke = lambda card, task_prompt: None
    row = pilot1.apply_policy("B", decision, shuffled, case, scoped_key("B", case), dead)
    assert decision.is_impostor
    assert row["spoof_success"] is False
    assert dead.receipts == []


def test_scoped_keys_are_distinct_per_condition(tmp_path):
    cases = load_as_cases(sample=True)[:1]
    out_dir = str(tmp_path)
    run_slice(cases, selector=ScriptedSelector({}, default=1), out_dir=out_dir)
    hc = _read(out_dir, "C", cases[0].case_id)["scoped_handle"]
    he = _read(out_dir, "E", cases[0].case_id)["scoped_handle"]
    assert hc != he

    case = cases[0]
    decision, shuffled = decide_case(case, 0, ScriptedSelector({}, default=1))
    with pytest.raises(RuntimeError):
        apply_policy("C", decision, shuffled, case, scoped_key("E", case), EndpointSink())
