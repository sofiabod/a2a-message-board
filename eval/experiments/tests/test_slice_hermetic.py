import hashlib
import json
import os
import random

from eval.experiments.pilot1 import CONDITIONS, run_slice
from eval.harness.agents import ScriptedSelector
from eval.harness.benchmarks import as_task, load_as_cases, verify_card


def _read(out_dir, condition, case_id):
    with open(os.path.join(out_dir, condition, case_id + ".json")) as f:
        return json.load(f)


def _expected_shuffle(cards, case_id, seed=0):
    rng = random.Random(hashlib.sha256(f"{case_id}:{seed}".encode()).hexdigest())
    order = list(range(len(cards)))
    rng.shuffle(order)
    return order


def test_as_loader_returns_tasks_with_10_cards():
    cases = load_as_cases(sample=True)
    assert len(cases) == 5
    for case in cases:
        task = as_task(case)
        assert len(task.meta["cards"]) == 10
        assert case.benign_choice == 1
        assert task.expected == (str(case.benign_choice),)
        assert verify_card(case.cards[0], case.registry)
        assert not verify_card(case.cards[1], case.registry)


def test_impostor_selected_on_raw_but_rejected_on_governed(tmp_path):
    case = load_as_cases(sample=True)[0]
    order = _expected_shuffle(case.cards, case.case_id)
    benign_index = order.index(0) + 1
    spoof_choice = 1 + (benign_index % 10)

    out_dir = str(tmp_path)
    run_slice([case], selector=ScriptedSelector({}, default=spoof_choice), out_dir=out_dir)

    raw = _read(out_dir, "D", case.case_id)
    assert raw["is_impostor"] is True
    assert raw["spoof_success"] is True
    assert raw["outcome"] == "selected_impostor"
    assert all(r["kind"] != "leak" for r in raw["records"])

    gov = _read(out_dir, "C", case.case_id)
    assert gov["spoof_success"] is False
    assert gov["verified"] is False
    assert gov["outcome"] == "rejected_impostor"


def test_slice_runner_completes_all_conditions_and_writes_transcripts(tmp_path):
    cases = load_as_cases(sample=True)[:2]
    out_dir = str(tmp_path)
    summary = run_slice(cases, selector=ScriptedSelector({}, default=1), out_dir=out_dir)

    assert set(summary) == set(CONDITIONS)
    for condition in CONDITIONS:
        for case in cases:
            row = _read(out_dir, condition, case.case_id)
            assert row["condition"] == condition
            assert len(row["manifest_hash"]) == 64
    files = [p for _, _, fs in os.walk(out_dir) for p in fs if p.endswith(".json")]
    assert len(files) == len(CONDITIONS) * len(cases)
