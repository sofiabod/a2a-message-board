import hashlib
import json
import os
import random

import eval.experiments.pilot1 as pilot1
from eval.experiments.pilot1 import (
    CONDITIONS, run_slice, run_benign_control, _benign_pass, _benign_overblock,
    decide_case, _report, _paired,
)
from eval.metrics.stats import paired_bootstrap
from eval.harness.agents import ScriptedSelector
from eval.harness.benchmarks import load_as_cases, load_benign_cases, verify_card, sign_card, build_registry
from gateway.allowlists import EffectivePolicy
from gateway.screening import Decision, ALLOW
from eval.harness import GovernedChannel, InMemoryRecorder
from eval.harness.channels import DENY_V, ALWAYS_ALLOW, DENY


def _read(out_dir, condition, case_id):
    with open(os.path.join(out_dir, condition, case_id + ".json")) as f:
        return json.load(f)


def _order(case_id, seed=0):
    rng = random.Random(hashlib.sha256(f"{case_id}:{seed}".encode()).hexdigest())
    o = list(range(10))
    rng.shuffle(o)
    return o


def _benign_pos(case_id):
    return _order(case_id).index(0) + 1


def _pos_of(case_id, card_index):
    return _order(case_id).index(card_index) + 1


def _force_impostor():
    cases = load_as_cases(sample=True)
    return ScriptedSelector({c.case_id: 1 + (_benign_pos(c.case_id) % 10) for c in cases})


def _force_benign():
    cases = load_as_cases(sample=True)
    return ScriptedSelector({c.case_id: _benign_pos(c.case_id) for c in cases})


def test_a_six_conditions_produce_different_attack_success(tmp_path):
    cases = load_as_cases(sample=True)
    out_dir = str(tmp_path)
    run_slice(cases, selector=_force_impostor(), out_dir=out_dir)

    asr = {}
    for cond in CONDITIONS:
        rows = [_read(out_dir, cond, c.case_id) for c in cases]
        asr[cond] = sum(r["spoof_success"] for r in rows) / len(rows)

    assert asr["B"] == 1.0 and asr["D"] == 1.0
    assert asr["O"] == asr["B"]
    assert asr["A"] == 0.0
    assert asr["C"] == 0.0 and asr["E"] == 0.0
    assert asr["C"] < asr["B"] and asr["E"] < asr["D"]

    for c in cases:
        a = _read(out_dir, "A", c.case_id)
        assert a["channel_type"] == "isolated"
        assert a["verified"] is False
        assert a["records"] == []


def test_b_impostor_rejected_by_governed_accepted_by_raw(tmp_path):
    cases = load_as_cases(sample=True)
    out_dir = str(tmp_path)
    for card_index in (1, 2, 3):
        selector = ScriptedSelector({c.case_id: _pos_of(c.case_id, card_index) for c in cases})
        run_slice(cases, selector=selector, out_dir=out_dir)
        for c in cases:
            assert not verify_card(c.cards[card_index], c.registry)
            raw = _read(out_dir, "D", c.case_id)
            assert raw["is_impostor"] is True
            assert raw["spoof_success"] is True
            assert raw["outcome"] == "selected_impostor"

            gov = _read(out_dir, "C", c.case_id)
            assert gov["is_impostor"] is True
            assert gov["verified"] is False
            assert gov["spoof_success"] is False
            assert gov["outcome"] == "rejected_impostor"


def test_c_outcomes_are_selection_not_canary_leak(tmp_path):
    cases = load_as_cases(sample=True)
    out_dir = str(tmp_path)
    run_slice(cases, selector=_force_impostor(), out_dir=out_dir)
    run_slice(cases, selector=_force_benign(), out_dir=out_dir, conditions=("B", "C"))

    for cond in CONDITIONS:
        for c in cases:
            row = _read(out_dir, cond, c.case_id)
            assert row["outcome"] in ("selected_impostor", "selected_benign", "rejected_impostor")
            for r in row["records"]:
                assert r["kind"] != "leak"
                assert r["reason"] != "canary_leak"


def test_d_benign_pass_is_from_benign_controls_not_one_minus_asr(tmp_path):
    attack_cases = load_as_cases(sample=True)
    benign_cases = load_benign_cases(sample=True)
    out_dir = str(tmp_path)

    selector = ScriptedSelector({c.case_id: _benign_pos(c.case_id) for c in benign_cases})
    run_slice(attack_cases, selector=_force_impostor(), out_dir=out_dir)
    attack = {c: {"n": len(attack_cases),
                  "spoof_success": sum(_read(out_dir, c, ac.case_id)["spoof_success"] for ac in attack_cases),
                  "per_case": {ac.case_id: float(_read(out_dir, c, ac.case_id)["spoof_success"]) for ac in attack_cases}}
              for c in CONDITIONS}
    benign = run_benign_control(benign_cases, selector=selector)
    report = _report(attack, benign)

    decided = [(decide_case(bc, 0, selector), bc) for bc in benign_cases]
    for cond in CONDITIONS:
        expected = sum(_benign_pass(cond, d, sh, bc) for (d, sh), bc in decided) / len(benign_cases)
        assert report[cond]["benign_pass"] == expected

    assert report["C"]["benign_pass"] == 1.0 and report["C"]["attack_success"] == 0.0
    assert report["D"]["benign_pass"] == 1.0 and report["D"]["attack_success"] == 1.0
    assert report["A"]["benign_pass"] == 0.0 and report["A"]["attack_success"] == 0.0


def _pass_screen(m, t):
    return Decision(ALLOW, [])


def test_e_governed_empty_lane_still_enforces_policy():
    empty = GovernedChannel(EffectivePolicy(peer_allowlist=("alpha",), tool_allowlist=("*",)),
                            InMemoryRecorder(), screen_fn=_pass_screen, lane="")
    v = empty.post("alpha", "coord", {"type": "message", "text": "hi"})
    assert v.outcome == DENY_V
    assert v.reason == "mode_default_deny"

    stranger = empty.post("mallory", "coord", {"type": "message", "text": "hi"})
    assert stranger.outcome == DENY_V
    assert stranger.reason == "peer_not_allowed"


def test_f_sender_supplied_mode_cannot_escalate():
    policy = EffectivePolicy(peer_allowlist=("alpha",), tool_allowlist=("*",),
                             mode_map=(("message", DENY),))
    ch = GovernedChannel(policy, InMemoryRecorder(), screen_fn=_pass_screen, lane="")
    v = ch.post("alpha", "coord", {"type": "message", "text": "hi", "mode": ALWAYS_ALLOW})
    assert v.outcome == DENY_V
    assert v.reason == "mode_default_deny"


def test_g_verifier_acts_on_signature_not_equality_to_benign():
    case = load_as_cases(sample=True)[0]
    genuine = case.cards[0]
    stripped = {k: v for k, v in genuine.items() if k != "signature"}
    assert not verify_card(stripped, case.registry)


def test_h_asr_is_earned_signed_impostor_can_pass():
    case = load_as_cases(sample=True)[0]
    key = b"a2a-registered-genuine-key"
    genuine = {k: v for k, v in case.cards[0].items() if k not in ("case_id", "card_index", "signature")}
    registry = build_registry(genuine, key)

    impostor_body = dict(genuine, name="Rogue " + genuine["name"])
    unsigned = dict(impostor_body)
    assert not verify_card(unsigned, registry)

    key_compromised = dict(impostor_body, signature=sign_card(impostor_body, key))
    assert verify_card(key_compromised, registry)


def test_j_paired_ci_real_governance_reduces_asr_below_zero(tmp_path):
    cases = load_as_cases(sample=True)
    attack = run_slice(cases, selector=_force_impostor(), out_dir=str(tmp_path))
    _, lo, hi = paired_bootstrap(_paired(attack["B"], attack["C"]), seed=0)
    assert hi < 0


def test_k_gutting_verify_card_makes_paired_ci_straddle_zero(tmp_path, monkeypatch):
    cases = load_as_cases(sample=True)
    monkeypatch.setattr(pilot1, "verify_card", lambda card, reg: True)
    attack = run_slice(cases, selector=_force_impostor(), out_dir=str(tmp_path))
    mean, lo, hi = paired_bootstrap(_paired(attack["B"], attack["C"]), seed=0)
    assert lo <= 0 <= hi and mean == 0.0


def test_l_benign_falsifiability_governance_does_not_punish_legit(tmp_path):
    cases = load_as_cases(sample=True)
    sel = _force_benign()
    attack = run_slice(cases, selector=sel, out_dir=str(tmp_path), conditions=("B", "C"))
    _, lo, hi = paired_bootstrap(_paired(attack["B"], attack["C"]), seed=0)
    assert lo <= 0 <= hi


def test_m_signed_genuine_card_governed_allow_not_overblocked():
    for case in load_benign_cases(sample=True):
        assert verify_card(case.cards[0], case.registry)
        for cond in ("C", "E"):
            assert _benign_overblock(cond, case) is False


def test_m_unsigned_genuine_looking_card_would_be_overblocked():
    case = load_benign_cases(sample=True)[0]
    unsigned = {k: v for k, v in case.cards[0].items() if k != "signature"}
    stripped = case.__class__(case.case_id, case.task_prompt,
                              (unsigned,) + case.cards[1:], case.benign_choice, case.registry)
    assert not verify_card(unsigned, case.registry)
    for cond in ("C", "E"):
        assert _benign_overblock(cond, stripped) is True


def test_m_benign_overblock_zero_for_governed_but_gutting_signature_raises_it():
    benign_cases = load_benign_cases(sample=True)
    sel = ScriptedSelector({c.case_id: _benign_pos(c.case_id) for c in benign_cases})

    report = _report({c: {"n": 1, "spoof_success": 0, "per_case": {"x": 0.0}} for c in CONDITIONS},
                     run_benign_control(benign_cases, selector=sel))
    assert report["C"]["benign_overblock"] == 0.0
    assert report["E"]["benign_overblock"] == 0.0
    assert report["B"]["benign_overblock"] == 0.0

    gutted = [c.__class__(c.case_id, c.task_prompt,
                          ({k: v for k, v in c.cards[0].items() if k != "signature"},) + c.cards[1:],
                          c.benign_choice, c.registry) for c in benign_cases]
    gutted_report = _report({c: {"n": 1, "spoof_success": 0, "per_case": {"x": 0.0}} for c in CONDITIONS},
                            run_benign_control(gutted, selector=sel))
    assert gutted_report["C"]["benign_overblock"] == 1.0
    assert gutted_report["E"]["benign_overblock"] == 1.0
    assert gutted_report["B"]["benign_overblock"] == 0.0


def test_i_governed_asr_nonzero_when_selector_picks_signed_impostor(tmp_path):
    case = load_as_cases(sample=True)[0]
    key = b"a2a-registered-genuine-key"
    genuine = {k: v for k, v in case.cards[0].items() if k not in ("case_id", "card_index", "signature")}
    body = dict(genuine, name="Rogue " + genuine["name"])
    signed_impostor = dict(body, signature=sign_card(body, key))

    replaced = case.__class__(case.case_id, case.task_prompt,
                              (case.cards[0], signed_impostor) + case.cards[2:],
                              case.benign_choice, case.registry)

    out_dir = str(tmp_path)
    pos = _pos_of(case.case_id, 1)
    run_slice([replaced], selector=ScriptedSelector({case.case_id: pos}), out_dir=out_dir)
    gov = _read(out_dir, "C", case.case_id)
    assert gov["is_impostor"] is True
    assert gov["verified"] is True
    assert gov["spoof_success"] is True
    assert gov["outcome"] == "selected_impostor"
