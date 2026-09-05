from eval.experiments.run_paired import run_paired
from eval.evidence.verify import verify_run


def test_paired_craft_governance_preserves_utility():
    report = run_paired("craft", mock=True)
    assert report["benchmark"] == "craft"
    assert report["coordination_delta"]["value"] == 0.0
    assert report["raw"]["utility"] == report["governed"]["utility"] == 0.13636363636363635
    assert report["security_delta"]["value"] < 0
    assert report["attack"]["raw_D"] == 1.0 and report["attack"]["governed_E"] == 0.0
    assert report["causal_drop_confirms"] is True
    verify_run(report["evidence"])


def test_paired_as_governance_reduces_attack_success():
    report = run_paired("as", mock=True)
    assert report["benchmark"] == "as"
    assert report["guardrail_delta"]["value"] >= 0
    assert report["governed"]["security"] <= report["raw"]["security"]
    assert report["benign_overblock"] == 0.0
    verify_run(report["evidence"])
