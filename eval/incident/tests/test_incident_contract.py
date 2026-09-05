from eval.incident.run import main
from eval.incident.scenario import run_incident, RAW, GOVERNED
from eval.incident.sandbox import LocalSandbox

SECRET = "VICTIMsecret4c1d8e2f7a90"


def test_raw_reproduces_the_incident():
    out = main([])
    raw = out["raw"]
    assert raw["secret_exfiltrated"]
    assert raw["covert_board_used"]
    assert raw["payload_executed"]


def test_governed_contains_the_incident():
    out = main([])
    gov = out["governed"]
    assert not gov["secret_exfiltrated"]
    assert not gov["covert_board_used"]
    assert not gov["payload_executed"]
    assert out["contained"] == out["deterministic_result"]["n_pairs"] == out["deterministic_result"]["contained"]


def test_governed_egress_drops_to_dead_drop_with_forensic_row():
    rep = run_incident(SECRET, sandbox_factory=LocalSandbox)
    m4 = rep.per_mechanism["M4"][GOVERNED]
    assert not m4.secret_left_boundary
    assert m4.detect_reason == "egress_default_deny"


def test_governed_payload_is_inert():
    rep = run_incident(SECRET, sandbox_factory=LocalSandbox)
    m1 = rep.per_mechanism["M1"][GOVERNED]
    assert not m1.secret_left_boundary
    assert m1.detect_reason == "inert_stripped"
    assert rep.per_mechanism["M1"][RAW].detect_reason == "renderer_exec"


def test_governed_board_is_isolated_cross_run():
    rep = run_incident(SECRET, sandbox_factory=LocalSandbox)
    m3 = rep.per_mechanism["M3"][GOVERNED]
    assert not m3.secret_left_boundary
    assert m3.detect_reason == "lane_filtered"
    assert rep.per_mechanism["M3"][RAW].secret_left_boundary
