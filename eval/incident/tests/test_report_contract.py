import pathlib

import eval.incident.run as run
from eval.incident.run import _run_local, _run_modal
from eval.incident.sandbox import LocalSandbox

PROVENANCE = {"backend", "timestamp", "sandbox_ids", "receipts"}
CHAIN = {"completed", "depth", "secret_left", "gate_reason"}
STATS = {"mcnemar", "bootstrap", "p_value", "pvalue", "p", "ci", "stat", "statistic"}


def _flat_keys(d):
    out = set()
    for k, v in d.items():
        out.add(k)
        if isinstance(v, dict):
            out |= _flat_keys(v)
    return out


def test_local_report_has_no_mcnemar_or_bootstrap():
    out = _run_local(0, 5)
    assert out["replay"] == "scripted_faithful_replay"
    assert out["role"] == "appendix_mechanism_replay"
    assert not (_flat_keys(out) & STATS)


def test_replay_labelled_as_appendix():
    assert _run_local(0, 1)["role"] == "appendix_mechanism_replay"
    assert "mechanism appendix" in run.__doc__.lower()


def test_local_shape_matches_modal_contract(monkeypatch):
    monkeypatch.setattr(run, "ModalSandbox", LocalSandbox)
    local = _run_local(0, 5)
    modal = _run_modal(0)

    assert local["replay"] == modal["replay"] == "scripted_faithful_replay"
    assert set(local["provenance"]) == PROVENANCE == {k for k in modal if k in PROVENANCE}
    assert set(modal["chain"]["raw"]) == set(modal["chain"]["governed"]) == CHAIN
    assert set(local["raw"]["chain"]) == set(local["governed"]["chain"]) == CHAIN


def test_no_model_driven_identifier_in_incident():
    root = pathlib.Path(run.__file__).parent
    for path in root.rglob("*.py"):
        if path.parent.name == "tests":
            continue
        text = path.read_text().lower()
        assert "model-driven" not in text, path
        assert "model_driven" not in text, path
