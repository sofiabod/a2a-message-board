import json
import os

import pytest

from scripts import modal_eval


def test_child_failure_propagates_and_seals_failed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / "evidence" / "runs" / "abc-0")
    (tmp_path / "evidence" / "runs" / "abc-0" / "manifest.json").write_text("{}")
    out = tmp_path / "out"
    os.makedirs(out)

    def boom():
        raise RuntimeError("child died")

    with pytest.raises(SystemExit):
        modal_eval._seal(str(out), "craft", 0, boom)

    status = json.loads((out / "eval_status.json").read_text())
    assert status["status"] == "failed" and status["returncode"] == 1
    assert os.path.exists(out / "runs" / "abc-0")


def test_child_success_reports_passed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    os.makedirs(out)
    report = modal_eval._seal(str(out), "craft", 0, lambda: {"evidence": "x"})
    assert report == {"evidence": "x"}
    status = json.loads((out / "eval_status.json").read_text())
    assert status["status"] == "passed"
