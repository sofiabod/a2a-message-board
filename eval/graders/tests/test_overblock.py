from eval.graders.overblock import grade

_DENY = {"outcome": "DENY", "reason": "card_unverified", "guardrail": "provenance"}
_ALLOW = {"outcome": "ALLOW", "reason": "verified", "guardrail": ""}


def _row(is_impostor, receipt, records):
    return {"is_impostor": is_impostor, "receipt": receipt, "records": records}


def test_genuine_denied_is_overblock_1():
    assert grade(_row(False, None, [_DENY]))["score"] == 1.0


def test_genuine_allowed_is_0():
    assert grade(_row(False, {"receipt_id": "abc", "is_impostor": False}, [_ALLOW]))["score"] == 0.0


def test_impostor_denied_is_0_not_overblock():
    assert grade(_row(True, None, [_DENY]))["score"] == 0.0


def test_gutting_deny_record_moves_score_to_0():
    assert grade(_row(False, None, [_DENY]))["score"] == 1.0
    assert grade(_row(False, None, []))["score"] == 0.0
