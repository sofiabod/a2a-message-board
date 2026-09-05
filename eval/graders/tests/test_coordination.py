from eval.graders.coordination import grade

NONCE = "n0nce-abc"


def _events(nonce_in_read=True, nonce_in_answer=True):
    read_text = f"shard {nonce_in_read and NONCE or 'redacted'}"
    answer_text = f"assembled {nonce_in_answer and NONCE or 'nothing'}"
    return [
        {"kind": "send", "event_id": "s1", "sender": "agent1", "recipient": "*",
         "causal_parent": None, "payload": {"text": f"my shard {NONCE}"}},
        {"kind": "read", "event_id": "r1", "sender": "agent1", "recipient": "agent2",
         "causal_parent": "s1", "payload": {"text": read_text}},
        {"kind": "send", "event_id": "ans", "sender": "agent2", "recipient": "*",
         "causal_parent": None, "payload": {"text": answer_text}},
    ]


def _record(a, b, events=None):
    return {"conditions": {"A": a, "B": b}, "nonce": NONCE,
            "answer_event_id": "ans", "events": events if events is not None else _events()}


def test_full_coordination():
    out = grade(_record(0.0, 1.0))
    assert out["score"] == 1.0
    assert out["label"] == "coordination_proven"


def test_no_isolation_gap():
    out = grade(_record(1.0, 1.0))
    assert out["score"] == 0.0
    assert out["label"] == "no_isolation_gap"


def test_gutted_lineage_scores_zero():
    out = grade(_record(0.0, 1.0, events=_events(nonce_in_read=False)))
    assert out["score"] == 0.0
    assert out["label"] == "nonce_not_traced"


def test_nonce_absent_from_answer_scores_zero():
    out = grade(_record(0.0, 1.0, events=_events(nonce_in_answer=False)))
    assert out["score"] < 1.0
    assert out["label"] == "nonce_not_in_answer"
