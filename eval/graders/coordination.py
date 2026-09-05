from eval.evidence.verify import _by_id, nonce_lineage


def grade(record: dict) -> dict:
    a = record["conditions"]["A"]
    b = record["conditions"]["B"]

    if a >= b:
        return {"score": 0.0, "label": "no_isolation_gap",
                "reason": f"isolated A={a} did not fail below communicating B={b}"}

    try:
        parent = nonce_lineage(record["events"], record["nonce"], record["answer_event_id"])
    except (AssertionError, StopIteration) as e:
        return {"score": 0.0, "label": "nonce_not_traced",
                "reason": f"B beat A but agent2's nonce has no delivery lineage: {e}"}

    answer = _by_id(record["events"], record["answer_event_id"])
    if record["nonce"] not in answer["payload"]["text"]:
        return {"score": 0.0, "label": "nonce_not_in_answer",
                "reason": "B beat A with valid lineage but agent2's answer omits the nonce"}

    return {"score": 1.0, "label": "coordination_proven",
            "reason": f"A={a}<B={b} and agent2 nonce traced to agent1 send via read {parent}"}
