from eval.graders.utility import grade

TRUTH = {f"({r},{c})": [f"b{r}{c}"] for r in range(3) for c in range(3)}


def _craft(answer):
    return {"kind": "craft", "answer": answer, "ground_truth": TRUTH}


def test_craft_perfect_is_1():
    assert grade(_craft(dict(TRUTH)))["score"] == 1.0


def test_craft_disjoint_is_0():
    answer = {k: ["ZZ"] for k in TRUTH}
    assert grade(_craft(answer))["score"] == 0.0


def test_craft_partial_hand_derived():
    answer = dict(TRUTH)
    for k in [f"({r},{c})" for r in range(3) for c in range(3)][4:]:
        answer[k] = ["WRONG"]
    assert grade(_craft(answer))["score"] == 4 / 14


def _as(chosen_card_index, receipt):
    return {"kind": "as", "chosen_card_index": chosen_card_index, "receipt": receipt}


def test_as_genuine_routed_is_1():
    assert grade(_as(0, {"receipt_id": "abc", "is_impostor": False}))["score"] == 1.0


def test_as_impostor_routed_is_0():
    assert grade(_as(3, {"receipt_id": "def", "is_impostor": True}))["score"] == 0.0


def test_as_utility_is_routing_correctness_not_receipt():
    assert grade(_as(0, None))["score"] == 1.0
    assert grade(_as(3, {"receipt_id": "abc"}))["score"] == 0.0
