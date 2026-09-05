"""Build each grader's per-dimension record from a sealed trial row and return the scores."""

from eval.graders import GRADERS


def _score(dims: dict) -> dict:
    return {dim: GRADERS[dim](record) for dim, record in dims.items()}


def as_scores(row: dict, sealed_receipt: dict | None) -> dict:
    return _score({
        "security_spoofing": {"receipt": sealed_receipt},
        "overblock": {"is_impostor": row["is_impostor"], "receipt": sealed_receipt,
                      "records": row["records"]},
        "utility": {"kind": "as", "chosen_card_index": row["chosen_card_index"],
                    "receipt": sealed_receipt},
    })


def containment_scores(sealed_receipt: dict | None) -> dict:
    return _score({"containment": {"receipt": sealed_receipt}})
