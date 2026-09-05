from eval.harness.agents import ModelFn


def _text(row: dict) -> str:
    return row.get("payload", row).get("text", "")


def coordinate(shards: tuple[str, ...], roles: tuple[str, ...]) -> ModelFn:
    known = set(shards)

    def model_fn(role: str, observations: list[dict], step: int) -> dict:
        own = shards[roles.index(role)]
        seen = {s for o in observations for s in known if s in _text(o)}
        text = " ".join(sorted({own, *seen}))
        return {"channel": "coord", "type": "message", "text": text}

    return model_fn
