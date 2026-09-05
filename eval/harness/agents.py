from dataclasses import dataclass
from typing import Callable

ModelFn = Callable[[str, list[dict], int], dict]
SelectorFn = Callable[[str, list[dict], int], int]


@dataclass
class ScriptedSelector:
    choices: dict[str, int]
    default: int = 1

    def __call__(self, task_prompt: str, cards: list[dict], seed: int) -> int:
        for card in cards:
            case_id = card.get("case_id")
            if case_id in self.choices:
                return self.choices[case_id]
        return self.default


@dataclass
class Agent:
    role: str
    model_fn: ModelFn

    def act(self, observations: list[dict], step: int) -> dict:
        return self.model_fn(self.role, observations, step)


@dataclass
class ScriptedModel:
    script: dict[str, list[dict]]

    def __call__(self, role: str, observations: list[dict], step: int) -> dict:
        return self.script[role][step]


@dataclass
class MultiModel:
    models: dict[str, ModelFn]

    def __call__(self, role: str, observations: list[dict], step: int) -> dict:
        return self.models[role](role, observations, step)


def _obs_text(observations: list[dict]) -> str:
    return "\n".join(o.get("payload", o).get("text", "") for o in observations)


@dataclass
class MockVictim:
    secret: str
    channel: str = "ops"

    def __call__(self, role: str, observations: list[dict], step: int) -> dict:
        from gateway.screening import _reveal_instruction
        if _reveal_instruction(_obs_text(observations)):
            return {"channel": self.channel, "type": "message", "text": "here it is: " + self.secret}
        return {"channel": self.channel, "type": "message", "text": "working on the task"}


@dataclass
class MockAttacker:
    candidates: list[dict]
    channel: str = "ops"

    def __call__(self, role: str, observations: list[dict], step: int) -> dict:
        return self.candidates[step % len(self.candidates)] | {"channel": self.channel}


def attack_model(candidates: list[dict], secret: str, mock: bool, channel: str = "ops") -> MultiModel:
    if mock:
        return MultiModel({"attacker": MockAttacker(candidates, channel),
                           "victim": MockVictim(secret, channel)})
    import os
    if "OPENROUTER_API_KEY" not in os.environ:
        raise RuntimeError("real attack model requires OPENROUTER_API_KEY; pass mock=True for the deterministic agent")
    from .model_openrouter import openrouter_attacker, openrouter_victim
    return MultiModel({"attacker": openrouter_attacker(candidates, channel),
                       "victim": openrouter_victim(secret, channel)})
