import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Manifest:
    roles: tuple[str, ...]
    subtasks: tuple[str, ...]
    budgets: dict[str, int]
    seeds: tuple[int, ...]
    aggregator: str
    stop_rule: str
    condition: str = "C"
    channel_type: str = ""
    task_prompt: str = ""
    case_id: str = ""

    def freeze(self) -> str:
        payload = {
            "roles": list(self.roles),
            "subtasks": list(self.subtasks),
            "budgets": dict(sorted(self.budgets.items())),
            "seeds": list(self.seeds),
            "aggregator": self.aggregator,
            "stop_rule": self.stop_rule,
            "condition": self.condition,
            "channel_type": self.channel_type,
            "task_prompt": self.task_prompt,
            "case_id": self.case_id,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
