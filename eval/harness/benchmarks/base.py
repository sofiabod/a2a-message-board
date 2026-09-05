from dataclasses import dataclass, field
from typing import Protocol
from ..channels import Verdict


@dataclass(frozen=True)
class Task:
    id: str
    prompt: str
    expected: tuple[str, ...]
    meta: dict = field(default_factory=dict)


class Benchmark(Protocol):
    def iter_tasks(self) -> list[Task]: ...
    def verify(self, task: Task, transcript: list[dict]) -> bool: ...
    def score(self, task: Task, transcript: list[dict], verdicts: list[Verdict]) -> float: ...
