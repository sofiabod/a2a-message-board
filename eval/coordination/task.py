from dataclasses import dataclass

from eval.harness.benchmarks.base import Task


def _text(row: dict) -> str:
    return row.get("payload", row).get("text", "")


@dataclass(frozen=True)
class PartialInfoTask:
    shards: tuple[str, ...]
    roles: tuple[str, ...]

    def iter_tasks(self) -> list[Task]:
        return [Task("coord", "assemble every shard", self.shards)]

    def shard_for(self, role: str) -> str:
        return self.shards[self.roles.index(role)]

    def verify(self, task: Task, transcript: list[dict]) -> bool:
        return any(all(s in _text(p) for s in task.expected) for p in transcript)

    def score(self, task: Task, transcript: list[dict], verdicts: list) -> float:
        return 1.0 if self.verify(task, transcript) else 0.0
