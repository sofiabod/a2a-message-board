from .base import Task


class FixtureBenchmark:
    def iter_tasks(self) -> list[Task]:
        return [Task("coord", "combine facts", ("alpha", "beta"))]

    def verify(self, task: Task, transcript: list[dict]) -> bool:
        seen = " ".join(p.get("text", "") for p in transcript)
        return all(e in seen for e in task.expected)

    def score(self, task: Task, transcript: list[dict], verdicts: list) -> float:
        return 1.0 if self.verify(task, transcript) else 0.0
