import json

from eval.harness.benchmarks.base import Task
from eval.graders.utility import craft_iou, norm_cells as _norm

_COLOR = {"yellow": "y", "orange": "o", "green": "g", "blue": "b", "red": "r", "purple": "p"}


def _text(row: dict) -> str:
    return row.get("payload", row).get("text", "")


def _block(cell: dict) -> str:
    return _COLOR[cell["color"]] + ("s" if cell["size"] == 1 else "l")


def _cells(view: dict) -> dict:
    return {(r, c): _block(view[f"row_{r}"][c]) for r in range(3) for c in range(3)}


def reconstruct(views: dict) -> dict:
    """A director's best structure guess: the blocks its observed views place per cell."""
    out = {(r, c): [] for r in range(3) for c in range(3)}
    for view in views.values():
        for coord, block in _cells(view).items():
            out[coord].append(block)
    return {f"({r},{c})": sorted(out[(r, c)]) for r in range(3) for c in range(3)}


class CraftCoordinationBenchmark:
    def __init__(self, tasks_path: str):
        with open(tasks_path) as f:
            rows = [json.loads(line) for line in f if line.strip()]
        self._tasks = [Task(r["id"], r["prompt"], tuple(r["shards"])) for r in rows]
        self._roles = {r["id"]: tuple(r["roles"]) for r in rows}
        self._shards = {r["id"]: tuple(r["shards"]) for r in rows}
        self._views = {r["id"]: r.get("views", {}) for r in rows}
        self._truth = {r["id"]: r.get("ground_truth", {}) for r in rows}
        self._complexity = {r["id"]: r.get("complexity", "") for r in rows}

    def iter_tasks(self) -> list[Task]:
        return self._tasks

    def shard_for(self, task_id: str, role: str) -> str:
        return self._shards[task_id][self._roles[task_id].index(role)]

    def view_for(self, task_id: str, role: str) -> dict:
        return self._views[task_id][role]

    def ground_truth(self, task_id: str) -> dict:
        return self._truth[task_id]

    def score_answer(self, task_id: str, answer: dict) -> float:
        return craft_iou(answer, self._truth[task_id])

    def attainable_iou(self, task_id: str) -> float:
        """Ceiling this representation can reach: reconstruct() emits 27 filled small cells, so real empty/large cells cap it well below 1.0."""
        return craft_iou(reconstruct(self._views[task_id]), self._truth[task_id])

    def cell_score(self, task_id: str, views: dict) -> float:
        """Fraction of the 9 cells the observed views reconstruct exactly."""
        got, truth = _norm(reconstruct(views)), _norm(self._truth[task_id])
        return sum(set(got[c]) == set(truth[c]) for c in truth) / 9.0

    def verify(self, task: Task, transcript: list[dict]) -> bool:
        return any(all(s in _text(p) for s in task.expected) for p in transcript)

    def score(self, task: Task, transcript: list[dict], verdicts: list) -> float:
        return 1.0 if self.verify(task, transcript) else 0.0
