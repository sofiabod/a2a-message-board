from dataclasses import dataclass
from .manifest import Manifest
from .channels import Channel, Verdict, ALLOW_V
from .agents import Agent, ModelFn
from .benchmarks import Benchmark


@dataclass
class RunResult:
    manifest_hash: str
    seed: int
    verdicts: list[Verdict]
    transcript: list[dict]
    verified: bool
    score: float


def _aggregate(aggregator: str, scores: list[float]) -> float:
    if aggregator == "sum":
        return sum(scores)
    if aggregator == "min":
        return min(scores)
    return sum(scores) / len(scores)


def run(manifest: Manifest, channel: Channel, benchmark: Benchmark,
        model_fn: ModelFn, seed: int) -> RunResult:
    agents = [Agent(role, model_fn) for role in manifest.roles]
    steps = manifest.budgets["steps"]

    all_verdicts: list[Verdict] = []
    all_transcript: list[dict] = []
    task_scores: list[float] = []
    all_verified = True

    for task in benchmark.iter_tasks():
        verdicts: list[Verdict] = []
        transcript: list[dict] = []
        for step in range(steps):
            for agent in agents:
                observations = channel.read(agent.role, task.id)
                action = agent.act(observations, step)
                verdict = channel.post(agent.role, action["channel"], action)
                verdicts.append(verdict)
                if verdict.outcome == ALLOW_V:
                    transcript.append(action)
            if manifest.stop_rule == "all_verified" and benchmark.verify(task, transcript):
                break
        verified = benchmark.verify(task, transcript)
        all_verified = all_verified and verified
        task_scores.append(benchmark.score(task, transcript, verdicts))
        all_verdicts.extend(verdicts)
        all_transcript.extend(transcript)

    return RunResult(
        manifest_hash=manifest.freeze(),
        seed=seed,
        verdicts=all_verdicts,
        transcript=all_transcript,
        verified=all_verified,
        score=_aggregate(manifest.aggregator, task_scores),
    )
