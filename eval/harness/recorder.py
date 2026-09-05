from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Record:
    kind: str
    principal: str
    channel: str | None
    outcome: str
    reason: str
    guardrail: str
    body_hash: str
    attempted_type: str = ""
    author: str = ""
    step: int = -1
    mode: str = ""
    leaked_from: str = ""
    leaked_action: int = -1


def staleness(rec: Record, now_step: int) -> int:
    return now_step - rec.step


class Recorder(Protocol):
    def record(self, rec: Record) -> None: ...
    def all(self) -> list[Record]: ...


@dataclass
class InMemoryRecorder:
    _recs: list = field(default_factory=list)

    def record(self, rec: Record) -> None:
        self._recs.append(rec)

    def all(self) -> list[Record]:
        return list(self._recs)
