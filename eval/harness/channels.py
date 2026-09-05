import hashlib
import json
from dataclasses import dataclass, field
from typing import Protocol, Callable

from gateway.allowlists import EffectivePolicy, peer_allowed, tool_allowed, egress_allowed, mode_for, dest_matches, lane_for
from gateway.screening import screen, Decision, QUARANTINE, REQUIRE_APPROVAL

from .recorder import Recorder, Record


@dataclass(frozen=True)
class Credential:
    principal: str
    scope: frozenset[str]
    expires_step: int


def body_hash(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

ALLOW_V = "ALLOW"
DENY_V = "DENY"
QUARANTINE_V = "QUARANTINE"
APPROVAL_V = "APPROVAL"

ALWAYS_ALLOW = "ALWAYS_ALLOW"
DENY = "DENY"
AUTO_REVIEW = "REQUIRE_APPROVAL"
HANDOFF = "control.handoff"

ScreenFn = Callable[[list[str], list[str]], Decision]


@dataclass(frozen=True)
class Verdict:
    outcome: str
    reason: str
    guardrail: str


class Channel(Protocol):
    def post(self, principal: str, channel: str, payload: dict) -> Verdict: ...
    def read(self, principal: str, channel: str) -> list[dict]: ...


@dataclass
class IsolatedChannel:
    def post(self, principal: str, channel: str, payload: dict) -> Verdict:
        return Verdict(DENY_V, "isolated", "isolation")

    def read(self, principal: str, channel: str) -> list[dict]:
        return []


@dataclass
class RawChannel:
    _store: dict = field(default_factory=dict)

    def post(self, principal: str, channel: str, payload: dict) -> Verdict:
        self._store.setdefault(channel, []).append(
            {"principal": principal, "channel": channel, "payload": payload}
        )
        return Verdict(ALLOW_V, "raw", "")

    def read(self, principal: str, channel: str) -> list[dict]:
        return self._store.get(channel, [])


@dataclass
class ObserveOnlyChannel:
    recorder: Recorder
    _store: dict = field(default_factory=dict)

    def post(self, principal: str, channel: str, payload: dict) -> Verdict:
        rec = {"principal": principal, "channel": channel, "payload": payload, "type": payload["type"]}
        self._store.setdefault(channel, []).append(rec)
        self.recorder.record(Record("post", principal, channel, ALLOW_V, "observed", "", body_hash(payload), payload["type"]))
        return Verdict(ALLOW_V, "observed", "")

    def read(self, principal: str, channel: str) -> list[dict]:
        return self._store.get(channel, [])


def default_screen(messages, trajectory):
    return screen(messages, trajectory)


@dataclass
class GovernedChannel:
    policy: EffectivePolicy
    recorder: Recorder
    screen_fn: ScreenFn = default_screen
    lane: str = ""
    _store: dict = field(default_factory=dict)
    _creds: dict = field(default_factory=dict)

    def mint(self, handle: str, cred: Credential) -> None:
        self._creds[handle] = cred

    def _resolve_mode(self, payload: dict) -> str:
        return mode_for(self.policy, payload["type"])

    def _cred_ok(self, principal: str, channel: str, payload: dict) -> bool:
        cred = self._creds.get(payload["cred"])
        step = len(self._store.get(channel, []))
        host = payload["dest"].split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
        return not (cred is None or cred.principal != principal or step >= cred.expires_step
                    or not any(dest_matches(s, host) for s in cred.scope))

    def _deny(self, principal, channel, payload, reason, guardrail, outcome=DENY_V):
        self.recorder.record(
            Record("denied", principal, channel, outcome, reason, guardrail, body_hash(payload), payload.get("type", ""))
        )
        return Verdict(outcome, reason, guardrail)

    def post(self, principal: str, channel: str, payload: dict) -> Verdict:
        if not peer_allowed(self.policy, principal):
            return self._deny(principal, channel, payload, "peer_not_allowed", "profile")

        tool = payload.get("tool")
        if tool is not None and not tool_allowed(self.policy, tool):
            return self._deny(principal, channel, payload, "tool_not_allowed", "profile")

        if payload.get("type") == "network.egress" and not egress_allowed(self.policy, payload["dest"]):
            return self._deny(principal, channel, payload, "egress_default_deny", "profile")

        if payload.get("type") == "credential.present" and not self._cred_ok(principal, channel, payload):
            return self._deny(principal, channel, payload, "cred_out_of_scope", "credential")

        trajectory = [r["payload"]["text"] for r in self._store.get(channel, [])]
        d = self.screen_fn([payload["text"]], trajectory)
        if d.decision == QUARANTINE:
            return self._deny(principal, channel, payload, d.reasons[0], "screening", QUARANTINE_V)
        if d.decision == REQUIRE_APPROVAL:
            return self._deny(principal, channel, payload, d.reasons[0], "screening", APPROVAL_V)

        if payload["type"] == HANDOFF:
            return self._deny(principal, channel, payload, "handoff_to_human", "collab", APPROVAL_V)
        mode = self._resolve_mode(payload)
        if mode == DENY:
            return self._deny(principal, channel, payload, "mode_default_deny", "collab", DENY_V)
        if mode == AUTO_REVIEW:
            return self._deny(principal, channel, payload, "auto_review", "collab", APPROVAL_V)

        step = len(self._store.get(channel, []))
        self._store.setdefault(channel, []).append(
            {"principal": principal, "channel": channel, "payload": payload,
             "author": principal, "step": step, "lane": self.lane}
        )
        self.recorder.record(Record("post", principal, channel, ALLOW_V, "ok", "",
                                    body_hash(payload), payload["type"],
                                    author=principal, step=step, mode=mode))
        return Verdict(ALLOW_V, "ok", "")

    def read(self, principal: str, channel: str) -> list[dict]:
        lane = lane_for(self.policy, principal)
        rows = self._store.get(channel, [])
        return [r for r in rows if r.get("lane", "") == lane or r["author"] == principal]
