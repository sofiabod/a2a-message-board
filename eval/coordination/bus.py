import hashlib
import json
from dataclasses import dataclass, field

from eval.harness.channels import body_hash
from eval.evidence.writer import log_event, log_model_call, has_model_call


@dataclass
class _Bus:
    rd: object
    cond: str
    channel: str = "coord"
    _seq: int = 0
    events: list = field(default_factory=list)
    _last_send: dict = field(default_factory=dict)

    def _event_id(self, sender: str, bhash: str) -> str:
        eid = hashlib.sha256(f"{self.cond}{sender}{self.channel}{bhash}{self._seq}".encode()).hexdigest()
        self._seq += 1
        return eid

    def send(self, sender: str, text: str, outcome: str, reason: str) -> str:
        payload = {"text": text}
        bhash = body_hash(payload)
        eid = self._event_id(sender, bhash)
        ev = {"kind": "send", "event_id": eid, "sender": sender, "recipient": "*",
              "channel": self.channel, "causal_parent": None, "body_hash": bhash,
              "outcome": outcome, "reason": reason, "payload": payload}
        self.events.append(ev)
        log_event(self.rd, event_id=eid, kind="send", sender=sender, recipient="*",
                  channel=self.channel, causal_parent=None, body_hash=bhash,
                  outcome=outcome, reason=reason, payload=payload)
        if outcome == "ALLOW":
            self._last_send[sender] = ev
        return eid

    def deliver(self, reader: str, from_agent: str, text: str) -> None:
        parent = self._last_send[from_agent]
        payload = {"text": text}
        bhash = body_hash(payload)
        eid = self._event_id(reader, bhash)
        ev = {"kind": "read", "event_id": eid, "sender": from_agent, "recipient": reader,
              "channel": self.channel, "causal_parent": parent["event_id"], "body_hash": bhash,
              "outcome": "ALLOW", "reason": "delivered", "payload": payload}
        self.events.append(ev)
        log_event(self.rd, event_id=eid, kind="read", sender=from_agent, recipient=reader,
                  channel=self.channel, causal_parent=parent["event_id"], body_hash=bhash,
                  outcome="ALLOW", reason="delivered", payload=payload)

    def answer_event(self, sender: str, text: str) -> str:
        payload = {"text": text}
        bhash = body_hash(payload)
        eid = self._event_id(sender, bhash)
        ev = {"kind": "send", "event_id": eid, "sender": sender, "recipient": "*",
              "channel": self.channel, "causal_parent": None, "body_hash": bhash,
              "outcome": "ALLOW", "reason": "answer", "payload": payload}
        self.events.append(ev)
        log_event(self.rd, event_id=eid, kind="send", sender=sender, recipient="*",
                  channel=self.channel, causal_parent=None, body_hash=bhash,
                  outcome="ALLOW", reason="answer", payload=payload)
        return eid


def _read_action(proc, role: str, step: int, rd, refs: list, slice_tag: str) -> dict:
    line = proc.stdout.readline()
    if not line:
        proc.wait()
        err = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"agent {role!r} (step {step}) produced no output "
                           f"(exit {proc.returncode}):\n{err}")
    wire = json.loads(line)
    call = wire.get("call")
    if call is not None:
        ref = hashlib.sha256(f"{slice_tag}{role}{step}{call['output']}".encode()).hexdigest()[:16]
        if not has_model_call(rd, ref):
            log_model_call(rd, principal=role, seed=step, messages=call["messages"],
                           response=call["output"], provider_id=call["provider_id"],
                           usage=call["usage"], call_ref=ref)
        refs.append(ref)
    return wire["action"]
