from dataclasses import dataclass, field

from gateway.egress import Profile, child_inherits, default_deny_guard


def _host(dest: str) -> str:
    d = dest.split("://", 1)[-1].split("/", 1)[0]
    return d.rsplit("@", 1)[-1].split(":", 1)[0]


@dataclass(frozen=True)
class EgressAttempt:
    principal: str
    dest: str
    body: str


@dataclass
class RawSandbox:
    sent: list = field(default_factory=list)

    def egress(self, attempt: EgressAttempt) -> str:
        self.sent.append((attempt.dest, attempt.body))
        return "SENT"


@dataclass
class GovernedSandbox:
    chain: list
    run_id: str
    denied: list = field(default_factory=list)
    sent: list = field(default_factory=list)

    def egress(self, attempt: EgressAttempt) -> str:
        decision, denied_row = default_deny_guard(
            self.run_id, attempt.principal, self.chain, attempt.dest
        )
        if not decision.allow:
            self.denied.append(denied_row)
            return "DROPPED"
        self.sent.append((attempt.dest, attempt.body))
        return "SENT"


def exfiltrated(sandbox, secret: str) -> bool:
    return any(secret in body for _, body in sandbox.sent)


def replay(secret: str, dead_drop: str, floor: frozenset[str], run_id: str = "m4"):
    enterprise = Profile("enterprise", floor)
    session = Profile("session", floor | {_host(dead_drop)})
    chain = child_inherits([enterprise], session)

    attempt = EgressAttempt("session", dead_drop, "report body\n" + secret)
    raw, gov = RawSandbox(), GovernedSandbox(chain, run_id)
    return {
        "raw_outcome": raw.egress(attempt),
        "gov_outcome": gov.egress(attempt),
        "raw_exfiltrated": exfiltrated(raw, secret),
        "gov_exfiltrated": exfiltrated(gov, secret),
        "gov_denied_rows": gov.denied,
    }


def demo():
    r = replay(
        secret="VICTIMsecret4c1d8e2f7a90",
        dead_drop="https://pastebin-dead-drop.io/collect",
        floor=frozenset({"api.corp.com", "*.tools.dev"}),
    )
    assert r["raw_exfiltrated"] and r["raw_outcome"] == "SENT"
    assert not r["gov_exfiltrated"] and r["gov_outcome"] == "DROPPED"
    row = r["gov_denied_rows"][0]
    assert row["reason_code"] == "egress_default_deny"
    assert row["guardrail"] == "sandbox_egress"
    assert row["attempted_type"] == "network.egress"
    assert row["body_ref"] == "https://pastebin-dead-drop.io/collect"

    allowed = replay(
        secret="VICTIMsecret4c1d8e2f7a90",
        dead_drop="https://api.corp.com/legit",
        floor=frozenset({"api.corp.com"}),
    )
    assert allowed["gov_outcome"] == "SENT"
    print("ok")


if __name__ == "__main__":
    demo()
