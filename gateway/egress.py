from dataclasses import dataclass

from .allowlists import EffectivePolicy, dest_matches


@dataclass(frozen=True)
class Profile:
    principal_id: str
    allow_domains: frozenset[str]


@dataclass(frozen=True)
class EgressDecision:
    allow: bool
    reason: str


def _host(dest: str) -> str:
    d = dest.strip().lower()
    d = d.split("://", 1)[-1]
    d = d.split("/", 1)[0]
    d = d.rsplit("@", 1)[-1]
    d = d.split(":", 1)[0]
    return d


def _domain_matches(host: str, allowed: str) -> bool:
    return dest_matches(allowed, host)


def child_inherits(parent_chain: list[Profile], child: Profile) -> list[Profile]:
    return parent_chain + [child]


def resolve_allowlist(chain: list[Profile]) -> frozenset[str]:
    allow = None
    for p in chain:
        allow = p.allow_domains if allow is None else allow & p.allow_domains
    return allow or frozenset()


def check_egress(chain: list[Profile], dest: str) -> EgressDecision:
    host = _host(dest)
    if not host:
        return EgressDecision(False, "egress_no_host")
    allow = resolve_allowlist(chain)
    for a in allow:
        if _domain_matches(host, a):
            return EgressDecision(True, "egress_allowed")
    return EgressDecision(False, "egress_default_deny")


def default_deny_guard(run_id, principal_id, chain: list[Profile], dest: str):
    decision = check_egress(chain, dest)
    if decision.allow:
        return decision, None
    denied_row = {
        "run_id": run_id,
        "channel_id": None,
        "principal_id": principal_id,
        "attempted_type": "network.egress",
        "body_hash": "",
        "body_ref": dest,
        "outcome": "DENY",
        "reason_code": decision.reason,
        "guardrail": "sandbox_egress",
    }
    return decision, denied_row


def egress_decision(policy: EffectivePolicy, dest: str) -> EgressDecision:
    host = _host(dest)
    if not host:
        return EgressDecision(False, "egress_no_host")
    if policy.network_allowlist is None:
        return EgressDecision(False, "egress_default_deny")
    if any(dest_matches(a, host) for a in policy.network_allowlist):
        return EgressDecision(True, "egress_allowed")
    return EgressDecision(False, "egress_default_deny")


if __name__ == "__main__":
    parent = Profile("p", frozenset({"api.example.com", "*.tools.dev"}))
    child = Profile("c", frozenset({"api.example.com", "evil.com"}))
    chain = child_inherits([parent], child)
    assert check_egress(chain, "https://api.example.com/x").allow
    assert not check_egress(chain, "https://evil.com").allow
    assert check_egress([parent], "run.tools.dev:443").allow
    assert not check_egress(chain, "run.tools.dev:443").allow
    assert not check_egress(chain, "https://api.example.com.attacker.net").allow
    d, row = default_deny_guard("r1", "c", chain, "https://evil.com")
    assert not d.allow and row["reason_code"] == "egress_default_deny"
    assert row["guardrail"] == "sandbox_egress" and row["body_ref"] == "https://evil.com"
    d, row = default_deny_guard("r1", "c", chain, "https://api.example.com")
    assert d.allow and row is None
    print("ok")
