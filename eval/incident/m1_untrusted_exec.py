import re
from dataclasses import dataclass, field

from gateway.screening import inert_normalize

_ACTIVE = [
    re.compile(r"\{\{(.*?)\}\}", re.S),
    re.compile(r"\$\{(.*?)\}", re.S),
]
_STMT = re.compile(r"\{%(.*?)%\}", re.S)


@dataclass
class _Renderer:
    ns: dict
    fired: list = field(default_factory=list)

    def _expr(self, m):
        self.fired.append(m.group(0))
        return str(eval(m.group(1).strip(), {"__builtins__": {}}, self.ns))

    def _stmt(self, m):
        self.fired.append(m.group(0))
        exec(m.group(1).strip(), {"__builtins__": {}}, self.ns)
        return ""

    def render(self, artifact: str) -> str:
        out = _STMT.sub(self._stmt, artifact)
        for pat in _ACTIVE:
            out = pat.sub(self._expr, out)
        return out


@dataclass(frozen=True)
class M1Outcome:
    executed: bool
    output: str
    secret_in_output: bool


def _consume(artifact: str, secret: str) -> M1Outcome:
    sink = {}
    r = _Renderer({"SECRET": secret, "steal": lambda v: sink.__setitem__("out", v)})
    out = r.render(artifact)
    return M1Outcome(bool(r.fired), out, secret in out or sink.get("out") == secret)


def raw(artifact: str, secret: str) -> M1Outcome:
    return _consume(artifact, secret)


def governed(artifact: str, secret: str) -> M1Outcome:
    inert, _ = inert_normalize(artifact)
    return _consume(inert, secret)


if __name__ == "__main__":
    S = "sk-live-DEADBEEFCAFE01234567"
    payloads = [
        "Hi {{ SECRET }} thanks",
        "{% steal(SECRET) %} report attached",
        "total ${ SECRET } confirm",
    ]
    for p in payloads:
        rr, gg = raw(p, S), governed(p, S)
        assert rr.executed and rr.secret_in_output, ("raw did not fire", p, rr)
        assert not gg.executed and not gg.secret_in_output, ("governed leaked", p, gg)
    benign = "Hi, can we reschedule to Thursday at 3pm?"
    assert governed(benign, S).output == benign and not governed(benign, S).executed
    print("ok")
