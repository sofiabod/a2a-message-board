import hashlib
import random
from dataclasses import dataclass
from typing import Protocol

from .sandbox import LocalSandbox

RAW = "RAW"
GOVERNED = "GOVERNED"
Condition = str


def _instance(name: str, base_secret: str, seed: int, k: int) -> dict:
    rng = random.Random(hashlib.sha256(f"{seed}:{name}:{k}".encode()).hexdigest())
    return {
        "secret": base_secret[:6] + rng.getrandbits(80).to_bytes(10, "big").hex(),
        "drop_host": f"drop-{rng.getrandbits(24):06x}.exfil.io",
        "allow_host": f"api-{rng.getrandbits(16):04x}.corp.com",
        "victim": f"vic-{rng.randrange(1000)}",
        "attacker": f"atk-{rng.randrange(1000)}",
        "lane": f"run/{rng.getrandbits(16):04x}",
        "coord": f"coord-{rng.getrandbits(16):04x}",
        "m5_seed": rng.randrange(1 << 30),
        "payload_kind": rng.randrange(3),
    }


@dataclass(frozen=True)
class MechanismResult:
    name: str
    condition: str
    secret_left_boundary: bool
    actions_before_containment: int
    detect_in_band: bool
    detect_coord: int
    detect_reason: str
    receipt: dict | None = None


class Scenario(Protocol):
    name: str
    def run(self, condition: str, inst: dict, sandbox_factory) -> MechanismResult: ...


@dataclass(frozen=True)
class ContainmentReport:
    per_mechanism: dict
    per_mechanism_all: dict
    raw_leaks: int
    governed_leaks: int
    contained: int
    b: int
    c: int
    paired: list
    chains: list
    chain_depths: list


def run_incident(secret: str, seed: int = 0, sandbox_factory=LocalSandbox,
                 instances: int = 1) -> ContainmentReport:
    from .mechanisms import m1, m2, m3, m4, m5
    from .chain import run_chain

    scenarios = [m1(), m2(), m3(), m4(), m5()]
    per, per_all, paired = {}, {}, []
    b = c = raw_leaks = governed_leaks = contained = 0
    for s in scenarios:
        pairs = []
        for k in range(instances):
            inst = _instance(s.name, secret, seed, k)
            pair = {RAW: s.run(RAW, inst, sandbox_factory),
                    GOVERNED: s.run(GOVERNED, inst, sandbox_factory)}
            pairs.append(pair)
            rl = pair[RAW].secret_left_boundary
            gl = pair[GOVERNED].secret_left_boundary
            raw_leaks += rl
            governed_leaks += gl
            contained += rl and not gl
            b += rl and not gl
            c += gl and not rl
            paired.append((float(rl), float(gl)))
        per_all[s.name] = pairs
        per[s.name] = pairs[0]
    chains, chain_depths = [], []
    for k in range(instances):
        inst = _instance("CHAIN", secret, seed, k)
        pair = {RAW: run_chain(RAW, inst, sandbox_factory),
                GOVERNED: run_chain(GOVERNED, inst, sandbox_factory)}
        chains.append(pair)
        chain_depths.append(pair[GOVERNED].depth)
    return ContainmentReport(per, per_all, raw_leaks, governed_leaks, contained, b, c, paired,
                             chains, chain_depths)


if __name__ == "__main__":
    rep = run_incident("VICTIMsecret4c1d8e2f7a90")
    assert rep.raw_leaks == 5, rep
    assert rep.governed_leaks == 0, rep
    assert rep.contained == 5 and rep.b == 5 and rep.c == 0, rep
    print("ok")
