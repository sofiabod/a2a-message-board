from gateway.allowlists import EffectivePolicy
from eval.harness.channels import RawChannel, GovernedChannel, Credential
from eval.harness.recorder import InMemoryRecorder
from eval.incident import m1_untrusted_exec
from eval.attacks.schedule import cred_reuse_event

from eval.incident.mechanisms import m1, m2, m3, m4, DEAD_DROP, _host, _M2_MODE, _pass
from eval.incident.scenario import GOVERNED, RAW, _instance
from eval.incident.sandbox import EgressPolicy, LocalSandbox

SECRET = "VICTIMsecret4c1d8e2f7a90"


def test_m1_falsifiable_benign_allowed():
    out = m1_untrusted_exec.governed("Hi, reschedule to Thursday?", SECRET)
    assert not out.secret_in_output and not out.executed


def test_m1_gutted_leaks(monkeypatch):
    monkeypatch.setattr(m1_untrusted_exec, "inert_normalize", lambda t: (t, []))
    inst = _instance("M1", SECRET, 0, 0)
    r = m1().run(GOVERNED, inst, LocalSandbox)
    assert r.secret_left_boundary


def test_m2_falsifiable_in_scope_allowed():
    policy = EffectivePolicy(peer_allowlist=("victim",), tool_allowlist=("*",), mode_map=_M2_MODE)
    ch = GovernedChannel(policy, InMemoryRecorder())
    ch.mint("vic-cred", Credential("victim", frozenset({"api.corp.com"}), expires_step=10))
    ev = cred_reuse_event("https://api.corp.com/legit").payload | {"principal": "victim"}
    assert ch.post("victim", "ops", ev).outcome == "ALLOW"


def test_m2_gutted_accepts_replay():
    ch = RawChannel()
    ev = cred_reuse_event(DEAD_DROP).payload
    assert ch.post("attacker", "ops", ev).outcome == "ALLOW"


def test_m3_falsifiable_own_lane_reads():
    policy = EffectivePolicy(peer_allowlist=("svc-a", "attacker"), tool_allowlist=("*",),
                             mode_map=(("message", "ALWAYS_ALLOW"),),
                             lane_bindings=(("attacker", "run/victim"),))
    ch = GovernedChannel(policy, InMemoryRecorder(), _pass, lane="run/victim")
    ch.post("svc-a", "coord", {"type": "message", "text": SECRET})
    assert any(SECRET in r["payload"]["text"] for r in ch.read("attacker", "coord"))


def test_m3_gutted_cross_lane_leaks(monkeypatch):
    monkeypatch.setattr(GovernedChannel, "read",
                        lambda self, principal, channel: self._store.get(channel, []))
    policy = EffectivePolicy(peer_allowlist=("svc-a", "attacker"), tool_allowlist=("*",),
                             mode_map=(("message", "ALWAYS_ALLOW"),),
                             lane_bindings=(("attacker", "run/attacker"),))
    ch = GovernedChannel(policy, InMemoryRecorder(), _pass, lane="run/victim")
    ch.post("svc-a", "coord", {"type": "message", "text": SECRET})
    rows = ch.read("attacker", "coord")
    assert any(SECRET in r["payload"]["text"] for r in rows)


def test_m4_falsifiable_in_allowlist_sent():
    pol = EgressPolicy(floor=frozenset({"api.corp.com"}))
    assert LocalSandbox(pol).egress("session", "https://api.corp.com/legit", SECRET).outcome == "SENT"


def test_m4_gutted_floor_includes_deaddrop_sent():
    pol = EgressPolicy(floor=frozenset({"api.corp.com", _host(DEAD_DROP)}))
    assert LocalSandbox(pol).egress("session", DEAD_DROP, SECRET).outcome == "SENT"
