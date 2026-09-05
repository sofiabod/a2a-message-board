from gateway.allowlists import EffectivePolicy
from gateway.screening import Decision, ALLOW

from eval.harness import GovernedChannel, InMemoryRecorder
from eval.harness.channels import ALLOW_V, DENY_V, APPROVAL_V, ALWAYS_ALLOW, DENY, HANDOFF, AUTO_REVIEW
from eval.harness.recorder import staleness


def _policy():
    return EffectivePolicy(peer_allowlist=("alpha", "beta"), tool_allowlist=("*",))


def _policy_msg(mode):
    return EffectivePolicy(peer_allowlist=("alpha", "beta"), tool_allowlist=("*",), mode_map=(("message", mode),))


def _pass(m, t):
    return Decision(ALLOW, [])


def _ch(lane="", policy=None):
    return GovernedChannel(policy or _policy(), InMemoryRecorder(), screen_fn=_pass, lane=lane)


def test_collab_layer():
    legacy = _ch(policy=_policy_msg(ALWAYS_ALLOW))
    assert legacy.post("alpha", "coord", {"type": "message", "text": "hi"}).outcome == ALLOW_V

    laned = _ch(lane="flights")
    assert laned.post("alpha", "coord", {"type": "message", "text": "hi"}).reason == "mode_default_deny"

    once = _ch(policy=_policy_msg(ALWAYS_ALLOW))
    assert once.post("alpha", "coord", {"type": "message", "text": "a"}).outcome == ALLOW_V
    assert once.post("alpha", "coord", {"type": "message", "text": "b"}).outcome == ALLOW_V
    assert once.post("beta", "coord", {"type": "message", "text": "c"}).outcome == ALLOW_V

    handoff = _ch()
    assert handoff.post("alpha", "coord", {"type": HANDOFF, "text": "take over"}).outcome == APPROVAL_V

    pol = EffectivePolicy(peer_allowlist=("alpha", "beta"), tool_allowlist=("*",),
                          mode_map=(("message", ALWAYS_ALLOW),), lane_bindings=(("alpha", "flights"),))
    scoped = GovernedChannel(pol, InMemoryRecorder(), screen_fn=_pass, lane="hotels")
    scoped.post("alpha", "coord", {"type": "message", "text": "hotel row"})
    scoped.lane = "flights"
    scoped.post("beta", "coord", {"type": "message", "text": "flight row"})
    rows = scoped.read("alpha", "coord")
    texts = {r["payload"]["text"] for r in rows}
    assert texts == {"hotel row", "flight row"}


def test_require_approval_mode_yields_approval():
    ch = _ch(lane="flights", policy=_policy_msg(AUTO_REVIEW))
    v = ch.post("alpha", "coord", {"type": "message", "text": "hi"})
    assert v.outcome == APPROVAL_V
    assert v.reason == "auto_review"
    assert v.guardrail == "collab"


def test_payload_mode_key_is_ignored():
    ch = _ch(lane="flights")
    v = ch.post("alpha", "coord", {"type": "message", "text": "hi", "mode": ALWAYS_ALLOW})
    assert v.outcome == DENY_V
    assert v.reason == "mode_default_deny"


def test_sender_cannot_self_escalate_via_payload_mode():
    denied = _ch(lane="flights", policy=_policy_msg(DENY))
    v = denied.post("alpha", "coord", {"type": "message", "text": "hi", "mode": ALWAYS_ALLOW})
    assert v.outcome == DENY_V
    assert v.reason == "mode_default_deny"

    reviewed = _ch(lane="flights", policy=_policy_msg(AUTO_REVIEW))
    v = reviewed.post("alpha", "coord", {"type": "message", "text": "hi", "mode": ALWAYS_ALLOW})
    assert v.outcome == APPROVAL_V
    assert v.reason == "auto_review"

    allowed = _ch(lane="flights", policy=_policy_msg(ALWAYS_ALLOW))
    v = allowed.post("alpha", "coord", {"type": "message", "text": "hi", "mode": DENY})
    assert v.outcome == ALLOW_V


def test_deny_is_default_for_unscoped_peer():
    ch = _ch(lane="flights")
    v = ch.post("alpha", "coord", {"type": "message", "text": "hi"})
    assert v.outcome == DENY_V
    assert v.reason == "mode_default_deny"


def test_always_allow_persists_across_posts():
    ch = _ch(lane="flights", policy=_policy_msg(ALWAYS_ALLOW))
    assert ch.post("alpha", "coord", {"type": "message", "text": "a"}).outcome == ALLOW_V
    assert ch.post("alpha", "coord", {"type": "message", "text": "b"}).outcome == ALLOW_V
    assert ch.post("alpha", "coord", {"type": "message", "text": "c"}).outcome == ALLOW_V


def test_handoff_is_recorded_as_handoff():
    ch = _ch()
    v = ch.post("alpha", "coord", {"type": HANDOFF, "text": "take over"})
    assert v.outcome == APPROVAL_V
    rec = ch.recorder.all()[-1]
    assert rec.attempted_type == HANDOFF
    assert rec.reason == "handoff_to_human"
    assert rec.guardrail == "collab"


def test_lane_scoped_read_never_returns_another_agents_lane():
    pol = EffectivePolicy(peer_allowlist=("alpha", "beta"), tool_allowlist=("*",),
                          mode_map=(("message", ALWAYS_ALLOW),), lane_bindings=(("beta", "flights"),))
    ch = GovernedChannel(pol, InMemoryRecorder(), screen_fn=_pass, lane="hotels")
    ch.post("alpha", "coord", {"type": "message", "text": "hotel row"})
    ch.lane = "flights"
    ch.post("beta", "coord", {"type": "message", "text": "flight row"})

    rows = ch.read("beta", "coord")
    texts = {r["payload"]["text"] for r in rows}
    assert texts == {"flight row"}
    assert "hotel row" not in texts


def test_records_carry_source_step_and_staleness():
    ch = _ch(policy=_policy_msg(ALWAYS_ALLOW))
    ch.post("alpha", "coord", {"type": "message", "text": "a"})
    ch.post("beta", "coord", {"type": "message", "text": "b"})
    posts = [r for r in ch.recorder.all() if r.kind == "post"]
    assert [(r.author, r.step) for r in posts] == [("alpha", 0), ("beta", 1)]
    now = len(posts)
    assert [staleness(r, now) for r in posts] == [2, 1]
