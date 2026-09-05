from gateway.allowlists import EffectivePolicy, egress_allowed, peer_allowed, tool_allowed


def test_egress_default_deny():
    assert egress_allowed(EffectivePolicy(), "example.com") is False


def test_egress_wildcard_hostname():
    p = EffectivePolicy(network_allowlist=("*.example.com",))
    assert egress_allowed(p, "api.example.com")
    assert not egress_allowed(p, "example.org")


def test_egress_cidr_and_exact_ip():
    p = EffectivePolicy(network_allowlist=("10.0.0.0/8", "1.2.3.4"))
    assert egress_allowed(p, "10.9.9.9")
    assert egress_allowed(p, "1.2.3.4")
    assert not egress_allowed(p, "11.0.0.1")


def test_cidr_does_not_match_hostname():
    p = EffectivePolicy(network_allowlist=("10.0.0.0/8",))
    assert not egress_allowed(p, "example.com")


def test_peer_by_id_and_display():
    p = EffectivePolicy(peer_allowlist=("agent-a", "abc"))
    assert peer_allowed(p, "abc")
    assert peer_allowed(p, {"id": "abc", "display": "x"})
    assert peer_allowed(p, {"id": "z", "display": "agent-a"})
    assert not peer_allowed(p, {"id": "z", "display": "nope"})


def test_tool_default_deny_and_wildcard():
    assert not tool_allowed(EffectivePolicy(), "email.send")
    p = EffectivePolicy(tool_allowlist=("email.*",))
    assert tool_allowed(p, "email.send")
    assert not tool_allowed(p, "shell.exec")
