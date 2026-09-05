from gateway.egress import Profile as EProfile, check_egress, child_inherits, resolve_allowlist, _domain_matches, egress_decision
from gateway.allowlists import EffectivePolicy, egress_allowed, dest_matches


def test_child_cannot_widen_beyond_parent():
    parent = EProfile("p", frozenset({"a.com"}))
    child = EProfile("c", frozenset({"a.com", "evil.com"}))
    chain = child_inherits([parent], child)
    assert resolve_allowlist(chain) == frozenset({"a.com"})
    assert not check_egress(chain, "https://evil.com").allow


def test_egress_lowercases_dest():
    chain = [EProfile("p", frozenset({"api.example.com"}))]
    assert check_egress(chain, "https://API.EXAMPLE.COM/x").allow


def test_egress_rejects_suffix_confusion():
    chain = [EProfile("p", frozenset({"api.example.com"}))]
    assert not check_egress(chain, "https://api.example.com.attacker.net").allow


def test_egress_trailing_dot_is_denied():
    chain = [EProfile("p", frozenset({"api.example.com"}))]
    assert not check_egress(chain, "https://api.example.com./x").allow


def test_egress_wildcard_entry_should_not_grant_apex():
    chain = [EProfile("p", frozenset({"*.example.com"}))]
    assert check_egress(chain, "https://sub.example.com").allow
    assert not check_egress(chain, "https://example.com").allow


def test_egress_dotwild_should_not_match_bare_subdomain():
    assert not _domain_matches("x.example.com", "*.*.example.com")
    assert not _domain_matches("x.example.com", ".example.com")


def test_allowlists_star_overmatches_internal_hosts():
    p = EffectivePolicy(network_allowlist=("*",))
    assert not egress_allowed(p, "169.254.169.254")
    assert not egress_allowed(p, "internal.corp")


def test_allowlists_mid_wildcard_overmatches():
    p = EffectivePolicy(network_allowlist=("api.*.com",))
    assert not egress_allowed(p, "api.attacker.com")


def test_empty_child_profile_denies_all():
    parent = EProfile("p", frozenset({"a.com"}))
    assert resolve_allowlist([parent, EProfile("c", frozenset())]) == frozenset()


def test_shared_matcher_wildcard_never_matches_internal():
    for entry in ("*", "*.*", "api.*.com", ""):
        assert not dest_matches(entry, "169.254.169.254")
        assert not dest_matches(entry, "internal.corp")
        assert not dest_matches(entry, "metadata.google.internal")


def test_shared_matcher_cidr_never_matches_hostname():
    assert dest_matches("10.0.0.0/8", "10.0.0.5")
    assert not dest_matches("10.0.0.0/8", "internal.corp")
    assert not dest_matches("10.0.0.0/8", "10.internal.corp")


def test_shared_matcher_ip_hostname_cross_denied():
    assert not dest_matches("1.2.3.4", "api.example.com")
    assert not dest_matches("api.example.com", "1.2.3.4")


def test_shared_matcher_exact_and_dotted_suffix():
    assert dest_matches("api.example.com", "api.example.com")
    assert not dest_matches("api.example.com", "api.example.com.attacker.net")
    assert dest_matches("*.example.com", "sub.example.com")
    assert not dest_matches("*.example.com", "example.com")


def test_egress_routes_agree_deny_internal():
    entries = frozenset({"*.example.com", "10.0.0.0/8"})
    chain = [EProfile("p", entries)]
    eff = EffectivePolicy(network_allowlist=tuple(entries))
    for host in ("169.254.169.254", "internal.corp", "example.com"):
        assert not check_egress(chain, "https://" + host).allow
        assert not egress_allowed(eff, host)
        assert not egress_decision(eff, "https://" + host).allow


def test_egress_routes_agree_allow_intended():
    entries = frozenset({"*.example.com", "10.0.0.0/8"})
    chain = [EProfile("p", entries)]
    eff = EffectivePolicy(network_allowlist=tuple(entries))
    for host in ("sub.example.com", "10.0.0.5"):
        assert check_egress(chain, "https://" + host).allow
        assert egress_allowed(eff, host)
        assert egress_decision(eff, "https://" + host).allow
