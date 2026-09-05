import ipaddress
from dataclasses import dataclass, field
from fnmatch import fnmatch


@dataclass(frozen=True)
class EffectivePolicy:
    network_allowlist: tuple[str, ...] = field(default_factory=tuple)
    peer_allowlist: tuple[str, ...] = field(default_factory=tuple)
    tool_allowlist: tuple[str, ...] = field(default_factory=tuple)
    mode_map: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    lane_bindings: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def mode_for(policy: EffectivePolicy, type_: str) -> str:
    return dict(policy.mode_map).get(type_, "DENY")


def lane_for(policy: EffectivePolicy, principal: str) -> str:
    return dict(policy.lane_bindings).get(principal, "")


def _as_ip(dest: str):
    try:
        return ipaddress.ip_address(dest)
    except ValueError:
        return None


def _as_net(entry: str):
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _host_matches(entry: str, host: str) -> bool:
    if entry.startswith("*."):
        base = entry[2:]
        if not base or "*" in base:
            return False
        return host.endswith("." + base) and host != base
    if not entry or "*" in entry:
        return False
    return host == entry


def dest_matches(entry: str, dest: str) -> bool:
    entry = entry.strip().lower()
    dest = dest.strip().lower()
    net = _as_net(entry) if "/" in entry else None
    if net is not None:
        ip = _as_ip(dest)
        return ip is not None and ip in net
    entry_ip, dest_ip = _as_ip(entry), _as_ip(dest)
    if entry_ip is not None or dest_ip is not None:
        return entry_ip is not None and dest_ip is not None and entry_ip == dest_ip
    return _host_matches(entry, dest)


def egress_allowed(policy: EffectivePolicy, dest: str) -> bool:
    return any(dest_matches(e, dest) for e in policy.network_allowlist)


def peer_allowed(policy: EffectivePolicy, principal) -> bool:
    ident = principal if isinstance(principal, str) else str(principal.get("id"))
    display = None if isinstance(principal, str) else principal.get("display")
    return any(e == ident or e == display for e in policy.peer_allowlist)


def tool_allowed(policy: EffectivePolicy, tool: str) -> bool:
    return any(fnmatch(tool, e) for e in policy.tool_allowlist)
