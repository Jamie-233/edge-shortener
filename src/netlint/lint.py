"""Checks for common mistakes in network device configs (Cisco IOS + Huawei VRP)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class Issue:
    rule: str
    severity: str  # "error" | "warning"
    detail: str


def _vlan_ids(spec: str) -> set[int]:
    """Parse IOS '10,20,30-40' into a set of ints."""
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


def _vrp_vlan_ids(spec: str) -> set[int]:
    """Parse VRP '10 20 to 25' into a set of ints."""
    out: set[int] = set()
    tokens = spec.split()
    i = 0
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i + 1] == "to":
            out.update(range(int(tokens[i]), int(tokens[i + 2]) + 1))
            i += 3
        else:
            out.add(int(tokens[i]))
            i += 1
    return out


def _lines(config: str) -> list[str]:
    return [ln for ln in config.splitlines() if ln.strip()]


def check_plaintext_enable(config: str) -> list[Issue]:
    issues = []
    for ln in _lines(config):
        m = re.match(r"\s*enable password (\S+)", ln)
        if m:
            issues.append(
                Issue("plaintext-enable", "error",
                      f"enable password '{m.group(1)}' is stored in plaintext; use 'enable secret'")
            )
    return issues


def check_snmp_community(config: str) -> list[Issue]:
    issues = []
    for ln in _lines(config):
        m = re.match(r"\s*snmp-server community (\S+)", ln)
        if m and m.group(1).lower() in ("public", "private"):
            issues.append(
                Issue("snmp-community", "error",
                      f"SNMP community '{m.group(1)}' is a default value and should not be used")
            )
    return issues


def check_trunk_vlan1(config: str) -> list[Issue]:
    issues = []
    for ln in _lines(config):
        m = re.match(r"\s*switchport trunk allowed vlan ([\d,\-\s]+)", ln)
        if m and 1 in _vlan_ids(m.group(1)):
            issues.append(
                Issue("trunk-vlan1", "warning",
                      "trunk carries VLAN 1; use a dedicated unused native VLAN and prune VLAN 1 from trunks")
            )
    return issues


def check_telnet_enabled(config: str) -> list[Issue]:
    issues = []
    if re.search(r"transport input telnet", config, re.IGNORECASE):
        issues.append(Issue("telnet-enabled", "error",
                            "telnet is allowed on vty lines; restrict to SSH"))
    return issues


def check_http_server(config: str) -> list[Issue]:
    issues = []
    if re.search(r"^\s*ip http server\b", config, re.MULTILINE):
        issues.append(Issue("http-server", "warning",
                            "plaintext HTTP server is enabled; use 'ip http secure-server' instead"))
    return issues


def check_ntp_auth(config: str) -> list[Issue]:
    issues = []
    ntp = re.search(r"^\s*ntp server (\S+)", config, re.MULTILINE)
    if ntp and not re.search(r"^\s*ntp authenticate", config, re.MULTILINE):
        issues.append(Issue("ntp-unauthenticated", "warning",
                            f"NTP server {ntp.group(1)} configured without 'ntp authenticate'"))
    return issues


def check_duplicate_addresses(config: str) -> list[Issue]:
    issues = []
    seen: dict[str, str] = {}
    for ln in _lines(config):
        m = re.match(r"\s*ip address (\S+) (\S+)", ln)
        if m:
            addr = m.group(1)
            try:
                ip = str(ipaddress.ip_interface(addr).ip)
            except ValueError:
                continue
            if ip in seen:
                issues.append(Issue("duplicate-address", "error",
                                    f"address {ip} is configured more than once (near '{seen[ip]}' and '{ln.strip()}')"))
            else:
                seen[ip] = ln.strip()
    return issues


def check_unused_vlans(config: str) -> list[Issue]:
    issues = []
    defined: set[int] = set()
    referenced: set[int] = set()

    # VRP uses 'vlan batch 10 20 to 25'; IOS uses 'vlan 10'.
    for ln in _lines(config):
        m = re.match(r"\s*vlan (\d+)", ln)
        if m:
            defined.add(int(m.group(1)))
    for ln in _lines(config):
        m = re.match(r"\s*vlan batch (.+)", ln)
        if m:
            defined.update(_vrp_vlan_ids(m.group(1)))

    for ln in _lines(config):
        for m in re.finditer(r"switchport (?:access vlan|trunk allowed vlan) ([\d,\-\s]+)", ln):
            referenced.update(_vlan_ids(m.group(1)))
        for m in re.finditer(r"port (?:default vlan (\d+)|trunk allow-pass vlan (.+)|trunk pvid vlan (\d+))", ln):
            if m.group(1):
                referenced.add(int(m.group(1)))
            elif m.group(2):
                referenced.update(_vrp_vlan_ids(m.group(2)))
            elif m.group(3):
                referenced.add(int(m.group(3)))

    for vlan in sorted(defined - referenced):
        issues.append(Issue("unused-vlan", "warning", f"VLAN {vlan} is defined but never referenced by any port"))
    return issues


_CHECKS = [
    check_plaintext_enable,
    check_snmp_community,
    check_trunk_vlan1,
    check_telnet_enabled,
    check_http_server,
    check_ntp_auth,
    check_duplicate_addresses,
    check_unused_vlans,
]


def lint(config: str) -> list[Issue]:
    issues: list[Issue] = []
    for fn in _CHECKS:
        issues.extend(fn(config))
    return issues
