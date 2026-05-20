"""Heuristics for pcap-hardening-advisor.

Pure functions. Input: aggregate counters + per-flow sample. Output: lists of
overrides, ufw rules, and findings — each tagged `category` (security/performance/both)
so renderers can split them.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Override:
    key: str
    value: Any
    category: str  # "security" | "performance" | "both"
    evidence: str


@dataclass
class UfwRule:
    action: str  # "allow" | "deny" | "limit"
    port: str
    proto: str
    source: str  # "any" or an IP/CIDR
    reason: str


@dataclass
class Finding:
    id: str
    severity: str  # "high" | "medium" | "low" | "info"
    title: str
    detail: str
    evidence: str


@dataclass
class Aggregates:
    total_packets: int = 0
    syn: int = 0
    syn_ack: int = 0
    rst: int = 0
    fin: int = 0
    icmp_echo_broadcast: int = 0
    icmp_bogus_error: int = 0
    icmp_redirect: int = 0
    ip_source_routed: int = 0
    ipv6_ra_seen: int = 0
    ipv6_ra_sources: set = field(default_factory=set)
    tcp_timestamps_seen: int = 0
    tcp_sack_seen: int = 0
    tcp_window_scale_seen: int = 0
    martian_candidates: int = 0  # inbound to non-listening port w/o reply
    asymmetric_iface_packets: int = 0
    syn_retrans: int = 0
    synack_retrans: int = 0
    rst_after_close_wait: int = 0  # crude TIME-WAIT-assassination signal
    listening_ports: set = field(default_factory=set)  # (proto, port)
    ssh_attempt_sources: set = field(default_factory=set)
    plaintext_protocols: set = field(default_factory=set)
    flows: int = 0


# Tunable thresholds.
SYN_FLOOD_RATIO = 5  # SYN-to-completed-handshake ratio
SSH_SOURCES_LIMIT = 5  # distinct sources hitting 22/tcp -> limit
PERF_SYN_BACKLOG_TRIGGER = 50  # SYN retransmits seen
PERF_ACCEPT_QUEUE_TRIGGER = 50  # SYN-ACK retransmits seen


def analyze(agg: Aggregates) -> dict:
    overrides: list[Override] = []
    ufw: list[UfwRule] = []
    findings: list[Finding] = []

    completed = max(agg.syn_ack, 1)
    syn_ratio = agg.syn / completed

    # ---- security: TCP/ICMP/IPv6 hardening signals ----
    if agg.syn > 100 and syn_ratio > SYN_FLOOD_RATIO:
        ev = f"{agg.syn} SYNs vs {agg.syn_ack} SYN-ACKs (ratio {syn_ratio:.1f}x)"
        findings.append(Finding(
            "syn_flood", "high",
            "SYN-flood-like pattern detected",
            "SYN-to-handshake ratio is high; enable SYN cookies.",
            ev,
        ))
        overrides.append(Override("net.ipv4.tcp_syncookies", 1, "security", ev))

    if agg.tcp_timestamps_seen > 0:
        ev = f"{agg.tcp_timestamps_seen} packets carrying TCP timestamps observed"
        findings.append(Finding(
            "tcp_timestamps", "low",
            "TCP timestamps observed (uptime leak)",
            "TCP timestamps can leak host uptime; disable.",
            ev,
        ))
        overrides.append(Override("net.ipv4.tcp_timestamps", 0, "security", ev))

    if agg.rst_after_close_wait > 0:
        ev = f"{agg.rst_after_close_wait} RST packets observed after FIN exchange"
        findings.append(Finding(
            "tw_assassination", "medium",
            "TIME-WAIT assassination signal",
            "Spurious RSTs into TIME-WAIT sockets seen; enable RFC 1337.",
            ev,
        ))
        overrides.append(Override("net.ipv4.tcp_rfc1337", 1, "security", ev))

    if agg.icmp_echo_broadcast > 0:
        ev = f"{agg.icmp_echo_broadcast} ICMP echo requests to broadcast destination"
        findings.append(Finding(
            "icmp_broadcast", "medium",
            "ICMP echo to broadcast address",
            "Host is being probed via broadcast pings.",
            ev,
        ))
        overrides.append(Override("net.ipv4.icmp_echo_ignore_broadcasts", 1, "security", ev))

    if agg.icmp_bogus_error > 0:
        ev = f"{agg.icmp_bogus_error} bogus ICMP error responses"
        overrides.append(Override("net.ipv4.icmp_ignore_bogus_error_responses", 1, "security", ev))

    if agg.icmp_redirect > 0:
        ev = f"{agg.icmp_redirect} ICMP redirect packets received"
        findings.append(Finding(
            "icmp_redirect", "medium",
            "ICMP redirects observed",
            "Drop ICMP redirects to prevent route hijacking.",
            ev,
        ))
        overrides.append(Override("net.ipv4.conf.all.accept_redirects", 0, "security", ev))

    if agg.ip_source_routed > 0:
        ev = f"{agg.ip_source_routed} source-routed IP packets observed"
        findings.append(Finding(
            "source_route", "high",
            "Source-routed packets observed",
            "Source routing should be refused.",
            ev,
        ))
        overrides.append(Override("net.ipv4.conf.all.accept_source_route", 0, "security", ev))

    if agg.ipv6_ra_seen > 0:
        ev = f"{agg.ipv6_ra_seen} IPv6 RAs from {len(agg.ipv6_ra_sources)} sources"
        findings.append(Finding(
            "ipv6_ra", "medium",
            "IPv6 Router Advertisements observed",
            "Disable RA acceptance unless this host is an IPv6 client by design.",
            ev,
        ))
        overrides.append(Override("net.ipv6.conf.all.accept_ra", 0, "security", ev))

    if agg.martian_candidates > 0:
        ev = f"{agg.martian_candidates} inbound packets to non-listening ports without reply"
        overrides.append(Override("net.ipv4.conf.all.log_martians", 1, "security", ev))

    if agg.asymmetric_iface_packets > 0:
        ev = f"{agg.asymmetric_iface_packets} packets arrived on unexpected interface"
        findings.append(Finding(
            "asymmetric_routing", "low",
            "Asymmetric routing detected",
            "If asymmetric paths are legitimate consider rp_filter=2; otherwise keep strict.",
            ev,
        ))

    # ---- performance: backlog / queue / memory signals ----
    if agg.syn_retrans >= PERF_SYN_BACKLOG_TRIGGER:
        ev = f"{agg.syn_retrans} SYN retransmits seen"
        overrides.append(Override("net.ipv4.tcp_max_syn_backlog", 4096, "performance", ev))
        overrides.append(Override("net.core.somaxconn", 4096, "performance", ev))

    if agg.synack_retrans >= PERF_ACCEPT_QUEUE_TRIGGER and not any(
        o.key == "net.core.somaxconn" for o in overrides
    ):
        ev = f"{agg.synack_retrans} SYN-ACK retransmits seen"
        overrides.append(Override("net.core.somaxconn", 4096, "performance", ev))

    # ---- UFW rules from listening ports + SSH source spread ----
    # Skip plaintext ports — never auto-allow them; they're reported as findings.
    plaintext_ports = {21, 23, 25, 80, 110, 143, 389}
    for proto, port in sorted(agg.listening_ports):
        if proto == "tcp" and port == 22 and len(agg.ssh_attempt_sources) > SSH_SOURCES_LIMIT:
            ufw.append(UfwRule(
                "limit", "22", "tcp", "any",
                f"SSH attempts from {len(agg.ssh_attempt_sources)} distinct sources",
            ))
            continue
        if proto == "tcp" and port in plaintext_ports:
            continue
        ufw.append(UfwRule(
            "allow", str(port), proto, "any",
            "observed completed handshakes",
        ))

    if agg.plaintext_protocols:
        findings.append(Finding(
            "plaintext_protocols", "medium",
            "Plain-text protocols observed",
            "Migrate to encrypted equivalents (HTTPS/SFTP/SSH).",
            ", ".join(sorted(agg.plaintext_protocols)),
        ))

    return {
        "stats": {
            "total_packets": agg.total_packets,
            "flows": agg.flows,
            "syn": agg.syn,
            "syn_ack": agg.syn_ack,
            "rst": agg.rst,
            "fin": agg.fin,
        },
        "findings": [asdict(f) for f in findings],
        "sysctl_overrides": [asdict(o) for o in overrides],
        "ufw_rules": [asdict(r) for r in ufw],
    }
