"""Heuristics for journal-hardening-advisor.

Input: per-class counts + per-class sample of raw entries + per-class top sources.
Output: dict with sysctl_overrides, ssh_overrides, ufw_rules, journald_advisories, findings.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Override:
    key: str
    value: Any
    category: str
    evidence: str


@dataclass
class UfwRule:
    action: str
    port: str
    proto: str
    source: str
    reason: str


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    evidence: str


@dataclass
class JournaldAdvisory:
    file: str
    setting: str
    value: Any
    evidence: str


# Trigger thresholds.
SSH_FAILURE_FLOOD = 20          # per single source
SSH_FAILURE_SPREAD_SOURCES = 5  # distinct sources
AUDIT_LOST_TRIGGER = 1
JOURNALD_RATELIMIT_TRIGGER = 3


def analyze(counts: dict[str, int],
            top_sources: dict[str, dict[str, int]]) -> dict:
    sysctl: list[Override] = []
    ssh: list[Override] = []
    ufw: list[UfwRule] = []
    journald: list[JournaldAdvisory] = []
    findings: list[Finding] = []

    # ---- sshd failures ----
    sshd_fail = counts.get("sshd:auth_failure", 0)
    sshd_sources = top_sources.get("sshd:auth_failure", {})
    worst_source = max(sshd_sources.items(), key=lambda kv: kv[1], default=(None, 0))

    if sshd_fail > 0:
        ev = f"{sshd_fail} sshd auth failures from {len(sshd_sources)} sources"
        findings.append(Finding(
            "sshd_auth_failures", "high" if sshd_fail >= 50 else "medium",
            "SSH authentication failures observed",
            "Tighten SSH retries, disable password auth, rate-limit at the firewall.",
            ev + (f"; worst: {worst_source[0]} ({worst_source[1]})" if worst_source[0] else ""),
        ))
        ssh.append(Override("ssh_max_auth_retries", 2, "security", ev))

        if (worst_source[1] >= SSH_FAILURE_FLOOD
                or len(sshd_sources) >= SSH_FAILURE_SPREAD_SOURCES):
            ufw.append(UfwRule("limit", "22", "tcp", "any",
                               f"{sshd_fail} ssh failures, {len(sshd_sources)} sources"))
            ssh.append(Override("ssh_server_password_login", False, "security", ev))
            ssh.append(Override("ssh_login_grace_time", "30s", "security", ev))

    if counts.get("sshd:root_login_attempt", 0) > 0:
        ev = f"{counts['sshd:root_login_attempt']} root login attempts seen"
        findings.append(Finding(
            "ssh_root_attempts", "high",
            "Direct root SSH login attempts",
            "Keep PermitRootLogin no.",
            ev,
        ))
        ssh.append(Override("ssh_permit_root_login", "no", "security", ev))

    if counts.get("sshd:dns_lookup_slow", 0) >= 3:
        ev = f"{counts['sshd:dns_lookup_slow']} reverse-DNS failures slowing sshd"
        ssh.append(Override("ssh_use_dns", False, "both", ev))
        findings.append(Finding(
            "ssh_use_dns", "low",
            "Slow / failing reverse DNS for sshd",
            "Set UseDNS no to speed up logins.",
            ev,
        ))

    if counts.get("sudo:auth_failure", 0) > 0:
        findings.append(Finding(
            "sudo_failures", "medium",
            "Repeated sudo authentication failures",
            "Privilege-escalation candidate; review sudoers + faillock.",
            f"{counts['sudo:auth_failure']} sudo failures",
        ))

    # ---- kernel / network security signals ----
    if counts.get("kernel:martian_source", 0) > 0:
        ev = f"{counts['kernel:martian_source']} martian-source kernel messages"
        sysctl.append(Override("net.ipv4.conf.all.log_martians", 1, "security", ev))
        sysctl.append(Override("net.ipv4.conf.all.rp_filter", 1, "security", ev))
        findings.append(Finding(
            "martian_source", "medium",
            "Kernel reported martian-source packets",
            "rp_filter is dropping packets with bogus source addresses.",
            ev,
        ))

    if counts.get("kernel:netfilter_drop", 0) > 0:
        findings.append(Finding(
            "ufw_drops", "info",
            "UFW/iptables drops being logged",
            "Healthy if UFW default-deny is active; correlate with allowed services.",
            f"{counts['kernel:netfilter_drop']} drop entries",
        ))

    # ---- audit ----
    if counts.get("audit:lost_events", 0) >= AUDIT_LOST_TRIGGER:
        ev = f"{counts['audit:lost_events']} audit-loss messages"
        sysctl.append(Override("os_auditd_enabled", True, "both", ev))
        findings.append(Finding(
            "audit_lost", "high",
            "auditd is dropping events",
            "Raise the audit backlog and confirm auditd is running and writing logs.",
            ev,
        ))

    if counts.get("systemd:unit_failed_security", 0) > 0:
        ev = f"{counts['systemd:unit_failed_security']} units exited via core-dump"
        sysctl.append(Override("fs.suid_dumpable", 0, "security", ev))
        findings.append(Finding(
            "core_dumps", "medium",
            "Services core-dumping",
            "Confirm fs.suid_dumpable=0 to avoid leaks via SUID core dumps.",
            ev,
        ))

    # ---- performance signals ----
    if counts.get("journald:rate_limit_hit", 0) >= JOURNALD_RATELIMIT_TRIGGER:
        ev = f"{counts['journald:rate_limit_hit']} journald rate-limit suppressions"
        journald.append(JournaldAdvisory(
            "/etc/systemd/journald.conf.d/10-rate-limit.conf",
            "RateLimitIntervalSec", "30s", ev,
        ))
        journald.append(JournaldAdvisory(
            "/etc/systemd/journald.conf.d/10-rate-limit.conf",
            "RateLimitBurst", 10000, ev,
        ))
        findings.append(Finding(
            "journald_rate_limit", "low",
            "journald is suppressing messages",
            "Raise journald RateLimit settings; you are losing log data.",
            ev,
        ))

    if counts.get("kernel:nf_conntrack_full", 0) > 0:
        ev = f"{counts['kernel:nf_conntrack_full']} conntrack-table-full kernel messages"
        sysctl.append(Override("net.netfilter.nf_conntrack_max", 524288, "performance", ev))
        findings.append(Finding(
            "conntrack_full", "high",
            "nf_conntrack table is filling up",
            "Increase table size or shorten conntrack timeouts.",
            ev,
        ))

    if counts.get("kernel:tcp_listen_overflow", 0) > 0:
        ev = f"{counts['kernel:tcp_listen_overflow']} listen-queue overflow messages"
        sysctl.append(Override("net.ipv4.tcp_max_syn_backlog", 4096, "performance", ev))
        sysctl.append(Override("net.core.somaxconn", 4096, "performance", ev))
        findings.append(Finding(
            "listen_overflow", "medium",
            "TCP listen-queue overflow",
            "Raise tcp_max_syn_backlog and somaxconn; consider app accept() backlog.",
            ev,
        ))

    if counts.get("kernel:neighbour_table_overflow", 0) > 0:
        ev = f"{counts['kernel:neighbour_table_overflow']} ARP table overflow messages"
        sysctl.append(Override("net.ipv4.neigh.default.gc_thresh1", 4096, "performance", ev))
        sysctl.append(Override("net.ipv4.neigh.default.gc_thresh2", 8192, "performance", ev))
        sysctl.append(Override("net.ipv4.neigh.default.gc_thresh3", 16384, "performance", ev))

    if counts.get("kernel:oom_killer", 0) > 0:
        findings.append(Finding(
            "oom_killer", "high",
            "OOM-killer invoked",
            "Investigate memory pressure; consider workload limits before tuning vm sysctls.",
            f"{counts['kernel:oom_killer']} OOM events",
        ))

    if counts.get("kernel:softlockup", 0) > 0:
        findings.append(Finding(
            "soft_lockup", "high",
            "Kernel soft-lockup or RCU stall",
            "Likely hypervisor/CPU/scheduler issue; review the host, not sysctls.",
            f"{counts['kernel:softlockup']} stall events",
        ))

    if counts.get("pam:account_locked", 0) > 0:
        findings.append(Finding(
            "pam_locked", "medium",
            "Accounts locked by PAM/faillock",
            "Review who is being locked out and why.",
            f"{counts['pam:account_locked']} lock events",
        ))

    return {
        "stats": dict(counts),
        "findings": [asdict(f) for f in findings],
        "sysctl_overrides": [asdict(o) for o in sysctl],
        "ssh_overrides": [asdict(o) for o in ssh],
        "ufw_rules": [asdict(r) for r in ufw],
        "journald_advisories": [asdict(j) for j in journald],
    }
