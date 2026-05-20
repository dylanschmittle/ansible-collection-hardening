"""Event classifiers for journal-hardening-advisor.

Maps a journal entry (dict from `journalctl -o json`) to zero or one event class.
Each classifier is a (class_id, identifier_match, message_regex, source_ip_extractor).
"""

from __future__ import annotations

import re
from typing import Callable, NamedTuple


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _ipv4(msg: str) -> str | None:
    m = IPV4_RE.search(msg)
    return m.group(0) if m else None


class Rule(NamedTuple):
    cls: str
    ident_match: Callable[[str], bool]
    pattern: re.Pattern
    extract_source: Callable[[str], str | None]


def _ident_eq(name: str) -> Callable[[str], bool]:
    return lambda v: v == name


def _ident_in(*names: str) -> Callable[[str], bool]:
    s = set(names)
    return lambda v: v in s


RULES: list[Rule] = [
    Rule(
        "sshd:auth_failure",
        _ident_eq("sshd"),
        re.compile(r"(Failed password|Invalid user|authentication failure)", re.IGNORECASE),
        _ipv4,
    ),
    Rule(
        "sshd:root_login_attempt",
        _ident_eq("sshd"),
        re.compile(r"(root login|user root from)", re.IGNORECASE),
        _ipv4,
    ),
    Rule(
        "sshd:dns_lookup_slow",
        _ident_eq("sshd"),
        re.compile(r"reverse mapping checking getaddrinfo", re.IGNORECASE),
        _ipv4,
    ),
    Rule(
        "sudo:auth_failure",
        _ident_eq("sudo"),
        re.compile(r"(incorrect password attempts|authentication failure)", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "kernel:martian_source",
        _ident_eq("kernel"),
        re.compile(r"martian source", re.IGNORECASE),
        _ipv4,
    ),
    Rule(
        "kernel:netfilter_drop",
        _ident_eq("kernel"),
        re.compile(r"(\[UFW BLOCK\]|iptables:.*DROP)", re.IGNORECASE),
        _ipv4,
    ),
    Rule(
        "kernel:tcp_listen_overflow",
        _ident_eq("kernel"),
        re.compile(r"Possible SYN flooding.*Dropping request", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "kernel:nf_conntrack_full",
        _ident_eq("kernel"),
        re.compile(r"nf_conntrack:\s*table full", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "kernel:neighbour_table_overflow",
        _ident_eq("kernel"),
        re.compile(r"neighbour:\s*.*neighbor table overflow", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "kernel:oom_killer",
        _ident_eq("kernel"),
        re.compile(r"(Out of memory|invoked oom-killer|Killed process)", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "kernel:softlockup",
        _ident_eq("kernel"),
        re.compile(r"(soft lockup|rcu_sched.*stall)", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "audit:lost_events",
        _ident_in("audit", "auditd", "kernel"),
        re.compile(r"(audit:\s*backlog limit exceeded|audit_lost=|lost \d+ audit messages)",
                   re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "systemd:unit_failed_security",
        _ident_eq("systemd"),
        re.compile(r"Failed with result 'core-dump'", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "journald:rate_limit_hit",
        _ident_in("systemd-journald", "systemd"),
        re.compile(r"Suppressed \d+ messages", re.IGNORECASE),
        lambda _m: None,
    ),
    Rule(
        "pam:account_locked",
        _ident_in("sshd", "login", "su"),
        re.compile(r"account locked due to", re.IGNORECASE),
        _ipv4,
    ),
]


def classify(entry: dict) -> tuple[str | None, str | None]:
    """Return (class_id, source_ip_or_none) or (None, None) if no rule matches."""
    ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or ""
    msg = entry.get("MESSAGE") or ""
    if isinstance(msg, list):
        # journalctl emits a byte-array list for binary messages; join as string.
        try:
            msg = bytes(msg).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            msg = " ".join(str(x) for x in msg)
    for r in RULES:
        if r.ident_match(ident) and r.pattern.search(msg):
            return r.cls, r.extract_source(msg)
    return None, None
