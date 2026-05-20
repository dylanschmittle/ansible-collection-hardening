#!/usr/bin/env python3
"""Analyze a pcap for devsec.hardening tuning suggestions.

Streams the capture with pyshark, samples up to K packets per 5-tuple flow,
runs heuristics, and prints a single JSON object to stdout.

Usage:
    analyze_pcap.py <pcap> [--per-flow-cap N]

Requires: tshark (system), pyshark (pip).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from heuristics import Aggregates, analyze  # noqa: E402

PLAINTEXT_PORT_MAP = {
    21: "ftp",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
}


def _flow_key(pkt) -> tuple | None:
    try:
        if hasattr(pkt, "ip"):
            src, dst = pkt.ip.src, pkt.ip.dst
            ver = 4
        elif hasattr(pkt, "ipv6"):
            src, dst = pkt.ipv6.src, pkt.ipv6.dst
            ver = 6
        else:
            return None
        if hasattr(pkt, "tcp"):
            return (ver, "tcp", src, int(pkt.tcp.srcport), dst, int(pkt.tcp.dstport))
        if hasattr(pkt, "udp"):
            return (ver, "udp", src, int(pkt.udp.srcport), dst, int(pkt.udp.dstport))
        if hasattr(pkt, "icmp") or hasattr(pkt, "icmpv6"):
            return (ver, "icmp", src, 0, dst, 0)
    except (AttributeError, ValueError):
        return None
    return None


def _tcp_flags(pkt) -> dict:
    """Extract TCP flag booleans from a pyshark packet."""
    if not hasattr(pkt, "tcp"):
        return {}
    t = pkt.tcp
    def b(name, default="0"):
        return getattr(t, name, default) == "1"
    return {
        "syn": b("flags_syn"),
        "ack": b("flags_ack"),
        "rst": b("flags_reset"),
        "fin": b("flags_fin"),
    }


def run(pcap_path: str, per_flow_cap: int) -> dict:
    try:
        import pyshark
    except ImportError:
        print(json.dumps({
            "error": "pyshark not importable",
            "hint": "pip install pyshark (and ensure tshark is on PATH)",
        }))
        sys.exit(2)

    if not os.path.exists(pcap_path):
        print(json.dumps({"error": f"file not found: {pcap_path}"}))
        sys.exit(2)

    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    agg = Aggregates()
    per_flow: dict[tuple, int] = defaultdict(int)
    per_flow_rsv: dict[tuple, list] = defaultdict(list)
    seen_handshake_completed: set[tuple] = set()
    seen_fin_pair: set[tuple] = set()
    syn_seen_per_flow: dict[tuple, int] = defaultdict(int)
    synack_seen_per_flow: dict[tuple, int] = defaultdict(int)

    for pkt in cap:
        agg.total_packets += 1
        key = _flow_key(pkt)
        if key is None:
            continue
        per_flow[key] += 1
        if per_flow[key] == 1:
            agg.flows += 1

        # stratified sampling: keep up to per_flow_cap per flow (reservoir).
        bucket = per_flow_rsv[key]
        if len(bucket) < per_flow_cap:
            bucket.append(agg.total_packets)
        else:
            j = random.randint(0, per_flow[key] - 1)
            if j < per_flow_cap:
                bucket[j] = agg.total_packets

        _, proto, src, sport, dst, dport = key

        if proto == "tcp":
            flags = _tcp_flags(pkt)
            if flags.get("syn") and not flags.get("ack"):
                agg.syn += 1
                syn_seen_per_flow[key] += 1
                if syn_seen_per_flow[key] > 1:
                    agg.syn_retrans += 1
            if flags.get("syn") and flags.get("ack"):
                agg.syn_ack += 1
                synack_seen_per_flow[key] += 1
                if synack_seen_per_flow[key] > 1:
                    agg.synack_retrans += 1
                # the side sending SYN-ACK is the listener: (dst, dport)
                agg.listening_ports.add(("tcp", dport))
            if flags.get("rst"):
                agg.rst += 1
                if key in seen_fin_pair:
                    agg.rst_after_close_wait += 1
            if flags.get("fin"):
                agg.fin += 1
                seen_fin_pair.add(key)
            if flags.get("ack") and key not in seen_handshake_completed:
                # heuristic: ACK after SYN-ACK indicates completed handshake.
                seen_handshake_completed.add(key)

            # TCP options: timestamps / sack / window-scale presence.
            opts = getattr(pkt.tcp, "options", "") or ""
            if "Timestamps" in opts:
                agg.tcp_timestamps_seen += 1
            if "SACK" in opts:
                agg.tcp_sack_seen += 1
            if "Window scale" in opts or "WS" in opts:
                agg.tcp_window_scale_seen += 1

            # plaintext protocol detection: completed inbound handshake on listed port.
            if dport in PLAINTEXT_PORT_MAP and key in seen_handshake_completed:
                agg.plaintext_protocols.add(PLAINTEXT_PORT_MAP[dport])

            # SSH source tracking.
            if dport == 22:
                agg.ssh_attempt_sources.add(src)

        elif proto == "udp":
            agg.listening_ports.add(("udp", dport))  # noisy but useful

        # ICMP signals
        if hasattr(pkt, "icmp"):
            try:
                icmp_type = int(pkt.icmp.type)
            except (AttributeError, ValueError):
                icmp_type = -1
            if icmp_type == 5:  # redirect
                agg.icmp_redirect += 1
            if icmp_type == 8 and dst.endswith(".255"):
                agg.icmp_echo_broadcast += 1
            if icmp_type in (3, 11):
                # bogus error responses are hard to detect from a pcap alone; flag if
                # we see ICMP errors referencing flows we never saw established.
                pass

        # IP options: source-routing
        try:
            if hasattr(pkt, "ip") and getattr(pkt.ip, "opt_lsr", None) is not None:
                agg.ip_source_routed += 1
            if hasattr(pkt, "ip") and getattr(pkt.ip, "opt_ssr", None) is not None:
                agg.ip_source_routed += 1
        except AttributeError:
            pass

        # IPv6 RA
        if hasattr(pkt, "icmpv6"):
            try:
                if int(pkt.icmpv6.type) == 134:
                    agg.ipv6_ra_seen += 1
                    agg.ipv6_ra_sources.add(src)
            except (AttributeError, ValueError):
                pass

    cap.close()

    # crude martian candidate: inbound TCP to a port nobody listens on (no SYN-ACK seen).
    listening_tcp = {p for proto, p in agg.listening_ports if proto == "tcp"}
    for key in per_flow:
        _, proto, _, _, _, dport = key
        if proto == "tcp" and dport not in listening_tcp and key not in seen_handshake_completed:
            agg.martian_candidates += 1

    return analyze(agg)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", help="path to pcap/pcapng/cap file")
    ap.add_argument("--per-flow-cap", type=int, default=100,
                    help="max packets sampled per 5-tuple flow (default 100)")
    args = ap.parse_args()

    result = run(args.pcap, args.per_flow_cap)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
