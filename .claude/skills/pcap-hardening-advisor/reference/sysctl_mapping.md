# Pcap heuristic → `os_hardening` variable mapping

Line numbers refer to `roles/os_hardening/defaults/main.yml` at the time this skill was written; verify if the file has shifted.

## Security category (overrides existing defaults)

| Observation | Override | Variable | Line |
|---|---|---|---|
| SYN-to-handshake ratio high | `1` | `net.ipv4.tcp_syncookies` | 219 |
| TCP timestamps observed | `0` | `net.ipv4.tcp_timestamps` | 201 |
| Spurious RSTs after FIN | `1` | `net.ipv4.tcp_rfc1337` | 211 |
| ICMP echo to broadcast | `1` | `net.ipv4.icmp_echo_ignore_broadcasts` | 186 |
| Bogus ICMP error responses | `1` | `net.ipv4.icmp_ignore_bogus_error_responses` | 191 |
| ICMP redirects received | `0` | `net.ipv4.conf.all.accept_redirects` | 257 |
| Source-routed IP packets | `0` | `net.ipv4.conf.all.accept_source_route` | 227 |
| Unsolicited IPv6 RAs | `0` | `net.ipv6.conf.all.accept_ra` | 264 |
| Inbound to non-listening ports w/o reply | `1` | `net.ipv4.conf.all.log_martians` | 245 |
| Asymmetric routing detected | report only — recommend `2` only if asymmetry is by design | `net.ipv4.conf.all.rp_filter` | 181 |

## Performance category (additions — not in current `sysctl_config`)

These keys are not part of the security baseline; the skill marks them as additions so the user reviews them before applying.

| Observation | Suggested setting | Notes |
|---|---|---|
| SYN retransmits to listening ports | `net.ipv4.tcp_max_syn_backlog: 4096` + `net.core.somaxconn: 4096` | Pair both; app must also pass an `accept` backlog ≥ somaxconn |
| SYN-ACK retransmits | `net.core.somaxconn: 4096` | Accept-queue pressure |
| Many TIME_WAIT entries on outbound client flows | `net.ipv4.tcp_tw_reuse: 1` | **Never** suggest `tcp_tw_recycle` (removed in 4.12) |
| SACK absent in observed TCP options | `net.ipv4.tcp_sack: 1` | Default-on; only flag if seen off |
| Window scaling absent / capped low | `net.ipv4.tcp_window_scaling: 1` | Default-on |
| Sustained throughput near link rate | `net.core.rmem_max: 16777216`, `net.ipv4.tcp_rmem: "4096 87380 16777216"` | Optional, environment-specific |
| cwnd-limited transfers | `net.core.wmem_max: 16777216`, `net.ipv4.tcp_wmem: "4096 65536 16777216"` | Optional |
| Long idle flows reset | `net.ipv4.tcp_keepalive_time: 600` | App-dependent |
| Ephemeral port exhaustion | `net.ipv4.ip_local_port_range: "1024 65535"` | Marked perf |
| BBR not in use + congestion observed | `net.ipv4.tcp_congestion_control: bbr`, `net.core.default_qdisc: fq` | Kernel-version-gated; advisory only |
