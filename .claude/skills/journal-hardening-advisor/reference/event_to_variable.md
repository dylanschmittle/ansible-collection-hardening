# Journal event → role variable mapping

Line numbers refer to the relevant `defaults/main.yml` files at the time this
skill was written; verify if they have shifted.

## Security category

| Event class | Trigger | Suggested override | File:line |
|---|---|---|---|
| `sshd:auth_failure` (any) | any failure entry | `ssh_max_auth_retries: 2` | `roles/ssh_hardening/defaults/main.yml:60` |
| `sshd:auth_failure` (flood / spread) | >20 from one source OR ≥5 distinct sources | `ssh_server_password_login: false`, `ssh_login_grace_time: 30s`, UFW `limit 22/tcp` | `roles/ssh_hardening/defaults/main.yml:31`, `:56` |
| `sshd:root_login_attempt` | any | `ssh_permit_root_login: "no"` | `roles/ssh_hardening/defaults/main.yml:80` |
| `sshd:dns_lookup_slow` | ≥3 entries | `ssh_use_dns: false` (also `category: both` — perf benefit) | `roles/ssh_hardening/defaults/main.yml:18` |
| `kernel:martian_source` | any | `log_martians: 1`, confirm `rp_filter: 1` | `roles/os_hardening/defaults/main.yml:245`, `:181` |
| `audit:lost_events` | any | `os_auditd_enabled: true` (and bump backlog manually) | `roles/os_hardening/defaults/main.yml:333` |
| `systemd:unit_failed_security` | core-dump exit | `fs.suid_dumpable: 0` | `roles/os_hardening/defaults/main.yml:94` |
| `sudo:auth_failure` | any | report only — privilege-escalation candidate | n/a |
| `pam:account_locked` | any | report only | n/a |
| `kernel:netfilter_drop` | any | report only — confirm UFW default-deny is correct | n/a |

## Performance category

| Event class | Trigger | Suggested setting | Notes |
|---|---|---|---|
| `journald:rate_limit_hit` | ≥3 suppression entries | `/etc/systemd/journald.conf.d/10-rate-limit.conf` → `RateLimitIntervalSec=30s`, `RateLimitBurst=10000` | Drop-in advisory, not an Ansible var |
| `kernel:nf_conntrack_full` | any | `net.netfilter.nf_conntrack_max: 524288` | Addition to `sysctl_config` |
| `kernel:tcp_listen_overflow` | any | `net.ipv4.tcp_max_syn_backlog: 4096`, `net.core.somaxconn: 4096` | Addition |
| `kernel:neighbour_table_overflow` | any | `net.ipv4.neigh.default.gc_thresh{1,2,3}: 4096/8192/16384` | Addition |
| `kernel:oom_killer` | any | report only — investigate memory pressure | n/a |
| `kernel:softlockup` | any | report only — likely hardware/hypervisor | n/a |

## Tagged `both` (security + performance)

| Event class | Notes |
|---|---|
| `sshd:dns_lookup_slow` | Disabling UseDNS removes a sec-vs-latency trap. |
| `audit:lost_events` | Losing audit events is both a security gap and a perf signal (backlog too small). |
