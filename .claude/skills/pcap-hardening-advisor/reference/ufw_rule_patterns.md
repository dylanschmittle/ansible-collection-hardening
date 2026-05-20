# UFW rule synthesis patterns

The analyzer derives UFW commands from observed traffic. Patterns:

- **Listening port with completed handshakes** → `ufw allow <port>/<proto>`.
  If observed source IPs are narrow (≤ 3), the renderer may instead suggest `ufw allow from <ip> to any port <port> proto <proto>`.
- **SSH (22/tcp) attempts from > 5 distinct sources** → `ufw limit 22/tcp` (rate-limit instead of allow).
- **High-volume outbound flow with no inbound peer** → keep the role's default `ufw_default_input_policy: DROP`; document the outbound service in findings only.
- **Plain-text protocols (FTP/HTTP/Telnet/POP3/IMAP/LDAP)** → never auto-allow; emit a finding recommending the encrypted equivalent.
- **Many UDP listeners on the same host** → list them in findings; do not auto-allow (UDP services have varied risk profiles).

The role's relevant variables (`roles/os_hardening/defaults/main.yml`):

| Variable | Line | Default |
|---|---|---|
| `ufw_manage_defaults` | 59 | `true` |
| `ufw_default_input_policy` | 68 | `DROP` |
| `ufw_default_output_policy` | 69 | `ACCEPT` |
| `ufw_default_forward_policy` | 70 | `DROP` |
| `ufw_enable_ipv6` | 77 | `true` |

The skill does NOT manage UFW rules via Ansible variables (the role only handles defaults). It emits raw `ufw` CLI commands the user can wrap in their own task.
