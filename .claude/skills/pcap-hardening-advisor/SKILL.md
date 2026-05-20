---
name: pcap-hardening-advisor
description: Analyze a pcap/tcpdump capture and suggest devsec.hardening os_hardening overrides (security + performance), UFW rules, and a network anomaly report. Use when the user provides a .pcap/.pcapng/.cap file or asks to derive hardening or tuning settings from observed traffic.
---

# pcap-hardening-advisor

Turn a captured pcap into concrete Ansible variable overrides for the `devsec.hardening.os_hardening` role plus UFW rules, separating **security** and **performance** suggestions so a reviewer can stage them independently.

## Inputs you accept

- A path to a `.pcap`, `.pcapng`, or `.cap` file.
- Optional caps for sampling (`--per-flow-cap`, default 100) so large dumps stay tractable.

## How to run

1. Confirm tooling. Do NOT auto-install anything; tell the user what to install if missing:
   - `which tshark` — required (the wireshark CLI; provides packet dissection).
   - `python -c 'import pyshark'` — required (pip package `pyshark`).
   If either is missing, stop and tell the user the exact install hint (e.g. `apt install tshark` and `pip install pyshark`).

2. Run the analyzer:
   ```
   python .claude/skills/pcap-hardening-advisor/scripts/analyze_pcap.py <pcap-path> [--per-flow-cap 100]
   ```
   The script prints a single JSON object to stdout with shape:
   ```
   {
     "stats": {...},
     "findings": [{"id","severity","title","detail","evidence"}],
     "sysctl_overrides": [{"key","value","category","evidence"}],
     "ufw_rules": [{"action","port","proto","source","reason"}]
   }
   ```

3. Render results to the user in this order:
   1. **Findings**, sorted by severity (high → low). One line per finding plus the evidence excerpt.
   2. **Security sysctl overlay** — fenced YAML block containing only entries with `category` in {`security`, `both`}. Format the block as a `sysctl_config:` mapping ready to drop into `group_vars/`.
   3. **Performance sysctl overlay** — fenced YAML block containing only entries with `category` in {`performance`, `both`}. Same format.
   4. **UFW commands** — fenced bash block with one `ufw` command per rule.

4. For every override, cross-reference the line in `roles/os_hardening/defaults/main.yml`. Use `reference/sysctl_mapping.md` for the table. If a key is NOT in current defaults, call it out as an **addition**, not an override.

## Hard rules

- Never edit files under `roles/`. The skill's output is always advisory.
- Never recommend `net.ipv4.tcp_tw_recycle` — it was removed from the kernel and breaks NAT.
- If the analyzer fails or returns empty findings, say so plainly. Do not invent results.
- Treat IPs and hostnames in evidence as potentially sensitive — warn the user before quoting them into a PR description.

## Files in this skill

- `scripts/analyze_pcap.py` — CLI; streams the pcap, samples per flow, runs heuristics.
- `scripts/heuristics.py` — pure functions producing overrides + findings; unit-testable.
- `reference/sysctl_mapping.md` — heuristic → variable mapping, with file:line refs.
- `reference/ufw_rule_patterns.md` — UFW synthesis patterns.
- `templates/overlay.yml.example` — sample of the YAML overlay shape.
- `tests/fixtures/` — drop synthetic pcaps here for smoke tests.
