---
name: journal-hardening-advisor
description: Analyze a systemd journal (export, `journalctl -o json` output, or live journal file) and suggest devsec.hardening overrides for os_hardening / ssh_hardening (security + performance), UFW rate-limit rules, and a security-event findings report. Use when the user provides a `.journal` file, a journalctl JSON-lines export, asks to derive hardening or tuning from logs, or asks to harden via journal/auth.log.
---

# journal-hardening-advisor

Turn a systemd journal into concrete Ansible variable overrides for the `devsec.hardening` collection plus UFW rate-limit rules. Splits **security** and **performance** suggestions into separate overlays.

## Inputs you accept

- A path to a `journalctl -o json` JSON-lines file (one entry per line).
- A path to a raw journal file (`.journal`, `.journal~`, or anything under `/var/log/journal/`) — the script will shell out to `journalctl --file=<path> -o json`.
- `-` to read JSON lines from stdin (e.g. `journalctl -o json --since "1 day ago" | ... -`).

## How to run

1. Confirm tooling. The script uses only the Python stdlib. The only external requirement is `journalctl` — and only when the input is a raw journal file (not needed for JSON-lines input).
   - For JSON-lines input: no system deps.
   - For a journal file: `which journalctl`.
2. Run the analyzer:
   ```
   python .claude/skills/journal-hardening-advisor/scripts/analyze_journal.py <path-or-->  [--per-class-cap 50]
   ```
   The script prints one JSON object to stdout:
   ```
   {
     "stats": {...},
     "findings": [...],
     "sysctl_overrides": [{"key","value","category","evidence"}],
     "ssh_overrides":    [{"key","value","category","evidence"}],
     "ufw_rules":        [{"action","port","proto","source","reason"}],
     "journald_advisories": [{"file","setting","value","evidence"}]
   }
   ```

3. Render results to the user in this order:
   1. **Findings** sorted by severity (high → low) — one line per finding plus an evidence excerpt.
   2. **Security overlay** — single fenced YAML block containing every override (sysctl + ssh) with `category` in {`security`, `both`}.
   3. **Performance overlay** — fenced YAML block with overrides whose `category` is in {`performance`, `both`}, plus any `journald_advisories` rendered as a drop-in file under `/etc/systemd/journald.conf.d/`.
   4. **UFW commands** — fenced bash block.

4. For each override, cross-reference the file:line in `roles/os_hardening/defaults/main.yml` or `roles/ssh_hardening/defaults/main.yml`. Use `reference/event_to_variable.md` for the table.

## Hard rules

- Never edit files under `roles/`. Output is advisory only.
- Never auto-pull journals from remote hosts; the skill reads local files or stdin.
- If the user is on a live host and intent is clear, suggest the `journalctl -o json --since ...` command but **do not run it without confirmation** — journal queries can be slow on busy hosts and may include sensitive data.
- IPs/usernames in evidence are sensitive: warn the user before quoting them into a PR or commit message.

## Files in this skill

- `scripts/analyze_journal.py` — CLI; dispatches input type, classifies entries, runs heuristics.
- `scripts/classifiers.py` — regex table mapping SYSLOG_IDENTIFIER + MESSAGE to event classes.
- `scripts/heuristics.py` — event-class counters → overrides + findings.
- `reference/event_to_variable.md` — event class → role variable mapping with line refs.
- `reference/sampling_strategy.md` — describes the per-class reservoir sampling + top-N source tracking.
- `templates/overlay.yml.example` — sample output overlay.
- `tests/fixtures/` — drop synthetic JSONL fixtures here for smoke tests.
