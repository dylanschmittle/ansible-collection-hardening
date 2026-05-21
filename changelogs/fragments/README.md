# Changelog fragments

Per-pull-request changelog entries rendered into `CHANGELOG.md` by
[antsibull-changelog](https://docs.ansible.com/projects/antsibull-changelog/).

## Adding a fragment

Create a YAML file in this directory named after your PR or topic:

```yaml
# changelogs/fragments/<short-slug>.yml
---
minor_changes:
  - >-
    ssh_hardening - add a new ``ssh_strict_host_key_checking`` variable
    (https://github.com/dev-sec/ansible-collection-hardening/pull/123).
bugfixes:
  - >-
    os_hardening - fix sysctl reload on systemd-free systems
    (https://github.com/dev-sec/ansible-collection-hardening/pull/124).
```

## Allowed sections

| Section | Use for |
| --- | --- |
| `release_summary` | One-paragraph summary, one per release; usually only set by maintainers at release time. |
| `major_changes` | User-visible behavioural changes that warrant a major-version bump. |
| `minor_changes` | New options, new tasks, expanded platform support. |
| `breaking_changes` | Removed options, renamed variables, default flips that break existing playbooks. |
| `deprecated_features` | Options marked deprecated but still functional. |
| `removed_features` | Previously deprecated options now gone. |
| `security_fixes` | Fixes for issues with security impact. |
| `bugfixes` | Fixes that don't qualify as `security_fixes`. |
| `known_issues` | Bugs the release ships with. |
| `trivial` | Doc / typo / CI fixes — collapsed and not rendered. Use this to satisfy the changelog-fragment CI check for non-user-facing PRs. |

## Style

- Each entry is a single sentence ending in a period.
- Prefix with `<role_name> -` (e.g. `ssh_hardening -`) when the change
  scopes to one role.
- End with a PR link in parentheses.
- Wrap lines around 80 columns. YAML `>-` block scalars handle the
  wrapping cleanly.

## Rendering locally

```sh
python -m pip install antsibull-changelog
antsibull-changelog lint        # validate fragments parse
antsibull-changelog generate    # only at release time
```

The repository's history before the introduction of fragments lives in
[`../CHANGELOG.md`](../CHANGELOG.md) (collection) and
[`../OS_HARDENING_CHANGELOG.md`](../OS_HARDENING_CHANGELOG.md) (legacy
standalone role) — those files stay as historical archives.
