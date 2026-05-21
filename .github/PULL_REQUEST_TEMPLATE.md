<!--
Thanks for contributing to devsec.hardening!

Please fill in the sections below. Delete anything that doesn't apply.
-->

## Summary

<!-- One-paragraph description. What does this PR do and why? -->

## Type

<!-- Pick one and delete the rest. -->

- [ ] bug fix (non-breaking change which fixes an issue)
- [ ] new feature (non-breaking change which adds functionality)
- [ ] breaking change (fix or feature that would cause existing playbooks
      to behave differently)
- [ ] documentation, CI, or other non-user-facing change

## Affected roles

<!-- Tick all that apply. -->

- [ ] os_hardening
- [ ] ssh_hardening
- [ ] mysql_hardening
- [ ] nginx_hardening
- [ ] collection-wide / none

## Linked issue

<!-- Closes #123 / Refs #123, or "none". -->

## Checklist

- [ ] I signed off the commits (`git commit -s`).
- [ ] I added a changelog fragment under `changelogs/fragments/` (or
      used `trivial:` for docs/CI-only PRs).
- [ ] I updated `meta/argument_specs.yml` if I added or renamed a role
      variable.
- [ ] I added or updated tests where relevant.
- [ ] Local tests pass (`molecule test -s <scenario>` for behavioural
      changes; `python -m pytest tests/structure -v` for structural).
