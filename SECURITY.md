# Security Policy

The `devsec.hardening` collection is itself a security tool: it changes
system configuration to reduce attack surface. We take vulnerabilities in
the collection — and in the defaults it ships — seriously.

## Supported versions

Security fixes are applied to the latest release line on the `master`
branch. Earlier major versions are not maintained; users should track the
most recent release published to
[Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/devsec/hardening/).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Instead, report privately via one of:

1. **GitHub private vulnerability reporting** — preferred. Use the
   *Security → Report a vulnerability* form on the repository.
2. **Email** — `hello@dev-sec.io` with subject `SECURITY:
   ansible-collection-hardening`.

When reporting, please include:

- The collection version (`galaxy.yml` / `ansible-galaxy collection list`).
- The affected role(s) and platform(s).
- A minimal reproduction (playbook snippet or molecule scenario) and the
  observed vs. expected behaviour.
- Any known mitigations or workarounds.

We will acknowledge receipt within 7 days and aim to provide an initial
assessment within 14 days. Coordinated disclosure timelines are agreed on
a case-by-case basis depending on severity and affected platforms.

## Scope

In scope:

- Bugs in this collection that weaken, bypass, or disable the hardening it
  is supposed to apply.
- Defaults shipped by the collection that fail to meet the corresponding
  DevSec Inspec baseline on a supported platform.
- Tasks that introduce a regression on a supported platform.

Out of scope:

- Upstream OS, OpenSSH, MySQL/MariaDB, or Nginx vulnerabilities — please
  report those to the respective projects.
- Vulnerabilities in unsupported platforms or end-of-life software
  versions.
- Findings produced by a static scanner without a concrete impact path.

## Disclosure

After a fix is released, we publish details in `CHANGELOG.md` and, where
relevant, in the GitHub Security Advisories tab. Reporters are credited
unless they request otherwise.
