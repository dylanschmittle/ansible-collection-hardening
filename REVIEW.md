# Repository Review: devsec.hardening

This document is a snapshot review of the `dev-sec/ansible-collection-hardening`
repository (the `devsec.hardening` Ansible Collection). It is intended as an
orientation aid for new contributors and as the rationale for a follow-up
"polish" pull request.

## 1. Purpose

The collection bundles four production roles that apply opinionated, battle-
tested hardening to common server components, aligned with the
[DevSec Inspec baselines](https://dev-sec.io/baselines/):

| Baseline | Role | Role README |
| --- | --- | --- |
| linux-baseline | `os_hardening` | [roles/os_hardening/README.md](roles/os_hardening/README.md) |
| ssh-baseline | `ssh_hardening` | [roles/ssh_hardening/README.md](roles/ssh_hardening/README.md) |
| mysql-baseline | `mysql_hardening` | [roles/mysql_hardening/README.md](roles/mysql_hardening/README.md) |
| nginx-baseline | `nginx_hardening` | [roles/nginx_hardening/README.md](roles/nginx_hardening/README.md) |

Two additional role slots are reserved but currently empty placeholders:
`apache_hardening` and `windows_hardening`. The standalone archives for these
are still linked from the top-level README.

## 2. Metadata

- **Namespace / name / version:** `devsec.hardening` 10.1.0 (`galaxy.yml`).
- **License:** Apache-2.0.
- **Minimum Ansible:** 2.9.10 (`meta/runtime.yml`).
- **Dependencies:** `ansible.posix`, `community.crypto`, `community.general`,
  `community.mysql`.
- **Supported targets** (from README):
  - Linux: CentOS 9, Rocky 8/9, Debian 11/12, Ubuntu 20.04/22.04/24.04;
    partial: Amazon Linux, Arch, Fedora 39/40, openSUSE Tumbleweed.
  - MariaDB ≥ 5.5.65 / 10.1.45 / 10.3.17; MySQL ≥ 5.7.31 / 8.0.3.
  - Nginx ≥ 1.0.16.
  - OpenSSH ≥ 5.3.

## 3. Role inventory

| Role | README | Defaults (lines) | Notes |
| --- | :---: | ---: | --- |
| `os_hardening` | yes | ~501 | Largest role; sysctl, PAM, auditd, modules, suid/sgid, etc. |
| `ssh_hardening` | yes | ~228 | Linux + BSD support; multiple templates. |
| `mysql_hardening` | yes | ~51 | MariaDB + MySQL flavours. |
| `nginx_hardening` | yes | ~33 | Headers, TLS, modules. Defaults are sparsely commented. |
| `apache_hardening` | **no** | — | Empty placeholder. |
| `windows_hardening` | **no** | — | Empty placeholder. |

Each active role has an `argument_specs.yml` (auto-rendered into the README
via the `roles-readme` workflow using
[`aar-doc`](https://github.com/ansible-network/aar-doc)).

## 4. CI & quality gates

GitHub Actions workflows under `.github/workflows/`:

- **Per-role molecule tests** — `os_hardening`, `os_hardening_vm`,
  `ssh_hardening`, `ssh_hardening_bsd`, `ssh_hardening_custom_tests`,
  `mysql_hardening`, `nginx_hardening`.
- **Static checks** — `ansible-lint`, `codespell`, `prettier-md`,
  `roles-readme` (regenerates role READMEs from `argument_specs.yml`).
- **Release** — `galaxy-publish`, `release`, `enforce-labels`.

Molecule scenarios mirror the role test workflows under `molecule/`.

## 5. Contributor experience

- `CONTRIBUTING.md` covers DCO sign-off, branch flow, and how to run molecule.
- Bug-report and feature-request issue templates are present
  (`.github/ISSUE_TEMPLATE/`).
- Renovate keeps dependencies fresh (`renovate.json`).
- Two changelogs live in the tree: `CHANGELOG.md` (collection) and
  `OS_HARDENING_CHANGELOG.md` (legacy standalone role history).

## 6. Observations & improvement candidates

The repository is in a healthy state; nothing below is a blocker. These are
small, non-behavioural polish items suited to a follow-up PR. Anything that
would change what the roles *do* on a target host is intentionally out of
scope.

1. **`SECURITY.md` is missing.** GitHub surfaces a security-policy banner when
   this file is present, and a security-focused collection benefits from a
   clear vulnerability-disclosure channel.
2. **`CODE_OF_CONDUCT.md` is only referenced externally.** Adopting the
   Contributor Covenant in-tree matches the rest of the Ansible ecosystem.
3. **`.editorconfig` is absent.** A minimal file (YAML 2-space, LF, trim
   trailing whitespace) prevents drift across editors.
4. **`.gitignore` is short** (4 lines) and misses common Python / editor
   artefacts (`venv/`, `__pycache__/`, `*.swp`, `.idea/`, `.vscode/`,
   `.DS_Store`, `*.retry`, etc.).
5. **Placeholder roles have no README.** `roles/apache_hardening/` and
   `roles/windows_hardening/` are empty directories; a one-paragraph README
   noting their status and linking to the archived standalone repositories
   would help users who land there directly.
6. **Top-level README has no end-to-end example.** Section *Using this
   collection* (line 75) says "refer to the readmes of the role" but does not
   show a single playbook composing the four roles.
7. **`galaxy.yml` description is terse** (≈80 characters). A slightly longer
   description that mentions the DevSec baselines improves Galaxy search
   results.

A second PR implements items 1-5 (and a small description tweak for item 7)
without touching any role tasks or defaults.

## 7. Files of interest for new contributors

- `galaxy.yml` — collection metadata, dependencies, build ignores.
- `meta/runtime.yml` — minimum Ansible version and routing.
- `roles/<role>/argument_specs.yml` — source of truth for each role's
  variables; README sections are generated from these.
- `roles/<role>/defaults/main.yml` — default values for the spec above.
- `molecule/<scenario>/` — local reproduction of CI test runs.
- `.github/workflows/` — CI definitions; mirror what runs on PRs.
