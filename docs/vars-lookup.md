# Per-OS variable lookup convention

Roles that need to vary defaults across operating systems load them via a
single `with_first_found` block in `tasks/hardening.yml` (or
`tasks/main.yml`), consulting four candidate files in order of
specificity:

```yaml
- name: Fetch OS dependent variables
  ansible.builtin.include_vars:
    file: "{{ item }}"
    name: os_vars
  with_first_found:
    - files:
        - "{{ ansible_facts.distribution }}_{{ ansible_facts.distribution_major_version }}.yml"  # e.g. RedHat_9.yml
        - "{{ ansible_facts.distribution }}.yml"                                                  # e.g. RedHat.yml
        - "{{ ansible_facts.os_family }}_{{ ansible_facts.distribution_major_version }}.yml"      # e.g. Debian_12.yml
        - "{{ ansible_facts.os_family }}.yml"                                                     # e.g. Debian.yml
      skip: true
  tags: always
```

| Order | File | Use when |
| --- | --- | --- |
| 1 | `<Distribution>_<major>.yml` | A single distribution major version needs different defaults (RHEL 9 cryptopolicies, Fedora 37 nftables). |
| 2 | `<Distribution>.yml` | All majors of one distribution share the same overrides. |
| 3 | `<os_family>_<major>.yml` | Rare; one os_family major (e.g. `Debian_12.yml`) needs an override. |
| 4 | `<os_family>.yml` | Catch-all for the whole family (`RedHat`, `Debian`, `Suse`, ...). |

When none of the four files exists, the role falls back to the defaults
in `roles/<role>/defaults/main.yml`. `skip: true` keeps the play from
failing on platforms with no overrides.

## When to add a new file

Only add a per-distribution-major file (`vars/RedHat_10.yml`,
`vars/Fedora_41.yml`) when the *behaviour* genuinely diverges — most
hardening defaults are the same across a vendor's clones. Resist the
temptation to ship one file per `os_family` × major combination just to
match the upstream RHEL-system-roles pattern; that organisation makes
sense when each clone (`AlmaLinux`, `Rocky`, `CentOS Stream`) needs
distinct settings, which is rarely the case here.

## Roles that follow this convention

| Role | `vars/` files |
| --- | --- |
| `os_hardening` | `Alpine.yml`, `Archlinux.yml`, `Debian.yml`, `Fedora.yml`, `RedHat.yml`, `Suse.yml`, `Amazon_2.yml`, `main.yml` |
| `ssh_hardening` | `Alpine.yml`, `Amazon_2.yml`, `Archlinux.yml`, `Debian.yml`, `Fedora.yml`, `Fedora_37.yml`, `FreeBSD.yml`, `OpenBSD.yml`, `RedHat.yml`, `RedHat_9.yml`, `SmartOS.yml`, `Suse.yml`, `main.yml` |
| `mysql_hardening` | `Debian.yml`, `RedHat.yml`, `Suse.yml`, `main.yml` |

`nginx_hardening` does not vary defaults across operating systems and
therefore has no `vars/` directory.

## Test coverage

[`tests/structure/test_roles.py`](../tests/structure/test_roles.py)
asserts that each role that ships a `vars/` directory loads it via the
four-file `with_first_found` chain above. A role that quietly drops one
of the four lookup levels — easy to do during a refactor — would let
per-distribution overrides silently stop applying, so the test guards
against that regression.
