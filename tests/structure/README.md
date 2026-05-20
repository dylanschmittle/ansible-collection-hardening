# Structural test suite

Fast, syntactic checks that complement the per-role
[molecule](https://ansible.readthedocs.io/projects/molecule/) suites. They
catch the kind of mistakes that don't otherwise surface until a galaxy
build or a full molecule run: missing required `galaxy.yml` keys, an
unparseable `meta/runtime.yml`, a role whose `argument_specs.yml` lost its
`main` entry, a top-level doc that got deleted in a refactor, and so on.

This suite **does not** run any Ansible tasks against a target host;
behavioural coverage stays in molecule.

## Running locally

From the repository root:

```sh
python -m pip install -r tests/structure/requirements.txt
python -m pytest tests/structure -v
```

## What it checks

- `test_collection.py`
  - Required top-level files exist and are non-empty (`README.md`,
    `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
    `CHANGELOG.md`, `galaxy.yml`, `.gitignore`, `.editorconfig`).
  - `galaxy.yml` parses, has the required keys, the expected namespace /
    name, a semver-like version, an Apache-2.0 license, the expected
    dependencies, and excludes `tests/` from `build_ignore` so this suite
    is not shipped to Galaxy.
  - `meta/runtime.yml` pins a minimum Ansible version.
- `test_roles.py`
  - Each active role (`os_hardening`, `ssh_hardening`, `mysql_hardening`,
    `nginx_hardening`) has the standard Ansible layout (`README.md`,
    `defaults/main.yml`, `tasks/main.yml`, `handlers/main.yml`,
    `meta/main.yml`, `meta/argument_specs.yml`) and that those YAML files
    parse.
  - Each role's `argument_specs.yml` exposes a `main` entry with
    non-empty `options`, and every option carries a `description`.
  - The in-development roles (`apache_hardening`, `windows_hardening`)
    are declared in `.gitmodules` and point at the archived standalone
    repositories — a missing submodule entry would silently turn the
    directory into an untracked empty path on fresh clones.

## CI

Runs on every push and pull request via
[`.github/workflows/structure-tests.yml`](../../.github/workflows/structure-tests.yml).
