"""Per-role structural sanity checks.

For each active role we assert the standard Ansible layout (defaults,
tasks, handlers, meta) plus an argument_specs.yml whose options each carry
a description. For placeholder roles we only require a README that flags
its placeholder status, so contributors landing in the directory directly
are not misled.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conftest import ACTIVE_ROLES, SUBMODULE_ROLES

REQUIRED_ROLE_FILES = (
    "README.md",
    "defaults/main.yml",
    "tasks/main.yml",
    "handlers/main.yml",
    "meta/main.yml",
    "meta/argument_specs.yml",
)


def _load_yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text())


@pytest.mark.parametrize("role", ACTIVE_ROLES)
@pytest.mark.parametrize("relpath", REQUIRED_ROLE_FILES)
def test_active_role_has_required_file(
    roles_dir: Path, role: str, relpath: str
) -> None:
    path = roles_dir / role / relpath
    assert path.is_file(), f"roles/{role}/{relpath} is missing"
    assert path.stat().st_size > 0, f"roles/{role}/{relpath} is empty"


@pytest.mark.parametrize("role", ACTIVE_ROLES)
@pytest.mark.parametrize(
    "relpath",
    ("defaults/main.yml", "tasks/main.yml", "meta/main.yml", "meta/argument_specs.yml"),
)
def test_active_role_yaml_parses(
    roles_dir: Path, role: str, relpath: str
) -> None:
    path = roles_dir / role / relpath
    try:
        _load_yaml(path)
    except yaml.YAMLError as exc:
        pytest.fail(f"roles/{role}/{relpath} is not valid YAML: {exc}")


@pytest.mark.parametrize("role", ACTIVE_ROLES)
def test_active_role_argument_specs_shape(roles_dir: Path, role: str) -> None:
    spec = _load_yaml(roles_dir / role / "meta" / "argument_specs.yml")
    assert isinstance(spec, dict)
    assert "argument_specs" in spec, f"{role}: missing top-level argument_specs"
    main = spec["argument_specs"].get("main")
    assert main is not None, f"{role}: argument_specs is missing the 'main' entry"
    assert isinstance(main.get("options"), dict), (
        f"{role}: argument_specs.main.options must be a mapping"
    )
    assert main["options"], f"{role}: argument_specs.main.options is empty"


@pytest.mark.parametrize("role", ACTIVE_ROLES)
def test_active_role_argument_specs_options_have_descriptions(
    roles_dir: Path, role: str
) -> None:
    spec = _load_yaml(roles_dir / role / "meta" / "argument_specs.yml")
    options = spec["argument_specs"]["main"]["options"]
    missing = sorted(
        name
        for name, opt in options.items()
        if not isinstance(opt, dict) or not opt.get("description")
    )
    assert not missing, (
        f"{role}: argument_specs options without a description: {missing}"
    )


VARS_LOOKUP_CHAIN = (
    "{{ ansible_facts.distribution }}_{{ ansible_facts.distribution_major_version",
    "{{ ansible_facts.distribution }}.yml",
    "{{ ansible_facts.os_family }}_{{ ansible_facts.distribution_major_version",
    "{{ ansible_facts.os_family }}.yml",
)


@pytest.mark.parametrize("role", ACTIVE_ROLES)
def test_per_os_vars_lookup_chain(roles_dir: Path, role: str) -> None:
    """Roles that ship a vars/ directory must load it via the four-file
    with_first_found chain documented in docs/vars-lookup.md.

    Dropping one of the four levels (easy to do during a refactor) would
    let per-distribution overrides silently stop applying."""

    vars_dir = roles_dir / role / "vars"
    if not vars_dir.is_dir():
        pytest.skip(f"{role} has no vars/ directory")

    tasks_text = "\n".join(
        p.read_text() for p in (roles_dir / role / "tasks").glob("*.yml")
    )
    for needle in VARS_LOOKUP_CHAIN:
        assert needle in tasks_text, (
            f"{role}: tasks/ does not reference the lookup level "
            f"{needle!r}; see docs/vars-lookup.md"
        )


@pytest.mark.parametrize("role,expected_url", list(SUBMODULE_ROLES.items()))
def test_submodule_role_declared_in_gitmodules(
    repo_root: Path, role: str, expected_url: str
) -> None:
    """The two in-development roles are git submodules pointing at the
    archived standalone repositories. Verify the .gitmodules entries are
    intact — a missing entry would silently turn the directory into an
    untracked empty path on fresh clones."""

    gitmodules = (repo_root / ".gitmodules").read_text()
    expected_path = f"path = roles/{role}"
    expected_url_line = f"url = {expected_url}"
    assert expected_path in gitmodules, (
        f".gitmodules is missing path entry for roles/{role}"
    )
    assert expected_url_line in gitmodules, (
        f".gitmodules entry for roles/{role} does not point at {expected_url}"
    )
