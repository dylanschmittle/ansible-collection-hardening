"""Top-level collection sanity checks.

These are fast, syntactic checks that complement the per-role molecule
suites. They run on every PR via .github/workflows/structure-tests.yml and
catch the kind of mistakes that don't surface until a galaxy build or a
molecule run: missing required galaxy.yml keys, an unparsable
meta/runtime.yml, a deleted top-level doc, and so on.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REQUIRED_GALAXY_KEYS = (
    "namespace",
    "name",
    "version",
    "readme",
    "authors",
    "description",
    "license",
    "tags",
    "dependencies",
    "repository",
)

REQUIRED_TOP_LEVEL_FILES = (
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "galaxy.yml",
    ".gitignore",
    ".editorconfig",
)


@pytest.fixture(scope="module")
def galaxy(repo_root: Path) -> dict:
    return yaml.safe_load((repo_root / "galaxy.yml").read_text())


@pytest.fixture(scope="module")
def runtime(repo_root: Path) -> dict:
    return yaml.safe_load((repo_root / "meta" / "runtime.yml").read_text())


@pytest.mark.parametrize("filename", REQUIRED_TOP_LEVEL_FILES)
def test_required_top_level_file_present(repo_root: Path, filename: str) -> None:
    path = repo_root / filename
    assert path.is_file(), f"missing required top-level file: {filename}"
    assert path.stat().st_size > 0, f"{filename} is empty"


@pytest.mark.parametrize("key", REQUIRED_GALAXY_KEYS)
def test_galaxy_yml_has_required_key(galaxy: dict, key: str) -> None:
    assert key in galaxy, f"galaxy.yml missing required key: {key}"
    assert galaxy[key], f"galaxy.yml key {key} is empty"


def test_galaxy_namespace_and_name(galaxy: dict) -> None:
    assert galaxy["namespace"] == "devsec"
    assert galaxy["name"] == "hardening"


def test_galaxy_version_is_semver_like(galaxy: dict) -> None:
    version = str(galaxy["version"])
    parts = version.split(".")
    assert len(parts) == 3, f"version {version!r} is not MAJOR.MINOR.PATCH"
    for part in parts:
        assert part.isdigit(), f"version component {part!r} is not numeric"


def test_galaxy_license_is_apache(galaxy: dict) -> None:
    licenses = galaxy["license"]
    assert "Apache-2.0" in licenses


def test_galaxy_dependencies_listed(galaxy: dict) -> None:
    deps = galaxy["dependencies"]
    for required in ("ansible.posix", "community.general"):
        assert required in deps, f"galaxy.yml missing dependency: {required}"


def test_galaxy_build_ignore_excludes_tests(galaxy: dict) -> None:
    """tests/ must be in build_ignore so this suite is not shipped to Galaxy."""

    assert "tests" in galaxy.get("build_ignore", []), (
        "tests/ must be listed in galaxy.yml build_ignore to keep the "
        "structural test suite out of the published collection"
    )


def test_runtime_requires_ansible(runtime: dict) -> None:
    assert "requires_ansible" in runtime
    assert runtime["requires_ansible"].startswith(">="), (
        "requires_ansible should pin a minimum version, got "
        f"{runtime['requires_ansible']!r}"
    )
