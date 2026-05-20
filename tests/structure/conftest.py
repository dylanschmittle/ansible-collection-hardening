"""Shared fixtures for the structural test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

ACTIVE_ROLES = (
    "os_hardening",
    "ssh_hardening",
    "mysql_hardening",
    "nginx_hardening",
)

SUBMODULE_ROLES = {
    "apache_hardening": "https://github.com/dev-sec/ansible-apache-hardening/",
    "windows_hardening": "https://github.com/dev-sec/ansible-windows-hardening/",
}


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def roles_dir(repo_root: Path) -> Path:
    return repo_root / "roles"
