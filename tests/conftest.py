"""Shared pytest fixtures for DevSecret tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_vault(tmp_path: Path) -> Path:
    return tmp_path / "vault.enc"
