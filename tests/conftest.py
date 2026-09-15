"""Pytest configuration and shared fixtures."""

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from schlock.core.cache import ValidationCache
from schlock.core.parser import BashCommandParser


@pytest.fixture
def plugin_root():
    """Path to plugin root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def data_dir(plugin_root):
    """Path to data/ directory with configuration files."""
    return plugin_root / "data"


@pytest.fixture
def safety_rules_path(data_dir):
    """Path to rules directory for validation tests.

    Points to data/rules/ directory containing the canonical rule set.
    The validator's load_rules() detects directories and loads appropriately.
    """
    return str(data_dir / "rules")


@pytest.fixture
def rules_dir_path(safety_rules_path):
    """Alias for safety_rules_path for clarity in tests."""
    return safety_rules_path


@pytest.fixture
def parser():
    """BashCommandParser instance for testing."""
    return BashCommandParser()


@pytest.fixture
def cache():
    """ValidationCache instance with reasonable defaults."""
    return ValidationCache(max_size=10)


@dataclass
class MockResult:
    """Mock validation result for cache testing."""

    value: str


@pytest.fixture
def mock_result():
    """Factory fixture for creating MockResult instances."""

    def _create(value="test"):
        return MockResult(value)

    return _create


@pytest.fixture
def fake_binary(tmp_path):
    """Factory: write an executable stand-in for `schlock-parse` that runs `body` (Python source).

    Shared by the bridge tests and the tier state-machine tests so each spec §6
    failure row can be scripted (exit codes, hangs, garbage output) without
    the real vendored binary.
    """

    def _make(body: str) -> Path:
        script = tmp_path / "fake-schlock-parse"
        script.write_text("#!/usr/bin/env python3\nimport sys\n" + body, encoding="utf-8")
        script.chmod(0o755)
        return script

    return _make


@pytest.fixture
def spawned(monkeypatch):
    """Record every `subprocess.Popen` the code under test creates.

    Lets a test assert spawn count and that a killed child was reaped
    (`returncode is not None`) without re-implementing the shim.
    """
    procs = []
    real_popen = subprocess.Popen

    def recording(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        procs.append(proc)
        return proc

    monkeypatch.setattr(subprocess, "Popen", recording)
    return procs
