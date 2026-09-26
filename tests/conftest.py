"""Pytest configuration and shared fixtures."""

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from schlock.core import validator
from schlock.core.cache import ValidationCache
from schlock.core.parser import BashCommandParser
from schlock.core.validator import clear_caches


@pytest.fixture
def no_shellcheck(monkeypatch):
    """Pin verdicts to schlock's rule and AST engine."""
    monkeypatch.setattr(validator, "is_shellcheck_available", lambda: False)
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def clean_worktree():
    """Report a clean tree to the hard-reset guard.

    That guard (validator.py) shells out to `git status --porcelain` and escalates
    to BLOCKED on a dirty tree, which would mask the rule-driven verdict a test is
    about. It is keyed on cwd, so without this the verdict depends on the checkout.
    """
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    with patch("subprocess.run", return_value=result):
        yield


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
