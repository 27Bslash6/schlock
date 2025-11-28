"""Pytest configuration and shared fixtures."""

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
    """Path to safety_rules.yaml configuration file.

    DEPRECATED: Use rules_dir_path for new tests.
    This loads from the single file, not the rules directory.
    """
    return str(data_dir / "safety_rules.yaml")


@pytest.fixture
def rules_dir_path(data_dir):
    """Path to data/rules/ directory with organized rule files.

    Use this for tests that need the full rule set from the
    organized rules directory (11_dynamic_linker.yaml, etc.)
    """
    return str(data_dir / "rules")


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
