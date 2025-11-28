"""Tests for configuration writer module."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from schlock.setup.config_writer import (
    WizardChoices,
    WriteResult,
    create_backup,
    generate_config_yaml,
    validate_config_yaml,
    write_config,
)


@pytest.fixture
def wizard_choices_enabled():
    """WizardChoices with ad blocker enabled."""
    return WizardChoices(ad_blocker_enabled=True)


@pytest.fixture
def wizard_choices_disabled():
    """WizardChoices with ad blocker disabled."""
    return WizardChoices(ad_blocker_enabled=False)


class TestWizardChoices:
    """Test suite for WizardChoices dataclass."""

    def test_wizard_choices_immutable(self, wizard_choices_enabled):
        """WizardChoices should be immutable (frozen)."""
        with pytest.raises(AttributeError):
            wizard_choices_enabled.ad_blocker_enabled = False


class TestWriteResult:
    """Test suite for WriteResult dataclass."""

    def test_write_result_immutable(self):
        """WriteResult should be immutable (frozen)."""
        result = WriteResult(
            success=True,
            config_path=Path("test.yaml"),
            backup_path=None,
            error=None,
        )
        with pytest.raises(AttributeError):
            result.success = False


class TestGenerateConfigYaml:
    """Test suite for generate_config_yaml function."""

    def test_generate_ad_blocker_enabled(self, wizard_choices_enabled):
        """Generate config with ad blocker enabled."""
        config = generate_config_yaml(wizard_choices_enabled)

        # Check structure
        assert "_metadata" in config
        assert "commit_filter" in config

        # Check metadata
        assert "generated_at" in config["_metadata"]
        assert "wizard_version" in config["_metadata"]
        assert "last_modified_by" in config["_metadata"]
        assert config["_metadata"]["wizard_version"] == "0.1.0"
        assert config["_metadata"]["last_modified_by"] == "setup-wizard"

        # Check ad blocker config
        assert config["commit_filter"]["enabled"] is True
        assert config["commit_filter"]["rules"]["advertising"]["enabled"] is True

    def test_generate_ad_blocker_disabled(self, wizard_choices_disabled):
        """Generate config with ad blocker disabled."""
        config = generate_config_yaml(wizard_choices_disabled)

        # Should only have metadata, no commit_filter
        assert "_metadata" in config
        assert "commit_filter" not in config

    def test_generate_metadata_timestamp(self, wizard_choices_enabled):
        """Generated config should have valid ISO 8601 timestamp."""
        config = generate_config_yaml(wizard_choices_enabled)

        timestamp_str = config["_metadata"]["generated_at"]
        # Should parse as valid ISO 8601
        timestamp = datetime.fromisoformat(timestamp_str)
        assert timestamp.tzinfo is not None  # Should be timezone-aware


class TestValidateConfigYaml:
    """Test suite for validate_config_yaml function."""

    def test_validate_valid_config(self, wizard_choices_enabled):
        """Valid config should have no errors."""
        config = generate_config_yaml(wizard_choices_enabled)
        errors = validate_config_yaml(config)
        assert errors == []

    def test_validate_missing_metadata(self):
        """Config missing metadata should fail validation."""
        config = {
            "commit_filter": {
                "enabled": True,
                "rules": {"advertising": {"enabled": True}},
            }
        }
        errors = validate_config_yaml(config)
        assert "Missing required _metadata section" in errors

    def test_validate_missing_metadata_fields(self):
        """Config with incomplete metadata should fail validation."""
        config = {
            "_metadata": {"generated_at": "2025-01-07T12:00:00Z"},
            "commit_filter": {
                "enabled": True,
                "rules": {"advertising": {"enabled": True}},
            },
        }
        errors = validate_config_yaml(config)
        assert any("wizard_version" in e for e in errors)
        assert any("last_modified_by" in e for e in errors)

    def test_validate_no_commit_filter(self):
        """Config without commit_filter should fail."""
        config = {
            "_metadata": {
                "generated_at": "2025-01-07T12:00:00Z",
                "wizard_version": "0.1.0",
                "last_modified_by": "setup-wizard",
            }
        }
        errors = validate_config_yaml(config)
        assert "commit_filter must be present" in errors

    def test_validate_invalid_boolean(self):
        """Config with non-boolean enabled flag should fail."""
        config = {
            "_metadata": {
                "generated_at": "2025-01-07T12:00:00Z",
                "wizard_version": "0.1.0",
                "last_modified_by": "setup-wizard",
            },
            "commit_filter": {
                "enabled": "yes",  # Should be bool
                "rules": {"advertising": {"enabled": True}},
            },
        }
        errors = validate_config_yaml(config)
        assert any("boolean" in e.lower() for e in errors)


class TestCreateBackup:
    """Test suite for create_backup function."""

    def test_create_backup_success(self):
        """Create backup of existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("original content", encoding="utf-8")

            backup_path = create_backup(config_path)

            assert backup_path is not None
            assert backup_path.exists()
            assert backup_path.read_text(encoding="utf-8") == "original content"
            assert backup_path.name.startswith("config.yaml.backup.")

    def test_create_backup_nonexistent_file(self):
        """Create backup of nonexistent file should return None."""
        backup_path = create_backup(Path("/nonexistent/file.yaml"))
        assert backup_path is None

    def test_create_backup_timestamp_format(self):
        """Backup filename should have correct timestamp format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("content", encoding="utf-8")

            backup_path = create_backup(config_path)

            assert backup_path is not None
            # Format: config.yaml.backup.YYYYMMDD_HHMMSS  # noqa: ERA001
            timestamp_part = backup_path.name.split(".")[-1]
            assert len(timestamp_part) == 15  # YYYYMMDD_HHMMSS
            assert "_" in timestamp_part


class TestWriteConfig:
    """Test suite for write_config function."""

    def test_write_config_success(self, wizard_choices_enabled):
        """Write config file successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            result = write_config(wizard_choices_enabled, config_path, create_backup_flag=False)

            assert result.success is True
            assert result.config_path == config_path
            assert result.backup_path is None
            assert result.error is None
            assert result.validation_errors == []
            assert config_path.exists()

    def test_write_config_creates_directory(self, wizard_choices_enabled):
        """Write config should create parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "nested" / "dir" / "config.yaml"

            result = write_config(wizard_choices_enabled, config_path, create_backup_flag=False)

            assert result.success is True
            assert config_path.parent.exists()
            assert config_path.exists()

    def test_write_config_with_backup(self, wizard_choices_enabled):
        """Write config should create backup of existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("old content", encoding="utf-8")

            result = write_config(wizard_choices_enabled, config_path, create_backup_flag=True)

            assert result.success is True
            assert result.backup_path is not None
            assert result.backup_path.exists()
            assert result.backup_path.read_text(encoding="utf-8") == "old content"

    def test_write_config_without_backup(self, wizard_choices_enabled):
        """Write config without backup flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("old content", encoding="utf-8")

            result = write_config(wizard_choices_enabled, config_path, create_backup_flag=False)

            assert result.success is True
            assert result.backup_path is None

    def test_write_config_validation_failure(self):
        """Write config with invalid choices should fail validation."""
        # Ad blocker disabled = no features enabled = validation error
        choices = WizardChoices(ad_blocker_enabled=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            result = write_config(choices, config_path)

            assert result.success is False
            assert "commit_filter must be present" in result.validation_errors

    def test_write_config_atomic_write(self, wizard_choices_enabled):
        """Write config should be atomic (no partial writes on failure)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            # Mock yaml.dump to fail
            with patch("schlock.setup.config_writer.yaml.dump", side_effect=yaml.YAMLError("test error")):
                result = write_config(wizard_choices_enabled, config_path)

                assert result.success is False
                assert not config_path.exists()  # No partial file left behind
                # Temp file should be cleaned up
                temp_files = list(Path(tmpdir).glob("*.tmp"))
                assert len(temp_files) == 0

    def test_write_config_file_permissions(self, wizard_choices_enabled):
        """Written config file should have correct permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            result = write_config(wizard_choices_enabled, config_path)

            assert result.success is True
            # Check file is readable
            assert config_path.stat().st_mode & 0o444  # At least r--r--r--

    def test_write_config_idempotent(self, wizard_choices_enabled):
        """Writing same config twice should produce identical content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            # First write
            result1 = write_config(wizard_choices_enabled, config_path)
            content1 = config_path.read_text(encoding="utf-8")

            # Second write (with backup)
            result2 = write_config(wizard_choices_enabled, config_path, create_backup_flag=True)
            content2 = config_path.read_text(encoding="utf-8")

            assert result1.success is True
            assert result2.success is True

            # Parse YAML to compare structure (timestamps will differ)
            config1 = yaml.safe_load(content1)
            config2 = yaml.safe_load(content2)

            # Same structure except timestamp
            assert config1["commit_filter"] == config2["commit_filter"]
            assert config1["_metadata"]["wizard_version"] == config2["_metadata"]["wizard_version"]
