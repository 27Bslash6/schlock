"""Tests for wizard helper utilities."""

import pytest

from schlock.setup.config_writer import WizardChoices
from schlock.setup.wizard import format_config_review, validate_wizard_choices


@pytest.fixture
def wizard_choices_enabled():
    """WizardChoices with ad blocker enabled."""
    return WizardChoices(ad_blocker_enabled=True)


@pytest.fixture
def wizard_choices_disabled():
    """WizardChoices with ad blocker disabled."""
    return WizardChoices(ad_blocker_enabled=False)


class TestFormatConfigReview:
    """Test suite for format_config_review function."""

    def test_format_ad_blocker_enabled(self, wizard_choices_enabled):
        """Format config review with ad blocker enabled."""
        output = format_config_review(wizard_choices_enabled)

        assert "Configuration Summary:" in output
        assert "✓ Claude Advertising Blocker: Enabled" in output
        assert ".claude/hooks/schlock-config.yaml" in output

    def test_format_ad_blocker_disabled(self, wizard_choices_disabled):
        """Format config review with ad blocker disabled."""
        output = format_config_review(wizard_choices_disabled)

        assert "Configuration Summary:" in output
        assert "✗ Claude Advertising Blocker: Disabled" in output
        assert ".claude/hooks/schlock-config.yaml" in output

    def test_format_includes_config_path(self, wizard_choices_enabled):
        """Config review should include destination path."""
        output = format_config_review(wizard_choices_enabled)

        assert "Config will be written to:" in output
        assert ".claude/hooks/schlock-config.yaml" in output

    def test_format_multiline_structure(self, wizard_choices_enabled):
        """Output should be multi-line with proper structure."""
        output = format_config_review(wizard_choices_enabled)

        lines = output.split("\n")
        assert len(lines) >= 3  # At least: header, blocker, path
        assert lines[0] == "Configuration Summary:"


class TestValidateWizardChoices:
    """Test suite for validate_wizard_choices function."""

    def test_validate_ad_blocker_enabled(self, wizard_choices_enabled):
        """Ad blocker enabled should be valid."""
        errors = validate_wizard_choices(wizard_choices_enabled)
        assert errors == []

    def test_validate_ad_blocker_disabled(self, wizard_choices_disabled):
        """Ad blocker disabled should fail validation."""
        errors = validate_wizard_choices(wizard_choices_disabled)
        assert len(errors) > 0
        assert any("must be enabled" in e.lower() for e in errors)

    def test_validate_error_message_mentions_precommit(self, wizard_choices_disabled):
        """Error should mention pre-commit hooks as alternative."""
        errors = validate_wizard_choices(wizard_choices_disabled)
        assert any("pre-commit" in e.lower() for e in errors)

    def test_validate_returns_list(self, wizard_choices_enabled):
        """validate_wizard_choices should always return a list."""
        errors = validate_wizard_choices(wizard_choices_enabled)
        assert isinstance(errors, list)
