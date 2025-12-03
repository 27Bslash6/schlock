"""Tests for wizard helper utilities."""

import pytest

from schlock.setup.config_writer import RISK_PRESETS, WizardChoices
from schlock.setup.wizard import (
    format_config_review,
    format_risk_preset_menu,
    get_preset_from_choice,
    validate_wizard_choices,
)


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

    def test_validate_invalid_risk_preset(self):
        """Invalid risk preset should fail validation."""
        choices = WizardChoices(ad_blocker_enabled=True, risk_preset="nonexistent")
        errors = validate_wizard_choices(choices)
        assert len(errors) > 0
        assert any("invalid risk preset" in e.lower() for e in errors)


class TestFormatRiskPresetMenu:
    """Test suite for format_risk_preset_menu function."""

    def test_returns_string(self):
        """Menu should return a string."""
        menu = format_risk_preset_menu()
        assert isinstance(menu, str)

    def test_contains_all_presets(self):
        """Menu should contain all three risk presets."""
        menu = format_risk_preset_menu()
        assert "Permissive" in menu
        assert "Balanced" in menu
        assert "Paranoid" in menu

    def test_contains_numbered_options(self):
        """Menu should have numbered options."""
        menu = format_risk_preset_menu()
        assert "[1]" in menu
        assert "[2]" in menu
        assert "[3]" in menu

    def test_contains_default_marker(self):
        """Menu should mark the default preset."""
        menu = format_risk_preset_menu()
        assert "[DEFAULT]" in menu

    def test_contains_descriptions(self):
        """Menu should include preset descriptions from RISK_PRESETS."""
        menu = format_risk_preset_menu()
        for preset in RISK_PRESETS.values():
            assert preset["description"] in menu

    def test_header_question(self):
        """Menu should start with the question."""
        menu = format_risk_preset_menu()
        assert menu.startswith("How do you want to handle risky commands?")


class TestGetPresetFromChoice:
    """Test suite for get_preset_from_choice function."""

    def test_choice_1_returns_permissive(self):
        """Choice 1 should return permissive preset."""
        assert get_preset_from_choice(1) == "permissive"

    def test_choice_2_returns_balanced(self):
        """Choice 2 should return balanced preset."""
        assert get_preset_from_choice(2) == "balanced"

    def test_choice_3_returns_paranoid(self):
        """Choice 3 should return paranoid preset."""
        assert get_preset_from_choice(3) == "paranoid"

    def test_invalid_choice_zero_raises(self):
        """Choice 0 should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid choice"):
            get_preset_from_choice(0)

    def test_invalid_choice_four_raises(self):
        """Choice 4 should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid choice"):
            get_preset_from_choice(4)

    def test_invalid_choice_negative_raises(self):
        """Negative choice should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid choice"):
            get_preset_from_choice(-1)
