"""Tests for wizard helper utilities."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from schlock.setup.config_writer import RISK_PRESETS, WizardChoices
from schlock.setup.wizard import (
    find_schlock_root,
    format_config_review,
    format_risk_preset_menu,
    get_preset_from_choice,
    setup_schlock_imports,
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


class TestFindSchlockRoot:
    """Test suite for find_schlock_root function."""

    def test_development_mode_finds_cwd(self, tmp_path, monkeypatch):
        """Development mode: cwd with src/schlock should be found."""
        # Create src/schlock structure
        (tmp_path / "src" / "schlock").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        result = find_schlock_root()
        assert result == tmp_path

    def test_registry_lookup_finds_plugin(self, tmp_path, monkeypatch):
        """Registry lookup: installed_plugins.json should be searched."""
        # Ensure cwd doesn't have src/schlock
        monkeypatch.chdir(tmp_path)

        # Create plugin structure under the expected .claude/plugins path
        plugins_dir = tmp_path / ".claude" / "plugins"
        plugin_path = plugins_dir / "marketplaces" / "27b"
        (plugin_path / "src" / "schlock").mkdir(parents=True)

        # Create registry
        registry = plugins_dir / "installed_plugins.json"
        registry_data = {
            "plugins": {
                "schlock@27b": {
                    "installPath": str(plugin_path),
                }
            }
        }
        registry.write_text(json.dumps(registry_data))

        # Mock home to use our tmp_path and patch os.name for non-Windows path
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("schlock.setup.wizard.os.name", "posix"),
        ):
            result = find_schlock_root()

        assert result == plugin_path.resolve()

    def test_marketplace_scan_finds_plugin(self, tmp_path, monkeypatch):
        """Marketplace scan: marketplaces directory should be searched."""
        # Ensure cwd doesn't have src/schlock
        monkeypatch.chdir(tmp_path)

        # Create marketplace plugin structure
        marketplace = tmp_path / ".claude" / "plugins" / "marketplaces" / "27b"
        (marketplace / "src" / "schlock").mkdir(parents=True)

        # Mock home directory
        with patch.object(Path, "home", return_value=tmp_path), patch("schlock.setup.wizard.os.name", "posix"):
            result = find_schlock_root()

        assert result == marketplace.resolve()

    def test_raises_when_not_found(self, tmp_path, monkeypatch):
        """RuntimeError should be raised when schlock is not found."""
        monkeypatch.chdir(tmp_path)

        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("schlock.setup.wizard.os.name", "posix"),
            pytest.raises(RuntimeError, match="Could not find schlock"),
        ):
            find_schlock_root()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_checks_appdata(self, tmp_path, monkeypatch):
        """Windows: APPDATA and LOCALAPPDATA should be checked."""
        monkeypatch.chdir(tmp_path)

        # Create plugin in APPDATA location
        appdata = tmp_path / "appdata"
        plugin_path = appdata / ".claude" / "plugins" / "marketplaces" / "27b"
        (plugin_path / "src" / "schlock").mkdir(parents=True)

        with (
            patch("schlock.setup.wizard.os.name", "nt"),
            patch.dict("os.environ", {"APPDATA": str(appdata), "LOCALAPPDATA": ""}),
            patch.object(Path, "home", return_value=tmp_path / "home"),
        ):
            result = find_schlock_root()

        assert result == plugin_path.resolve()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_path_construction(self, tmp_path, monkeypatch):
        """Windows env vars should be included in base_dirs when os.name is 'nt'."""
        # This tests the path construction logic without actually using Windows paths
        # We verify that when os.name == 'nt', the APPDATA/LOCALAPPDATA paths are checked

        # First, make sure cwd doesn't have src/schlock (otherwise returns early)
        monkeypatch.chdir(tmp_path)

        # Create plugin at APPDATA location
        appdata = tmp_path / "appdata"
        plugin_path = appdata / ".claude" / "plugins" / "marketplaces" / "27b"
        (plugin_path / "src" / "schlock").mkdir(parents=True)

        with (
            patch("schlock.setup.wizard.os.name", "nt"),
            patch.dict(
                "os.environ",
                {"APPDATA": str(appdata), "LOCALAPPDATA": str(tmp_path / "localappdata")},
            ),
            patch.object(Path, "home", return_value=tmp_path / "home"),
        ):
            result = find_schlock_root()

        # If Windows paths are being checked, we should find the plugin
        assert result == plugin_path.resolve()

    def test_registry_invalid_json_continues(self, tmp_path, monkeypatch):
        """Invalid JSON in registry should be skipped gracefully."""
        monkeypatch.chdir(tmp_path)

        # Create invalid registry
        plugins_dir = tmp_path / ".claude" / "plugins"
        plugins_dir.mkdir(parents=True)
        (plugins_dir / "installed_plugins.json").write_text("not valid json")

        # Create fallback in marketplace
        marketplace = plugins_dir / "marketplaces" / "27b"
        (marketplace / "src" / "schlock").mkdir(parents=True)

        with patch.object(Path, "home", return_value=tmp_path), patch("schlock.setup.wizard.os.name", "posix"):
            result = find_schlock_root()

        assert result == marketplace.resolve()

    def test_registry_path_outside_basedirs_rejected(self, tmp_path, monkeypatch):
        """Registry paths outside base_dirs should be rejected for security."""
        monkeypatch.chdir(tmp_path)

        # Create plugin outside expected location
        outside_path = tmp_path / "somewhere" / "else"
        (outside_path / "src" / "schlock").mkdir(parents=True)

        # Create registry pointing to it
        plugins_dir = tmp_path / ".claude" / "plugins"
        plugins_dir.mkdir(parents=True)
        registry = plugins_dir / "installed_plugins.json"
        registry_data = {
            "plugins": {
                "schlock@27b": {
                    "installPath": str(outside_path),
                }
            }
        }
        registry.write_text(json.dumps(registry_data))

        # Should raise because path is outside base_dirs
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch("schlock.setup.wizard.os.name", "posix"),
            pytest.raises(RuntimeError, match="Could not find schlock"),
        ):
            find_schlock_root()


class TestSetupSchlockImports:
    """Test suite for setup_schlock_imports function."""

    def test_returns_plugin_root(self, tmp_path, monkeypatch):
        """setup_schlock_imports should return plugin root path."""
        # Create src/schlock structure for development mode
        (tmp_path / "src" / "schlock").mkdir(parents=True)
        (tmp_path / ".claude-plugin" / "vendor").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        # Track original sys.path
        original_path = sys.path.copy()

        try:
            result = setup_schlock_imports()
            assert result == tmp_path
        finally:
            # Restore sys.path
            sys.path[:] = original_path

    def test_adds_vendor_to_syspath(self, tmp_path, monkeypatch):
        """setup_schlock_imports should add vendor path to sys.path."""
        (tmp_path / "src" / "schlock").mkdir(parents=True)
        (tmp_path / ".claude-plugin" / "vendor").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        original_path = sys.path.copy()

        try:
            setup_schlock_imports()
            vendor_path = str(tmp_path / ".claude-plugin" / "vendor")
            assert vendor_path in sys.path
        finally:
            sys.path[:] = original_path

    def test_adds_src_to_syspath(self, tmp_path, monkeypatch):
        """setup_schlock_imports should add src path to sys.path."""
        (tmp_path / "src" / "schlock").mkdir(parents=True)
        (tmp_path / ".claude-plugin" / "vendor").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        original_path = sys.path.copy()

        try:
            setup_schlock_imports()
            src_path = str(tmp_path / "src")
            assert src_path in sys.path
        finally:
            sys.path[:] = original_path

    def test_idempotent_path_insertion(self, tmp_path, monkeypatch):
        """Calling setup_schlock_imports twice should not duplicate paths."""
        (tmp_path / "src" / "schlock").mkdir(parents=True)
        (tmp_path / ".claude-plugin" / "vendor").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        original_path = sys.path.copy()

        try:
            setup_schlock_imports()
            setup_schlock_imports()

            vendor_path = str(tmp_path / ".claude-plugin" / "vendor")
            src_path = str(tmp_path / "src")

            # Count occurrences
            vendor_count = sys.path.count(vendor_path)
            src_count = sys.path.count(src_path)

            assert vendor_count == 1, f"vendor_path appears {vendor_count} times"
            assert src_count == 1, f"src_path appears {src_count} times"
        finally:
            sys.path[:] = original_path
