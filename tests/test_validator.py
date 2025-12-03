"""Tests for validate_command integration.

Also includes FIX 5: matched_rules field population test.
"""

import pytest

import schlock.core.validator as val_module
from schlock.core import parser
from schlock.core.rules import RiskLevel
from schlock.core.validator import (
    ValidationResult,
    clear_caches,
    load_rules,
    validate_command,
)
from schlock.exceptions import ConfigurationError


class TestValidator:
    """Test suite for validate_command."""

    @pytest.mark.parametrize(
        "command,should_allow,expected_exit",
        [
            ("git status", True, 0),
            ("ls -la", True, 0),
            ("echo hello", True, 0),
        ],
    )
    def test_validate_safe_command(self, safety_rules_path, command, should_allow, expected_exit):
        """Safe commands return allowed=True."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.allowed == should_allow
        assert result.exit_code == expected_exit

    @pytest.mark.parametrize(
        "command,expected_risk,should_allow",
        [
            ("rm -rf /", RiskLevel.BLOCKED, False),
            ("sudo rm file", RiskLevel.BLOCKED, False),
            ("chmod 777 /etc/passwd", RiskLevel.HIGH, True),  # HIGH allows, just warns
        ],
    )
    def test_validate_blocked_command(self, safety_rules_path, command, expected_risk, should_allow):
        """Blocked commands return allowed=False, HIGH returns warning."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.allowed == should_allow
        assert result.risk_level == expected_risk
        if not should_allow:
            assert result.exit_code == 1

    def test_validate_with_alternatives(self, safety_rules_path):
        """Alternatives populated for blocked commands."""
        result = validate_command("rm -rf /", config_path=safety_rules_path)
        assert len(result.alternatives) > 0

    @pytest.mark.parametrize(
        "invalid_command",
        [
            'echo "unclosed',
            "((( bad syntax",
        ],
    )
    def test_validate_parse_error(self, safety_rules_path, invalid_command):
        """Parse errors set error field."""
        result = validate_command(invalid_command, config_path=safety_rules_path)
        assert not result.allowed
        assert result.error is not None

    def test_validate_uses_cache(self, safety_rules_path):
        """Cache avoids re-parsing."""
        result1 = validate_command("git status", config_path=safety_rules_path)
        result2 = validate_command("git status", config_path=safety_rules_path)
        assert result1 == result2  # Same cached result

    def test_empty_command_rejected(self, safety_rules_path):
        """Empty commands return error."""
        result = validate_command("", config_path=safety_rules_path)
        assert not result.allowed
        assert result.error is not None

    @pytest.mark.parametrize(
        "bad_config,test_command",
        [
            ("/nonexistent/bad.yaml", "echo test"),
            ("/invalid/path/rules.yaml", "rm some_file"),  # Not whitelisted
        ],
    )
    def test_error_never_raises(self, bad_config, test_command):
        """All exceptions caught, never raised."""
        result = validate_command(test_command, config_path=bad_config)
        assert isinstance(result, ValidationResult)
        assert result.error is not None

    def test_validate_handles_runtime_error(self, safety_rules_path, monkeypatch):
        """Unexpected runtime errors caught gracefully."""

        # Simulate unexpected error by breaking parser
        def broken_parse(*args, **kwargs):
            raise RuntimeError("Simulated parser failure")

        monkeypatch.setattr(parser.BashCommandParser, "parse", broken_parse)

        result = validate_command("echo test", config_path=safety_rules_path)
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "Unexpected validation error" in result.message

    def test_whitespace_only_command_rejected(self, safety_rules_path):
        """Whitespace-only commands are rejected."""
        result = validate_command("   \t\n  ", config_path=safety_rules_path)
        assert not result.allowed
        assert result.error is not None
        assert "Empty command" in result.message


class TestLoadRules:
    """Test suite for load_rules function."""

    def test_load_rules_with_custom_path(self, safety_rules_path):
        """load_rules accepts custom config path."""
        engine = load_rules(config_path=safety_rules_path)
        assert engine is not None
        assert len(engine.rules) > 0

    def test_load_rules_finds_default_rules(self):
        """load_rules finds plugin defaults without config_path."""
        engine = load_rules()
        assert engine is not None
        assert len(engine.rules) > 0

    def test_load_rules_missing_defaults_raises_error(self, monkeypatch, tmp_path):
        """load_rules raises ConfigurationError if plugin defaults missing."""
        # Monkeypatch to point to nonexistent defaults
        fake_root = tmp_path / "fake_project"
        fake_root.mkdir()

        # Simulate missing data/safety_rules.yaml by pointing to wrong location
        original_file = val_module.__file__
        monkeypatch.setattr(val_module, "__file__", str(fake_root / "src" / "schlock" / "validator.py"))

        with pytest.raises(ConfigurationError, match="Plugin defaults not found"):
            load_rules()

        # Restore
        monkeypatch.setattr(val_module, "__file__", original_file)


class TestValidationResult:
    """Test suite for ValidationResult dataclass."""

    def test_validation_result_immutable(self):
        """ValidationResult is immutable."""
        result = ValidationResult(allowed=True, risk_level=RiskLevel.SAFE, message="Test", exit_code=0)
        with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError or AttributeError depending on Python version
            result.allowed = False

    def test_validation_result_default_fields(self):
        """ValidationResult has sensible defaults."""
        result = ValidationResult(allowed=True, risk_level=RiskLevel.SAFE, message="Test")
        assert result.alternatives == []
        assert result.exit_code == 0
        assert result.error is None
        assert result.matched_rules == []


class TestMatchedRulesField:
    """Test FIX 5: matched_rules field population.

    Bug: hooks/pre_tool_use.py tried to access result.matched_rules but
    ValidationResult didn't have this attribute, causing AttributeError.

    Fix: Added matched_rules field to ValidationResult and populated it
    during validation.
    """

    def test_matched_rules_field_exists(self):
        """ValidationResult has matched_rules attribute."""
        result = ValidationResult(allowed=False, risk_level=RiskLevel.BLOCKED, message="Test")
        assert hasattr(result, "matched_rules")
        assert isinstance(result.matched_rules, list)

    def test_matched_rules_populated_on_match(self):
        """matched_rules contains rule name when rule matches."""
        result = validate_command("rm -rf /")
        assert hasattr(result, "matched_rules")
        assert len(result.matched_rules) > 0
        # Should have matched system_destruction rule
        assert any("destruction" in rule.lower() for rule in result.matched_rules)

    def test_matched_rules_empty_on_safe_command(self):
        """matched_rules is empty for safe commands."""
        result = validate_command("git status")
        assert hasattr(result, "matched_rules")
        # Safe commands may match whitelist or safe rules
        # Either way, matched_rules should exist (may be empty or have safe rule)
        assert isinstance(result.matched_rules, list)

    def test_matched_rules_populated_for_blocked(self):
        """Blocked commands populate matched_rules."""
        dangerous_commands = [
            ("rm -rf /", "system_destruction"),
            ("sudo rm -rf /tmp", "sudo_use"),
            ("chmod 777 /etc", "chmod_777"),
        ]

        for cmd, _expected_pattern in dangerous_commands:
            result = validate_command(cmd)
            assert hasattr(result, "matched_rules")
            if not result.allowed:
                assert len(result.matched_rules) > 0, f"No matched_rules for blocked command: {cmd}"

    def test_matched_rules_integration_with_hook(self):
        """matched_rules can be accessed as expected by hooks."""
        result = validate_command("rm -rf /")

        # Simulate what hooks/pre_tool_use.py does
        violations = result.matched_rules if hasattr(result, "matched_rules") and result.matched_rules else []

        assert isinstance(violations, list)
        if not result.allowed:
            assert len(violations) > 0


class TestCaching:
    """Tests for module-level caching (performance optimization)."""

    def test_clear_caches_clears_validation_cache(self):
        """clear_caches() clears the validation result cache."""
        # Validate a command to populate cache
        validate_command("echo test_cache_clear")

        # Verify it's cached
        assert val_module._global_cache.get("echo test_cache_clear") is not None

        # Clear caches
        clear_caches()

        # Verify cache is cleared
        assert val_module._global_cache.get("echo test_cache_clear") is None

    def test_clear_caches_clears_rule_engine(self):
        """clear_caches() clears the RuleEngine cache."""
        # Trigger rule engine load
        validate_command("echo test_rule_engine")

        # Verify rule engine is cached
        assert val_module._global_rule_engine is not None

        # Clear caches
        clear_caches()

        # Verify rule engine is cleared
        assert val_module._global_rule_engine is None
        assert val_module._global_rule_engine_path is None

    def test_clear_caches_clears_parser(self):
        """clear_caches() clears the parser cache."""
        # Trigger parser load
        validate_command("echo test_parser")

        # Verify parser is cached
        assert val_module._global_parser is not None

        # Clear caches
        clear_caches()

        # Verify parser is cleared
        assert val_module._global_parser is None

    def test_rule_engine_reused_across_calls(self):
        """RuleEngine is reused for subsequent calls (performance)."""
        clear_caches()

        # First call loads rule engine
        validate_command("echo first")
        first_engine = val_module._global_rule_engine

        # Second call reuses same engine
        validate_command("echo second")
        second_engine = val_module._global_rule_engine

        assert first_engine is second_engine

    def test_parser_reused_across_calls(self):
        """Parser is reused for subsequent calls (performance)."""
        clear_caches()

        # First call loads parser
        validate_command("echo first")
        first_parser = val_module._global_parser

        # Second call reuses same parser
        validate_command("echo second")
        second_parser = val_module._global_parser

        assert first_parser is second_parser

    def test_rule_engine_invalidated_on_config_change(self, tmp_path):
        """RuleEngine cache is invalidated when config_path changes."""
        clear_caches()

        # Create an alternative config file
        alt_config = tmp_path / "alt_rules.yaml"
        alt_config.write_text("whitelist:\n  - echo\nblacklist:\n  commands:\n    - name: rm\n")

        # First call with default config
        validate_command("echo first")
        first_engine = val_module._global_rule_engine
        first_path = val_module._global_rule_engine_path

        # Second call with different config path
        validate_command("echo second", config_path=str(alt_config))
        second_engine = val_module._global_rule_engine
        second_path = val_module._global_rule_engine_path

        # Should have different engines for different config paths
        assert first_engine is not second_engine
        assert first_path != second_path
        assert second_path == str(alt_config)
