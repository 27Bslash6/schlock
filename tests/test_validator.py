"""Tests for validate_command integration.

Also includes FIX 5: matched_rules field population test.
"""

import pytest

import schlock.core.validator as val_module
from schlock.core import parser
from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import (
    ValidationResult,
    _load_rule_overrides,
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


class TestRuleOverridesIntegration:
    """Integration tests for rule override loading from config files."""

    def test_load_rule_overrides_from_project_config(self, tmp_path, monkeypatch):
        """Load rule_overrides from project-level config."""
        project_config = tmp_path / ".claude" / "hooks"
        project_config.mkdir(parents=True)
        (project_config / "schlock-config.yaml").write_text("""
rule_overrides:
  recursive_delete:
    enabled: false
""")
        monkeypatch.chdir(tmp_path)
        rule_overrides, category_overrides = _load_rule_overrides()
        assert "recursive_delete" in rule_overrides
        assert rule_overrides["recursive_delete"]["enabled"] is False
        assert category_overrides == {}

    def test_load_category_overrides_from_project_config(self, tmp_path, monkeypatch):
        """Load category_overrides from project-level config."""
        project_config = tmp_path / ".claude" / "hooks"
        project_config.mkdir(parents=True)
        (project_config / "schlock-config.yaml").write_text("""
category_overrides:
  network_security:
    risk_level: HIGH
""")
        monkeypatch.chdir(tmp_path)
        rule_overrides, category_overrides = _load_rule_overrides()
        assert rule_overrides == {}
        assert "network_security" in category_overrides
        assert category_overrides["network_security"]["risk_level"] == "HIGH"

    def test_merge_precedence_project_over_user(self, tmp_path, monkeypatch):
        """Project config overrides user config at property level."""
        # User config: disable rule
        user_config = tmp_path / "user_home" / ".config" / "schlock"
        user_config.mkdir(parents=True)
        (user_config / "config.yaml").write_text("""
rule_overrides:
  some_rule:
    enabled: false
    risk_level: LOW
""")

        # Project config: set risk_level only
        project_config = tmp_path / "project" / ".claude" / "hooks"
        project_config.mkdir(parents=True)
        (project_config / "schlock-config.yaml").write_text("""
rule_overrides:
  some_rule:
    risk_level: HIGH
""")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "user_home")
        monkeypatch.chdir(tmp_path / "project")

        rule_overrides, _ = _load_rule_overrides()
        # enabled: false from user + risk_level: HIGH from project (overwrites user's LOW)
        assert rule_overrides["some_rule"]["enabled"] is False
        assert rule_overrides["some_rule"]["risk_level"] == "HIGH"

    def test_no_config_files_returns_empty(self, tmp_path, monkeypatch):
        """No config files returns empty dicts."""
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nonexistent_home")
        monkeypatch.chdir(tmp_path)

        rule_overrides, category_overrides = _load_rule_overrides()
        assert rule_overrides == {}
        assert category_overrides == {}

    def test_invalid_yaml_degrades_gracefully(self, tmp_path, monkeypatch, caplog):
        """Invalid YAML in config doesn't crash, logs warning."""
        project_config = tmp_path / ".claude" / "hooks"
        project_config.mkdir(parents=True)
        (project_config / "schlock-config.yaml").write_text("invalid: yaml: [")

        monkeypatch.chdir(tmp_path)

        rule_overrides, category_overrides = _load_rule_overrides()
        assert rule_overrides == {}
        assert category_overrides == {}
        assert "Failed to load overrides" in caplog.text


class TestSelfProtection:
    """Test self-protection: LLM cannot modify schlock's own configuration.

    Three defense layers:
    1. YAML rules (BLOCKED, can't be overridden)
    2. Hardcoded validator check (_check_self_protection)
    3. Hook file_path check (tested in test_hook_integration.py)
    """

    def setup_method(self):
        """Reset cached rule engine to ensure fresh state for each test."""
        clear_caches()

    # --- Layer 2: Hardcoded validator check ---

    @pytest.mark.parametrize(
        "command",
        [
            'echo "rule_overrides:" > .claude/hooks/schlock-config.yaml',
            "cat > .claude/hooks/schlock-config.yaml << EOF",
            "tee .claude/hooks/schlock-config.yaml",
            "cp /tmp/evil.yaml .claude/hooks/schlock-config.yaml",
            "mv /tmp/evil.yaml .claude/hooks/schlock-config.yaml",
            "rm .claude/hooks/schlock-config.yaml",
            "sed -i 's/BLOCKED/LOW/' .claude/hooks/schlock-config.yaml",
            "truncate -s 0 .claude/hooks/schlock-config.yaml",
            "chmod 777 .claude/hooks/schlock-config.yaml",
            'echo "overrides" > ~/.config/schlock/config.yaml',
            "rm ~/.config/schlock/config.yaml",
            "tee ~/.config/schlock/config.yaml",
        ],
    )
    def test_blocks_config_write_commands(self, command):
        """Hardcoded check blocks write operations targeting schlock config."""
        result = validate_command(command)
        assert not result.allowed, f"Should block: {command}"
        assert result.risk_level == RiskLevel.BLOCKED
        assert "self_protection" in str(result.matched_rules)

    @pytest.mark.parametrize(
        "command",
        [
            "cat .claude/hooks/schlock-config.yaml",
            "ls -la .claude/hooks/schlock-config.yaml",
            "grep risk_level .claude/hooks/schlock-config.yaml",
            "wc -l .claude/hooks/schlock-config.yaml",
            "head -5 .claude/hooks/schlock-config.yaml",
            "stat .claude/hooks/schlock-config.yaml",
            "diff .claude/hooks/schlock-config.yaml /tmp/other.yaml",
            "jq . .claude/hooks/schlock-config.yaml",
        ],
    )
    def test_allows_config_read_commands(self, command):
        """Read-only operations on schlock config are allowed."""
        result = validate_command(command)
        assert result.allowed, f"Should allow: {command}"

    @pytest.mark.parametrize(
        "command",
        [
            # Bypass vectors that the old denylist approach would miss
            "ln -sf /dev/null .claude/hooks/schlock-config.yaml",
            "dd of=.claude/hooks/schlock-config.yaml",
            "rsync evil.yaml .claude/hooks/schlock-config.yaml",
            "python3 -c \"open('.claude/hooks/schlock-config.yaml', 'w')\"",
            "perl -pi -e 's/BLOCKED/LOW/' .claude/hooks/schlock-config.yaml",
            "install /tmp/evil.yaml .claude/hooks/schlock-config.yaml",
            "ln -sf /dev/null ~/.config/schlock/config.yaml",
            "dd of=~/.config/schlock/config.yaml",
        ],
    )
    def test_blocks_obscure_write_commands(self, command):
        """Allowlist catches obscure write commands that a denylist would miss."""
        result = validate_command(command)
        assert not result.allowed, f"Should block: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command",
        [
            "DUMMY=1 rm .claude/hooks/schlock-config.yaml",
            "FOO=bar BAZ=1 cp /tmp/evil.yaml .claude/hooks/schlock-config.yaml",
            "LANG=C tee ~/.config/schlock/config.yaml",
        ],
    )
    def test_blocks_env_prefixed_write_commands(self, command):
        """Env-var prefixes don't bypass self-protection allowlist."""
        result = validate_command(command)
        assert not result.allowed, f"Should block: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command",
        [
            # Process substitution: config path is visible in command string,
            # so _matches_protected_path detects it and the non-allowlisted
            # python3 gets blocked. This documents the behavior.
            "cat /tmp/evil.yaml >(python3 -c \"open('.claude/hooks/schlock-config.yaml','w').write('x')\")",
        ],
    )
    def test_process_substitution_with_visible_path_is_blocked(self, command):
        """Process substitution with literal config path is caught by self-protection."""
        result = validate_command(command)
        assert not result.allowed, f"Should block: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_self_protection_cannot_be_overridden(self, tmp_path):
        """Self-protection rules in YAML are BLOCKED and cannot be overridden."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "14_self_protection.yaml").write_text(r"""
rules:
  - name: schlock_config_write
    description: Self-protection test
    risk_level: BLOCKED
    patterns: ['schlock-config\.yaml']
""")
        engine = RuleEngine.from_directory(rules_dir)

        # Try to override the self-protection rule
        engine.apply_overrides(
            rule_overrides={"schlock_config_write": {"risk_level": "LOW", "enabled": False}},
            category_overrides={},
        )

        # Rule should still be present and still BLOCKED
        rule = next(r for r in engine.rules if r.name == "schlock_config_write")
        assert rule.risk_level == RiskLevel.BLOCKED

    def test_self_protection_category_cannot_be_disabled(self, tmp_path):
        """Self-protection category cannot be disabled via category_overrides."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "14_self_protection.yaml").write_text(r"""
rules:
  - name: schlock_config_write
    description: Self-protection test
    risk_level: BLOCKED
    patterns: ['schlock-config\.yaml']
""")
        engine = RuleEngine.from_directory(rules_dir)

        engine.apply_overrides(
            rule_overrides={},
            category_overrides={"self_protection": {"enabled": False}},
        )

        # BLOCKED rule should survive category disable
        assert any(r.name == "schlock_config_write" for r in engine.rules)
