"""Tests for RuleEngine."""

import pytest

from schlock.core.rules import RiskLevel, RuleEngine, RuleMatch, SecurityRule
from schlock.exceptions import ConfigurationError


@pytest.fixture
def test_rules_file(tmp_path):
    """Create test rules YAML file."""
    rules = tmp_path / "test_rules.yaml"
    rules.write_text(r"""
whitelist:
  - ^git\s+status

rules:
  - name: test-blocked
    description: Test blocked rule
    risk_level: BLOCKED
    patterns: ['rm\s+-rf\s+/']
    alternatives: ['Do not do this']

  - name: test-high
    description: Test high rule
    risk_level: HIGH
    patterns: ['git\s+push.*--force']
    alternatives: ['Use --force-with-lease']
""")
    return rules


class TestRuleEngine:
    """Test suite for RuleEngine."""

    def test_load_rules_from_yaml(self, test_rules_file):
        """Load rules from valid YAML."""
        engine = RuleEngine(test_rules_file)
        assert len(engine.rules) == 2

    @pytest.mark.parametrize(
        "yaml_content,error_substring",
        [
            ("invalid: yaml: [", "Invalid YAML"),
        ],
    )
    def test_invalid_yaml_raises_error(self, tmp_path, yaml_content, error_substring):
        """Invalid YAML raises ConfigurationError."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text(yaml_content)
        with pytest.raises(ConfigurationError) as exc:
            RuleEngine(bad_yaml)
        assert error_substring in str(exc.value)

    def test_invalid_regex_raises_error(self, tmp_path):
        """Invalid regex raises ConfigurationError."""
        bad_pattern = tmp_path / "bad_pattern.yaml"
        bad_pattern.write_text("""
rules:
  - name: bad
    description: test
    risk_level: HIGH
    patterns: ['[invalid(regex']
""")
        with pytest.raises(ConfigurationError) as exc:
            RuleEngine(bad_pattern)
        assert "Invalid regex pattern" in str(exc.value)

    @pytest.mark.parametrize(
        "command,should_match,expected_risk",
        [
            ("rm -rf /", True, RiskLevel.BLOCKED),
            ("git push --force", True, RiskLevel.HIGH),
            ("echo hello", False, RiskLevel.SAFE),
        ],
    )
    def test_pattern_matching(self, test_rules_file, command, should_match, expected_risk):
        """Patterns match commands correctly."""
        engine = RuleEngine(test_rules_file)
        match = engine.match_command(command)
        assert match.matched == should_match
        assert match.risk_level == expected_risk

    def test_risk_level_priority(self, tmp_path):
        """Highest risk wins when multiple match."""
        rules = tmp_path / "multi.yaml"
        rules.write_text("""
rules:
  - name: low
    description: Low risk
    risk_level: LOW
    patterns: ['rm']
  - name: high
    description: High risk
    risk_level: HIGH
    patterns: ['rm.*-rf']
""")
        engine = RuleEngine(rules)
        match = engine.match_command("rm -rf test")
        assert match.risk_level == RiskLevel.HIGH

    @pytest.mark.parametrize(
        "command,should_be_whitelisted",
        [
            ("git status", True),
            ("git push", False),
            ("echo test", False),
        ],
    )
    def test_whitelist_override(self, test_rules_file, command, should_be_whitelisted):
        """Whitelist returns SAFE."""
        engine = RuleEngine(test_rules_file)
        assert engine.is_whitelisted(command) == should_be_whitelisted

    def test_no_match_returns_safe(self, test_rules_file):
        """Unknown commands are safe."""
        engine = RuleEngine(test_rules_file)
        match = engine.match_command("echo hello")
        assert not match.matched
        assert match.risk_level == RiskLevel.SAFE

    def test_nonexistent_file_raises_error(self, tmp_path):
        """Nonexistent rules file raises ConfigurationError."""
        missing_file = tmp_path / "nonexistent.yaml"
        with pytest.raises(ConfigurationError, match="Rules path not found"):
            RuleEngine(missing_file)

    def test_invalid_yaml_root_raises_error(self, tmp_path):
        """YAML with non-dict root raises ConfigurationError."""
        bad_yaml = tmp_path / "bad_root.yaml"
        bad_yaml.write_text("- just a list")
        with pytest.raises(ConfigurationError, match="YAML root must be a dictionary"):
            RuleEngine(bad_yaml)

    def test_empty_directory_raises_configuration_error(self, tmp_path):
        """Empty rules directory raises ConfigurationError."""
        # Create an empty directory - RuleEngine auto-detects directories
        empty_dir = tmp_path / "empty_rules_dir"
        empty_dir.mkdir()
        with pytest.raises(ConfigurationError, match="No YAML files found"):
            RuleEngine(empty_dir)

    def test_empty_rules_logs_warning(self, tmp_path, caplog):
        """Empty rules YAML logs warning."""
        empty_rules = tmp_path / "empty.yaml"
        empty_rules.write_text("rules: []")
        engine = RuleEngine(empty_rules)
        assert len(engine.rules) == 0
        assert "No rules found" in caplog.text

    def test_invalid_whitelist_pattern_raises_error(self, tmp_path):
        """Invalid whitelist regex raises ConfigurationError."""
        bad_whitelist = tmp_path / "bad_whitelist.yaml"
        bad_whitelist.write_text("""
whitelist:
  - '[invalid(regex'
rules: []
""")
        with pytest.raises(ConfigurationError, match="Invalid whitelist regex pattern"):
            RuleEngine(bad_whitelist)

    def test_rule_not_dict_raises_error(self, tmp_path):
        """Rule that's not a dict raises ConfigurationError."""
        bad_rule = tmp_path / "bad_rule_type.yaml"
        bad_rule.write_text("""
rules:
  - just a string
""")
        with pytest.raises(ConfigurationError, match="Rule at index 0 must be a dictionary"):
            RuleEngine(bad_rule)

    def test_invalid_risk_level_name_raises_error(self, tmp_path):
        """Invalid risk level name raises ConfigurationError."""
        bad_risk = tmp_path / "bad_risk.yaml"
        bad_risk.write_text("""
rules:
  - name: test
    description: Test
    risk_level: INVALID_LEVEL
    patterns: ['test']
""")
        with pytest.raises(ConfigurationError, match="Invalid risk_level: INVALID_LEVEL"):
            RuleEngine(bad_risk)

    def test_missing_required_rule_field_raises_error(self, tmp_path):
        """Missing required rule field raises ConfigurationError."""
        missing_field = tmp_path / "missing_field.yaml"
        missing_field.write_text("""
rules:
  - name: test
    risk_level: HIGH
    patterns: ['test']
""")
        with pytest.raises(ConfigurationError, match="Invalid rule structure at index 0"):
            RuleEngine(missing_field)

    def test_string_literal_filtering(self, test_rules_file):
        """Pattern matches inside string literals are ignored."""
        engine = RuleEngine(test_rules_file)
        # Command contains "rm -rf /" but it's in a quoted string
        match = engine.match_command('echo "rm -rf /"', string_literals=[(6, 15)])
        # Should not match because pattern is inside string literal
        assert not match.matched
        assert match.risk_level == RiskLevel.SAFE

    def test_string_literal_partial_match_not_filtered(self, test_rules_file):
        """Pattern match that partially overlaps string literal is not filtered."""
        engine = RuleEngine(test_rules_file)
        # Pattern starts outside string literal
        match = engine.match_command('rm -rf / "safe"', string_literals=[(9, 15)])
        # Should match because pattern is not ENTIRELY inside string literal
        assert match.matched
        assert match.risk_level == RiskLevel.BLOCKED

    def test_whitelist_with_no_rules(self, tmp_path):
        """Whitelist works even with no rules defined."""
        whitelist_only = tmp_path / "whitelist_only.yaml"
        whitelist_only.write_text(r"""
whitelist:
  - ^git\s+status
""")
        engine = RuleEngine(whitelist_only)
        match = engine.match_command("git status")
        assert not match.matched
        assert match.risk_level == RiskLevel.SAFE
        assert "whitelisted" in match.message.lower()


class TestRiskLevel:
    """Test suite for RiskLevel enum comparisons."""

    def test_risk_level_less_than(self):
        """Test < operator."""
        assert RiskLevel.SAFE < RiskLevel.LOW
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.BLOCKED
        assert not RiskLevel.BLOCKED < RiskLevel.SAFE

    def test_risk_level_less_equal(self):
        """Test <= operator."""
        assert RiskLevel.SAFE <= RiskLevel.LOW
        assert RiskLevel.LOW <= RiskLevel.LOW
        assert not RiskLevel.HIGH <= RiskLevel.LOW

    def test_risk_level_greater_than(self):
        """Test > operator."""
        assert RiskLevel.BLOCKED > RiskLevel.HIGH
        assert RiskLevel.HIGH > RiskLevel.MEDIUM
        assert not RiskLevel.SAFE > RiskLevel.HIGH

    def test_risk_level_greater_equal(self):
        """Test >= operator."""
        assert RiskLevel.BLOCKED >= RiskLevel.HIGH
        assert RiskLevel.HIGH >= RiskLevel.HIGH
        assert not RiskLevel.LOW >= RiskLevel.MEDIUM

    def test_risk_level_comparison_with_non_risk_level(self):
        """Comparisons with non-RiskLevel raise TypeError."""
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH < 5
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH <= "string"
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH > 5
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH >= "string"

    def test_risk_level_comparison_returns_not_implemented(self):
        """Comparison with incompatible types returns NotImplemented."""
        # Test that __lt__ returns NotImplemented for non-RiskLevel types
        result = RiskLevel.HIGH.__lt__(5)
        assert result is NotImplemented

        result = RiskLevel.HIGH.__le__(5)
        assert result is NotImplemented

        result = RiskLevel.HIGH.__gt__(5)
        assert result is NotImplemented

        result = RiskLevel.HIGH.__ge__(5)
        assert result is NotImplemented


class TestSecurityRule:
    """Test suite for SecurityRule validation."""

    def test_security_rule_empty_name_raises_error(self):
        """SecurityRule with empty name raises ValueError."""
        with pytest.raises(ValueError, match="Rule name cannot be empty"):
            SecurityRule(name="", description="Test", risk_level=RiskLevel.HIGH)

    def test_security_rule_empty_description_raises_error(self):
        """SecurityRule with empty description raises ValueError."""
        with pytest.raises(ValueError, match="Rule description cannot be empty"):
            SecurityRule(name="test", description="", risk_level=RiskLevel.HIGH)

    def test_security_rule_invalid_risk_level_raises_error(self):
        """SecurityRule with invalid risk_level raises ValueError."""
        with pytest.raises(ValueError, match="risk_level must be RiskLevel enum"):
            SecurityRule(name="test", description="Test", risk_level="HIGH")


class TestRuleMatch:
    """Test suite for RuleMatch validation."""

    def test_rule_match_matched_without_rule_raises_error(self):
        """RuleMatch with matched=True but no rule raises ValueError."""
        with pytest.raises(ValueError, match="If matched is True, rule must be provided"):
            RuleMatch(matched=True, rule=None, risk_level=RiskLevel.HIGH, message="Test")

    def test_rule_match_not_matched_with_rule_raises_error(self):
        """RuleMatch with matched=False but rule provided raises ValueError."""
        rule = SecurityRule(name="test", description="Test", risk_level=RiskLevel.HIGH)
        with pytest.raises(ValueError, match="If matched is False, rule must be None"):
            RuleMatch(matched=False, rule=rule, risk_level=RiskLevel.SAFE, message="Test")


class TestMultiFileRuleLoading:
    """Test suite for multi-file rule loading from directory."""

    @pytest.fixture
    def rules_directory(self, tmp_path):
        """Create test rules directory with multiple files."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Create category files
        (rules_dir / "01_blocked.yaml").write_text(r"""
rules:
  - name: test_rule_blocked
    description: Test blocked rule
    risk_level: BLOCKED
    patterns: ['rm\s+-rf\s+/']
    alternatives: ["Don't do this"]
""")

        (rules_dir / "02_high.yaml").write_text(r"""
rules:
  - name: test_rule_high
    description: Test high risk rule
    risk_level: HIGH
    patterns: ['git\s+push.*--force']
    alternatives: ["Use --force-with-lease"]
""")

        (rules_dir / "03_whitelist.yaml").write_text(r"""
whitelist:
  - ^git\s+status
  - ^ls\b

rules: []
""")

        return rules_dir

    def test_load_rules_from_directory(self, rules_directory):
        """Test loading rules from multiple YAML files."""
        engine = RuleEngine.from_directory(rules_directory)

        assert len(engine.rules) == 2
        assert engine.rules[0].name == "test_rule_blocked"
        assert engine.rules[1].name == "test_rule_high"

    def test_directory_rules_maintain_priority(self, rules_directory):
        """Test that rules from multiple files maintain risk priority."""
        engine = RuleEngine.from_directory(rules_directory)

        # BLOCKED rule should win
        match = engine.match_command("rm -rf /")
        assert match.matched
        assert match.risk_level == RiskLevel.BLOCKED

    def test_directory_whitelist_merged(self, rules_directory):
        """Test that whitelist patterns are merged from all files."""
        engine = RuleEngine.from_directory(rules_directory)

        # Both whitelist patterns should work
        assert engine.is_whitelisted("git status")
        assert engine.is_whitelisted("ls")
        assert not engine.is_whitelisted("git push")

    def test_directory_files_loaded_in_order(self, rules_directory):
        """Test that files are loaded in alphabetical order."""
        engine = RuleEngine.from_directory(rules_directory)

        # Files should be loaded in order: 01_, 02_, 03_
        # Check that rules appear in order they were loaded
        rule_names = [rule.name for rule in engine.rules]
        assert rule_names == ["test_rule_blocked", "test_rule_high"]

    def test_nonexistent_directory_raises_error(self, tmp_path):
        """Test that nonexistent directory raises ConfigurationError."""
        missing_dir = tmp_path / "nonexistent"
        with pytest.raises(ConfigurationError, match="Rules directory not found"):
            RuleEngine.from_directory(missing_dir)

    def test_empty_directory_raises_error(self, tmp_path):
        """Test that directory with no YAML files raises ConfigurationError."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(ConfigurationError, match="No YAML files found"):
            RuleEngine.from_directory(empty_dir)

    def test_directory_with_invalid_yaml_raises_error(self, tmp_path):
        """Test that directory with invalid YAML raises ConfigurationError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "bad.yaml").write_text("invalid: yaml: [")

        with pytest.raises(ConfigurationError, match="Invalid YAML syntax"):
            RuleEngine.from_directory(rules_dir)

    def test_directory_with_empty_file_skips_file(self, tmp_path):
        """Test that empty files are skipped."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "01_good.yaml").write_text("""
rules:
  - name: test_rule
    description: Test
    risk_level: HIGH
    patterns: ['test']
    alternatives: []
""")
        (rules_dir / "02_empty.yaml").write_text("")

        engine = RuleEngine.from_directory(rules_dir)
        assert len(engine.rules) == 1

    def test_directory_with_invalid_rule_raises_error(self, tmp_path):
        """Test that directory with invalid rule raises ConfigurationError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "bad_rule.yaml").write_text("""
rules:
  - name: bad
    risk_level: INVALID
    patterns: ['test']
""")

        with pytest.raises(ConfigurationError, match="Failed to load rule"):
            RuleEngine.from_directory(rules_dir)

    def test_backward_compatibility_single_file(self, test_rules_file):
        """Test that single file loading still works."""
        engine = RuleEngine(test_rules_file)
        assert len(engine.rules) == 2
        assert engine.rules[0].name == "test-blocked"

    def test_directory_loading_vs_single_file_equivalent(self, tmp_path):
        """Test that directory loading produces same results as single file."""
        # Create single file
        single_file = tmp_path / "single.yaml"
        single_file.write_text(r"""
whitelist:
  - ^git\s+status

rules:
  - name: test_rule
    description: Test
    risk_level: HIGH
    patterns: ['test']
    alternatives: []
""")

        # Create directory with same content
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "01_rules.yaml").write_text(r"""
whitelist:
  - ^git\s+status

rules:
  - name: test_rule
    description: Test
    risk_level: HIGH
    patterns: ['test']
    alternatives: []
""")

        # Both should produce identical results
        engine_single = RuleEngine(single_file)
        engine_dir = RuleEngine.from_directory(rules_dir)

        assert len(engine_single.rules) == len(engine_dir.rules)
        assert engine_single.rules[0].name == engine_dir.rules[0].name

        # Both should match commands identically
        match_single = engine_single.match_command("test command")
        match_dir = engine_dir.match_command("test command")

        assert match_single.matched == match_dir.matched
        assert match_single.risk_level == match_dir.risk_level


class TestRuleOverrides:
    """Test suite for rule and category overrides."""

    @pytest.fixture
    def override_engine(self, tmp_path):
        """Create a RuleEngine with known rules across categories for override testing."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "01_destruction.yaml").write_text(r"""
rules:
  - name: system_destruction
    description: Complete filesystem destruction
    risk_level: BLOCKED
    patterns: ['rm\s+-rf\s+/']
    alternatives: ["Don't do this"]

  - name: recursive_delete
    description: Recursive delete of directory
    risk_level: HIGH
    patterns: ['rm\s+-r\s+']
    alternatives: ["Be more specific"]
""")

        (rules_dir / "02_network.yaml").write_text(r"""
rules:
  - name: curl_pipe_bash
    description: Pipe curl to bash
    risk_level: BLOCKED
    patterns: ['curl.*\|\s*bash']
    alternatives: ["Download and inspect first"]

  - name: open_port
    description: Listening on a port
    risk_level: MEDIUM
    patterns: ['nc\s+-l']
    alternatives: ["Use a proper server"]
""")

        return RuleEngine.from_directory(rules_dir)

    # --- Rule-level overrides ---

    def test_upgrade_risk_level(self, override_engine):
        """Rule override can upgrade risk level."""
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"risk_level": "HIGH"}},
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "open_port")
        assert rule.risk_level == RiskLevel.HIGH

    def test_downgrade_non_blocked_rule(self, override_engine):
        """Rule override can downgrade non-BLOCKED rules."""
        override_engine.apply_overrides(
            rule_overrides={"recursive_delete": {"risk_level": "MEDIUM"}},
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "recursive_delete")
        assert rule.risk_level == RiskLevel.MEDIUM

    def test_cannot_downgrade_blocked_rule(self, override_engine):
        """BLOCKED rules cannot be downgraded — security floor."""
        override_engine.apply_overrides(
            rule_overrides={"system_destruction": {"risk_level": "HIGH"}},
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "system_destruction")
        assert rule.risk_level == RiskLevel.BLOCKED

    def test_disable_rule(self, override_engine):
        """Non-BLOCKED rules can be disabled."""
        override_engine.apply_overrides(
            rule_overrides={"recursive_delete": {"enabled": False}},
            category_overrides={},
        )
        assert not any(r.name == "recursive_delete" for r in override_engine.rules)
        assert "recursive_delete" not in override_engine.compiled_patterns

    def test_cannot_disable_blocked_rule(self, override_engine):
        """BLOCKED rules cannot be disabled."""
        override_engine.apply_overrides(
            rule_overrides={"system_destruction": {"enabled": False}},
            category_overrides={},
        )
        assert any(r.name == "system_destruction" for r in override_engine.rules)

    def test_unknown_rule_ignored(self, override_engine, caplog):
        """Unknown rule names are warned and ignored."""
        original_count = len(override_engine.rules)
        override_engine.apply_overrides(
            rule_overrides={"nonexistent_rule": {"risk_level": "HIGH"}},
            category_overrides={},
        )
        assert len(override_engine.rules) == original_count
        assert "unknown rule" in caplog.text.lower()

    def test_invalid_risk_level_ignored(self, override_engine, caplog):
        """Invalid risk_level values are warned and skipped."""
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"risk_level": "SUPER_BLOCKED"}},
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "open_port")
        assert rule.risk_level == RiskLevel.MEDIUM  # Unchanged
        assert "Invalid risk_level" in caplog.text

    def test_empty_overrides_noop(self, override_engine):
        """Empty overrides don't modify anything."""
        original_rules = list(override_engine.rules)
        override_engine.apply_overrides(rule_overrides={}, category_overrides={})
        assert override_engine.rules == original_rules

    def test_preserves_other_fields(self, override_engine):
        """Override only changes specified fields, preserves everything else."""
        override_engine.apply_overrides(
            rule_overrides={"recursive_delete": {"risk_level": "BLOCKED"}},
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "recursive_delete")
        assert rule.description == "Recursive delete of directory"
        assert rule.alternatives == ["Be more specific"]
        assert rule.category == "destruction"

    def test_non_dict_override_value_ignored(self, override_engine):
        """Non-dict override values are ignored gracefully."""
        original_count = len(override_engine.rules)
        override_engine.apply_overrides(
            rule_overrides={"recursive_delete": "not_a_dict"},
            category_overrides={},
        )
        assert len(override_engine.rules) == original_count

    def test_non_dict_category_override_value_ignored(self, override_engine):
        """Non-dict category override values are ignored gracefully."""
        original_count = len(override_engine.rules)
        override_engine.apply_overrides(
            rule_overrides={},
            category_overrides={"network": "not_a_dict"},
        )
        assert len(override_engine.rules) == original_count

    def test_multiple_rule_overrides(self, override_engine):
        """Multiple rules can be overridden simultaneously."""
        override_engine.apply_overrides(
            rule_overrides={
                "open_port": {"risk_level": "HIGH"},
                "recursive_delete": {"enabled": False},
            },
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "open_port")
        assert rule.risk_level == RiskLevel.HIGH
        assert not any(r.name == "recursive_delete" for r in override_engine.rules)

    # --- Category-level overrides ---

    def test_category_override_all_rules(self, override_engine):
        """Category override applies to all rules in that category."""
        override_engine.apply_overrides(
            rule_overrides={},
            category_overrides={"network": {"enabled": False}},
        )
        # open_port (MEDIUM) should be disabled, curl_pipe_bash (BLOCKED) should remain
        assert not any(r.name == "open_port" for r in override_engine.rules)
        assert any(r.name == "curl_pipe_bash" for r in override_engine.rules)

    def test_category_risk_level_override(self, override_engine):
        """Category override can change risk level for all non-BLOCKED rules."""
        override_engine.apply_overrides(
            rule_overrides={},
            category_overrides={"network": {"risk_level": "HIGH"}},
        )
        open_port = next(r for r in override_engine.rules if r.name == "open_port")
        assert open_port.risk_level == RiskLevel.HIGH
        # BLOCKED rule should be unchanged
        curl = next(r for r in override_engine.rules if r.name == "curl_pipe_bash")
        assert curl.risk_level == RiskLevel.BLOCKED

    def test_rule_override_wins_over_category(self, override_engine):
        """Rule-level override takes precedence over category-level."""
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"risk_level": "BLOCKED"}},
            category_overrides={"network": {"risk_level": "LOW"}},
        )
        open_port = next(r for r in override_engine.rules if r.name == "open_port")
        assert open_port.risk_level == RiskLevel.BLOCKED

    def test_rule_risk_level_wins_over_category_blocked_upgrade(self, override_engine):
        """Rule-level risk_level overrides a category upgrade to BLOCKED."""
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"risk_level": "HIGH"}},
            category_overrides={"network": {"risk_level": "BLOCKED"}},
        )
        # open_port was originally MEDIUM, category upgraded to BLOCKED,
        # but rule-level says HIGH — rule wins because original was not BLOCKED
        open_port = next(r for r in override_engine.rules if r.name == "open_port")
        assert open_port.risk_level == RiskLevel.HIGH

    def test_rule_enabled_wins_over_category_disabled(self, override_engine):
        """Rule enabled: true takes precedence over category enabled: false."""
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"enabled": True}},
            category_overrides={"network": {"enabled": False}},
        )
        # open_port should remain because rule-level enabled: true wins
        assert any(r.name == "open_port" for r in override_engine.rules)
        # curl_pipe_bash should also remain because it's originally BLOCKED
        assert any(r.name == "curl_pipe_bash" for r in override_engine.rules)

    def test_unknown_category_ignored(self, override_engine, caplog):
        """Unknown category names are warned and ignored."""
        original_count = len(override_engine.rules)
        override_engine.apply_overrides(
            rule_overrides={},
            category_overrides={"fantasy_category": {"enabled": False}},
        )
        assert len(override_engine.rules) == original_count
        assert "unknown category" in caplog.text.lower()

    def test_cannot_downgrade_blocked_via_category(self, override_engine):
        """BLOCKED rules in a category cannot be downgraded."""
        override_engine.apply_overrides(
            rule_overrides={},
            category_overrides={"destruction": {"risk_level": "MEDIUM"}},
        )
        system_dest = next(r for r in override_engine.rules if r.name == "system_destruction")
        assert system_dest.risk_level == RiskLevel.BLOCKED

    def test_can_disable_rule_upgraded_to_blocked(self, override_engine):
        """Rules upgraded to BLOCKED via override can still be disabled (original was not BLOCKED)."""
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"enabled": False}},
            category_overrides={"network": {"risk_level": "BLOCKED"}},
        )
        # open_port was originally MEDIUM, so it can be disabled even after upgrade
        assert not any(r.name == "open_port" for r in override_engine.rules)

    # --- Category field population ---

    def test_category_populated_during_directory_loading(self, override_engine):
        """Category field populated from filename during directory loading."""
        system_dest = next(r for r in override_engine.rules if r.name == "system_destruction")
        assert system_dest.category == "destruction"
        open_port = next(r for r in override_engine.rules if r.name == "open_port")
        assert open_port.category == "network"

    def test_apply_overrides_is_idempotent(self, override_engine):
        """Repeated apply_overrides uses original risk levels, not mutated ones."""
        # Phase 1: Upgrade open_port to BLOCKED via category
        override_engine.apply_overrides(
            rule_overrides={},
            category_overrides={"network": {"risk_level": "BLOCKED"}},
        )
        rule = next(r for r in override_engine.rules if r.name == "open_port")
        assert rule.risk_level == RiskLevel.BLOCKED

        # Phase 2: Downgrade open_port via rule override
        # Without idempotency fix, this would fail because the engine thinks
        # open_port was always BLOCKED
        override_engine.apply_overrides(
            rule_overrides={"open_port": {"risk_level": "MEDIUM"}},
            category_overrides={},
        )
        rule = next(r for r in override_engine.rules if r.name == "open_port")
        assert rule.risk_level == RiskLevel.MEDIUM

    def test_category_empty_for_single_file_loading(self, test_rules_file):
        """Category defaults to empty string for single-file loading."""
        engine = RuleEngine(test_rules_file)
        for rule in engine.rules:
            assert rule.category == ""
