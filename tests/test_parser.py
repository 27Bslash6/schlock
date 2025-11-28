"""Tests for BashCommandParser."""

import pytest

from schlock.exceptions import ParseError


class TestBashCommandParser:
    """Test suite for BashCommandParser."""

    def test_parse_simple_command(self, parser):
        """Parse simple commands successfully."""
        ast = parser.parse("echo hello")
        assert ast is not None

    @pytest.mark.parametrize(
        "command,expected_commands",
        [
            ("git log | grep pattern", ["git", "grep"]),
            ("ls -la | head -n 10 | tail -n 5", ["ls", "head", "tail"]),
        ],
    )
    def test_parse_pipes(self, parser, command, expected_commands):
        """Parse piped commands."""
        ast = parser.parse(command)
        commands = parser.extract_commands(ast)
        for expected in expected_commands:
            assert expected in commands

    @pytest.mark.parametrize(
        "command,expected_cmd",
        [
            ("echo foo > bar.txt", "echo"),
            ("cat input.txt >> output.txt", "cat"),
        ],
    )
    def test_parse_redirects(self, parser, command, expected_cmd):
        """Parse redirected commands."""
        ast = parser.parse(command)
        commands = parser.extract_commands(ast)
        assert expected_cmd in commands

    def test_parse_subshells(self, parser):
        """Parse subshell command substitution."""
        ast = parser.parse("rm $(whoami)")
        dangers = parser.has_dangerous_constructs(ast)
        assert "command substitution detected" in dangers

    @pytest.mark.parametrize(
        "invalid_command,error_substring",
        [
            ('echo "unclosed string', "Failed to parse"),
            ("((( invalid", "Failed to parse"),
        ],
    )
    def test_parse_invalid_syntax(self, parser, invalid_command, error_substring):
        """Raise ParseError on invalid syntax."""
        with pytest.raises(ParseError) as exc:
            parser.parse(invalid_command)
        assert error_substring in str(exc.value)

    def test_parse_empty_command(self, parser):
        """Raise ValueError on empty command."""
        with pytest.raises(ValueError) as exc:
            parser.parse("")
        assert "cannot be empty" in str(exc.value)

    @pytest.mark.parametrize(
        "command,expected_cmd",
        [
            ("ls -la", "ls"),
            ("git status", "git"),
            ("python script.py", "python"),
        ],
    )
    def test_extract_commands(self, parser, command, expected_cmd):
        """Extract command names correctly."""
        ast = parser.parse(command)
        commands = parser.extract_commands(ast)
        assert expected_cmd in commands

    @pytest.mark.parametrize(
        "command,danger_pattern",
        [
            ('eval "rm -rf /"', "eval command detected"),
            ("exec bash", "exec command detected"),
        ],
    )
    def test_dangerous_constructs(self, parser, command, danger_pattern):
        """Detect dangerous command constructs."""
        ast = parser.parse(command)
        dangers = parser.has_dangerous_constructs(ast)
        assert danger_pattern in dangers

    def test_parse_whitespace_only(self, parser):
        """Raise ValueError on whitespace-only command."""
        with pytest.raises(ValueError) as exc:
            parser.parse("   \t\n  ")
        assert "cannot be whitespace-only" in str(exc.value)

    def test_process_substitution_detection(self, parser):
        """Detect process substitution constructs."""
        ast = parser.parse("diff <(ls dir1) <(ls dir2)")
        dangers = parser.has_dangerous_constructs(ast)
        assert "process substitution detected" in dangers
