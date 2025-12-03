"""Tests for ShellCheck integration module."""

import pytest

from schlock.integrations.shellcheck import (
    SECURITY_RELEVANT_CODES,
    ShellCheckFinding,
    ShellCheckSeverity,
    format_findings_message,
    get_install_instructions,
    get_security_findings,
    get_shellcheck_path,
    get_shellcheck_version,
    has_security_relevant_findings,
    is_shellcheck_available,
    run_shellcheck,
)


class TestShellCheckDetection:
    """Test shellcheck detection and availability."""

    def test_is_shellcheck_available(self):
        """Test that we can detect if shellcheck is available."""
        # This just tests the function runs without error
        # Result depends on whether shellcheck is installed
        result = is_shellcheck_available()
        assert isinstance(result, bool)

    def test_get_shellcheck_path(self):
        """Test path detection returns string or None."""
        result = get_shellcheck_path()
        assert result is None or isinstance(result, str)

    def test_get_shellcheck_version(self):
        """Test version detection."""
        if is_shellcheck_available():
            version = get_shellcheck_version()
            assert version is not None
            # Version should be like "0.11.0"
            assert "." in version
        else:
            assert get_shellcheck_version() is None

    def test_get_install_instructions(self):
        """Test install instructions return platform-appropriate command."""
        instructions = get_install_instructions()
        assert isinstance(instructions, str)
        assert len(instructions) > 0


class TestShellCheckExecution:
    """Test shellcheck execution."""

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_run_shellcheck_finds_issues(self):
        """Test that shellcheck finds issues in problematic commands."""
        # SC2086: Double quote to prevent globbing
        findings = run_shellcheck("echo $HOME")
        assert len(findings) > 0
        assert any(f.code == 2086 for f in findings)

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_run_shellcheck_clean_command(self):
        """Test that shellcheck passes clean commands."""
        # Well-quoted command should have fewer/no issues
        findings = run_shellcheck('echo "hello world"')
        # May still have some style issues but not security
        security = get_security_findings(findings)
        assert len(security) == 0

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_run_shellcheck_eval_warning(self):
        """Test that eval with variables is flagged."""
        findings = run_shellcheck('eval "$user_input"')
        # Should flag SC2154 (referenced but not assigned)
        assert len(findings) > 0

    def test_run_shellcheck_not_installed(self):
        """Test graceful handling when shellcheck not installed."""
        # This tests the fallback path - always returns empty list
        from unittest.mock import patch  # noqa: PLC0415 - Test isolation

        with patch("schlock.integrations.shellcheck.get_shellcheck_path", return_value=None):
            findings = run_shellcheck("echo test")
            assert findings == []

    def test_run_shellcheck_timeout_handling(self):
        """Test timeout parameter is respected."""
        if is_shellcheck_available():
            # Very short timeout should still work for simple command
            findings = run_shellcheck("echo test", timeout=10.0)
            assert isinstance(findings, list)


class TestShellCheckFinding:
    """Test ShellCheckFinding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = ShellCheckFinding(
            code=2086,
            level=ShellCheckSeverity.INFO,
            message="Double quote to prevent globbing",
            line=1,
            column=6,
            end_line=1,
            end_column=11,
        )
        assert finding.code == 2086
        assert finding.level == ShellCheckSeverity.INFO
        assert finding.sc_code == "SC2086"
        assert "shellcheck.net/wiki/SC2086" in finding.wiki_url

    def test_finding_immutable(self):
        """Test finding is frozen."""
        finding = ShellCheckFinding(
            code=2086,
            level=ShellCheckSeverity.INFO,
            message="Test",
            line=1,
            column=1,
            end_line=1,
            end_column=1,
        )
        with pytest.raises(AttributeError):
            finding.code = 9999  # type: ignore


class TestSecurityFindings:
    """Test security-relevant finding detection."""

    def test_security_relevant_codes_defined(self):
        """Test that security codes are defined."""
        assert len(SECURITY_RELEVANT_CODES) > 0
        assert 2086 in SECURITY_RELEVANT_CODES  # Word splitting
        assert 2091 in SECURITY_RELEVANT_CODES  # Executing output

    def test_has_security_relevant_findings_true(self):
        """Test detection of security-relevant findings."""
        findings = [
            ShellCheckFinding(
                code=2086,  # Security relevant
                level=ShellCheckSeverity.INFO,
                message="Test",
                line=1,
                column=1,
                end_line=1,
                end_column=1,
            )
        ]
        assert has_security_relevant_findings(findings) is True

    def test_has_security_relevant_findings_false(self):
        """Test non-security findings don't trigger."""
        findings = [
            ShellCheckFinding(
                code=9999,  # Not security relevant
                level=ShellCheckSeverity.STYLE,
                message="Style issue",
                line=1,
                column=1,
                end_line=1,
                end_column=1,
            )
        ]
        assert has_security_relevant_findings(findings) is False

    def test_get_security_findings_filters(self):
        """Test filtering to security-only findings."""
        findings = [
            ShellCheckFinding(
                code=2086,  # Security
                level=ShellCheckSeverity.INFO,
                message="Security issue",
                line=1,
                column=1,
                end_line=1,
                end_column=1,
            ),
            ShellCheckFinding(
                code=9999,  # Not security
                level=ShellCheckSeverity.STYLE,
                message="Style issue",
                line=1,
                column=1,
                end_line=1,
                end_column=1,
            ),
        ]
        security_only = get_security_findings(findings)
        assert len(security_only) == 1
        assert security_only[0].code == 2086


class TestMessageFormatting:
    """Test finding message formatting."""

    def test_format_empty_findings(self):
        """Test empty findings return empty string."""
        assert format_findings_message([]) == ""

    def test_format_single_finding(self):
        """Test single finding formatting."""
        findings = [
            ShellCheckFinding(
                code=2086,
                level=ShellCheckSeverity.INFO,
                message="Double quote to prevent globbing",
                line=1,
                column=1,
                end_line=1,
                end_column=1,
            )
        ]
        message = format_findings_message(findings)
        assert "ShellCheck warnings:" in message
        assert "SC2086" in message
        assert "Double quote" in message

    def test_format_multiple_findings_truncated(self):
        """Test multiple findings are truncated."""
        findings = [
            ShellCheckFinding(
                code=2086 + i,
                level=ShellCheckSeverity.INFO,
                message=f"Issue {i}",
                line=1,
                column=1,
                end_line=1,
                end_column=1,
            )
            for i in range(5)
        ]
        message = format_findings_message(findings, max_findings=3)
        assert "... and 2 more" in message


class TestCircuitBreaker:
    """Test circuit breaker functionality."""

    def test_circuit_breaker_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures."""
        from unittest.mock import patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Reset circuit breaker state
        sc._circuit_breaker_failures.clear()
        sc._circuit_breaker_open_until = 0.0

        # Simulate failures reaching threshold
        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", side_effect=OSError("Simulated failure")),
        ):
            for _ in range(sc._CIRCUIT_BREAKER_THRESHOLD):
                sc.run_shellcheck("echo test")

        # Circuit should now be open
        assert sc._circuit_breaker_open_until > 0

        # Cleanup
        sc._circuit_breaker_failures.clear()
        sc._circuit_breaker_open_until = 0.0

    def test_circuit_breaker_skips_when_open(self):
        """Test shellcheck is skipped when circuit is open."""
        import time  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Force circuit open
        sc._circuit_breaker_open_until = time.monotonic() + 60.0

        result = sc.run_shellcheck("echo test")
        assert result == []

        # Cleanup
        sc._circuit_breaker_open_until = 0.0

    def test_circuit_breaker_resets_on_success(self):
        """Test circuit breaker resets after successful execution."""
        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Add some failures
        sc._circuit_breaker_failures.append(0.0)

        # Reset function should clear failures
        sc._reset_circuit_breaker()

        assert len(sc._circuit_breaker_failures) == 0
        assert sc._circuit_breaker_open_until == 0.0


class TestShellCheckErrorHandling:
    """Test error handling paths."""

    def test_exit_code_greater_than_one(self):
        """Test handling of exit code > 1 (actual errors)."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Reset circuit breaker
        sc._circuit_breaker_failures.clear()
        sc._circuit_breaker_open_until = 0.0

        mock_result = MagicMock()
        mock_result.returncode = 2  # Error exit code

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert findings == []

        # Cleanup
        sc._circuit_breaker_failures.clear()

    def test_empty_output(self):
        """Test handling of empty stdout."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""  # Empty output

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert findings == []

    def test_output_size_limit(self):
        """Test handling of oversized output."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Reset circuit breaker
        sc._circuit_breaker_failures.clear()
        sc._circuit_breaker_open_until = 0.0

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "x" * (sc._MAX_OUTPUT_SIZE + 1)  # Exceeds limit

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert findings == []

        # Cleanup
        sc._circuit_breaker_failures.clear()

    def test_findings_count_limit(self):
        """Test truncation of excessive findings."""
        import json  # noqa: PLC0415
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Create more findings than the limit
        many_findings = [
            {"code": 2086, "level": "info", "message": f"Issue {i}", "line": 1, "column": 1, "endLine": 1, "endColumn": 1}
            for i in range(sc._MAX_FINDINGS_COUNT + 10)
        ]

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps(many_findings)

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert len(findings) <= sc._MAX_FINDINGS_COUNT

    def test_invalid_code_skipped(self):
        """Test findings with invalid codes are skipped."""
        import json  # noqa: PLC0415
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Invalid codes: not integer, < 1000, > 9999
        findings_json = [
            {"code": "abc", "level": "info", "message": "Bad", "line": 1, "column": 1, "endLine": 1, "endColumn": 1},
            {"code": 999, "level": "info", "message": "Bad", "line": 1, "column": 1, "endLine": 1, "endColumn": 1},
            {"code": 10000, "level": "info", "message": "Bad", "line": 1, "column": 1, "endLine": 1, "endColumn": 1},
            {"code": 2086, "level": "info", "message": "Good", "line": 1, "column": 1, "endLine": 1, "endColumn": 1},
        ]

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps(findings_json)

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert len(findings) == 1  # Only the valid one
            assert findings[0].code == 2086

    def test_malformed_finding_skipped(self):
        """Test malformed findings are skipped."""
        import json  # noqa: PLC0415
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Invalid level causes ValueError when creating ShellCheckSeverity
        findings_json = [
            {"code": 2087, "level": "invalid_level", "message": "Test", "line": 1, "column": 1, "endLine": 1, "endColumn": 1},
            {"code": 2086, "level": "info", "message": "Good", "line": 1, "column": 1, "endLine": 1, "endColumn": 1},
        ]

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps(findings_json)

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            # Only the valid finding should be returned
            assert len(findings) == 1
            assert findings[0].code == 2086

    def test_timeout_handling(self):
        """Test timeout exception handling."""
        import subprocess  # noqa: PLC0415
        from unittest.mock import patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Reset circuit breaker
        sc._circuit_breaker_failures.clear()
        sc._circuit_breaker_open_until = 0.0

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("shellcheck", 2.0)),
        ):
            findings = sc.run_shellcheck("echo test")
            assert findings == []

        # Cleanup
        sc._circuit_breaker_failures.clear()

    def test_json_decode_error(self):
        """Test JSON decode error handling."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Reset circuit breaker
        sc._circuit_breaker_failures.clear()
        sc._circuit_breaker_open_until = 0.0

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "not valid json {"

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert findings == []

        # Cleanup
        sc._circuit_breaker_failures.clear()


class TestMessageSanitization:
    """Test message sanitization."""

    def test_sanitize_message_removes_control_chars(self):
        """Test control characters are removed from messages."""
        from schlock.integrations.shellcheck import _sanitize_message  # noqa: PLC0415

        # Control characters that should be removed
        dirty = "Hello\x00World\x1fTest\x7f"
        clean = _sanitize_message(dirty)
        assert "\x00" not in clean
        assert "\x1f" not in clean
        assert "\x7f" not in clean
        assert "HelloWorldTest" in clean

    def test_sanitize_message_truncates(self):
        """Test long messages are truncated."""
        from schlock.integrations.shellcheck import _MAX_MESSAGE_LENGTH, _sanitize_message  # noqa: PLC0415

        long_msg = "x" * (_MAX_MESSAGE_LENGTH + 100)
        result = _sanitize_message(long_msg)
        assert len(result) == _MAX_MESSAGE_LENGTH


class TestPlatformDetection:
    """Test platform-specific install instructions."""

    def test_linux_instructions(self):
        """Test Linux install instructions."""
        from unittest.mock import patch  # noqa: PLC0415

        with patch("sys.platform", "linux"):
            # Force re-evaluation
            import schlock.integrations.shellcheck as sc  # noqa: PLC0415

            result = sc.get_install_instructions()
            assert "apt" in result or "dnf" in result

    def test_darwin_instructions(self):
        """Test macOS install instructions."""
        from schlock.integrations.shellcheck import INSTALL_INSTRUCTIONS  # noqa: PLC0415

        assert "darwin" in INSTALL_INSTRUCTIONS
        assert "brew" in INSTALL_INSTRUCTIONS["darwin"]

    def test_windows_instructions(self):
        """Test Windows install instructions."""
        from schlock.integrations.shellcheck import INSTALL_INSTRUCTIONS  # noqa: PLC0415

        assert "win32" in INSTALL_INSTRUCTIONS
        assert "scoop" in INSTALL_INSTRUCTIONS["win32"] or "choco" in INSTALL_INSTRUCTIONS["win32"]


class TestShellCheckIntegration:
    """Integration tests for hook integration."""

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_hook_shellcheck_disabled_by_default(self):
        """Test that shellcheck is disabled by default in hook."""
        import sys  # noqa: PLC0415 - Test isolation
        from pathlib import Path  # noqa: PLC0415
        from unittest.mock import patch  # noqa: PLC0415

        # Add hooks to path
        sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

        import pre_tool_use  # noqa: PLC0415

        # Reset cached config
        pre_tool_use._shellcheck_config = None

        # Mock config file not existing
        with patch.object(Path, "exists", return_value=False):
            config = pre_tool_use.get_shellcheck_config()
            assert config["enabled"] is False

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_hook_shellcheck_when_enabled(self):
        """Test shellcheck integration when enabled."""
        import sys  # noqa: PLC0415 - Test isolation
        from pathlib import Path  # noqa: PLC0415
        from unittest.mock import patch  # noqa: PLC0415

        # Add hooks to path
        sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

        import pre_tool_use  # noqa: PLC0415

        # Reset cached config and mock get_shellcheck_config
        # Use severity="info" to capture SC2086 (which is info level)
        pre_tool_use._shellcheck_config = None
        enabled_config = {"enabled": True, "severity": "info", "security_only": True}

        with patch.object(pre_tool_use, "get_shellcheck_config", return_value=enabled_config):
            findings, message = pre_tool_use.run_shellcheck_analysis("echo $HOME")
            assert len(findings) > 0
            assert "SC2086" in message
