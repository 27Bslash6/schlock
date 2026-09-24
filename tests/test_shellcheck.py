"""Tests for ShellCheck integration module."""

from pathlib import Path

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
        assert findings is not None
        assert len(findings) > 0
        assert any(f.code == 2086 for f in findings)

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_run_shellcheck_clean_command(self):
        """Test that shellcheck passes clean commands."""
        # Well-quoted command should have fewer/no issues
        findings = run_shellcheck('echo "hello world"')
        assert findings is not None
        # May still have some style issues but not security
        security = get_security_findings(findings)
        assert len(security) == 0

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    def test_run_shellcheck_eval_warning(self):
        """Test that eval with variables is flagged."""
        findings = run_shellcheck('eval "$user_input"')
        assert findings is not None
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
        """An open circuit yields no verdict (None), not a clean result (LAB-4586)."""
        import time  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        # Force circuit open
        sc._circuit_breaker_open_until = time.monotonic() + 60.0

        result = sc.run_shellcheck("echo test")
        assert result is None

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
        mock_result.stdout = ""
        mock_result.stderr = "shellcheck: unrecognized option"

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")
            assert findings is None

        # Cleanup
        sc._circuit_breaker_failures.clear()

    @pytest.mark.parametrize("returncode", [0, 1, -9], ids=["exit0", "exit1", "sigkill"])
    def test_empty_output_is_no_verdict(self, returncode):
        """Empty stdout is not a clean run: `--format=json` prints `[]` when clean.

        A ShellCheck killed by a signal (negative code) or crashed with exit 1
        and nothing on stdout used to read as clean (LAB-4586, panel).
        """
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        sc._circuit_breaker_failures.clear()
        mock_result = MagicMock()
        mock_result.returncode = returncode
        mock_result.stdout = ""
        mock_result.stderr = ""

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")

        sc._circuit_breaker_failures.clear()
        assert findings is None

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
            assert findings is None

        # Cleanup
        sc._circuit_breaker_failures.clear()

    def test_no_finding_is_dropped_past_one_hundred(self):
        """A security finding after 110 inert ones is still returned.

        A 100-finding cap applied before callers filter to security codes let
        110 inert SC2034s push the SC2114 at the end off the list, and the caller
        read the empty security filter as clean (LAB-4586). There is no cap now;
        _MAX_OUTPUT_SIZE bounds the count. This pins that one is not re-added
        ahead of the filter.
        """
        import json  # noqa: PLC0415
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        inert = [
            {"code": 2034, "level": "warning", "message": f"a{i} unused", "line": 1, "column": 1, "endLine": 1, "endColumn": 1}
            for i in range(110)
        ]
        payload = {"code": 2114, "level": "warning", "message": "deletes", "line": 1, "column": 1, "endLine": 1, "endColumn": 1}

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps([*inert, payload])  # the one that matters is last

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result),
        ):
            findings = sc.run_shellcheck("echo test")

        assert findings is not None
        assert len(findings) == 111
        assert [f.code for f in sc.get_security_findings(findings)] == [2114]

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
            assert findings is not None
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
            assert findings is not None
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
            assert findings is None

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
            assert findings is None

        # Cleanup
        sc._circuit_breaker_failures.clear()


def _codes(findings):
    assert findings is not None, "ShellCheck gave no verdict (timeout or error exit)"
    return sorted(f.code for f in findings)


class TestShellCheckIgnoresCheckoutConfig:
    """The checkout and the environment cannot change what ShellCheck reports (LAB-5084).

    ShellCheck reads .shellcheckrc from the cwd, each parent dir and ~, and prepends
    SHELLCHECK_OPTS to its argv. A repo's `disable=SC2086` then switched a security code
    off, and a .shellcheckrc symlinked to /dev/zero ran every call into the timeout.
    """

    @pytest.fixture
    def dirs(self, tmp_path, monkeypatch):
        """A cwd two levels under a fake root, a fake HOME, no rc files, no SHELLCHECK_OPTS."""
        import schlock.integrations.shellcheck as sc  # noqa: PLC0415
        from schlock.core.validator import clear_caches  # noqa: PLC0415

        cwd = tmp_path / "repo" / "sub"
        cwd.mkdir(parents=True)
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.chdir(cwd)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.delenv("SHELLCHECK_OPTS", raising=False)
        monkeypatch.setattr(sc, "_circuit_breaker_failures", [])
        monkeypatch.setattr(sc, "_circuit_breaker_open_until", 0.0)
        clear_caches()
        yield {"cwd": cwd, "parent": cwd.parent, "home": home}
        clear_caches()

    def test_spawn_passes_norc_and_drops_shellcheck_opts(self, dirs, monkeypatch):
        """Binary-independent pin of the invocation: argv carries --norc, env lacks SHELLCHECK_OPTS."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415

        monkeypatch.setenv("SHELLCHECK_OPTS", "--exclude=SC2086")
        monkeypatch.setenv("SCHLOCK_LAB5084_PROBE", "kept")
        mock_result = MagicMock(returncode=0, stdout="[]", stderr="")

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=mock_result) as run,
        ):
            assert sc.run_shellcheck("echo hi") == []

        argv, env = run.call_args.args[0], run.call_args.kwargs["env"]
        assert "--norc" in argv
        assert "SHELLCHECK_OPTS" not in env
        assert env["SCHLOCK_LAB5084_PROBE"] == "kept"  # only SHELLCHECK_OPTS is dropped

    def test_binary_without_norc_gives_no_verdict(self, dirs):
        """Minimum supported ShellCheck is 0.7.0; an older one rejects --norc and gets no verdict.

        0.7.0 added --norc along with .shellcheckrc itself. Measured on the 0.6.0 release
        binary: exit 3 and this stderr. That is "no verdict", never "clean" (LAB-4586), so
        a quoted heredoc is BLOCKED rather than waved through with half its checks missing.
        """
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        import schlock.integrations.shellcheck as sc  # noqa: PLC0415
        from schlock.core.validator import validate_command  # noqa: PLC0415

        stderr = "unrecognized option `--norc'\n\nUsage: shellcheck [OPTIONS...] FILES...\n"
        pre_070 = MagicMock(returncode=3, stdout="", stderr=stderr)

        with (
            patch.object(sc, "get_shellcheck_path", return_value="/usr/bin/shellcheck"),
            patch("subprocess.run", return_value=pre_070),
        ):
            assert sc.run_shellcheck("echo hi") is None
            result = validate_command("cat <<'EOF'\nhi\nEOF")

        assert result.risk_level.name == "BLOCKED"
        assert "shellcheck:incomplete" in result.matched_rules

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    @pytest.mark.parametrize("where", ["cwd", "parent", "home"])
    @pytest.mark.parametrize("rc", ["disable=all", "disable=SC2086,SC2016,SC2046"])
    def test_rc_file_does_not_change_findings(self, dirs, where, rc):
        command = "rm -r $DIR/build"
        baseline = _codes(run_shellcheck(command))
        assert 2086 in baseline

        (dirs[where] / ".shellcheckrc").write_text(rc + "\n")

        assert _codes(run_shellcheck(command)) == baseline

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    @pytest.mark.skipif(not Path("/dev/zero").exists(), reason="no /dev/zero")
    def test_rc_symlinked_to_a_device_does_not_stall(self, dirs):
        """Before the fix ShellCheck read /dev/zero until the 2s timeout killed it (1+ GiB RSS)."""
        (dirs["cwd"] / ".shellcheckrc").symlink_to("/dev/zero")

        # Not None means it answered inside the timeout, so no wall-clock assert is needed.
        assert 2086 in _codes(run_shellcheck("rm -r $DIR/build"))

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    @pytest.mark.parametrize(("command", "code"), [("rm -r $DIR/build", 2086), ("rm -r$''f /usr", 2114)])
    def test_shellcheck_opts_does_not_change_findings(self, dirs, monkeypatch, command, code):
        baseline = _codes(run_shellcheck(command))
        assert code in baseline

        monkeypatch.setenv("SHELLCHECK_OPTS", "--exclude=SC2086,SC2114")

        assert _codes(run_shellcheck(command)) == baseline

    @pytest.mark.skipif(not is_shellcheck_available(), reason="ShellCheck not installed")
    @pytest.mark.parametrize(
        ("command", "rule"),
        [("rm -r $DIR/build", "shellcheck:SC2086"), ("rm -r$''f /usr", "shellcheck:SC2114")],
    )
    def test_rc_file_does_not_downgrade_the_verdict(self, dirs, command, rule):
        """Through validate_command: `disable=all` used to take both from BLOCKED to HIGH."""
        from schlock.core.validator import validate_command  # noqa: PLC0415

        (dirs["cwd"] / ".shellcheckrc").write_text("disable=all\n")

        result = validate_command(command)

        assert result.risk_level.name == "BLOCKED"
        assert rule in result.matched_rules


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

    def test_hook_reads_no_verdict_as_no_findings(self):
        """The hook's advisory pass keeps today's fail-open on a run with no verdict.

        run_shellcheck returns None on timeout / oversize / open circuit (LAB-4586).
        The validator's heredoc and payload spawns refuse that; this advisory layer
        does not, and the choice is pinned here so it can only change on purpose.
        """
        import sys  # noqa: PLC0415 - Test isolation
        from pathlib import Path  # noqa: PLC0415
        from unittest.mock import patch  # noqa: PLC0415

        sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

        import pre_tool_use  # noqa: PLC0415

        enabled_config = {"enabled": True, "severity": "info", "security_only": True}

        with (
            patch.object(pre_tool_use, "get_shellcheck_config", return_value=enabled_config),
            patch.object(pre_tool_use, "is_shellcheck_available", return_value=True),
            patch.object(pre_tool_use, "run_shellcheck", return_value=None),
        ):
            assert pre_tool_use.run_shellcheck_analysis("echo hi") == ([], "")
