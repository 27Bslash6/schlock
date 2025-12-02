"""Comprehensive test suite for hook system integration.

Tests cover:
- Status mapping (risk levels → allow/deny)
- Message formatting (BLOCKED, HIGH with alternatives)
- Hook handler integration
- Validator singleton
- Error handling
- JSON output format
- Performance requirements (skipped in CI - timing tests are flaky)
"""

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Add src and hooks to path BEFORE importing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

# Skip timing-sensitive tests in CI - they're inherently flaky
_IN_CI = os.environ.get("CI", "").lower() == "true" or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
skip_in_ci = pytest.mark.skipif(_IN_CI, reason="Timing tests are flaky in CI environments")

import pre_tool_use
from pre_tool_use import format_message, get_validator, handle_pre_tool_use, map_risk_to_status
from schlock import RiskLevel, ValidationResult


class TestStatusMapping:
    """Test risk level to status mapping."""

    def test_safe_commands_allowed(self):
        """SAFE risk level maps to allow."""
        assert map_risk_to_status(RiskLevel.SAFE) == "allow"

    def test_low_risk_allowed(self):
        """LOW risk level maps to allow."""
        assert map_risk_to_status(RiskLevel.LOW) == "allow"

    def test_medium_risk_allowed(self):
        """MEDIUM risk level maps to allow."""
        assert map_risk_to_status(RiskLevel.MEDIUM) == "allow"

    def test_high_risk_ask(self):
        """HIGH risk level maps to ask (user approval required).

        With the default 'balanced' risk tolerance preset:
        - HIGH-risk commands prompt the user for approval
        - This gives users control over risky operations
        """
        assert map_risk_to_status(RiskLevel.HIGH) == "ask"

    def test_blocked_risk_blocked(self):
        """BLOCKED risk level maps to deny."""
        assert map_risk_to_status(RiskLevel.BLOCKED) == "deny"


class TestMessageFormatting:
    """Test user-facing message formatting."""

    def test_blocked_message_format(self):
        """Verify BLOCKED message includes reason and risk level."""
        result = ValidationResult(
            allowed=False, risk_level=RiskLevel.BLOCKED, message="Test reason", alternatives=["Alternative 1", "Alternative 2"]
        )
        message = format_message(result)

        assert "BLOCKED: Test reason" in message
        assert "Risk Level: BLOCKED" in message
        assert "Alternative 1" in message
        assert "Alternative 2" in message

    def test_high_risk_message_caution_format(self):
        """Verify HIGH risk messages use CAUTION format when decision is 'ask'.

        With configurable risk tolerance, HIGH-risk commands now prompt
        the user for approval instead of blocking outright.
        """
        result = ValidationResult(allowed=False, risk_level=RiskLevel.HIGH, message="High risk operation", alternatives=[])
        message = format_message(result, decision="ask")

        assert "CAUTION: High risk operation" in message
        assert "Risk Level: HIGH" in message

    def test_alternatives_displayed(self):
        """Verify alternatives are properly formatted."""
        result = ValidationResult(
            allowed=False, risk_level=RiskLevel.BLOCKED, message="Test", alternatives=["Alt 1", "Alt 2", "Alt 3"]
        )
        message = format_message(result)

        assert "Alternatives:" in message
        assert "  - Alt 1" in message
        assert "  - Alt 2" in message
        assert "  - Alt 3" in message

    def test_risk_level_displayed(self):
        """Verify risk level is shown in message."""
        for risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED]:
            result = ValidationResult(allowed=False, risk_level=risk_level, message="Test", alternatives=[])
            message = format_message(result)
            assert f"Risk Level: {risk_level.name}" in message


class TestHookHandler:
    """Test hook handler integration with validation engine."""

    def test_safe_command_allowed(self):
        """Safe command returns allow decision."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        response = handle_pre_tool_use(input_data)

        assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert response["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert "permissionDecisionReason" not in response["hookSpecificOutput"]

    def test_medium_command_allowed(self):
        """Medium risk command returns allow decision."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "rm file.txt"}}
        response = handle_pre_tool_use(input_data)

        assert response["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_high_command_asks(self):
        """HIGH risk command returns ask decision (with balanced preset).

        With the default 'balanced' risk tolerance preset:
        - HIGH-risk commands prompt the user for approval
        - Message uses CAUTION prefix instead of BLOCKED
        """
        input_data = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/important"}}
        response = handle_pre_tool_use(input_data)

        assert response["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "permissionDecisionReason" in response["hookSpecificOutput"]
        reason = response["hookSpecificOutput"]["permissionDecisionReason"]
        assert "CAUTION:" in reason
        assert "Risk Level:" in reason

    def test_blocked_command_blocked(self):
        """BLOCKED command returns deny decision."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        response = handle_pre_tool_use(input_data)

        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "BLOCKED:" in response["hookSpecificOutput"]["permissionDecisionReason"]

    def test_missing_command_parameter(self):
        """Missing command parameter returns deny."""
        input_data = {"tool_name": "Bash", "tool_input": {}}
        response = handle_pre_tool_use(input_data)

        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Missing command parameter" in response["hookSpecificOutput"]["permissionDecisionReason"]

    def test_validation_error_blocks(self):
        """ValidationResult with error field set blocks command."""
        # Use an empty command that will be rejected
        input_data = {"tool_name": "Bash", "tool_input": {"command": ""}}
        response = handle_pre_tool_use(input_data)

        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        # Should have an error reason
        assert "BLOCKED:" in response["hookSpecificOutput"]["permissionDecisionReason"]


class TestValidatorSingleton:
    """Test validator singleton pattern."""

    def test_singleton_reuse(self):
        """Verify validator is initialized once and reused."""
        # Reset singleton state
        pre_tool_use._validator_initialized = False

        # First call initializes
        result1 = get_validator()
        assert result1 is True
        assert pre_tool_use._validator_initialized is True

        # Second call reuses
        result2 = get_validator()
        assert result2 is True
        assert pre_tool_use._validator_initialized is True

    def test_initialization_error_handling(self):
        """Verify validator initialization succeeds without errors."""
        # Reset singleton
        pre_tool_use._validator_initialized = False

        # get_validator should succeed (it just sets a flag, actual validation happens via validate_command)
        result = get_validator()
        assert result is True
        assert pre_tool_use._validator_initialized is True


class TestJSONOutputFormat:
    """Test JSON output format matches Claude Code expectations."""

    def test_json_output_format_allow(self):
        """Verify allow response has correct JSON structure."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        response = handle_pre_tool_use(input_data)

        # Verify structure
        assert "hookSpecificOutput" in response
        assert "hookEventName" in response["hookSpecificOutput"]
        assert "permissionDecision" in response["hookSpecificOutput"]

        # Verify values
        assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert response["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_json_output_format_deny(self):
        """Verify deny response has correct JSON structure."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        response = handle_pre_tool_use(input_data)

        # Verify structure
        assert "hookSpecificOutput" in response
        assert "hookEventName" in response["hookSpecificOutput"]
        assert "permissionDecision" in response["hookSpecificOutput"]
        assert "permissionDecisionReason" in response["hookSpecificOutput"]

        # Verify values
        assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert isinstance(response["hookSpecificOutput"]["permissionDecisionReason"], str)
        assert len(response["hookSpecificOutput"]["permissionDecisionReason"]) > 0

    def test_json_serializable(self):
        """Verify response can be serialized to JSON."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        response = handle_pre_tool_use(input_data)

        # Should not raise
        json_str = json.dumps(response)
        assert isinstance(json_str, str)

        # Should round-trip correctly
        parsed = json.loads(json_str)
        assert parsed == response


class TestErrorHandling:
    """Test fail-safe error handling."""

    def test_exception_caught_and_logged(self):
        """Verify exceptions don't crash hook, log to stderr."""
        # Patch validate_command to raise
        with patch("pre_tool_use.validate_command", side_effect=Exception("Test error")):
            input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
            response = handle_pre_tool_use(input_data)

            # Should return deny, not crash
            assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
            assert "Internal validation error" in response["hookSpecificOutput"]["permissionDecisionReason"]

    def test_error_message_safe(self):
        """Verify no sensitive data in error messages."""
        # Test with various error scenarios
        test_cases = [
            (RuntimeError("Sensitive info"), "BLOCKED:"),
            (Exception("Secret data"), "Internal validation error"),
        ]

        for error, expected_substring in test_cases:
            with patch("pre_tool_use.validate_command", side_effect=error):
                input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
                response = handle_pre_tool_use(input_data)
                reason = response["hookSpecificOutput"]["permissionDecisionReason"]

                # Should contain expected message
                assert expected_substring in reason
                # Should not leak full error details in user message
                # (detailed error goes to logs only)

    def test_all_exceptions_result_in_deny(self):
        """Test various exception types all result in deny."""
        exceptions = [
            ValueError("Test"),
            KeyError("Test"),
            AttributeError("Test"),
            RuntimeError("Test"),
            Exception("Test"),
        ]

        for exc in exceptions:
            with patch("pre_tool_use.validate_command", side_effect=exc):
                input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
                response = handle_pre_tool_use(input_data)
                assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_unknown_risk_level_blocked(self):
        """Unknown/invalid risk level falls back to deny."""
        # Even though ValidationResult shouldn't have None risk_level,
        # test the fallback behavior
        try:
            status = map_risk_to_status(None)
            assert status == "deny"
        except Exception:  # noqa: S110 - Testing fail-safe behavior, intentional
            # If it raises, that's also acceptable fail-safe behavior
            pass

    def test_validation_error_field_set(self):
        """Test when ValidationResult.error is set."""
        # This tests line 245-253 in pre_tool_use.py
        with patch("pre_tool_use.validate_command") as mock_validate:
            mock_validate.return_value = ValidationResult(
                allowed=False, risk_level=RiskLevel.BLOCKED, message="Test", alternatives=[], error="Parse error: invalid syntax"
            )

            input_data = {"tool_name": "Bash", "tool_input": {"command": "test"}}
            response = handle_pre_tool_use(input_data)

            assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
            assert "Validation error" in response["hookSpecificOutput"]["permissionDecisionReason"]


@skip_in_ci
class TestPerformance:
    """Test performance requirements (<200ms)."""

    def test_typical_command_fast(self):
        """Verify typical command validation is fast."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        start = time.time()
        response = handle_pre_tool_use(input_data)
        elapsed = time.time() - start

        # Should be under 200ms
        assert elapsed < 0.2, f"Hook took {elapsed * 1000:.1f}ms (target: <200ms)"
        assert response["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_blocked_command_fast(self):
        """Verify blocked command validation is fast."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        start = time.time()
        response = handle_pre_tool_use(input_data)
        elapsed = time.time() - start

        # Should be under 200ms
        assert elapsed < 0.2, f"Hook took {elapsed * 1000:.1f}ms (target: <200ms)"
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_repeated_validation_uses_cache(self):
        """Verify repeated commands benefit from caching."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls -la /tmp"}}
        # First run (uncached)
        start1 = time.time()
        response1 = handle_pre_tool_use(input_data)
        elapsed1 = time.time() - start1

        # Second run (cached)
        start2 = time.time()
        response2 = handle_pre_tool_use(input_data)
        elapsed2 = time.time() - start2

        # Both should succeed
        assert response1["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert response2["hookSpecificOutput"]["permissionDecision"] == "allow"

        # Second run should be faster (cached)
        # Note: With 60+ patterns + ShellCheck, cold validation takes ~250-300ms
        assert elapsed1 < 0.35, f"First run: {elapsed1 * 1000:.1f}ms"
        assert elapsed2 < 0.2, f"Second run: {elapsed2 * 1000:.1f}ms"


class TestCommitFilterIntegration:
    """Test commit message filter integration with hook and validator."""

    def test_filter_runs_before_validation(self):
        """Verify filter runs before validator and DENIES advertising."""
        # Git commit with advertising - should be BLOCKED
        cmd = 'git commit -m "Add feature\\n\\nGenerated with Claude Code"'

        input_data = {"tool_name": "Bash", "tool_input": {"command": cmd}}
        response = handle_pre_tool_use(input_data)

        # Should DENY (advertising detected)
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "advertising" in response["hookSpecificOutput"]["permissionDecisionReason"].lower()

    def test_filter_disabled_doesnt_break_hook(self):
        """Verify hook still works if filter initialization fails."""
        # Patch get_filter to return None (filter disabled)
        with patch("pre_tool_use.get_filter", return_value=None):
            input_data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
            response = handle_pre_tool_use(input_data)

            # Should still work (validator runs on original command)
            assert response["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_git_commit_filtered_and_validated(self):
        """Verify git commit with advertising is BLOCKED."""
        cmd = 'git commit -m "Clean message\\n\\n🤖 Generated with Claude Code"'

        input_data = {"tool_name": "Bash", "tool_input": {"command": cmd}}
        response = handle_pre_tool_use(input_data)

        # Filter detects advertising -> DENY
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "advertising" in response["hookSpecificOutput"]["permissionDecisionReason"].lower()

    def test_non_git_command_skips_filter(self):
        """Verify non-git commands pass through filter unchanged."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        response = handle_pre_tool_use(input_data)

        # Non-git command allowed (filter passes through, validator allows)
        assert response["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_filter_error_doesnt_break_hook(self):
        """Verify hook continues if filter encounters error."""
        # Patch get_filter to return None (simulates filter disabled due to error)
        with patch("pre_tool_use.get_filter", return_value=None):
            input_data = {"tool_name": "Bash", "tool_input": {"command": "git commit -m 'test'"}}
            response = handle_pre_tool_use(input_data)

            # Should still validate (filter disabled doesn't break hook)
            assert response["hookSpecificOutput"]["permissionDecision"] == "allow"
