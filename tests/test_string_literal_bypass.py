"""Test fix for Bug #1: String Literal Boundary Check.

Regression test to ensure that pattern matches are only ignored if the
ENTIRE match (both start AND end) falls within a string literal.

Also tests FIX 2: Empty quoted string range bug fix.
"""

from unittest.mock import patch

import pytest

from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel
from schlock.core.validator import clear_caches, validate_command


class TestStringLiteralBypassFix:
    """Test that string literal boundary check prevents bypasses."""

    @pytest.mark.parametrize(
        "command,should_block,description",
        [
            # Attack: Match starts inside string but ends outside
            ('echo "safe rm -rf / more"', False, "Entire pattern in string - safe"),
            ('echo "safe" rm -rf /', True, "Pattern outside string - dangerous"),
            ("echo 'safe' rm -rf /", True, "Pattern outside single quotes - dangerous"),
            ('echo "prefix rm -rf /" suffix', False, "Pattern inside quotes - safe"),
            # Edge cases
            ('echo "test" && rm -rf /', True, "Chained command outside string"),
            ('echo "rm -rf /"', False, "Just echoing - safe"),
            ("echo 'rm -rf /'", False, "Just echoing single quote - safe"),
            # Command substitution INSIDE quotes - these ARE executed by bash
            # FIX 1: Now detected by AST parser has_dangerous_constructs()
            # Previously this was a false negative, now correctly blocked
            ('echo "$(rm -rf /)"', True, "Command substitution inside quotes - now detected"),
            ('echo "`rm -rf /`"', True, "Backtick inside quotes - now detected"),
        ],
    )
    def test_string_literal_boundary_check(self, safety_rules_path, command, should_block, description):
        """String literal boundary check must verify entire match is inside."""
        result = validate_command(command, config_path=safety_rules_path)

        if should_block:
            assert not result.allowed, f"SECURITY BYPASS: {description} - Command: {command}"
            assert result.risk_level in [
                RiskLevel.HIGH,
                RiskLevel.BLOCKED,
            ], f"Expected HIGH/BLOCKED for {description}, got {result.risk_level}"
        else:
            # Should not block (false positive)
            assert result.allowed or result.risk_level in [
                RiskLevel.SAFE,
                RiskLevel.LOW,
                RiskLevel.MEDIUM,
            ], f"False positive: {description} - Command: {command}"

    def test_regression_original_bug(self, safety_rules_path):
        """Regression test for original bug report: echo 'safe" rm -rf / "more'."""
        # This was the exact attack vector - match starts in string but ends outside
        command = "echo 'safe\" rm -rf / \"more'"

        result = validate_command(command, config_path=safety_rules_path)

        # After analysis: This is actually SAFE. The single quotes wrap the entire thing.
        # In bash: echo 'safe" rm -rf / "more'
        # The outer single quotes make everything inside a literal string.
        # Double quotes inside single quotes are just literal characters.
        # So this just echoes: safe" rm -rf / "more
        # Nothing actually executes. The original bug report was theoretical, not practical.
        # The fix for boundary check is still correct for other cases.
        assert result.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM], (
            "This command is actually safe - wrapped in single quotes"
        )


class TestEmptyQuotedStringRangeFix:
    """Test FIX 2: Empty quoted string range bug.

    Bug: parser.extract_string_literals() created invalid ranges (7, 6) for
    empty strings like `echo ""`, breaking string literal protection.

    Fix: Only append ranges where start + 1 <= end - 1.
    """

    def test_empty_double_quotes_valid_ranges(self):
        """Empty double quotes should not create invalid ranges."""
        parser = BashCommandParser()
        command = 'echo "" && ls'
        ast = parser.parse(command)
        literals = parser.extract_string_literals(command, ast)

        # All ranges must be valid (start <= end)
        for start, end in literals:
            assert start <= end, f"Invalid range: ({start}, {end})"

    def test_empty_single_quotes_valid_ranges(self):
        """Empty single quotes should not create invalid ranges."""
        parser = BashCommandParser()
        command = "echo '' && ls"
        ast = parser.parse(command)
        literals = parser.extract_string_literals(command, ast)

        # All ranges must be valid
        for start, end in literals:
            assert start <= end, f"Invalid range: ({start}, {end})"

    def test_empty_string_doesnt_break_validation(self):
        """Commands with empty strings should still validate properly."""
        # The rm should be caught even though there's an empty string
        result = validate_command('echo "" && rm -rf /')
        assert not result.allowed, "rm -rf / should be blocked"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_multiple_empty_strings(self):
        """Multiple empty strings should not create invalid ranges."""
        parser = BashCommandParser()
        command = 'echo "" "" "" && ls'
        ast = parser.parse(command)
        literals = parser.extract_string_literals(command, ast)

        # All ranges must be valid
        for start, end in literals:
            assert start <= end, f"Invalid range: ({start}, {end})"

    def test_mixed_empty_and_nonempty_strings(self):
        """Mix of empty and non-empty strings should work correctly."""
        parser = BashCommandParser()
        command = 'echo "" "hello" "" "world" && ls'
        ast = parser.parse(command)
        literals = parser.extract_string_literals(command, ast)

        # All ranges must be valid
        for start, end in literals:
            assert start <= end, f"Invalid range: ({start}, {end})"

        # Should have detected the non-empty strings
        # Empty strings will not be in the list (they're skipped now)
        assert len(literals) >= 2, "Should have found at least 2 non-empty string literals"

    def test_empty_string_edge_case_positions(self):
        """Test edge case: empty string at various positions."""
        test_cases = [
            'echo ""',  # At end
            '"" && ls',  # At start
            'ls && "" && pwd',  # In middle
        ]

        parser = BashCommandParser()
        for command in test_cases:
            ast = parser.parse(command)
            literals = parser.extract_string_literals(command, ast)

            # All ranges must be valid
            for start, end in literals:
                assert start <= end, f"Invalid range in '{command}': ({start}, {end})"


class TestQuotedTokenDoesNotSuppressReconstructedPass:
    """LAB-1732: a quoted token must not disable the quote-stripped rule pass.

    The reconstructed-command pass is the only defence that catches a dangerous
    command whose *name* is quoted (bash treats `"chmod"` and `chmod`
    identically, so the quoting costs an attacker nothing). It used to be gated
    behind `if not string_literals:`, so a single quoted token anywhere -
    including the command name itself - switched the pass off for the whole
    command.

    ShellCheck is forced unavailable throughout: it independently catches some
    of these, which would mask a regression in schlock's own rule matching.
    """

    @pytest.mark.parametrize(
        "quoted,unquoted,expected_allowed,expected_risk",
        [
            ('"chmod" 777 /etc/shadow', "chmod 777 /etc/shadow", True, RiskLevel.HIGH),
            ('"dd" if=/dev/zero of=/dev/sda', "dd if=/dev/zero of=/dev/sda", False, RiskLevel.BLOCKED),
            ('"mkfs.ext4" /dev/sda', "mkfs.ext4 /dev/sda", False, RiskLevel.BLOCKED),
            # Quoted *flag* rather than quoted name - same bypass shape.
            ('rm "-rf" /', "rm -rf /", False, RiskLevel.BLOCKED),
        ],
    )
    def test_quoted_command_name_matches_unquoted_verdict(
        self, safety_rules_path, quoted, unquoted, expected_allowed, expected_risk
    ):
        """AC-1: quoting a token must not lower the verdict below its plain form."""
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            control = validate_command(unquoted, config_path=safety_rules_path)
            clear_caches()
            attack = validate_command(quoted, config_path=safety_rules_path)

        # Absolute values, not just parity: a mutation that flattens both forms
        # to SAFE must fail here rather than pass on equality.
        assert (control.allowed, control.risk_level) == (expected_allowed, expected_risk), (
            f"control drifted for {unquoted!r}: {control.allowed} {control.risk_level}"
        )
        assert (attack.allowed, attack.risk_level) == (expected_allowed, expected_risk), (
            f"SECURITY BYPASS: {quoted!r} scored {attack.risk_level} (allowed={attack.allowed}), "
            f"but {unquoted!r} scores {expected_risk}"
        )

    def test_multi_segment_reconstructs_per_segment(self, safety_rules_path):
        """AC-2: the multi-segment branch must reconstruct each segment too."""
        command = 'echo "${z:-y}" && "rm" -rf /'
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            result = validate_command(command, config_path=safety_rules_path)

        assert not result.allowed, f"SECURITY BYPASS: {command!r} was allowed (risk={result.risk_level})"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,expected_allowed,expected_risk",
        [
            # These are the false positives the old gate was protecting. The
            # quoted word covers the ENTIRE rule match in the reconstructed
            # string, so rebased literal ranges still suppress it.
            ('echo "rm -rf /"', True, RiskLevel.SAFE),
            ("echo 'rm -rf /'", True, RiskLevel.SAFE),
            ('git commit -m "fix: remove rm -rf / from docs"', True, RiskLevel.LOW),
            ('cat "rm -rf /"', True, RiskLevel.SAFE),
        ],
    )
    def test_quoted_data_verdicts_unchanged(self, safety_rules_path, command, expected_allowed, expected_risk):
        """AC-3: quoted *data* keeps its pre-fix verdict - no false-positive regression."""
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            result = validate_command(command, config_path=safety_rules_path)

        assert (result.allowed, result.risk_level) == (expected_allowed, expected_risk), (
            f"FALSE POSITIVE: {command!r} scored {result.risk_level} (allowed={result.allowed}), expected {expected_risk}"
        )
