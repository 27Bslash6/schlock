"""Test fix for Bug #1: String Literal Boundary Check.

Regression test to ensure that pattern matches are only ignored if the
ENTIRE match (both start AND end) falls within a string literal.

Also tests FIX 2: Empty quoted string range bug fix.
"""

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


class TestQuotedCommandNameBypass:
    """LAB-1732: a quoted token anywhere must not disable the quote-stripped rule pass.

    ``"chmod" 777 /etc/shadow`` executes exactly like ``chmod 777 /etc/shadow``; the
    reconstructed (quote-stripped) pass is the only check that sees it, and it used to be
    gated off by ``if not string_literals:`` -- so quoting *anything* hid the whole command.

    ShellCheck is forced unavailable so the verdict comes from the rule engine alone, and
    the expected values are pinned ABSOLUTELY (not "same tier as control") so a mutation
    that weakens both sides together still fails.
    """

    @pytest.fixture(autouse=True)
    def _no_shellcheck(self, monkeypatch):
        monkeypatch.setattr("schlock.core.validator.is_shellcheck_available", lambda: False)
        clear_caches()
        yield
        clear_caches()

    @pytest.mark.parametrize(
        "command,expected_risk",
        [
            # AC-1: quoted command name reaches the unquoted control's risk level
            ('"chmod" 777 /etc/shadow', RiskLevel.HIGH),
            ("'chmod' 777 /etc/shadow", RiskLevel.HIGH),
            ('"dd" if=/dev/zero of=/dev/sda', RiskLevel.BLOCKED),
            ('"mkfs.ext4" /dev/sda', RiskLevel.BLOCKED),
            ("'rm' -rf /", RiskLevel.BLOCKED),
            # behind an exec wrapper the quoted token IS the command (panel finding on this fix)
            ('env "mkfs.ext4" /dev/sda', RiskLevel.BLOCKED),
            ('nice "wipefs" -a /dev/sda', RiskLevel.BLOCKED),
            ('timeout 10 "mkswap" /dev/sda', RiskLevel.BLOCKED),
            # controls
            ("chmod 777 /etc/shadow", RiskLevel.HIGH),
            ("dd if=/dev/zero of=/dev/sda", RiskLevel.BLOCKED),
            ("mkfs.ext4 /dev/sda", RiskLevel.BLOCKED),
        ],
    )
    def test_quoted_command_name_matches_unquoted_risk(self, safety_rules_path, command, expected_risk):
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == expected_risk, f"{command!r}: got {result.risk_level}, want {expected_risk}"

    @pytest.mark.parametrize(
        "command",
        [
            # AC-2: multi-segment branch reconstructs per segment too
            'echo "${z:-y}" && "rm" -rf /',
            'echo "x" | "rm" -rf /',
            'true; "mkfs.ext4" /dev/sda',
        ],
    )
    def test_quoted_name_in_later_segment_is_denied(self, safety_rules_path, command):
        result = validate_command(command, config_path=safety_rules_path)
        assert result.allowed is False, f"{command!r} was allowed"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,expected_allowed,expected_risk",
        [
            # AC-3: quoted DATA keeps its pre-fix verdict (pinned on main @ 1353f73)
            ('echo "rm -rf /"', True, RiskLevel.SAFE),
            ('git commit -m "fix: remove rm -rf / from docs"', True, RiskLevel.LOW),
            ('cat "rm -rf /"', True, RiskLevel.SAFE),
            ("echo 'rm -rf /'", True, RiskLevel.SAFE),
            ('echo "mkfs.ext4 /dev/sda"', True, RiskLevel.SAFE),
            ('echo "a\\"b" tail', True, RiskLevel.SAFE),
        ],
    )
    def test_quoted_data_keeps_verdict(self, safety_rules_path, command, expected_allowed, expected_risk):
        result = validate_command(command, config_path=safety_rules_path)
        assert result.allowed is expected_allowed, f"{command!r}: allowed={result.allowed}"
        assert result.risk_level == expected_risk, f"{command!r}: got {result.risk_level}, want {expected_risk}"

    @pytest.mark.parametrize(
        "quoted,unquoted,expected_risk",
        [
            # ACCEPTED false-positive shifts: a quoted single token, or a quoted word a rule reads
            # past, now classifies exactly like its unquoted form. Pinned so the shift is a
            # decision, not drift. (pre-fix main: SAFE / SAFE / HIGH / LOW / SAFE)
            ('echo "mkfs"', "echo mkfs", RiskLevel.BLOCKED),
            ('echo "mkfs.xfs" /dev/sda', "echo mkfs.xfs /dev/sda", RiskLevel.BLOCKED),
            ('echo "chmod" 777 x', "echo chmod 777 x", RiskLevel.HIGH),
            ('git commit -m "wipefs"', "git commit -m wipefs", RiskLevel.BLOCKED),
            ('echo "rm" "-rf" "/"', "echo rm -rf /", RiskLevel.BLOCKED),
        ],
    )
    def test_quoted_token_has_parity_with_unquoted(self, safety_rules_path, quoted, unquoted, expected_risk):
        assert validate_command(quoted, config_path=safety_rules_path).risk_level == expected_risk
        assert validate_command(unquoted, config_path=safety_rules_path).risk_level == expected_risk


class TestReconstructWithLiterals:
    """Ranges are rebased onto the reconstructed string; the name and single tokens are never data."""

    @pytest.mark.parametrize(
        "command,expected_text,expected_literals",
        [
            ('"chmod" 777 /etc/shadow', "chmod 777 /etc/shadow", []),
            # ranges are widened onto the separators that replace the quote chars (clamped at the ends)
            ('echo "rm -rf /"', "echo rm -rf /", [(4, 13)]),
            ("echo 'rm -rf /'", "echo rm -rf /", [(4, 13)]),
            ('echo "rm -rf /" tail', "echo rm -rf / tail", [(4, 14)]),
            # escape inside quotes: word text shrinks, range follows the reconstructed text
            ('echo "a\\" b" tail', 'echo a" b tail', [(4, 10)]),
            # a quoted single token is not data: unquoted argv is identical, and behind a
            # wrapper it is the command
            ('echo "a\\"b" tail', 'echo a"b tail', []),
            ('env "mkswap" /dev/sda', "env mkswap /dev/sda", []),
            ('echo "mkfs"', "echo mkfs", []),
            # assignment prefix: the first *word* is the name, not the assignment
            ('FOO=bar "rm" -rf /', "FOO=bar rm -rf /", []),
            # partially quoted word is not a literal
            ('r"m" -rf /', "rm -rf /", []),
            ('echo "" tail', "echo  tail", []),
            ("rm\\ -rf\\ /", "rm -rf /", []),
        ],
    )
    def test_reconstruct_with_literals(self, parser, command, expected_text, expected_literals):
        ast = parser.parse(command)
        text, literals = parser.reconstruct_with_literals(command, ast)
        assert text == expected_text
        assert literals == expected_literals

    def test_empty_ast(self, parser):
        assert parser.reconstruct_with_literals("", []) == ("", [])
        assert parser.reconstruct_with_literals("", None) == ("", [])
