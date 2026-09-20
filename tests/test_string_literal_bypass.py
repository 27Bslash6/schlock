"""Test fix for Bug #1: String Literal Boundary Check.

Regression test to ensure that pattern matches are only ignored if the
ENTIRE match (both start AND end) falls within a string literal.

Also tests FIX 2: Empty quoted string range bug fix.
"""

import re

import pytest

from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import validate_command


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


class TestSuppressionIsPerOccurrence:
    """A suppressed occurrence must not disable its rule for the whole command.

    `RuleEngine.match_command` used `pattern.search`, which yields only the
    FIRST occurrence. When that one sat inside a quoted string the code moved
    straight on to the next pattern, so every later occurrence - including
    unquoted, executable ones - went unexamined. Quoting a decoy up front
    therefore disarmed the rule for the rest of the command (LAB-4321).

    `rm -rf /` does not guard this: `system_destruction` carries two patterns
    that match at different offsets, so a second pattern still catches the
    payload. `fork_bomb`'s patterns both match at the decoy, and the payload
    fragments under segment-by-segment validation, so it is the shape that
    actually exercises the leak.
    """

    FORK_BOMB = ":(){ :|:& };:"

    def test_quoted_decoy_does_not_hide_a_later_unquoted_danger(self, rules_dir_path):
        """Suppression is per-occurrence: the range covers the decoy, not the payload."""
        engine = RuleEngine(rules_dir_path)
        command = f"cat '{self.FORK_BOMB}'\n{self.FORK_BOMB}"
        start = command.index("'")
        end = command.index("'", start + 1) + 1

        match = engine.match_command(command, string_literals=[(start, end)])

        assert match.matched, "quoted decoy suppressed the rule for the unquoted fork bomb"
        assert match.risk_level == RiskLevel.BLOCKED

    def test_non_shell_heredoc_decoy_does_not_hide_a_later_danger(self, rules_dir_path):
        """Same leak via the other suppression range: heredoc body, then real payload."""
        body_start = len("cat <<'EOF'\n")
        command = f"cat <<'EOF'\n{self.FORK_BOMB}\nEOF\n{self.FORK_BOMB}"
        body_end = body_start + len(self.FORK_BOMB)

        match = RuleEngine(rules_dir_path).match_command(command, heredoc_ranges=[(body_start, body_end, False)])

        assert match.matched, "heredoc decoy suppressed the rule for the payload after the terminator"
        assert match.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "start_delta,is_shell,expect_match,description",
        [
            # Running out of occurrences is an answer, not a failure to find one:
            # the scan looks past a suppressed match because a later one may be
            # executable, and when none is it must exhaust and report nothing.
            (0, False, False, "inert body, sole occurrence - stays suppressed"),
            # The discriminator, in the under-block direction. A shell runs its
            # heredoc body, so the identical text must still match.
            (0, True, True, "same body fed to a shell - it executes, so it matches"),
            # Containment is both-ended, like `_is_in_string_literal`. A range
            # opening inside the match does not cover it and cannot excuse it.
            (4, False, True, "range opens mid-match - not covered, not inert"),
        ],
    )
    def test_heredoc_suppression_covers_exactly_the_inert_body(
        self, rules_dir_path, start_delta, is_shell, expect_match, description
    ):
        """Every decision `_is_in_non_shell_heredoc` makes, pinned in the direction that fails.

        None of the three had a guard that could go red. Disabling the heredoc
        arm of `_first_executable_match`, making `_is_in_non_shell_heredoc`
        ignore `is_shell`, or dropping its `start <= match_start` bound each
        left the whole suite green. The end-to-end row for the same shape
        (`tests/test_dangerous_commands.py`, "Heredoc with rm -rf") passes
        today, but its helper answers a false positive with `pytest.skip`, so
        on any of these regressions it degrades to a skip rather than a
        failure and can never pin this branch.

        Ranges come from the parser rather than hand-counted offsets: it emits
        `(10, 27, False)` here, running through the terminator line, so a
        hand-built body-only range would be testing a shape production never
        produces.
        """
        command = f"cat <<EOF\n{self.FORK_BOMB}\nEOF"
        parser = BashCommandParser()
        ((start, end, _),) = parser.extract_heredoc_ranges(command, parser.parse(command))

        match = RuleEngine(rules_dir_path).match_command(command, heredoc_ranges=[(start + start_delta, end, is_shell)])

        assert match.matched is expect_match, description
        if expect_match:
            assert match.risk_level == RiskLevel.BLOCKED, description
            assert match.rule is not None and match.rule.name == "fork_bomb", description
        else:
            assert match.risk_level == RiskLevel.SAFE, description
            # Not the whitelist short-circuit, which returns the same (False, SAFE) pair.
            assert match.message == "No security rules matched", description

    @pytest.mark.parametrize(
        "template,description",
        [
            # Leaked on `main` itself: the parser derives a literal for the decoy,
            # the newline stops the pattern spanning both, and the payload after
            # it was never looked at. Rated SAFE and ALLOWED before the fix.
            ("cat '{bomb}'\n{bomb}", "quoted decoy, payload on the next line"),
            # Blocked on `main` only by accident - it cannot derive a literal for
            # the segment, so it matches the DECOY rather than the payload. Once
            # the heredoc's ranges are rebased off the parent AST the decoy is
            # correctly suppressed, which is what un-gated the defect.
            ("cat '{bomb}' <<'EOF'\nbody\nEOF\n{bomb}", "canonical opener"),
        ],
    )
    def test_quoted_decoy_does_not_hide_the_payload_end_to_end(self, safety_rules_path, template, description):
        """End to end, through the parser that derives the suppression ranges."""
        command = template.format(bomb=self.FORK_BOMB)

        result = validate_command(command, config_path=safety_rules_path)

        assert result.risk_level == RiskLevel.BLOCKED, description
        assert result.allowed is False, description

    def test_scan_advances_one_char_so_an_overlapping_match_survives(self, rules_dir_path):
        """The scan steps by `match.start() + 1`, not `match.end()`.

        A later match that OVERLAPS the suppressed one starts before it ends, so
        resuming at `end()` steps straight over it - which is what `re.finditer`
        does. Greedy bounded quantifiers make this reachable with the shipped
        rules: a later-starting match can reach a target the first one cannot.
        Pinned on a synthetic pattern so it states the helper's contract rather
        than a rule file's current wording.
        """
        engine = RuleEngine(rules_dir_path)
        pattern = re.compile(r"A.{0,3}B")
        command = "AA..BB"
        assert [m.span() for m in pattern.finditer(command)] == [(0, 5)], "finditer stops after the first"

        match = engine._first_executable_match(pattern, command, [(0, 5)], None)

        assert match is not None, "an overlapping executable match was stepped over"
        assert match.span() == (1, 6)

    @pytest.mark.parametrize(
        "unit,expected,description",
        [
            # Under-block: `validate_command` runs its cross-segment scan ONLY when no
            # segment matched, so a bogus segment match hides the BLOCKED the whole
            # command earns. `_segment_nodes` fragments the fork bomb, so that scan is
            # the only thing that sees it.
            ("pip install -r requirements.txt", RiskLevel.BLOCKED, "decoy padding must not hide a later payload"),
            # Over-block: the same inert text with nothing dangerous after it is a
            # command a user may legitimately run.
            (None, RiskLevel.SAFE, "inert padding alone is not dangerous"),
        ],
    )
    def test_padding_a_literal_changes_no_verdict(self, safety_rules_path, unit, expected, description):
        """The scan never gives up early, at any repetition count.

        A bounded scan has to report something on exhaustion and both answers are
        wrong: the last suppressed match denies benign text and masks a higher
        verdict elsewhere in the command, while None lets padding silence the rule.
        40 repeats is past any bound worth writing; 31 is inside one, so the pair
        fails on a bounded implementation and passes on an exact one.
        """
        padding = " ".join(["sudo apt-get install -y pkg" if unit is None else unit] * 40)
        command = f"echo '{padding}'" + ("" if unit is None else f" && {self.FORK_BOMB}")

        result = validate_command(command, config_path=safety_rules_path)

        assert result.risk_level == expected, f"{description}: got {result.risk_level.name}"

    @pytest.mark.parametrize(
        "command,literal,description",
        [
            ('echo "rm -rf /"', slice(5, 15), "double-quoted decoy, no payload"),
        ],
    )
    def test_sole_occurrence_is_still_suppressed(self, rules_dir_path, command, literal, description):
        """Per-occurrence scanning must not break suppression when there is only one."""
        match = RuleEngine(rules_dir_path).match_command(command, string_literals=[(literal.start, literal.stop)])

        assert not match.matched, f"false positive: {description} - {command}"
        assert match.risk_level == RiskLevel.SAFE
