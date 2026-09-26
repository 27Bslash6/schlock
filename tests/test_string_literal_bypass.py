"""Test fix for Bug #1: String Literal Boundary Check.

Regression test to ensure that pattern matches are only ignored if the
ENTIRE match (both start AND end) falls within a string literal.

Also tests FIX 2: Empty quoted string range bug fix.
"""

import re
from unittest.mock import patch

import pytest

from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import clear_caches, validate_command
from schlock.exceptions import ParseError


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

    `rm -rf /` does not guard this: `system_destruction`'s `[^;|&]` run crosses
    the newline, so its first match starts inside the decoy, ends at the payload,
    and is never suppressed. The one `fork_bomb` pattern that matches this
    spelling matches wholly inside the decoy, and the payload fragments under
    segment-by-segment validation, so it is the shape that actually exercises
    the leak.
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
        command = f"cat <<EOF\n{self.FORK_BOMB}\nEOF\n{self.FORK_BOMB}"
        parser = BashCommandParser()
        heredoc_ranges = parser.extract_heredoc_ranges(command, parser.parse(command))

        match = RuleEngine(rules_dir_path).match_command(command, heredoc_ranges=heredoc_ranges)

        assert match.matched, "heredoc decoy suppressed the rule for the payload after the terminator"
        assert match.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "start_delta,is_shell,expect_match,description",
        [
            # An inert non-shell heredoc body is suppressed.
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

        Each row kills its own mutant: disabling the heredoc arm of
        `_first_executable_match`, making `_is_in_non_shell_heredoc` ignore
        `is_shell`, or dropping its `start <= match_start` bound. The last has no
        other guard - without it, the rest of the suite stays green. The end-to-end
        row for the same shape (`tests/test_dangerous_commands.py`, "Heredoc with
        rm -rf") cannot stand in: its helper answers a false positive with
        `pytest.skip`, so it degrades to a skip on the heredoc-arm regression and
        passes outright on the other two.

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
            # The parser derives a literal for the decoy and the newline stops the
            # pattern spanning both, so only a scan past the decoy reaches the payload.
            ("cat '{bomb}'\n{bomb}", "quoted decoy, payload on the next line"),
            # The same through a heredoc segment: the decoy is suppressed as data,
            # and only the per-occurrence scan reaches the payload.
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


class TestQuotedTokenDoesNotSuppressReconstructedPass:
    """LAB-1732: a quoted token must not disable the quote-stripped rule pass.

    The reconstructed-command pass is the only defence that catches a dangerous
    command whose *name* is quoted (bash treats `"chmod"` and `chmod`
    identically, so the quoting costs an attacker nothing). It used to be gated
    behind `if not string_literals:`, so a single quoted token anywhere -
    including the command name itself - switched the pass off for the whole
    command.

    Suppression now turns on whether a word's quotes DO anything, not on where
    the word sits, which is what covers the exec-wrapper forms below.

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

    def test_heredoc_segment_still_reconstructs(self, safety_rules_path):
        """AC-2 via heredoc: the body sits past the command's span, so the bare
        segment slice did not re-parse and the reconstructed pass was skipped -
        the original bug back through a side door. Found by CodeRabbit on #145.
        """
        quoted = 'echo hi && "chmod" 777 /etc/shadow <<EOF\nfoo\nEOF'
        unquoted = "echo hi && chmod 777 /etc/shadow <<EOF\nfoo\nEOF"
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            control = validate_command(unquoted, config_path=safety_rules_path)
            clear_caches()
            attack = validate_command(quoted, config_path=safety_rules_path)

        assert (control.allowed, control.risk_level) == (True, RiskLevel.HIGH), f"control drifted: {control.risk_level}"
        assert (attack.allowed, attack.risk_level) == (True, RiskLevel.HIGH), (
            f"SECURITY BYPASS: {quoted!r} scored {attack.risk_level} (allowed={attack.allowed})"
        )

    @pytest.mark.parametrize(
        "command,expected_allowed,expected_risk",
        [
            # Everyday heredoc pipe: must not trip the fail-closed segment branch.
            ("cat <<EOF | grep x\nhello\nEOF", True, RiskLevel.SAFE),
            # The segment suppresses its body; the whole-command scan does not, and
            # it now runs whatever the segments matched. Same verdict as the command
            # without `&& chmod`.
            ("cat <<EOF | grep x && chmod 777 f\nrm -rf /\nEOF", False, RiskLevel.BLOCKED),
            # A shell's heredoc body is code. Was HIGH (body never reached the
            # segment); now matches the single-segment `bash <<EOF` verdict.
            ("bash <<EOF | tee log\nrm -rf /\nEOF", False, RiskLevel.BLOCKED),
            # A heredoc NESTED in a substitution is not a direct redirect, so
            # _close_heredocs never sees it and it rides inside the outer
            # segment's slice. Its range is derived off the parent AST (LAB-912);
            # inside `<( … )` that range is is_shell - whatever reads the
            # substitution may run it - so the body is scanned as code.
            ("diff /dev/null <(cat <<EOF\nrm -rf /\nEOF\n); chmod +x x", False, RiskLevel.BLOCKED),
        ],
    )
    def test_heredoc_segment_verdicts(self, safety_rules_path, command, expected_allowed, expected_risk):
        """Segments carry their heredoc bodies and get per-segment heredoc suppression."""
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            result = validate_command(command, config_path=safety_rules_path)

        assert (result.allowed, result.risk_level) == (expected_allowed, expected_risk), (
            f"{command!r} scored {result.risk_level} (allowed={result.allowed}), expected {expected_risk}"
        )

    def test_no_segment_is_re_parsed_so_none_can_lose_its_reconstructed_pass(self, safety_rules_path, monkeypatch):
        """The gap this class exists to close is now shut structurally (LAB-912).

        The under-block was a segment reaching the rules with no AST: no literal
        suppression, no quote-stripped pass, so `"chmod" 777 /etc/shadow` scored
        SAFE. The first fix re-parsed each segment and failed closed when that
        threw. Segments now derive both their literals and their reconstruction
        from the parent AST (spec §3.2 parse-once), so there is no second parse
        left to fail - which is why the fail-closed branch that guarded one is
        gone rather than dropped.

        Forcing every parse but the whole command's to raise must therefore
        change nothing, and the quoted command name must still be caught.
        """
        real_parse = BashCommandParser.parse
        command = 'echo one && "chmod" 777 /etc/shadow'
        parsed = []

        def parse_recording(self, target):
            parsed.append(target)
            if target != command:
                raise ParseError(f"no segment may be re-parsed, got {target!r}")
            return real_parse(self, target)

        monkeypatch.setattr(BashCommandParser, "parse", parse_recording)
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            result = validate_command(command, config_path=safety_rules_path)

        assert parsed == [command], f"re-parsed {parsed[1:]}"
        assert (result.risk_level, result.matched_rules) == (RiskLevel.HIGH, ["chmod_777"])

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

    @pytest.mark.parametrize(
        "wrapper",
        [
            "env FOO=1",
            "timeout 5",
            "nice",
            "command",
            "nohup",
            "setsid",
            "stdbuf",
        ],
    )
    def test_quoted_name_behind_exec_wrapper(self, safety_rules_path, wrapper):
        """Bash executes a word that is NOT in command-name position here.

        Keying suppression off "is this parts[0]" missed all of these: the
        payload name is an *argument* of the wrapper, so it got a suppression
        range and `\\bmkfs\\b` - a pattern that fits entirely inside that one
        word - was swallowed whole. Found by the LAB-1732 expert panel.
        """
        attack = f'{wrapper} "mkfs.ext4" /dev/sda'
        control = f"{wrapper} mkfs.ext4 /dev/sda"
        with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
            clear_caches()
            attack_result = validate_command(attack, config_path=safety_rules_path)
            clear_caches()
            control_result = validate_command(control, config_path=safety_rules_path)

        assert (control_result.allowed, control_result.risk_level) == (False, RiskLevel.BLOCKED), (
            f"control drifted for {control!r}: {control_result.risk_level}"
        )
        assert (attack_result.allowed, attack_result.risk_level) == (False, RiskLevel.BLOCKED), (
            f"SECURITY BYPASS: {attack!r} scored {attack_result.risk_level} (allowed={attack_result.allowed})"
        )

    @pytest.mark.parametrize(
        "command,span,expected",
        [
            ('"abc"', (0, 5), True),
            ("'abc'", (0, 5), True),
            # Partial quoting: the outermost chars do not both belong to one quote
            ('x"y"', (0, 4), False),
            ('"a"b', (0, 4), False),
            ("'a'\"b\"", (0, 6), False),
            # A single quote char is not a quoted span - `end - start < 2`
            ('"', (0, 1), False),
            # Out-of-bounds spans must not raise
            ("abc", (5, 9), False),
        ],
    )
    def test_is_quoted_span_requires_both_ends(self, parser, command, span, expected):
        """Both ends must belong to the SAME quote pair.

        Pinned because this helper gates suppression on both the original and
        the reconstructed pass, so widening it (e.g. testing only the first
        character) silently widens suppression twice over - a mutation the
        LAB-1732 panel found surviving the whole suite.
        """
        assert parser._is_quoted_span(command, span) is expected

    @pytest.mark.parametrize(
        "word,expected",
        [
            # Bare tokens: quotes are pure obfuscation, bash runs them the same
            ("mkfs.ext4", False),
            ("rm", False),
            ("-rf", False),
            # Quotes do real work: without them this would not be one word
            ("rm -rf /", True),
            ("fix: remove rm -rf / from docs", True),
            ("a;b", True),
            ("a|b", True),
            ("$(x)", True),
        ],
    )
    def test_quoting_is_load_bearing(self, parser, word, expected):
        """A word only earns a suppression range when its quotes do work."""
        command = f'"{word}"'
        assert parser._quoting_is_load_bearing(command, word, (0, len(command))) is expected
