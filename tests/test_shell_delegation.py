"""Shell-delegated payloads are code, not data (LAB-2754).

`bash -c "<payload>"` hands `<payload>` to bash as a program. The AST sees a quoted
*argument*, so on `main` @ `1353f73` every spelling that kept the quotes off `-c` itself
came back **SAFE / allowed=True** - only the single literal spelling `bash -c "rm -rf /"`
was BLOCKED, by the `nested_shell_execution` regex. Pre-fix verdict is stated per case
below; to reproduce on `main`, comment out the import of the extraction helpers (they do
not exist there, so the module fails at collection rather than at the assertion).

Shell semantics asserted here were verified against the real binaries (bash 5.x, dash,
zsh): `bash -c -- PROG` runs PROG; `bash -ce PROG` runs PROG; `bash -cPROG` is rejected
with "option requires an argument", so an attached payload is not a thing.
"""

import pytest

from schlock.core import validator
from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel
from schlock.core.validator import (
    MAX_SHELL_DELEGATION_DEPTH,
    _dash_c_payload,
    _shell_delegated_payloads,
    _watch_payload,
    clear_caches,
    validate_command,
)


@pytest.fixture(autouse=True)
def _no_shellcheck(monkeypatch):
    """Pin verdicts to the rule/AST engine alone.

    ShellCheck independently elevates some of these to BLOCKED, which would let a regression
    hide on any machine that has it installed. AC-1 is specified with ShellCheck unavailable.
    """
    monkeypatch.setattr(validator, "is_shellcheck_available", lambda: False)
    clear_caches()
    yield
    clear_caches()


class TestDashCPayload:
    """Which word does the shell actually execute?"""

    def test_separate_flag(self):
        assert _dash_c_payload(["-c", "rm -rf /"]) == "rm -rf /"

    def test_clustered_flag_takes_next_word(self):
        # getopt: the cluster remainder is never the payload. `bash -ce PROG` runs PROG.
        assert _dash_c_payload(["-ce", "rm -rf /"]) == "rm -rf /"
        assert _dash_c_payload(["-ec", "rm -rf /"]) == "rm -rf /"

    def test_double_dash_before_payload_is_skipped(self):
        # `bash -c -- PROG` runs PROG; reading `--` as the payload was a total bypass.
        assert _dash_c_payload(["-c", "--", "rm -rf /"]) == "rm -rf /"

    def test_double_dash_before_flag_ends_options(self):
        assert _dash_c_payload(["--", "-c", "rm -rf /"]) is None

    def test_long_option_is_not_dash_c(self):
        assert _dash_c_payload(["--rcfile", "x"]) is None

    def test_dash_c_after_long_option_value_is_found(self):
        assert _dash_c_payload(["--rcfile", "x", "-c", "rm -rf /"]) == "rm -rf /"

    def test_leading_script_operand_ends_the_scan(self):
        # `bash deploy.sh -c production` passes -c to the SCRIPT, not to bash.
        assert _dash_c_payload(["deploy.sh", "-c", "production"]) is None

    def test_dangling_flag_has_no_payload(self):
        assert _dash_c_payload(["-c"]) is None

    def test_no_args(self):
        assert _dash_c_payload([]) is None


class TestWatchPayload:
    """`watch` runs its command through `sh -c`, flags and all."""

    def test_bare_command(self):
        assert _watch_payload(["rm -rf /"]) == "rm -rf /"

    def test_flags_of_the_program_survive(self):
        # Dropping every dashed word turned this into `rm /` and defanged the payload.
        assert _watch_payload(["-n", "5", "rm", "-rf", "/"]) == "rm -rf /"

    def test_attached_interval(self):
        assert _watch_payload(["-n5", "date"]) == "date"

    def test_double_dash_ends_watch_options(self):
        assert _watch_payload(["--", "git", "-c", "core.pager=/bin/sh", "log"]) == "git -c core.pager=/bin/sh log"

    def test_valueless_option(self):
        assert _watch_payload(["-d", "date"]) == "date"

    def test_no_command(self):
        assert _watch_payload([]) is None


class TestShellDelegatedPayloadExtraction:
    def _p(self, *cmds):
        return _shell_delegated_payloads(list(cmds))

    def test_plain_dash_c(self):
        assert self._p(("bash", ["-c", "rm -rf /"])) == ["rm -rf /"]

    def test_wrapper_prefix(self):
        assert self._p(("timeout", ["5", "bash", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_multicall_wrapper(self):
        assert self._p(("busybox", ["sh", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_wrapper_that_also_owns_dash_c(self):
        # `su -c PROG` and `runuser -u root -- bash -c PROG` are both reachable.
        assert self._p(("su", ["-c", "rm -rf /"])) == ["rm -rf /"]
        assert self._p(("runuser", ["-u", "root", "--", "bash", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_runner_operand_does_not_end_options(self):
        # `sg GROUP -c PROG` / `su USER -c PROG`: the operand is a group/user, not a script,
        # so unlike a shell it must not stop the scan for -c.
        assert self._p(("sg", ["root", "-c", "rm -rf /"])) == ["rm -rf /"]
        assert self._p(("su", ["postgres", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_shell_without_dash_c(self):
        assert self._p(("bash", ["script.sh"])) == []

    def test_non_delegator_is_untouched(self):
        assert self._p(("grep", ["-c", "pattern", "file"])) == []
        assert self._p(("echo", ["bash", "-c", "rm -rf /"])) == []

    def test_remote_delegation_is_out_of_scope(self):
        # ssh is a different trust domain; explicitly not covered.
        assert self._p(("ssh", ["host", "bash", "-c", "rm -rf /"])) == []

    def test_bare_shell_has_no_payload(self):
        assert self._p(("bash", [])) == []

    def test_empty_payload_is_ignored(self):
        assert self._p(("bash", ["-c", "   "])) == []


class TestShellDelegationEvasion:
    """AC-1: every spelling gets at least the bare payload's verdict.

    Pre-fix verdict on `main` @ `1353f73` for each of these: **SAFE / allowed=True**, except
    `bash -c "rm -rf /"` which the literal-quote regex already caught.
    """

    @pytest.mark.parametrize(
        "command",
        [
            'bash -c "rm -rf /"',
            'bash "-c" "rm -rf /"',
            "bash '-c' 'rm -rf /'",
            '"bash" -c "rm -rf /"',
            'bash -"c" "rm -rf /"',
            'timeout 5 bash "-c" "rm -rf /"',
            'bash -c "mkswap /dev/sda"',
            'sh "-c" "mkswap /dev/sda"',
            'watch "rm -rf /"',
            # Panel round: each of these was SAFE against the first cut of the fix.
            'bash -c -- "mkswap /dev/sda"',
            'bash -ce "mkswap /dev/sda"',
            'fish -c "mkswap /dev/sda"',
            'flock /tmp/l bash -c "mkswap /dev/sda"',
            'su -c "mkswap /dev/sda"',
            'sg root -c "mkswap /dev/sda"',
            'systemd-run bash -c "mkswap /dev/sda"',
            "watch -n 5 mkswap /dev/sda",
        ],
    )
    def test_repro_line_is_blocked(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False

    def test_bare_payload_controls_are_blocked(self):
        # The floor each wrapped form must reach.
        assert validate_command("rm -rf /").risk_level == RiskLevel.BLOCKED
        assert validate_command("mkswap /dev/sda").risk_level == RiskLevel.BLOCKED

    def test_nested_delegation_is_blocked(self):
        assert validate_command("""bash -c "sh -c 'rm -rf /'" """.strip()).risk_level == RiskLevel.BLOCKED

    def test_watch_preserves_flags_that_carry_the_danger(self):
        # `watch -n 5 git -c core.pager=/bin/sh log`: the danger IS the -c flag.
        assert validate_command("watch -n 5 git -c core.pager=/bin/sh log").risk_level == RiskLevel.BLOCKED

    def test_unparseable_payload_fails_closed(self):
        assert validate_command("""bash -c "if [ " """.strip()).risk_level == RiskLevel.BLOCKED

    def test_depth_cap_fails_closed(self):
        # Direct pin on the backstop: unreachable in normal use, so it can only rot untested.
        assert validate_command('bash -c "ls -la"', _depth=MAX_SHELL_DELEGATION_DEPTH).risk_level == RiskLevel.BLOCKED

    def test_recursive_verdicts_do_not_poison_the_cache(self):
        # The depth cap makes a verdict depth-dependent; the cache is keyed on the string alone.
        cold = validate_command("watch watch watch watch ls").risk_level
        clear_caches()
        validate_command("watch watch watch watch watch watch ls")
        assert validate_command("watch watch watch watch ls").risk_level == cold


class TestBenignDelegationUnchanged:
    """AC-2: absolute verdicts pinned against `main` @ `1353f73`."""

    @pytest.mark.parametrize(
        "command",
        [
            'bash -c "ls -la"',
            'sh -c "echo hi"',
            'watch "date"',
            "watch -n 5 date",
            "bash script.sh",
            "bash deploy.sh -c production",
            "grep -c pattern file",
        ],
    )
    def test_benign_stays_safe(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.SAFE, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is True

    def test_echo_of_a_shell_c_string_is_unchanged_at_high(self):
        # Extraction correctly ignores it (see test_non_delegator_is_untouched) - the HIGH comes
        # from the pre-existing `alternate_shells_and_escapes` regex, and is HIGH on main too.
        assert validate_command("echo bash -c rm").risk_level == RiskLevel.HIGH

    def test_shell_c_chain_is_not_over_blocked(self):
        # Widening the nested_shell_execution regex to make the quote optional turned this into
        # an unappealable BLOCKED (no preset can relax BLOCKED) on a chmod that is not even in
        # the payload. Reverted; pinned here so it is not re-introduced.
        assert validate_command("bash -c ls && chmod 755 build.sh").risk_level < RiskLevel.BLOCKED


# --------------------------------------------------------------------------------------------
# LAB-2768: here-strings (`bash <<< "..."`) are the same code-not-data sink as `-c`, but the
# payload hangs off a redirect node the word-walkers skip. On `main` @ `1de8e4c` (post-LAB-2754)
# `extract_stdin_program_redirects` does not exist, so the extraction class below fails at
# collection; the integration cases run and show the pre-fix verdict stated per case.
# --------------------------------------------------------------------------------------------


class TestHereStringPayloadExtraction:
    """The parser must surface the here-string a bare interpreter runs as a program."""

    def _extract(self, command):
        parser = BashCommandParser()
        return parser.extract_stdin_program_redirects(parser.parse(command))

    def test_bare_shell_here_string_is_the_program(self):
        assert self._extract('bash <<< "rm -rf /"') == [("bash", "rm -rf /")]

    def test_dash_s_reads_stdin_as_program(self):
        # `bash -s` explicitly reads commands from stdin.
        assert self._extract('bash -s <<< "mkswap /dev/sda"') == [("bash", "mkswap /dev/sda")]

    def test_dash_c_means_here_string_is_inert_data(self):
        # bash runs the -c program; the here-string is data on a stdin nothing reads.
        assert self._extract('bash -c "echo hi" <<< "rm -rf /"') == []

    def test_script_operand_means_here_string_is_data(self):
        assert self._extract('bash script.sh <<< "rm -rf /"') == []

    def test_non_interpreter_is_untouched(self):
        assert self._extract('cat <<< "some text"') == []
        assert self._extract('grep foo <<< "$line"') == []

    def test_multicall_resolves_to_applet(self):
        assert self._extract('busybox sh <<< "rm -rf /"') == [("sh", "rm -rf /")]

    def test_wrapper_passes_stdin_through_to_shell(self):
        # `timeout 5 bash <<< X` / `env FOO=1 bash <<< X` / `stdbuf ... bash <<< X`: the wrapper
        # execs bash, which inherits the wrapper's stdin (the here-string). Verified against the
        # real binaries (timeout/env/stdbuf/nice).
        assert self._extract('timeout 5 bash <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('env FOO=1 bash <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('stdbuf -o0 bash <<< "rm -rf /"') == [("bash", "rm -rf /")]

    def test_compound_here_string_finds_the_first_command_sink(self):
        # A `<<<` on a subshell/brace group feeds the group's stdin; the first command inside runs
        # it. bashlex hangs the redirect on the compound node, not the inner command (panel CRIT).
        assert self._extract('( bash ) <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('{ bash; } <<< "rm -rf /"') == [("bash", "rm -rf /")]

    def test_compound_wrapper_here_string(self):
        assert self._extract('( timeout 5 bash ) <<< "rm -rf /"') == [("bash", "rm -rf /")]

    def test_rbash_reads_stdin_as_program(self):
        # rbash is in _SHELL_COMMANDS (the `-c` path caught it); the here-string surface must agree.
        assert self._extract('rbash <<< "rm -rf /"') == [("rbash", "rm -rf /")]

    def test_wrapped_shell_with_dash_c_is_not_a_stdin_program(self):
        # `timeout 5 bash -c "echo hi" <<< X`: bash runs the -c program; the here-string is inert.
        assert self._extract('timeout 5 bash -c "echo hi" <<< "rm -rf /"') == []

    def test_here_string_off_a_non_stdin_redirect_is_ignored(self):
        # A plain input redirect (`< file`) is not a here-string; nothing to surface.
        assert self._extract("bash < script.sh") == []


class TestHereStringDelegationEvasion:
    """AC-1: a here-string payload gets at least the bare payload's verdict.

    Pre-fix verdict on `main` @ `1de8e4c` for each: **HIGH / allowed=True** (the payload is
    suppressed as a string literal inside the here-string quotes, so no rule fires on it), which
    `permissive` allows outright. `bash -s <<< "mkswap ..."` was BLOCKED pre-fix only by the raw
    string matching a rule regex - not by the delegation being recognised.
    """

    @pytest.mark.parametrize(
        "command",
        [
            'bash <<< "rm -rf /"',
            'sh <<< "rm -rf /"',
            'zsh <<< "rm -rf /"',
            'dash <<< "rm -rf /"',
            'bash -s <<< "rm -rf /"',
            'sh -s <<< "rm -rf /"',
            'bash <<< "chmod -R 777 /"',
            'busybox sh <<< "rm -rf /"',
            # Wrappers pass their stdin through to the shell they exec (pre-fix: HIGH / allowed).
            'timeout 5 bash <<< "rm -rf /"',
            'env FOO=1 bash <<< "rm -rf /"',
            'nice bash <<< "rm -rf /"',
            # Compound/group sinks - redirect rides the compound node (panel CRIT; pre-fix HIGH).
            '( bash ) <<< "rm -rf /"',
            '{ bash; } <<< "rm -rf /"',
            '( timeout 5 bash ) <<< "rm -rf /"',
            # rbash is a shell the `-c` path already caught; the `<<<` spelling must agree.
            'rbash <<< "rm -rf /"',
        ],
    )
    def test_here_string_payload_is_blocked(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False

    def test_bare_payload_control_is_blocked(self):
        # The floor each here-string form must reach.
        assert validate_command("rm -rf /").risk_level == RiskLevel.BLOCKED


class TestHereStringBenignUnchanged:
    """AC-2: absolute verdicts pinned against `main` @ `1de8e4c` (pre-fix values, unchanged)."""

    @pytest.mark.parametrize(
        "command",
        [
            'bash <<< "echo hi"',
            'cat <<< "some text"',
            'grep foo <<< "$line"',
        ],
    )
    def test_benign_here_string_stays_safe(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.SAFE, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is True

    def test_unexpanded_variable_matches_the_dash_c_path(self):
        # DECISION (LAB-2768): a here-string payload re-enters validation identically to a `-c`
        # payload, so `bash <<< "$CMD"` yields exactly what `bash -c "$CMD"` yields today (SAFE -
        # `$CMD` names no dangerous command). Fail-closing only the here-string spelling would make
        # two spellings of the identical delegation disagree, and would silently diverge from the
        # reviewed LAB-2754 `-c` behaviour. If unexpanded-var payloads should fail closed, that is
        # a new decision applied uniformly across `-c`, `<<<`, heredocs and `find -exec`.
        here = validate_command('bash <<< "$CMD"')
        dash_c = validate_command('bash -c "$CMD"')
        assert here.risk_level == RiskLevel.SAFE
        assert here.risk_level == dash_c.risk_level
        assert here.allowed == dash_c.allowed
