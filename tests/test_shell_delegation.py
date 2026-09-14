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


class TestFindExecPayloadExtraction:
    """LAB-2767: a shell inside `find -exec ... ;` is a command in its own right.

    `find`'s `-exec`/`-execdir`/`-ok`/`-okdir` clause is opaque `args` to find, so the shell
    it launches was never seen as a delegator. The extractor now re-enters each clause's
    sub-command through the same machinery. Pre-fix (`main` @ `1de8e4c`) every case below
    returned `[]`.

    Terminator note (verified against the parser): a bare `;` is eaten by bash as a command
    separator, so it never reaches find's args; an escaped `\\;` or quoted `';'` survives as a
    literal `;` word; `+` always survives. The escaped/quoted/`+` words end a clause; a bare
    `;` instead splits a later `-exec` clause into a `command not found` fragment that never
    runs the payload, so it is deliberately not chased (test below pins that).
    """

    def _p(self, *cmds):
        return _shell_delegated_payloads(list(cmds))

    def test_exec_shell_dash_c(self):
        assert self._p(("find", [".", "-exec", "bash", "-c", "mkswap /dev/sda"])) == ["mkswap /dev/sda"]

    def test_semicolon_word_terminates_clause(self):
        # Escaped `\\;` / quoted `';'` reach find as a literal `;` word.
        assert self._p(("find", [".", "-exec", "bash", "-c", "mkswap /dev/sda", ";"])) == ["mkswap /dev/sda"]

    def test_plus_terminates_clause(self):
        assert self._p(("find", [".", "-exec", "bash", "-c", "mkswap /dev/sda", "+"])) == ["mkswap /dev/sda"]

    def test_execdir_ok_okdir_all_covered(self):
        for flag in ("-execdir", "-ok", "-okdir"):
            assert self._p(("find", [".", flag, "sh", "-c", "rm -rf /"])) == ["rm -rf /"], flag

    def test_multiple_exec_clauses(self):
        # `find . -exec bash -c "echo hi" \\; -exec sh -c "mkswap /dev/sda" \\;`
        assert self._p(("find", [".", "-exec", "bash", "-c", "echo hi", ";", "-exec", "sh", "-c", "mkswap /dev/sda", ";"])) == [
            "echo hi",
            "mkswap /dev/sda",
        ]

    def test_bare_semicolon_split_pseudo_command_not_chased(self):
        # A bare `;` splits the AST, so a later clause surfaces as a command literally named
        # `-exec`. In a real shell that argv[0] is `command not found`, so the payload never
        # runs - deliberately not chased. A dangerous *first* clause still sits under `find`
        # and is caught by the normal path.
        assert self._p(("-exec", ["sh", "-c", "mkswap /dev/sda"])) == []

    def test_non_shell_exec_is_untouched(self):
        # `-exec grep`/`rm` is not a delegator; find's own rules judge those, not this path.
        assert self._p(("find", [".", "-exec", "grep", "-l", "TODO", "{}"])) == []
        assert self._p(("find", [".", "-exec", "rm", "{}", "+"])) == []

    def test_no_exec_clause(self):
        assert self._p(("find", [".", "-name", "*.pyc", "-delete"])) == []

    def test_brace_placeholder_in_payload_is_passed_through(self):
        # `{}` is a filename find substitutes, not code. It stays verbatim in the payload; the
        # re-validation of `echo {}` is what decides it is harmless, not any stripping here.
        assert self._p(("find", [".", "-exec", "bash", "-c", "echo {}"])) == ["echo {}"]

    def test_wrapper_inside_exec_clause(self):
        # The clause re-enters the FULL extractor, so a wrapped delegator is caught for free.
        assert self._p(("find", [".", "-exec", "sudo", "bash", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_dangling_exec_flag_has_no_payload(self):
        assert self._p(("find", [".", "-exec"])) == []
        assert self._p(("find", [".", "-exec", ";"])) == []


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


class TestFindExecDelegation:
    """LAB-2767: `find -exec <shell> -c "<payload>"` re-enters validation on the payload.

    Pre-fix verdicts (`main` @ `1de8e4c`, ShellCheck unavailable) stated per case. The HIGH
    ones came from the unrelated `find_exec_dangerous` rule (an ask under `balanced`, allowed
    outright under `permissive`), which never inspected the delegated payload.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # AC-1 repro. Pre-fix: HIGH / allowed=True.
            'find . -exec bash -c "mkswap /dev/sda" ;',
            # Terminator spellings that reach find as a real `;`/`+` word. Pre-fix: HIGH.
            r'find . -exec bash -c "mkswap /dev/sda" \;',
            'find . -exec bash -c "mkswap /dev/sda" +',
            # Every exec-family flag. Pre-fix: HIGH.
            'find . -execdir bash -c "mkswap /dev/sda" ;',
            'find . -ok bash -c "mkswap /dev/sda" ;',
            'find . -okdir bash -c "mkswap /dev/sda" ;',
            # A dangerous FIRST clause reaches find's own args even when a bare `;` splits a
            # later clause off, so it is still caught. Pre-fix: HIGH.
            'find . -exec bash -c "mkswap /dev/sda" ; -exec echo done ;',
            # Two properly-escaped clauses; the dangerous one is second. Pre-fix: HIGH.
            r'find . -exec echo hi \; -exec sh -c "mkswap /dev/sda" \;',
            # Wrapped delegator inside the clause, caught by the same re-entry. Pre-fix: HIGH.
            'find . -exec sudo bash -c "mkswap /dev/sda" ;',
        ],
    )
    def test_delegated_payload_is_blocked(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False

    def test_bare_payload_control_is_blocked(self):
        # The floor the wrapped forms must reach.
        assert validate_command("mkswap /dev/sda").risk_level == RiskLevel.BLOCKED

    def test_bare_semicolon_second_clause_is_not_executable(self):
        # `find ... -exec echo hi ; -exec sh -c "mkswap" ;` with a BARE `;`: bash splits it, and
        # the second `-exec` is `command not found`, so the payload never runs. schlock leaves it
        # at the pre-existing HIGH (find_exec_dangerous) rather than block a non-executable form.
        assert validate_command('find . -exec echo hi ; -exec sh -c "mkswap /dev/sda" ;').risk_level == RiskLevel.HIGH


class TestFindExecUnchanged:
    """AC-2: absolute verdicts pinned against `main` @ `1de8e4c` (ShellCheck unavailable).

    None of these carry a dangerous delegated payload, so the re-entry adds nothing above the
    verdict find's own command-aware rules already produce.
    """

    def test_readonly_exec_stays_safe(self):
        # `-exec grep` is read-only; find's rules leave it SAFE and the payload path is a no-op.
        assert validate_command("find . -exec grep -l TODO {} ;").risk_level == RiskLevel.SAFE

    def test_delete_predicate_stays_high(self):
        # `-delete` has no `-exec` clause; the `recursive_delete` rule keeps it HIGH.
        assert validate_command('find . -name "*.pyc" -delete').risk_level == RiskLevel.HIGH

    def test_brace_placeholder_payload_stays_high(self):
        # `echo {}` re-validates SAFE (< HIGH), so the pre-existing find_exec_dangerous HIGH stands.
        assert validate_command('find . -exec bash -c "echo {}" ;').risk_level == RiskLevel.HIGH
