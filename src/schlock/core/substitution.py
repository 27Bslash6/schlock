"""Command substitution validation module.

This module provides AST-based detection and validation of command substitution
$(cmd) and process substitution <(cmd) patterns.

Security Model:
1. WHITELIST FIRST - Known-safe commands (op, date, git, etc.) pass immediately
2. AST STRUCTURAL CHECKS - Detect brace expansion, variable commands, etc.
3. RECURSIVE VALIDATION - Full validation of inner commands with depth limit
4. DEFAULT-DENY - Unknown commands in substitution context are blocked

This prevents bypass attacks that defeat regex-only detection:
- Nested substitution: $(echo $(rm -rf /))
- Brace expansion: $({r,}m -rf /)
- Variable indirection: $($CMD)
- Encoding/obfuscation: AST sees through it
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .rules import RiskLevel

# Maximum recursion depth for nested substitution validation
MAX_SUBSTITUTION_DEPTH = 10

# Operators bashlex emits in a command-list node's parts. A well-formed list strictly alternates
# segment/operator and ends on a segment; anything else is a malformed AST -> fail closed.
_LIST_OPERATORS: frozenset[str] = frozenset({"&&", "||", ";", "&"})

# Commands that are ALWAYS safe inside substitution
# These are read-only, pure, or security-critical tools that don't modify state
SAFE_SUBSTITUTION_COMMANDS: frozenset[str] = frozenset(
    {
        # Secret management (designed for CLI use)
        "op",  # 1Password CLI - primary use case that triggered this fix
        # System info (read-only)
        "date",
        "pwd",
        "whoami",
        "hostname",
        "uname",
        "id",
        "groups",
        "uptime",
        "arch",
        # File listing (read-only)
        # NOTE: find requires contextual check for -exec/-delete in _has_dangerous_inner_structure()
        # NOTE: tee removed - always writes to files
        "ls",
        "stat",
        "file",
        "du",
        "df",
        "find",
        "locate",
        # File reading (read-only - content inspection)
        "cat",
        "less",
        "more",
        "tac",
        "nl",
        "od",
        "xxd",
        "hexdump",
        "strings",
        # Process inspection (read-only)
        "ps",
        "pgrep",
        "top",
        "htop",
        "pmap",
        "lsof",
        # File comparison (read-only)
        "diff",
        "cmp",
        "comm",
        "sdiff",
        # File operations that output (safe in substitution context)
        # NOTE: tee removed - writes to arbitrary files
        "md5sum",
        "sha256sum",
        "shasum",
        "cksum",
        # Git (read-only operations - write ops would fail in substitution anyway)
        "git",
        # Directory change (subshell-pure: only affects cwd inside the $() subshell, no exec).
        # Safe to whitelist now that $(cd … && …) parses; without it the canonical repro
        # X=$(cd "$(git rev-parse --git-dir)" && pwd) still hard-blocks on unknown "cd".
        "cd",
        # Path manipulation (pure functions)
        "basename",
        "dirname",
        "realpath",
        "readlink",
        # Text output (pure)
        "echo",
        "printf",
        # Environment inspection (read-only)
        # NOTE: env removed - executes arbitrary commands (env rm -rf / works)
        "printenv",
        # Which/type - NOTE: command removed (bypasses blacklist)
        "which",
        "type",
        # Math (pure)  # noqa: ERA001
        "expr",
        "bc",
        # String manipulation (pure)
        "tr",
        "cut",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "rev",
        "seq",
        "yes",
        "grep",
        "egrep",
        "fgrep",
        # Stream editors (read-only pipeline stages — the common case).
        # NOTE: awk requires contextual check for system()/getline/pipes/writes,
        # sed for -i/-f/e/w-class script commands, in _has_dangerous_inner_structure(). See #104.
        "awk",
        "sed",
        "jq",
        # Common pure utilities
        "true",
        "false",
        "sleep",
        "tty",
        "stty",
        "locale",
        "getconf",
        "nproc",
    }
)

# Commands that are conditionally safe inside substitution
# These require subcommand-level analysis AND still go through YAML rules.
# Unlike SAFE_SUBSTITUTION_COMMANDS (which bypass rules), contextual commands
# preserve defense-in-depth: the YAML rule engine catches dangerous patterns
# (e.g., kubectl_secrets_theft) that the subcommand allowlist alone would miss.
CONTEXTUAL_SUBSTITUTION_COMMANDS: frozenset[str] = frozenset(
    {
        # kubectl: read-only subcommands safe, state-modifying subcommands dangerous
        # NOTE: contextual checks in _has_dangerous_inner_structure()
        "kubectl",
    }
)

# kubectl global flags that consume the next argument as a value.
# Used to skip over flag values when finding the subcommand.
# Source: kubectl options (1.32). Regenerate with:
#   kubectl options | grep -E '^\s+--?\w' | grep -v '=false' | awk '{print $1}'
_KUBECTL_GLOBAL_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "-n",
        "--namespace",
        "-s",
        "--server",
        "--kubeconfig",
        "--kuberc",  # v1.33+: user preferences file path
        "--context",
        "--cluster",
        "--user",
        "--token",
        "--as",
        "--as-group",
        "--as-uid",
        "--as-user-extra",  # impersonation key=value pairs
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--cache-dir",
        "--request-timeout",
        "-v",
        "--tls-server-name",
        "--username",
        "--password",
        "--profile",
        "--profile-output",
        "--log-flush-frequency",
        "--log-backtrace-at",
        "--log-dir",
        "--log-file",
        "--log-file-max-size",
        "--stderrthreshold",
        "--vmodule",
    }
)

# Known kubectl boolean flags that do NOT consume the next argument.
# Used by _find_kubectl_subcommand: unrecognized short flags are assumed
# to consume a value (conservative/safe), so only known booleans are skipped.
_KUBECTL_BOOLEAN_SHORT_FLAGS: frozenset[str] = frozenset(
    {
        "-h",
        "-A",  # --all-namespaces
        "-R",  # --recursive
        "-w",  # --watch (boolean in most subcommands)
    }
)

# kubectl subcommands that are safe (read-only) inside substitutions.
# Everything NOT in this set is considered dangerous (default-deny).
_SAFE_KUBECTL_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        # Read-only cluster queries
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        "version",
        "api-resources",
        "api-versions",
        "cluster-info",
        "events",
        # Config inspection (sub-subcommands checked separately)
        "config",
        # Auth inspection (sub-subcommands checked separately)
        "auth",
        # Dry-run / comparison (no mutation)
        "diff",
        "wait",
        # Template generation (output only, no apply)
        "kustomize",
        # Rollout inspection (sub-subcommands checked separately)
        "rollout",
    }
)

# kubectl config sub-subcommands that modify kubeconfig state
_DANGEROUS_KUBECTL_CONFIG_OPS: frozenset[str] = frozenset(
    {
        "set",
        "set-context",
        "set-cluster",
        "set-credentials",
        "delete-context",
        "delete-cluster",
        "delete-user",
        "use-context",
        "rename-context",
        "unset",
    }
)

# kubectl rollout sub-subcommands that modify deployment state
_DANGEROUS_KUBECTL_ROLLOUT_OPS: frozenset[str] = frozenset(
    {
        "restart",
        "undo",
        "pause",
        "resume",
    }
)

# Commands that are ALWAYS dangerous inside substitution
# Even if they would be allowed outside substitution context
DANGEROUS_SUBSTITUTION_COMMANDS: frozenset[str] = frozenset(
    {
        # Destructive
        "rm",
        "rmdir",
        "shred",
        "truncate",
        "wipefs",
        # Privilege escalation
        "sudo",
        "su",
        "doas",
        "pkexec",
        # Arbitrary execution
        "eval",
        "exec",
        "source",
        "xargs",  # exec trampoline: pipes data into an arbitrary command (#104)
        # System modification
        "dd",
        "mkfs",
        "fdisk",
        "parted",
        "mount",
        "umount",
        # Process control
        "kill",
        "killall",
        "pkill",
        # Credential access (should go through proper channels)
        "security",  # macOS keychain
        "secret-tool",  # Linux keyring
        "pass",  # password store
        # Network exfiltration
        "curl",
        "wget",
        "fetch",  # FreeBSD/macOS HTTP(S) downloader — parity with curl/wget (#108)
        "aria2c",  # multi-protocol downloader — parity with curl/wget (#108)
        "nc",
        "netcat",
        "ncat",
        "socat",
        # Shell interpreters (RCE via process substitution)
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
    }
)


class SubstitutionType(Enum):
    """Type of shell substitution."""

    COMMAND = "command"  # $(cmd) or `cmd`
    PROCESS_INPUT = "process_input"  # <(cmd)
    PROCESS_OUTPUT = "process_output"  # >(cmd)


def _iter_kubectl_positionals(args: list[str]) -> Iterator[str]:
    """Yield only positional tokens from a kubectl argument list.

    Skips flags and their values:
    - ``--flag=value`` → skipped entirely
    - Known global value-taking flags → skip flag and next arg
    - Attached short forms (``-nproduction``, ``-n=prod``) → skipped entirely
    - Known boolean short flags (-A, -h, -R, -w) → skip flag only
    - Unrecognized short flags (-o, -f, -l, etc.) → assumed to consume
      the next arg (conservative; prevents subcommand masking attacks)
    - Unrecognized long flags → assumed boolean (--flag=value already handled)
    - ``kubectl`` literal → skipped
    """
    skip_next = False
    for arg in args:
        if arg == "kubectl":
            continue
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("--") and "=" in arg:
            continue
        if arg in _KUBECTL_GLOBAL_VALUE_FLAGS:
            skip_next = True
            continue
        if arg in _KUBECTL_BOOLEAN_SHORT_FLAGS:
            continue
        if arg.startswith("--"):
            continue
        # Short flag handling (-X...):
        # - Attached value (-ojson, -n=prod, -nfoo): value is embedded, skip
        #   without consuming next token (regardless of whether flag is known)
        # - Bare known boolean (-A, -h): skip without consuming
        # - Bare unrecognized (-o, -f): assume value-consuming, set skip_next
        if arg.startswith("-") and len(arg) > 1 and not arg.startswith("--"):
            if len(arg) > 2 or "=" in arg:
                continue  # attached value form: -ojson, -n=prod, -nfoo
            flag_letter = arg[:2]
            if flag_letter in _KUBECTL_BOOLEAN_SHORT_FLAGS:
                continue
            skip_next = True  # bare unrecognized: assume value-consuming
            continue
        yield arg


def _find_kubectl_subcommand(args: list[str]) -> str | None:
    """Find the kubectl subcommand (first positional token) from args.

    Uses _iter_kubectl_positionals which conservatively treats unrecognized
    short flags as value-consuming to prevent subcommand masking attacks.
    """
    return next(_iter_kubectl_positionals(args), None)


def _find_sub_subcommand(args: list[str], parent_subcommand: str) -> str | None:
    """Find the sub-subcommand token that follows a given parent subcommand.

    E.g., "set-context" in "kubectl config set-context".
    Uses _iter_kubectl_positionals for consistent flag-skipping.
    """
    found_parent = False
    for positional in _iter_kubectl_positionals(args):
        if not found_parent:
            if positional == parent_subcommand:
                found_parent = True
            continue
        return positional
    return None


def _is_truthy_flag_value(value: str) -> bool:
    """Check if a flag value like --raw=<value> is truthy.

    Returns True for: true, 1, yes, y (case-insensitive)
    Returns False for: false, 0, no, n (case-insensitive) and anything else
    """
    return value.lower() in ("true", "1", "yes", "y", "t")


# git boolean-literal values. A git -c config whose value is a boolean selects a built-in and
# names no executable (e.g. core.fsmonitor=true uses git's built-in monitor), so it cannot be RCE.
# Empty string covers a bare `-c key` (no =VALUE), which git treats as key=true.
_GIT_BOOLEAN_VALUES = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0", ""})


def _is_git_boolean(value: str) -> bool:
    """True if `value` is a git boolean literal (so it names no executable program)."""
    return value.strip().lower() in _GIT_BOOLEAN_VALUES


# git -c config keys that execute arbitrary commands when set via -c (top-level under-block fix).
# Lowercased for case-insensitive match against the config key.
_DANGEROUS_GIT_CONFIGS = frozenset(
    {
        "alias.",  # alias.x=!cmd executes a shell command
        "core.askpass",  # program invoked to obtain credentials -> RCE
        "core.editor",  # executed when editing messages
        "core.fsmonitor",  # external file-system-monitor program git spawns -> RCE
        "core.hookspath",  # redirects all git hooks to an attacker-controlled dir -> RCE
        "core.pager",  # executed when paging output
        "core.sshcommand",  # executed during SSH operations
        "credential.helper",  # executed for authentication
        "diff.external",  # executed during diff
        "gpg.program",  # binary invoked to sign/verify commits/tags -> RCE
        "merge.tool",  # executed during merge
        "sequence.editor",  # program invoked during interactive rebase -> RCE
    }
)


def dangerous_git_config(args: list[str]) -> str | None:
    """Return a reason string if `args` (a git command's word-args) sets a -c config that
    executes arbitrary commands, else None. Handles `-c KEY=VAL` and attached `-cKEY=VAL`.
    `alias.` is dangerous only when the alias VALUE starts with `!` (shell-command alias);
    a `!` elsewhere (e.g. a `--grep` pattern) is an ordinary git alias. Pure; the single
    source of truth shared by SubstitutionValidator and top-level validation.
    """
    for i, arg in enumerate(args):
        config_val = None
        if arg == "-c" and i + 1 < len(args):
            config_val = args[i + 1]
        elif arg.startswith("-c") and len(arg) > 2:
            config_val = arg[2:]
        if not config_val:
            continue
        config_lower = config_val.lower()
        for dangerous_prefix in _DANGEROUS_GIT_CONFIGS:
            if config_lower.startswith(dangerous_prefix):
                if dangerous_prefix == "alias.":
                    # git runs an alias as a shell command only when its VALUE starts with '!'
                    # (alias.<name>=!cmd). A '!' elsewhere is a normal git-subcommand alias.
                    _, _, alias_value = config_val.partition("=")
                    if not alias_value.lstrip().startswith("!"):
                        continue
                else:
                    # A boolean value selects a built-in and names no executable
                    # (e.g. core.fsmonitor=true); only a path/command value is RCE. A bare
                    # `-c key` (no =VALUE) is key=true to git -> also benign. See #97.
                    _, _, value = config_val.partition("=")
                    if _is_git_boolean(value):
                        continue
                return f"git config {dangerous_prefix.rstrip('.')} executes commands via -c flag"
    return None


# find flags that run arbitrary commands (-exec/-execdir/-ok/-okdir) or delete files (-delete).
_DANGEROUS_FIND_FLAGS = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete"})


def dangerous_find(args: list[str]) -> str | None:
    """Return a reason if a find arg list runs commands or deletes files, else None.

    Used by the SubstitutionValidator, which is conservative: ANY -exec*/-ok*/-delete inside a
    substitution is dangerous regardless of the command run. (Top-level find stays command-aware
    via the find_exec_dangerous / recursive_delete YAML rules, so read-only `find -exec grep` is
    still allowed there.) Order-independent and indifferent to a leading "find" token. See #97.
    """
    for arg in args:
        if arg in _DANGEROUS_FIND_FLAGS:
            return f"find {arg} executes commands or modifies files"
    return None


# awk constructs that execute commands or write files from inside the program text. Blunt regex
# scan over ALL args (program text, -v values, separators alike): over-blocking a rare string
# comparison like `$1 > "m"` inside a substitution is acceptable; missing system()/pipe-to-command/
# file writes is not. Known ceiling: a pipe/redirect target held in a VARIABLE (`print | c`) evades
# this text scan — the parser's pipe-to-shell layer and YAML rules remain as backstops. See #104.
_AWK_DANGEROUS_TEXT = re.compile(
    r"system\s*\("  # system("cmd") — arbitrary exec
    r"|getline"  # "cmd" | getline — exec; blunt: all getline forms blocked
    r'|\|\s*"'  # print | "cmd" — pipe to a command
    r'|"\s*\|'  # "cmd" | … — command string on the left of a pipe
    r"|\|&"  # gawk |& coprocess
    r'|>\s*"'  # print > "file" / >> "file" — file write from inside awk
    r"|@load|@include"  # gawk: load extension / include external source
)

# awk flags that load external program code (contents unknown -> fail closed) or enable writes.
# Prefix match covers attached forms (-fprog.awk). Case-sensitive: -F (field separator) is safe.
_AWK_DANGEROUS_FLAG_PREFIXES = ("-f", "--file", "-i", "--include", "-l", "--load", "-E", "--exec")


def dangerous_awk(args: list[str]) -> str | None:
    """Return a reason if an awk arg list executes commands, writes files, or loads external
    program code, else None. Pure; used by the SubstitutionValidator's contextual whitelist check.
    `args` may include the leading "awk" token (harmless to both scans).
    """
    for arg in args:
        if arg != "awk" and arg.startswith(_AWK_DANGEROUS_FLAG_PREFIXES):
            return f"awk {arg} loads external program code or enables writes"
        if _AWK_DANGEROUS_TEXT.search(arg):
            return "awk program executes commands or writes files (system/getline/pipe/redirect)"
    return None


# sed is allowed inside substitution only in a conservative read-only form: clusterable boolean
# flags -n/-r/-E/-s/-z/-u plus scripts limited to s///, y///, p, d, q, = with optional addresses.
# Everything else — -i in-place writes, -f external scripts, e/w/r/W commands, the GNU s///e exec
# flag, unknown flags — fails closed. Blunt over-block is acceptable in substitution context.
_SED_SAFE_SHORT_FLAGS = re.compile(r"-[nrEszu]+\Z")
_SED_SAFE_LONG_FLAGS = frozenset(
    {
        "--quiet",
        "--silent",
        "--regexp-extended",
        "--posix",
        "--separate",
        "--null-data",
        "--unbuffered",
        "--sandbox",
    }
)

# One sed command: optional address(es) (N / $ / /regex/), then s|y with any delimiter (safe flags
# only — no e/w), or p/d/=/q. The (.) delimiter backreference keeps s|a|b|e (delimiter '|') safe
# while rejecting the GNU exec FLAG in s/a/b/e. Scripts are split on ;/newline before matching;
# a split inside an s/// replacement only over-blocks (both fragments fail), never under-blocks.
# The escaped-pair / single-char alternatives must stay mutually exclusive on backslash
# (\\. vs [^\\]): if both can consume a backslash, a run of backslashes with no closing
# delimiter backtracks exponentially (ReDoS on the hook path). Valid sed never has a bare
# trailing backslash — every \ starts a 2-char escape — so excluding it only over-blocks
# commands sed itself rejects as unterminated.
_SED_ADDR = r"(?:[0-9]+|\$|/(?:\\.|[^\\/])*/)"
_SED_SAFE_COMMAND = re.compile(
    r"^\s*(?:" + _SED_ADDR + r"(?:\s*,\s*" + _SED_ADDR + r")?)?\s*"
    r"(?:"
    r"[sy](.)(?:\\.|(?!\1)[^\\])*\1(?:\\.|(?!\1)[^\\])*\1[gIiMmp0-9]*"
    r"|[pd=]"
    r"|q[0-9]*"
    r")?\s*\Z"
)


def dangerous_sed(args: list[str]) -> str | None:  # noqa: PLR0911, PLR0912 - flag dispatch
    """Return a reason if a sed arg list falls outside the safe read-only subset, else None.

    Identifies script args (values of -e/--expression, or the first positional when no -e is
    given; remaining positionals are input files) and requires every ;/newline-separated command
    to match _SED_SAFE_COMMAND. Pure; used by the SubstitutionValidator's contextual whitelist
    check. `args` may include the leading "sed" token.
    """
    scripts: list[str] = []
    positionals: list[str] = []
    saw_expression = False
    expect_expression_value = False
    after_double_dash = False
    rest = args[1:] if args and args[0] == "sed" else list(args)
    for arg in rest:
        if expect_expression_value:
            scripts.append(arg)
            expect_expression_value = False
            continue
        if not after_double_dash and arg.startswith("-") and arg != "-":
            if arg == "--":
                after_double_dash = True
                continue
            if arg in ("-e", "--expression"):
                saw_expression = True
                expect_expression_value = True
                continue
            if arg.startswith("-e") and not arg.startswith("--"):
                saw_expression = True
                scripts.append(arg[2:])
                continue
            if arg.startswith("--expression="):
                saw_expression = True
                scripts.append(arg.split("=", 1)[1])
                continue
            if arg.startswith(("-i", "--in-place")):
                return "sed -i writes files in place"
            if arg.startswith(("-f", "--file")):
                return "sed -f loads an external script (contents unknown)"
            if arg.startswith("--"):
                if arg in _SED_SAFE_LONG_FLAGS:
                    continue
                return f"sed flag {arg} is outside the safe read-only subset"
            if _SED_SAFE_SHORT_FLAGS.match(arg):
                continue
            return f"sed flag {arg} is outside the safe read-only subset"
        positionals.append(arg)
    if not saw_expression and positionals:
        scripts.append(positionals[0])  # first positional is THE script; the rest are input files
    for script in scripts:
        for piece in re.split(r"[;\n]", script):
            if not _SED_SAFE_COMMAND.match(piece):
                return f"sed script {piece!r} is outside the safe read-only subset (s///, y///, p, d, q)"
    return None


def dangerous_kubectl(args: list[str]) -> str | None:  # noqa: PLR0911, PLR0912 - subcommand dispatch
    """Return a reason if a kubectl arg list modifies cluster state, executes code, or exposes
    secrets/credentials, else None.

    Safety depends on the subcommand: get/describe/logs are read-only; exec/apply/delete/run modify
    state or execute code. Uses an allowlist of safe subcommands (default-deny for unknown) plus
    argument-level checks within otherwise-safe subcommands. Pure; the single source of truth shared
    by SubstitutionValidator and top-level validation. `_find_kubectl_subcommand` skips a leading
    "kubectl" token if present, so `args` may or may not include it.
    """
    subcommand = _find_kubectl_subcommand(args)
    if not subcommand:
        return "kubectl without an identifiable subcommand"

    if subcommand not in _SAFE_KUBECTL_SUBCOMMANDS:
        return f"kubectl {subcommand} modifies cluster state or executes code"

    # --- Argument-level checks for otherwise-safe subcommands (position-independent) ---
    # Block --raw on get (accesses arbitrary API paths, bypasses resource-type checks).
    if subcommand == "get" and any(arg == "--raw" or arg.startswith("--raw=") for arg in args):
        return "kubectl get --raw accesses raw API paths"

    # Block secret/secrets resource access on get/describe. Positional args only, to avoid
    # false positives on paths like --kubeconfig /etc/secrets/kubeconfig.
    if subcommand in ("get", "describe"):
        for positional in _iter_kubectl_positionals(args):
            tokens = [t for part in positional.lower().replace(",", "/").split("/") if (t := part.split(".")[0])]
            if any(t in ("secret", "secrets") for t in tokens):
                return f"kubectl {subcommand} accesses secrets"

    # kubectl config view -> safe, but set-context/etc. modify kubeconfig; --raw/--flatten expose creds.
    if subcommand == "config":
        sub_sub = _find_sub_subcommand(args, "config")
        if sub_sub and sub_sub in _DANGEROUS_KUBECTL_CONFIG_OPS:
            return f"kubectl config {sub_sub} modifies kubeconfig"
        if sub_sub == "view":
            for flag in ("--raw", "--flatten"):
                if any(arg == flag for arg in args):
                    return "kubectl config view --raw/--flatten exposes credentials"
                prefix = flag + "="
                for arg in args:
                    if arg.startswith(prefix) and _is_truthy_flag_value(arg.split("=", 1)[1]):
                        return "kubectl config view --raw/--flatten exposes credentials"

    if subcommand == "auth" and _find_sub_subcommand(args, "auth") == "reconcile":
        return "kubectl auth reconcile modifies RBAC"

    if subcommand == "rollout":
        sub_sub = _find_sub_subcommand(args, "rollout")
        if sub_sub and sub_sub in _DANGEROUS_KUBECTL_ROLLOUT_OPS:
            return f"kubectl rollout {sub_sub} modifies deployment state"

    if subcommand == "cluster-info" and _find_sub_subcommand(args, "cluster-info") == "dump":
        return "kubectl cluster-info dump exfiltrates cluster data"

    return None


# Commands that write to a file via an ARGUMENT (not a shell redirect). Inside a substitution any
# such write is dangerous: a substitution's job is to produce a value, so a file write as a side
# effect is suspicious — mirrors the "any output redirection in $() is BLOCKED" rule. These three
# are also in SAFE_SUBSTITUTION_COMMANDS, so without this check they take the whitelist fast path
# and bypass the YAML rules that would catch them at the top level. `tee` is intentionally absent:
# it is not whitelisted, never reaches _has_dangerous_inner_structure, and is already BLOCKED in
# substitution by the truncation YAML rule. See #113.
_WRITE_ARG_COMMANDS: frozenset[str] = frozenset({"sort", "sdiff", "xxd"})


def _options_before_double_dash(args: list[str]) -> Iterator[str]:
    """Yield tokens up to a ``--`` end-of-options marker (exclusive).

    After ``--`` the shell treats everything as positionals, so a later ``-o``/``-r`` is a filename,
    not a flag, and must not be scanned as a write flag (e.g. ``sort -- -o`` reads a file named
    ``-o``). See #113.
    """
    for arg in args:
        if arg == "--":
            return
        yield arg


def dangerous_write_arg(base_command: str, args: list[str]) -> str | None:
    """Return a reason if `base_command` writes to a file via its arguments, else None.

    Pure; the single source of truth for the SubstitutionValidator's write-via-arg check. `args` is
    the command's word list and may include the leading command token (harmless to the flag scans
    below). Blunt by design — ANY write target is dangerous inside a substitution, regardless of the
    destination path. See #113.
    """
    if base_command not in _WRITE_ARG_COMMANDS:
        return None

    if base_command in ("sort", "sdiff"):
        for arg in _options_before_double_dash(args):
            # long form: --output or --output=FILE
            if arg == "--output" or arg.startswith("--output="):
                return f"{base_command} -o writes output to a file"
            # Any short-flag cluster containing 'o' is sort/sdiff's -o (write output to a file):
            # covers -o, -ofile, -ro, -rofile. 'o' is the ONLY short flag of sort/sdiff that uses
            # that letter, so an attached value char ('o' as another flag's value, e.g. -to) only
            # ever over-matches — an acceptable blunt over-block inside a substitution. See #113.
            if arg.startswith("-") and not arg.startswith("--") and "o" in arg[1:]:
                return f"{base_command} -o writes output to a file"
    elif base_command == "xxd":
        for arg in _options_before_double_dash(args):
            if arg in ("-r", "--reverse"):
                return "xxd -r decodes hex to raw bytes (write/obfuscation vector)"
            # combined short flags, e.g. -rp / -pr
            if arg.startswith("-") and not arg.startswith("--") and "r" in arg[1:]:
                return "xxd -r decodes hex to raw bytes (write/obfuscation vector)"

    return None


@dataclass
class SubstitutionNode:
    """Represents a command or process substitution in the AST."""

    substitution_type: SubstitutionType
    inner_command: str | None  # The command text inside the substitution (None if unrenderable, e.g. compound list segment)
    base_command: str | None  # First word of inner command (e.g., "op" from "op read ...")
    ast_node: Any  # The bashlex AST node
    nested_substitutions: list[SubstitutionNode] = field(default_factory=list)
    depth: int = 0  # Nesting depth


class _ListSegment:
    """Minimal stand-in that exposes one segment of a command list as a substitution's
    ``.command``, so the extraction/validation helpers (which read ``node.command``) can be reused
    to validate each `&&`/`||`/`;`/`&` segment independently.
    """

    __slots__ = ("command",)

    def __init__(self, command: Any) -> None:
        self.command = command


@dataclass
class SubstitutionValidationResult:
    """Result of validating a substitution."""

    allowed: bool
    risk_level: RiskLevel
    message: str
    whitelisted: bool = False  # True if matched whitelist (fast path)
    depth_exceeded: bool = False  # True if hit MAX_SUBSTITUTION_DEPTH
    inner_results: list[SubstitutionValidationResult] = field(default_factory=list)


class SubstitutionValidator:
    """Validates commands inside shell substitution constructs.

    Uses a three-layer approach:
    1. Whitelist check for known-safe commands (fast path)
    2. AST structural checks for suspicious patterns
    3. Recursive validation with depth limit

    Example:
        >>> validator = SubstitutionValidator(parser, rule_engine)
        >>> result = validator.validate_command_with_substitutions("echo $(date)")
        >>> result.allowed
        True
    """

    def __init__(self, parser: Any, rule_engine: Any) -> None:
        """Initialize validator with parser and rule engine.

        Args:
            parser: BashCommandParser instance
            rule_engine: RuleEngine instance for YAML rule matching
        """
        self.parser = parser
        self.rule_engine = rule_engine

    def extract_substitutions(self, ast_nodes: list[Any], depth: int = 0) -> list[SubstitutionNode]:
        """Extract all substitution nodes from AST.

        Args:
            ast_nodes: List of bashlex AST nodes
            depth: Current nesting depth

        Returns:
            List of SubstitutionNode objects representing all substitutions
        """
        substitutions: list[SubstitutionNode] = []

        def visit(node: Any, current_depth: int) -> None:
            if not hasattr(node, "kind"):
                return

            if node.kind == "commandsubstitution":
                sub_node = self._create_substitution_node(node, SubstitutionType.COMMAND, current_depth)
                if sub_node:
                    substitutions.append(sub_node)
                return  # Don't recurse into substitution here - handled by _create_substitution_node

            if node.kind == "processsubstitution":
                # Determine if input <(cmd) or output >(cmd)
                sub_type = SubstitutionType.PROCESS_INPUT  # Default, could enhance detection
                sub_node = self._create_substitution_node(node, sub_type, current_depth)
                if sub_node:
                    substitutions.append(sub_node)
                return

            # Recurse into child nodes
            for attr in ["parts", "command", "list", "pipe", "compound"]:
                if hasattr(node, attr):
                    child = getattr(node, attr)
                    if isinstance(child, list):
                        for item in child:
                            visit(item, current_depth)
                    elif child:
                        visit(child, current_depth)

        for node in ast_nodes or []:
            visit(node, depth)

        return substitutions

    def _create_substitution_node(self, node: Any, sub_type: SubstitutionType, depth: int) -> SubstitutionNode | None:
        """Create a SubstitutionNode from an AST node.

        Args:
            node: The bashlex commandsubstitution or processsubstitution node
            sub_type: Type of substitution
            depth: Current nesting depth

        Returns:
            SubstitutionNode or None if extraction fails
        """
        inner_command = self._extract_inner_command_text(node)
        # A command list ($(a && b), $(a; b)) is validated per-segment from its AST, so it must
        # survive even when text rendering is partial (e.g. a compound segment renders to None).
        # Dropping it here would silently skip validation -> fail OPEN. Per-segment logic blocks
        # the unrenderable segment instead. Non-list substitutions with no extractable command
        # stay dropped (genuinely unparseable).
        cmd_node = getattr(node, "command", None)
        is_list = getattr(cmd_node, "kind", None) == "list"
        if not inner_command and not is_list:
            return None

        base_command = self._extract_base_command(node)

        # Find nested substitutions
        nested: list[SubstitutionNode] = []
        if depth < MAX_SUBSTITUTION_DEPTH and hasattr(node, "command"):
            try:
                inner_ast = [node.command] if node.command else []
                nested = self.extract_substitutions(inner_ast, depth + 1)
            except Exception:  # noqa: S110 - Parse errors treated as suspicious AST
                nested = []  # Failed to parse nested - treat as no nested subs

        return SubstitutionNode(
            substitution_type=sub_type,
            inner_command=inner_command,
            base_command=base_command,
            ast_node=node,
            nested_substitutions=nested,
            depth=depth,
        )

    def _extract_inner_command_text(self, node: Any) -> str | None:  # noqa: PLR0911, PLR0912
        """Extract the command text from inside a substitution.

        Args:
            node: The substitution AST node

        Returns:
            Command string or None
        """
        if not hasattr(node, "command"):
            return None

        cmd_node = node.command
        if not cmd_node:
            return None

        # Handle pipeline: $(cmd1 | cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "pipeline":
            parts_text: list[str] = []
            if hasattr(cmd_node, "parts"):
                for part in cmd_node.parts:
                    if hasattr(part, "kind"):
                        if part.kind == "command" and hasattr(part, "parts"):
                            cmd_words = [p.word for p in part.parts if hasattr(p, "word")]
                            if cmd_words:
                                parts_text.append(" ".join(cmd_words))
                        elif part.kind == "pipe":
                            parts_text.append("|")
            return " ".join(parts_text) if parts_text else None

        # Handle command list: $(cmd1; cmd2), $(cmd1 && cmd2), $(cmd1 | cmd2 || cmd3), ...
        # This text feeds the Layer-4 YAML rule match and the audit log, so it must render EVERY
        # segment faithfully. A segment that cannot be rendered returns None (fail closed) rather
        # than a truncated string that would hide a dropped pipeline/compound from the rule engine.
        if hasattr(cmd_node, "kind") and cmd_node.kind == "list":
            parts_text = []
            if hasattr(cmd_node, "parts"):
                for part in cmd_node.parts:
                    kind = getattr(part, "kind", None)
                    if kind == "operator":
                        if not hasattr(part, "op"):
                            return None
                        parts_text.append(part.op)
                        continue
                    rendered = self._render_segment_text(part)
                    if rendered is None:
                        return None  # unrenderable segment -> fail closed
                    parts_text.append(rendered)
            return " ".join(parts_text) if parts_text else None

        # Handle simple command: try to get from parts
        words: list[str] = []
        if hasattr(cmd_node, "parts"):
            for part in cmd_node.parts:
                if hasattr(part, "word"):
                    words.append(part.word)

        if words:
            return " ".join(words)

        # Fallback: try to get from list (compound commands)
        if hasattr(cmd_node, "list") and cmd_node.list:
            # For compound commands, return first command
            first = cmd_node.list[0] if cmd_node.list else None
            if first and hasattr(first, "parts"):
                words = [p.word for p in first.parts if hasattr(p, "word")]
                return " ".join(words) if words else None

        return None

    def _segment_base_command(self, node: Any) -> str | None:
        """First word of a list segment (a `command`, or the first command of a `pipeline`).

        Returns None for a compound segment or anything without a leading word, which the caller
        treats as fail-closed (base_command=None -> blocked).
        """
        kind = getattr(node, "kind", None)
        if kind == "command":
            parts = getattr(node, "parts", None)
            if parts and hasattr(parts[0], "word"):
                return parts[0].word
            return None
        if kind == "pipeline":
            for part in getattr(node, "parts", []):
                if getattr(part, "kind", None) == "command":
                    parts = getattr(part, "parts", None)
                    if parts and hasattr(parts[0], "word"):
                        return parts[0].word
                    return None
            return None
        return None

    def _render_segment_text(self, node: Any) -> str | None:
        """Render one list segment (command or pipeline) to faithful command text.

        Returns None for anything that cannot be rendered verbatim (compound `{ … }`/`( … )`,
        a pipeline containing a reserved word like `!`, or an empty command). Callers treat None
        as fail-closed: the segment is still validated structurally via its AST node, but it never
        contributes a truncated string to the rule engine or audit log. Redirections are dropped
        from the text (they are detected structurally), matching the simple-command rendering.
        """
        kind = getattr(node, "kind", None)
        if kind == "command":
            words = [p.word for p in getattr(node, "parts", []) if hasattr(p, "word")]
            return " ".join(words) if words else None
        if kind == "pipeline":
            rendered: list[str] = []
            for part in getattr(node, "parts", []):
                part_kind = getattr(part, "kind", None)
                if part_kind == "pipe":
                    rendered.append("|")
                elif part_kind == "command":
                    words = [p.word for p in getattr(part, "parts", []) if hasattr(p, "word")]
                    if not words:
                        return None
                    rendered.append(" ".join(words))
                else:
                    return None  # reserved word / unexpected node -> fail closed
            return " ".join(rendered) if rendered else None
        return None  # compound or unknown segment -> cannot render faithfully

    def _extract_base_command(self, node: Any) -> str | None:  # noqa: PLR0911, PLR0912
        """Extract the base command (first word) from a substitution.

        Args:
            node: The substitution AST node

        Returns:
            Base command string or None
        """
        if not hasattr(node, "command"):
            return None

        cmd_node = node.command
        if not cmd_node:
            return None

        # Handle command list: $(cmd1 && cmd2) / $(cmd1; cmd2) -> first segment's base command.
        # Without this the list base_command is None and validate_substitution falls through to
        # the "Cannot determine command in substitution" hard block.
        if hasattr(cmd_node, "kind") and cmd_node.kind == "list":
            for part in getattr(cmd_node, "parts", []):
                if getattr(part, "kind", None) == "operator":
                    continue
                return self._segment_base_command(part)
            return None

        # Handle pipeline - get first command in pipeline
        if hasattr(cmd_node, "kind") and cmd_node.kind == "pipeline":
            if hasattr(cmd_node, "parts") and cmd_node.parts:
                first_cmd = cmd_node.parts[0]
                if hasattr(first_cmd, "parts") and first_cmd.parts:
                    first_word = first_cmd.parts[0]
                    if hasattr(first_word, "word"):
                        return first_word.word
            return None

        # Handle simple command
        if hasattr(cmd_node, "parts") and cmd_node.parts:
            first_part = cmd_node.parts[0]
            if hasattr(first_part, "word"):
                return first_part.word

        # Handle compound command (command list)
        if hasattr(cmd_node, "list") and cmd_node.list:
            first = cmd_node.list[0]
            if hasattr(first, "parts") and first.parts:
                first_part = first.parts[0]
                if hasattr(first_part, "word"):
                    return first_part.word

        return None

    @lru_cache(maxsize=256)  # noqa: B019 - OK, validator is singleton
    def is_whitelisted(self, base_command: str | None) -> bool:
        """Check if a command is in the safe whitelist.

        Args:
            base_command: The base command name

        Returns:
            True if whitelisted (safe)
        """
        if not base_command:
            return False
        return base_command in SAFE_SUBSTITUTION_COMMANDS

    @lru_cache(maxsize=256)  # noqa: B019 - OK, validator is singleton
    def is_blacklisted(self, base_command: str | None) -> bool:
        """Check if a command is in the dangerous blacklist.

        Args:
            base_command: The base command name

        Returns:
            True if blacklisted (dangerous)
        """
        if not base_command:
            return False
        return base_command in DANGEROUS_SUBSTITUTION_COMMANDS

    def has_suspicious_ast_patterns(self, node: Any) -> tuple[bool, str]:
        """Check for suspicious AST patterns that indicate bypass attempts.

        Args:
            node: The substitution AST node

        Returns:
            Tuple of (is_suspicious, reason)
        """
        if not hasattr(node, "command"):
            return False, ""

        cmd_node = node.command
        if not cmd_node:
            return False, ""

        # Check for brace expansion in command position
        # This catches $({r,}m -rf /) type attacks
        if self._has_brace_expansion_in_command(cmd_node):
            return True, "brace expansion in command name"

        # Check for variable as command
        # This catches $($CMD) type attacks
        if self._has_variable_as_command(cmd_node):
            return True, "variable used as command name"

        # Check for parameter expansion that could construct commands
        if self._has_suspicious_parameter_expansion(cmd_node):
            return True, "suspicious parameter expansion"

        return False, ""

    def _has_brace_expansion_in_command(self, cmd_node: Any) -> bool:
        """Check if command name uses brace expansion."""
        if not hasattr(cmd_node, "parts") or not cmd_node.parts:
            return False

        first_part = cmd_node.parts[0]

        # Check if first part has brace expansion
        if hasattr(first_part, "kind") and first_part.kind == "compound":
            return True

        # Check for brace in the word itself
        if hasattr(first_part, "word"):
            word = first_part.word
            if "{" in word and "," in word and "}" in word:
                return True

        return False

    def _has_variable_as_command(self, cmd_node: Any) -> bool:
        """Check if command name is a variable reference."""
        if not hasattr(cmd_node, "parts") or not cmd_node.parts:
            return False

        first_part = cmd_node.parts[0]

        # Check for parameter/variable node
        if hasattr(first_part, "kind"):
            if first_part.kind in ("parameter", "variable"):
                return True

        # Check for $ in word position (variable expansion)
        if hasattr(first_part, "word"):
            word = first_part.word
            # $VAR or ${VAR} as command
            if word.startswith("$"):
                return True

        # Check parts of the first word for parameter expansions
        if hasattr(first_part, "parts"):
            for subpart in first_part.parts:
                if hasattr(subpart, "kind") and subpart.kind == "parameter":
                    return True

        return False

    def _has_suspicious_parameter_expansion(self, cmd_node: Any) -> bool:
        """Check for parameter expansion that could construct dangerous paths."""
        # Check for ${VAR:offset:length} substring extraction
        # This is used to construct commands from environment variables
        pattern = re.compile(r"\$\{[^}]+:[0-9]+:[0-9]+\}")

        def check_node(node: Any) -> bool:
            if hasattr(node, "word"):
                if pattern.search(node.word):
                    return True
            if hasattr(node, "parts"):
                for part in node.parts:
                    if check_node(part):
                        return True
            return False

        return check_node(cmd_node)

    def _has_dangerous_inner_structure(  # noqa: PLR0911, PLR0912, PLR0915
        self, node: Any, base_command: str | None = None
    ) -> tuple[bool, str]:
        """Check if inner command has dangerous structures or arguments.

        These structures can weaponize even whitelisted commands:
        - $(date | bash) - pipeline bypasses date's safety
        - $(date; rm -rf /) - chain runs additional commands
        - $(for x in ...; do rm $x; done) - compound executes loop
        - $(echo x > /etc/cron.d/x) - output redirection writes files
        - $(git -c 'alias.x=!rm' x) - git alias executes shell command

        Args:
            node: The substitution AST node
            base_command: The base command being validated (for arg checks)

        Returns:
            Tuple of (is_dangerous, reason)
        """
        if not hasattr(node, "command"):
            return False, ""

        cmd_node = node.command
        if not cmd_node:
            return False, ""

        # Pipeline: $(cmd1 | cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "pipeline":
            return True, "pipeline in substitution"

        # Command list: $(cmd1; cmd2) or $(cmd1 && cmd2) or $(cmd1 || cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "list":
            return True, "command chain in substitution"

        # Compound command: $(if ...; then ...; fi) etc.
        if hasattr(cmd_node, "kind") and cmd_node.kind == "compound":
            return True, "compound command in substitution"

        # Check for output redirections and dangerous arguments
        if hasattr(cmd_node, "parts"):
            args: list[str] = []
            for part in cmd_node.parts:
                # Output redirection: $(echo x > file) or $(echo x >> file)
                if hasattr(part, "kind") and part.kind == "redirect":
                    if hasattr(part, "type") and part.type in (">", ">>", ">&"):
                        # >/dev/null and 2>/dev/null DISCARD output — nothing is written, so the
                        # common noise-suppression idiom $(ls dir 2>/dev/null | wc -l) stays
                        # allowed. Any other target (including >&2, whose output is an int fd,
                        # not a word) keeps the blunt no-writes-in-substitution block. See #104.
                        target = getattr(getattr(part, "output", None), "word", None)
                        if target != "/dev/null":
                            return True, "output redirection in substitution"

                # Collect arguments for dangerous pattern checks
                if hasattr(part, "word"):
                    args.append(part.word)

            if base_command == "git" and args:
                git_reason = dangerous_git_config(args)
                if git_reason:
                    return True, git_reason

            # find (-exec*/-ok*/-delete) and kubectl (state-modifying subcommands) via shared
            # helpers. dangerous_kubectl is reused at the top level (HIGH); top-level find stays
            # command-aware via the find_exec_dangerous / recursive_delete YAML rules. See #97.
            if base_command == "find" and args:
                find_reason = dangerous_find(args)
                if find_reason:
                    return True, find_reason

            if base_command == "kubectl" and args:
                kubectl_reason = dangerous_kubectl(args)
                if kubectl_reason:
                    return True, kubectl_reason

            # awk/sed are whitelisted as read-only pipeline stages but carry exec/write escape
            # hatches (awk system()/getline/pipes, sed -i/-f/e/w commands) — same contextual
            # pattern as find above. See #104.
            if base_command == "awk" and args:
                awk_reason = dangerous_awk(args)
                if awk_reason:
                    return True, awk_reason

            if base_command == "sed" and args:
                sed_reason = dangerous_sed(args)
                if sed_reason:
                    return True, sed_reason

            # Write-via-arg: sort/sdiff/xxd are whitelisted and would otherwise take the SAFE fast
            # path, bypassing the YAML rules that catch these at the top level (sort/sdiff ->
            # write_via_arg_persistence in 08_system_modification.yaml; xxd -> code_obfuscation in
            # 05_code_execution.yaml). Blunt: any write target inside a substitution is dangerous.
            # See #113.
            if base_command in _WRITE_ARG_COMMANDS and args:
                write_reason = dangerous_write_arg(base_command, args)
                if write_reason:
                    return True, write_reason

        return False, ""

    def _check_structural_and_nested(self, sub_node: SubstitutionNode, depth: int) -> SubstitutionValidationResult | None:
        """Check structural safety and nested substitutions.

        Shared logic between Layer 1 (whitelist) and Layer 1b (contextual whitelist).

        Returns:
            A BLOCKED result if checks fail, or None if everything passes.
        """
        from .rules import RiskLevel  # noqa: PLC0415

        has_dangerous, structure_reason = self._has_dangerous_inner_structure(sub_node.ast_node, sub_node.base_command)
        if has_dangerous:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Dangerous structure in substitution: {structure_reason}",
            )

        # AST-level bypass detection (brace expansion, variable-as-command, etc.)
        # Defense-in-depth: even whitelisted commands should reject obfuscated invocations.
        is_suspicious, reason = self.has_suspicious_ast_patterns(sub_node.ast_node)
        if is_suspicious:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Suspicious pattern in substitution: {reason}",
            )

        for nested in sub_node.nested_substitutions:
            nested_result = self.validate_substitution(nested, depth + 1)
            if not nested_result.allowed:
                return SubstitutionValidationResult(
                    allowed=False,
                    risk_level=nested_result.risk_level,
                    message=f"Nested substitution blocked: {nested_result.message}",
                    inner_results=[nested_result],
                )

        return None

    def _is_valid_list_topology(self, parts: list[Any]) -> bool:
        """True if ``parts`` is a well-formed bashlex command list: strictly alternating
        segment / operator, odd length >= 1, ending on a segment, with every operator slot a
        recognized list operator. Anything else is a malformed AST and the caller fails closed.
        """
        if not parts or len(parts) % 2 == 0:
            return False
        for index, part in enumerate(parts):
            is_operator = getattr(part, "kind", None) == "operator"
            if index % 2 == 0:
                if is_operator:
                    return False  # segment slot occupied by an operator
            elif not is_operator or getattr(part, "op", None) not in _LIST_OPERATORS:
                return False  # operator slot missing a recognized op
        return True

    def _validate_list_segments(self, sub_node: SubstitutionNode, cmd_node: Any, depth: int) -> SubstitutionValidationResult:
        """Validate a command-list substitution segment-by-segment.

        Each non-operator segment ($(a && b) -> [a, b]) is validated independently via
        ``_validate_segments``. Fail-closed: a malformed list topology blocks the whole list.
        """
        from .rules import RiskLevel  # noqa: PLC0415

        parts = list(getattr(cmd_node, "parts", []))
        # Validate the raw topology BEFORE dropping operators: a well-formed list strictly
        # alternates segment/operator and ends on a segment. A malformed shape (e.g. a trailing or
        # op-less operator node) must block rather than silently validate the surviving segments.
        if not self._is_valid_list_topology(parts):
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="Malformed list topology in substitution",
            )

        # A valid topology guarantees at least one segment (index 0 is always a segment slot),
        # so there is no separate empty-list branch.
        segments = [p for p in parts if getattr(p, "kind", None) != "operator"]
        return self._validate_segments(sub_node, segments, depth, "Command list segments validated")

    def _is_valid_pipeline_topology(self, parts: list[Any]) -> bool:
        """True if ``parts`` is a well-formed bashlex pipeline: strictly alternating
        stage / pipe, odd length >= 3, ending on a stage. Anything else — including a leading
        ``!`` negation (reservedword makes the length even) — fails closed.
        """
        if len(parts) < 3 or len(parts) % 2 == 0:  # noqa: PLR2004 - a pipeline is cmd,pipe,cmd
            return False
        for index, part in enumerate(parts):
            is_pipe = getattr(part, "kind", None) == "pipe"
            if index % 2 == 0:
                if is_pipe:
                    return False  # stage slot occupied by a pipe
            elif not is_pipe:
                return False  # pipe slot missing a pipe node
        return True

    def _validate_pipeline_stages(self, sub_node: SubstitutionNode, cmd_node: Any, depth: int) -> SubstitutionValidationResult:
        """Validate a pipeline substitution stage-by-stage.

        Each stage ($(a | b) -> [a, b]) is validated independently via ``_validate_segments``, so
        a pipeline is allowed exactly when every stage would be allowed on its own: whitelisted
        readers pass, blacklisted/unknown commands and dangerous per-command modes (find -exec,
        git -c, awk system(), …) block. A pipe only moves data between stages; the danger lives in
        the stages themselves. Fail-closed on any non-alternating topology. See #104.
        """
        from .rules import RiskLevel  # noqa: PLC0415

        parts = list(getattr(cmd_node, "parts", []))
        if not self._is_valid_pipeline_topology(parts):
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="Unsupported or malformed pipeline topology in substitution",
            )

        stages = [p for p in parts if getattr(p, "kind", None) != "pipe"]
        return self._validate_segments(sub_node, stages, depth, "Pipeline stages validated")

    def _validate_segments(
        self, sub_node: SubstitutionNode, segments: list[Any], depth: int, success_message: str
    ) -> SubstitutionValidationResult:
        """Shared segment loop for command lists and pipelines.

        Each segment is wrapped as its own substitution and run through the full
        ``validate_substitution`` pipeline at the SAME depth (decomposition, not nesting). The
        whole is allowed only if every segment is allowed; the combined risk is the max over
        segments and it is whitelisted only if every segment is. The whole rendered text is then
        re-checked against the YAML rules to catch cross-segment patterns.

        Fail-closed: a segment we cannot turn into a substitution node (e.g. a compound
        ``{ … }``/``( … )``/``if`` segment) blocks the whole substitution.
        """
        from .rules import RiskLevel  # noqa: PLC0415

        risk_order = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCKED]

        inner_results: list[SubstitutionValidationResult] = []
        max_risk = RiskLevel.SAFE
        all_whitelisted = True

        for segment in segments:
            child = self._create_substitution_node(_ListSegment(segment), sub_node.substitution_type, depth)
            if child is None:
                # Unrenderable segment (compound command, empty, etc.) -> block fail-closed.
                return SubstitutionValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message="Cannot determine command in substitution segment",
                    inner_results=inner_results,
                )
            result = self.validate_substitution(child, depth)
            inner_results.append(result)
            if not result.allowed:
                return SubstitutionValidationResult(
                    allowed=False,
                    risk_level=result.risk_level,
                    message=result.message,
                    inner_results=inner_results,
                )
            if risk_order.index(result.risk_level) > risk_order.index(max_risk):
                max_risk = result.risk_level
            all_whitelisted = all_whitelisted and result.whitelisted

        # Cross-segment defense-in-depth: re-match the full rendered text against the rules.
        if sub_node.inner_command and self.rule_engine is not None:
            rule_match = self.rule_engine.match_command(sub_node.inner_command)
            if rule_match and rule_match.matched:
                amplified_risk = self._amplify_risk(rule_match.risk_level)
                if amplified_risk in (RiskLevel.BLOCKED, RiskLevel.HIGH):
                    return SubstitutionValidationResult(
                        allowed=False,
                        risk_level=RiskLevel.BLOCKED,
                        message=f"Inner command blocked: {rule_match.message}",
                        inner_results=inner_results,
                    )

        return SubstitutionValidationResult(
            allowed=True,
            risk_level=max_risk,
            message=success_message,
            whitelisted=all_whitelisted,
            inner_results=inner_results,
        )

    def validate_substitution(  # noqa: PLR0911, PLR0912
        self, sub_node: SubstitutionNode, depth: int = 0
    ) -> SubstitutionValidationResult:
        """Validate a single substitution node.

        Args:
            sub_node: The substitution node to validate
            depth: Current recursion depth

        Returns:
            SubstitutionValidationResult
        """
        # Import here to avoid circular dependency
        from .rules import RiskLevel  # noqa: PLC0415

        # Check depth limit
        if depth > MAX_SUBSTITUTION_DEPTH:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Substitution nesting depth exceeded (max {MAX_SUBSTITUTION_DEPTH})",
                depth_exceeded=True,
            )

        # Command list: $(a && b), $(a; b), $(a & b), $(a || b). Validate each segment
        # independently and combine. Done BEFORE the whitelist fast path because a list's
        # base_command is just its FIRST segment's command — fast-pathing the whole chain on that
        # would skip validation of later segments (e.g. $(date; rm -rf /)).
        cmd_node = getattr(sub_node.ast_node, "command", None)
        if getattr(cmd_node, "kind", None) == "list":
            return self._validate_list_segments(sub_node, cmd_node, depth)

        # Pipeline: $(a | b). Validate each stage independently and combine, same as lists above —
        # a pure-reader pipeline ($(ls | wc -l)) is allowed, while any blacklisted/unknown stage
        # or dangerous per-command mode blocks. Done BEFORE the whitelist fast path because a
        # pipeline's base_command is just its FIRST stage's command — fast-pathing the whole
        # pipeline on that would skip validation of later stages ($(date | bash)). See #104.
        if getattr(cmd_node, "kind", None) == "pipeline":
            return self._validate_pipeline_stages(sub_node, cmd_node, depth)

        # Layer 1: Whitelist check (fast path) - WITH STRUCTURAL VALIDATION
        if self.is_whitelisted(sub_node.base_command):
            blocked = self._check_structural_and_nested(sub_node, depth)
            if blocked:
                return blocked
            return SubstitutionValidationResult(
                allowed=True,
                risk_level=RiskLevel.SAFE,
                message=f"Whitelisted command: {sub_node.base_command}",
                whitelisted=True,
            )

        # Layer 1b: Contextual whitelist — commands with subcommand-dependent safety.
        # Unlike the full whitelist, these STILL go through YAML rules (defense in depth).
        # e.g., kubectl: "get pods" is safe, but "get secrets -o json" is caught by YAML rules.
        if sub_node.base_command in CONTEXTUAL_SUBSTITUTION_COMMANDS:
            blocked = self._check_structural_and_nested(sub_node, depth)
            if blocked:
                return blocked

            # YAML rule check — defense in depth for contextual commands.
            # This catches patterns like kubectl_secrets_theft, kubectl_rbac_manipulation
            # that the structural checks alone would miss.
            if sub_node.inner_command:
                rule_match = self.rule_engine.match_command(sub_node.inner_command)
                if rule_match and rule_match.matched:
                    amplified_risk = self._amplify_risk(rule_match.risk_level)
                    if amplified_risk in (RiskLevel.BLOCKED, RiskLevel.HIGH):
                        return SubstitutionValidationResult(
                            allowed=False,
                            risk_level=RiskLevel.BLOCKED,
                            message=f"Inner command blocked: {rule_match.message}",
                        )

            # Passed structural checks AND YAML rules — safe in substitution
            return SubstitutionValidationResult(
                allowed=True,
                risk_level=RiskLevel.SAFE,
                message=f"Contextual whitelist: {sub_node.base_command}",
            )

        # Layer 1c: Blacklist check
        if self.is_blacklisted(sub_node.base_command):
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Dangerous command in substitution: {sub_node.base_command}",
            )

        # Layer 2: AST structural checks
        is_suspicious, reason = self.has_suspicious_ast_patterns(sub_node.ast_node)
        if is_suspicious:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Suspicious pattern in substitution: {reason}",
            )

        # Layer 3: Recursive validation of nested substitutions
        inner_results: list[SubstitutionValidationResult] = []
        for nested in sub_node.nested_substitutions:
            nested_result = self.validate_substitution(nested, depth + 1)
            inner_results.append(nested_result)
            if not nested_result.allowed:
                return SubstitutionValidationResult(
                    allowed=False,
                    risk_level=nested_result.risk_level,
                    message=f"Nested substitution blocked: {nested_result.message}",
                    inner_results=inner_results,
                )

        # Layer 4: Validate inner command against YAML rules
        if sub_node.inner_command:
            rule_match = self.rule_engine.match_command(sub_node.inner_command)
            if rule_match and rule_match.matched:
                # Amplify risk by +1 level for substitution context
                amplified_risk = self._amplify_risk(rule_match.risk_level)
                if amplified_risk == RiskLevel.BLOCKED:
                    return SubstitutionValidationResult(
                        allowed=False,
                        risk_level=RiskLevel.BLOCKED,
                        message=f"Inner command blocked: {rule_match.message}",
                        inner_results=inner_results,
                    )
                if amplified_risk == RiskLevel.HIGH:
                    # HIGH in substitution context - treat as blocked for safety
                    # Could be configurable based on risk tolerance
                    return SubstitutionValidationResult(
                        allowed=False,
                        risk_level=RiskLevel.BLOCKED,
                        message=f"High-risk command in substitution context: {rule_match.message}",
                        inner_results=inner_results,
                    )

        # Unknown command - default deny in substitution context
        if not sub_node.base_command:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="Cannot determine command in substitution",
            )

        # Command not in whitelist and not explicitly dangerous
        # This is the "gray area" - we block by default for security
        return SubstitutionValidationResult(
            allowed=False,
            risk_level=RiskLevel.HIGH,
            message=f"Unknown command in substitution: {sub_node.base_command}. Add to whitelist if safe.",
            inner_results=inner_results,
        )

    def _amplify_risk(self, risk_level: RiskLevel) -> RiskLevel:
        """Amplify risk level for substitution context.

        Substitution adds indirection which makes auditing harder.
        Risk is increased by one level (capped at BLOCKED).

        Args:
            risk_level: Original risk level

        Returns:
            Amplified risk level
        """
        from .rules import RiskLevel  # noqa: PLC0415

        risk_order = [
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ]

        try:
            idx = risk_order.index(risk_level)
            new_idx = min(idx + 1, len(risk_order) - 1)
            return risk_order[new_idx]
        except ValueError:
            return RiskLevel.BLOCKED  # Unknown risk level - be safe

    def validate_all_substitutions(self, ast_nodes: list[Any]) -> list[SubstitutionValidationResult]:
        """Validate all substitutions in an AST.

        Args:
            ast_nodes: The parsed AST nodes

        Returns:
            List of validation results for each substitution found
        """
        substitutions = self.extract_substitutions(ast_nodes)
        results: list[SubstitutionValidationResult] = []

        for sub in substitutions:
            result = self.validate_substitution(sub)
            results.append(result)

        return results

    def check_process_substitution_context(self, ast_nodes: list[Any], sub_node: SubstitutionNode) -> tuple[bool, str]:
        """Check if process substitution is in a dangerous context.

        Process substitution to a shell interpreter is RCE:
        - bash <(curl ...)  -> BLOCKED
        - diff <(ls dir1) <(ls dir2)  -> SAFE

        Args:
            ast_nodes: Full AST for context
            sub_node: The process substitution node

        Returns:
            Tuple of (is_dangerous, reason)
        """
        if sub_node.substitution_type not in (
            SubstitutionType.PROCESS_INPUT,
            SubstitutionType.PROCESS_OUTPUT,
        ):
            return False, ""

        # Find the outer command that uses this process substitution
        outer_cmd = self._find_outer_command(ast_nodes, sub_node.ast_node)

        if outer_cmd in DANGEROUS_SUBSTITUTION_COMMANDS:
            return True, f"Process substitution to shell interpreter: {outer_cmd}"

        # Specifically check for shell interpreters
        shell_interpreters = {"bash", "sh", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node"}
        if outer_cmd in shell_interpreters:
            return True, f"Process substitution to {outer_cmd} is arbitrary code execution"

        return False, ""

    def _find_outer_command(self, ast_nodes: list[Any], target_node: Any) -> str | None:
        """Find the outer command that contains a substitution node.

        Args:
            ast_nodes: Full AST
            target_node: The substitution node to find context for

        Returns:
            The outer command name or None
        """
        # This is a simplified implementation
        # A full implementation would track parent references in AST traversal
        for node in ast_nodes or []:
            if hasattr(node, "kind") and node.kind == "command":
                if hasattr(node, "parts") and node.parts:
                    first_word = node.parts[0]
                    if hasattr(first_word, "word"):
                        return first_word.word
        return None
