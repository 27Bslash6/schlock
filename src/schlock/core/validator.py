"""Command validation orchestrator.

This module orchestrates the validation flow, integrating the parser,
rule engine, and cache. It provides the main validate_command() API and
handles configuration layering (plugin defaults → user → project).
"""

import logging
import re
import subprocess
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

import yaml

from schlock.exceptions import ConfigurationError, ParseError
from schlock.integrations.shellcheck import (
    get_security_findings,
    is_shellcheck_available,
    run_shellcheck,
)

from .cache import ValidationCache
from .parser import BashCommandParser
from .rules import RiskLevel, RuleEngine, RuleMatch, SecurityRule
from .substitution import SubstitutionValidator

logger = logging.getLogger(__name__)


# Module-level cache (shared across all validation calls)
_global_cache = ValidationCache(max_size=1000)

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
    """Get cached SubstitutionValidator.

    PERF: SubstitutionValidator caches whitelist lookups.
    Thread-safe: Uses _cache_lock to prevent race conditions.
    """
    global _global_substitution_validator  # noqa: PLW0603

    with _cache_lock:
        if _global_substitution_validator is None:
            parser = _get_parser()
            engine = _get_rule_engine(config_path)
            _global_substitution_validator = SubstitutionValidator(parser, engine)
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


# The rewrite emits its own delimiter rather than reusing the real one, which
# can legally contain whitespace or metacharacters (`<<'A;B'`) that would change
# the surrounding command's structure once unquoted.
_HEREDOC_PLACEHOLDER = "SCHLOCK_HEREDOC"

# Strips the rewritten redirection back off a segment. Exact rather than a
# guess, because the rewrite chose this delimiter itself.
_HEREDOC_REDIRECT_RE = re.compile(rf"\s*<<-?{_HEREDOC_PLACEHOLDER}")

# Bash ends an unquoted word at a blank or an operator character.
_WORD_END = frozenset(" \t;&|<>()")

# `#` opens a comment only at the start of a word.
_WORD_START_AFTER = frozenset(" \t;&|(<>")


def _read_delimiter(text: str, pos: int) -> tuple[str, int]:
    """Read the heredoc delimiter word at ``pos``, applying bash's quote removal.

    Bash takes the whole word after `<<`, removes its quotes, and uses the result
    as the terminator: `<<EOF`, `<< "E"OF`, `<< 'E'OF` and `<<\\EOF` all end at a
    line reading exactly `EOF`. Reading only the first quoted run instead yields
    `E`, and the body then swallows every command after the real terminator.

    Args:
        text: Line being lexed
        pos: Offset of the first delimiter character

    Returns:
        ``(delimiter, offset just past the word)``

    Raises:
        ParseError: on an unterminated quote or an empty delimiter. A delimiter
            this cannot tokenize is a body boundary it cannot locate, so the
            caller must not vouch for anything around it.
    """
    delimiter: list[str] = []
    while pos < len(text) and text[pos] not in _WORD_END:
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


def _rewrite_openers(line: str, quote: str) -> tuple[str, list[tuple[str, bool, int]], str]:
    """Replace this line's heredoc delimiters with the placeholder, in shell order.

    Only an *unquoted* `<<` opens a heredoc. Bash reads `echo "x << y"` and
    `# note << z` as plain text, and `<<<` as a here-string; a scan that does not
    track lexical state invents heredocs in all three, and the phantom body then
    swallows the real commands that follow. That is the LAB-1731 lesson one
    lexical context over: enumerate the tokenization deltas before trusting a
    rewrite, and deny when the reading is uncertain.

    Args:
        line: One line of the command
        quote: Quote character left open by the previous line, or "" - a string
            spanning lines means the next line is not shell to be scanned

    Returns:
        ``(rewritten line, [(delimiter, strips_tabs, offset)] in opener order, open quote)``
        where ``offset`` is where the `<<` sits in ``line`` - the only honest source
        for "what command owns this heredoc", since a second regex looking for the
        first `<<` would find the quoted ones this skipped

    Raises:
        ParseError: propagated from :func:`_read_delimiter`
    """
    out: list[str] = []
    openers: list[tuple[str, bool, int]] = []
    pos = 0

    while pos < len(line):
        char = line[pos]

        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"' and pos + 1 < len(line):
                out.append(char)
                pos += 1
                char = line[pos]
            out.append(char)
            pos += 1
        elif char == "\\":
            out.append(line[pos : pos + 2])
            pos += 2
        elif char in "'\"":
            quote = char
            out.append(char)
            pos += 1
        elif char == "#" and (pos == 0 or line[pos - 1] in _WORD_START_AFTER):
            out.append(line[pos:])  # comment: text, not shell
            break
        elif line.startswith("<<<", pos):
            out.append("<<<")  # here-string, not a heredoc (LAB-2768)
            pos += 3
        elif line.startswith("<<", pos):
            opener_at = pos
            pos += 2
            strips_tabs = line.startswith("-", pos)
            pos += 1 if strips_tabs else 0
            while pos < len(line) and line[pos] in " \t":
                pos += 1
            delimiter, pos = _read_delimiter(line, pos)
            openers.append((delimiter, strips_tabs, opener_at))
            out.append(f"<<{'-' if strips_tabs else ''}{_HEREDOC_PLACEHOLDER}")
        else:
            out.append(char)
            pos += 1

    return "".join(out), openers, quote


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

    Args:
        command: Full command string containing at least one heredoc

    Returns:
        ``(rewritten command, text before the first heredoc opener)``

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
    quote = ""
    index = 0

    while index < len(lines):
        line, openers, quote = _rewrite_openers(lines[index], quote)
        rewritten.append(line)
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
                index += 1
                if (body.lstrip("\t") if strips_tabs else body) == delimiter:
                    rewritten.append(_HEREDOC_PLACEHOLDER)
                    break
            else:
                raise ParseError(f"Heredoc {delimiter!r} has no terminator; its body has no end")

    if base_command is None:
        raise ParseError("No heredoc opener found in a command bashlex rejected as a heredoc")
    if not base_command:
        raise ParseError("Heredoc with no command in front of it")

    return "\n".join(rewritten), base_command


def _validate_heredoc_command(
    command: str,
    config_path: Optional[str] = None,
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
        base_result = _heredoc_base_result(engine, base_command)
        return _escalate_past_heredoc(engine, command, neutered, base_result, config_path)
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

    # Check if base command matches any dangerous patterns
    match = engine.match_command(base_command)
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


def _escalate_past_heredoc(
    engine: "RuleEngine",
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
    validated individually as well, because a whitelisted prefix short-circuits
    the whole-command pass before the per-segment loop it relies on (LAB-2752).
    Neither pass subsumes the other: the whole-command pass is the only one that
    sees `curl … | sh` as a pipeline, the per-segment pass is the only one the
    whitelist cannot silence. Cost of the extra passes, measured with ShellCheck
    installed: ~12ms for a heredoc followed by two commands, and 538ms for a
    pathological 2000-command chain - against 409ms for that same chain with no
    heredoc in front of it, so this path stays within reach of the ordinary one.

    Escalation only ever raises risk. That is what keeps a legitimate heredoc's
    existing verdict intact, and it bounds a misread rewrite to a false positive.

    Args:
        engine: Rule engine, already loaded
        command: Full command string with heredoc
        neutered: Rewrite of ``command`` from :func:`_neuter_heredocs`
        result: Verdict for the heredoc's own command
        config_path: Optional rules config path

    Returns:
        ``result``, or the worst verdict among the commands around the heredoc
    """
    parser = _get_parser()
    segments = parser.extract_command_segments(neutered, parser.parse(neutered))

    # `neutered != command` keeps the recursion finite: re-validating an
    # unchanged command would re-enter this same fallback forever.
    candidates = [neutered] if neutered != command else []
    # A segment that owns a heredoc keeps its redirection, and standalone that
    # reads as an unterminated heredoc - which would deny every heredoc there
    # is. Strip the redirection instead of skipping the segment: the command in
    # front of it is exactly the one nothing used to look at, and
    # `chmod -R 777 / <<'Y'` is not made safe by owning a body.
    candidates += [_HEREDOC_REDIRECT_RE.sub("", segment) for segment in segments]

    for candidate in candidates:
        if not candidate.strip():
            continue
        candidate_result = validate_command(candidate, config_path)
        if candidate_result.risk_level.value > result.risk_level.value:
            result = replace(candidate_result, message=f"Alongside heredoc: {candidate_result.message}")

    return result


def validate_command(  # noqa: PLR0911, PLR0912, PLR0915 - Complex validation flow
    command: str,
    config_path: Optional[str] = None,
) -> ValidationResult:
    """Validate command for safety.

    Main validation API. Orchestrates parsing, rule matching, and caching.

    Validation flow:
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

    Returns:
        ValidationResult with validation outcome (never raises)

    Example:
        >>> result = validate_command("rm -rf /")
        >>> print(result.allowed)  # False
        >>> print(result.risk_level)  # RiskLevel.BLOCKED
        >>> print(result.exit_code)  # 1
    """
    try:
        # Step 1: Check cache
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
            for sub_result in sub_results:
                if not sub_result.allowed:
                    return ValidationResult(
                        allowed=False,
                        risk_level=sub_result.risk_level,
                        message=f"BLOCKED: {sub_result.message}",
                        alternatives=[
                            "Use whitelisted read-only commands in substitution (e.g. ls, cat, grep, head, wc, sort, git)",
                            "Run the command directly instead of using substitution",
                            "If this command is safe, request it be added to the whitelist",
                        ],
                        exit_code=1,
                        error=None,
                    )
                # Don't cache (substitution content may vary)

            # SECURITY: Pure AST-based dangerous command detection
            # Uses bashlex AST for BOTH command names AND arguments (no regex shortcuts)
            # This catches quoted command names that bypass regex patterns (e.g., "nc" -e)
            # Must run AFTER parsing but BEFORE regex matching for defense in depth
            commands_with_args = parser.extract_commands_with_args(ast)
            dangerous_check = _check_dangerous_command_flags(commands_with_args)
            if dangerous_check is not None:
                return dangerous_check

        except (ParseError, ValueError) as e:
            # Check if this is a heredoc parse failure (bashlex doesn't support quoted delimiters)
            # e.g., python3 << 'EOF' ... EOF
            if "<<" in command and ("here-document" in str(e) or "heredoc" in str(e).lower()):
                # Extract command before heredoc and validate that instead
                heredoc_result = _validate_heredoc_command(command, config_path)
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
            segments = parser.extract_command_segments(command, ast)

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
                if engine.is_whitelisted(command):
                    result = ValidationResult(
                        allowed=True,
                        risk_level=RiskLevel.SAFE,
                        message="Command is whitelisted",
                        alternatives=[],
                        exit_code=0,
                        error=None,
                        matched_rules=[],
                    )
                    _global_cache.set(command, result)
                    return result

                highest_risk = RiskLevel.SAFE
                highest_match = None

                for segment in segments:
                    # Parse segment to get its string literals
                    try:
                        seg_ast = parser.parse(segment)
                        seg_literals = parser.extract_string_literals(segment, seg_ast)
                    except (ParseError, ValueError):
                        seg_literals = []

                    seg_match = engine.match_command(segment, string_literals=seg_literals)

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
                    match = engine.match_command(command, string_literals=string_literals)
                    all_matched_rules = []
            else:
                # Single segment - validate both original and reconstructed command
                # SECURITY: Bashlex unescapes characters (e.g., 'rm\ -rf\ /' → 'rm -rf /')
                # We must match against both to catch escape-based evasion attempts
                match = engine.match_command(
                    command,
                    string_literals=string_literals,
                    heredoc_ranges=heredoc_ranges,
                )

                # Also check reconstructed command (catches escaped characters)
                # SECURITY: Reconstruction strips quotes, which is useful for detecting
                # escape sequences like 'rm\ -rf\ /' → 'rm -rf /', but we must NOT
                # use it if the original match was inside a string literal (would cause false positives)
                reconstructed = parser.reconstruct_command(ast)
                if reconstructed and reconstructed != command:
                    # Only check reconstructed if there are no string literals that would explain the difference
                    # (i.e., difference is due to escapes, not quotes)
                    if not string_literals:
                        recon_match = engine.match_command(reconstructed, string_literals=[])
                        # Use higher risk match
                        if recon_match.risk_level > match.risk_level:
                            match = recon_match
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

        # Step 6: ShellCheck integration (if available)
        # ShellCheck can catch issues our regex patterns miss, like $'' expansions
        # SC2114: "Warning: deletes a system directory" catches rm -r$''f /
        shellcheck_elevated = False
        security_findings: list = []  # Initialize for type checker
        if is_shellcheck_available() and match.risk_level < RiskLevel.BLOCKED:
            findings = run_shellcheck(command)
            security_findings = get_security_findings(findings)
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

        # Step 7: Cache successful validation
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
    _global_cache.clear()
    _global_rule_engine = None
    _global_rule_engine_path = None
    _global_parser = None
    _global_substitution_validator = None
