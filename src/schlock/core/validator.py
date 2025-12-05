"""Command validation orchestrator.

This module orchestrates the validation flow, integrating the parser,
rule engine, and cache. It provides the main validate_command() API and
handles configuration layering (plugin defaults → user → project).
"""

import logging
import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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
    return RuleEngine.from_directory(rules_dir)


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


def _validate_heredoc_command(
    command: str,
    config_path: Optional[str] = None,
) -> Optional[ValidationResult]:
    """Validate command containing heredoc that bashlex couldn't parse.

    Bashlex doesn't support quoted heredoc delimiters (e.g., << 'EOF').
    This extracts the command before the heredoc and validates that.

    Args:
        command: Full command string with heredoc
        config_path: Optional rules config path

    Returns:
        ValidationResult if heredoc command validated, None if fallback failed
    """
    # Find heredoc marker - match << followed by optional quotes and delimiter
    # e.g., "python3 << 'EOF'" -> extract "python3"
    heredoc_match = re.match(r"^(.+?)\s*<<\s*['\"]?\w+['\"]?", command)
    if not heredoc_match:
        return None

    base_command = heredoc_match.group(1).strip()
    if not base_command:
        return None

    # Recursively validate the base command (without heredoc)
    # Use a simple approach: just validate the command name for whitelist
    first_word = base_command.split()[0] if base_command.split() else ""

    # Check whitelist and rules
    try:
        engine = _get_rule_engine(config_path)
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
    except Exception as e:
        logger.debug(f"Heredoc validation fallback failed: {e}")
        return None


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
                            "Use whitelisted commands in substitution: op, date, git, pwd, whoami, hostname",
                            "Run the command directly instead of using substitution",
                            "If this command is safe, request it be added to the whitelist",
                        ],
                        exit_code=1,
                        error=None,
                    )
                # Don't cache (substitution content may vary)
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
    global _global_rule_engine, _global_rule_engine_path, _global_parser  # noqa: PLW0603
    _global_cache.clear()
    _global_rule_engine = None
    _global_rule_engine_path = None
    _global_parser = None
