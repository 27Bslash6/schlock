"""Command validation orchestrator.

This module orchestrates the validation flow, integrating the parser,
rule engine, and cache. It provides the main validate_command() API and
handles configuration layering (plugin defaults → user → project).
"""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from schlock.exceptions import ConfigurationError, ParseError

from .cache import ValidationCache
from .parser import BashCommandParser
from .rules import RiskLevel, RuleEngine

logger = logging.getLogger(__name__)


# Module-level cache (shared across all validation calls)
_global_cache = ValidationCache(max_size=1000)


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
    """Load rules with configuration layering.

    Configuration layers (later overrides earlier):
    1. Plugin defaults: data/rules/ directory or data/safety_rules.yaml (required)
    2. User overrides: Platform-specific config directory (optional, future feature)
    3. Project overrides: .claude/hooks/schlock-config.yaml (optional)

    Loading priority:
    1. If config_path provided, use it (testing/override)
    2. If data/rules/ directory exists, load from multiple files (NEW)
    3. Otherwise, fall back to data/safety_rules.yaml (backward compatibility)

    Args:
        config_path: Optional path to rules file (for testing)

    Returns:
        RuleEngine loaded with merged configuration

    Raises:
        ConfigurationError: If plugin defaults are missing or invalid
    """
    if config_path:
        # Testing/override path
        return RuleEngine(config_path)

    # Default: check for multi-file structure first
    # Path: core/validator.py -> core -> schlock -> src -> project_root
    project_root = Path(__file__).parent.parent.parent.parent
    rules_dir = project_root / "data" / "rules"

    if rules_dir.exists() and rules_dir.is_dir():
        # Multi-file loading (NEW)
        logger.info(f"Loading rules from directory: {rules_dir}")
        return RuleEngine.from_directory(rules_dir)

    # Fall back to single file (BACKWARD COMPATIBILITY)
    default_rules = project_root / "data" / "safety_rules.yaml"

    if not default_rules.exists():
        raise ConfigurationError(
            f"Plugin defaults not found. Expected either {rules_dir}/ or {default_rules}. "
            "This is a fatal error - plugin installation may be corrupted.",
            file_path=str(default_rules),
        )

    logger.info(f"Loading rules from file: {default_rules}")
    return RuleEngine(default_rules)


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
        engine = load_rules(config_path)
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


def validate_command(  # noqa: PLR0911 - Multiple validation paths require multiple exits
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
        parser = BashCommandParser()
        try:
            ast = parser.parse(command)
            # Extract string literals for context-aware matching
            string_literals = parser.extract_string_literals(command, ast)

            # Check for dangerous constructs (command/process substitution, eval)
            dangerous_constructs = parser.has_dangerous_constructs(ast)
            if dangerous_constructs:
                return ValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message=f"BLOCKED: Dangerous shell construct detected - {', '.join(dangerous_constructs)}",
                    alternatives=[
                        "Avoid command substitution $(cmd) or `cmd` - run commands explicitly",
                        "Avoid process substitution <(cmd) or >(cmd)",
                        "Never use eval or exec - they enable arbitrary code execution",
                        "Run commands directly instead of dynamically generating them",
                    ],
                    exit_code=1,
                    error=None,
                )
                # Don't cache (construct may be context-dependent)
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
            engine = load_rules(config_path)
            # Pass string literals to enable context-aware matching
            match = engine.match_command(command, string_literals=string_literals)
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

        # Step 6: Build ValidationResult
        # BLOCKED commands are not allowed
        allowed = match.risk_level != RiskLevel.BLOCKED
        exit_code = 0 if allowed else 1

        # Extract matched rule names for audit logging
        matched_rules = [match.rule.name] if match.matched and match.rule else []

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
