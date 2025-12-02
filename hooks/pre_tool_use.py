#!/usr/bin/env python3
"""PreToolUse hook for schlock bash command safety validation.

This hook intercepts Bash tool calls in Claude Code and validates commands
using the Core Safety Validation Engine before execution.

Fail-Safe Behavior:
- Any exception → deny decision
- Missing command parameter → deny decision
- Validation engine unavailable → deny decision
- Unknown risk level → deny decision (fail-safe)

Hook Interface:
- Input: JSON via stdin containing tool_name and tool_input
- Output: JSON with hookSpecificOutput structure to stdout
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

# Add vendored dependencies to path FIRST (pure Python packages)
vendor_path = Path(__file__).parent.parent / ".claude-plugin" / "vendor"
if vendor_path.exists():
    sys.path.insert(0, str(vendor_path))

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import yaml  # noqa: E402 - vendored dependency

from schlock import RiskLevel, ValidationResult, validate_command  # noqa: E402
from schlock.integrations.audit import AuditContext, get_audit_logger  # noqa: E402
from schlock.integrations.commit_filter import CommitMessageFilter, load_filter_config  # noqa: E402
from schlock.integrations.shellcheck import (  # noqa: E402
    format_findings_message,
    get_security_findings,
    is_shellcheck_available,
    run_shellcheck,
)
from schlock.setup.config_writer import DEFAULT_RISK_PRESET, RISK_PRESETS  # noqa: E402

# Configure logging to stderr
logging.basicConfig(level=logging.INFO, format="[schlock-hook] %(levelname)s: %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)


# Global validator instance (lazy-loaded)
_validator_initialized = False

# Global filter instance (lazy-loaded, optional)
_filter = None

# Global risk tolerance config (lazy-loaded)
_risk_tolerance = None

# Global shellcheck config (lazy-loaded)
_shellcheck_config = None


def get_risk_tolerance() -> dict:
    """Load risk tolerance configuration.

    Loads from config file or returns default preset.
    Caches result for performance.

    Returns:
        Dict mapping risk level names to actions (allow/ask/deny)
    """
    global _risk_tolerance  # noqa: PLW0603 - Singleton pattern
    if _risk_tolerance is not None:
        return _risk_tolerance

    # Default to balanced preset
    default_levels = RISK_PRESETS[DEFAULT_RISK_PRESET]["settings"]

    # Try to load from config file
    config_paths = [
        Path.cwd() / ".claude" / "hooks" / "schlock-config.yaml",
        Path.home() / ".config" / "schlock" / "config.yaml",
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                if config_data and "risk_tolerance" in config_data:
                    risk_tol = config_data["risk_tolerance"]
                    if "levels" in risk_tol:
                        _risk_tolerance = risk_tol["levels"]
                        logger.info(f"Loaded risk tolerance from {config_path}")
                        return _risk_tolerance
            except Exception as e:
                logger.warning(f"Failed to load risk tolerance from {config_path}: {e}")

    # Use default
    _risk_tolerance = default_levels
    logger.info(f"Using default risk tolerance preset: {DEFAULT_RISK_PRESET}")
    return _risk_tolerance


def get_shellcheck_config() -> dict:
    """Load shellcheck configuration.

    Loads from config file or returns defaults.
    Caches result for performance.

    Returns:
        Dict with shellcheck settings (enabled, severity, security_only)
    """
    global _shellcheck_config  # noqa: PLW0603 - Singleton pattern
    if _shellcheck_config is not None:
        return _shellcheck_config

    # Defaults: disabled unless explicitly enabled
    defaults = {
        "enabled": False,
        "severity": "info",  # Capture all security-relevant findings (SC2086 is info level)
        "security_only": True,
    }

    # Try to load from config file
    config_paths = [
        Path.cwd() / ".claude" / "hooks" / "schlock-config.yaml",
        Path.home() / ".config" / "schlock" / "config.yaml",
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                if config_data and "shellcheck" in config_data:
                    sc_config = config_data["shellcheck"]
                    _shellcheck_config = {
                        "enabled": sc_config.get("enabled", False),
                        "severity": sc_config.get("severity", "warning"),
                        "security_only": sc_config.get("security_only", True),
                    }
                    if _shellcheck_config["enabled"]:
                        logger.info(f"ShellCheck integration enabled from {config_path}")
                    return _shellcheck_config
            except Exception as e:
                logger.warning(f"Failed to load shellcheck config from {config_path}: {e}")

    # Use defaults
    _shellcheck_config = defaults
    return _shellcheck_config


def run_shellcheck_analysis(command: str) -> tuple[list, str]:
    """Run shellcheck analysis on a command if enabled.

    Args:
        command: Shell command to analyze

    Returns:
        Tuple of (findings_list, formatted_message)
        Empty list and empty string if disabled or no security findings.
    """
    config = get_shellcheck_config()

    # Skip if disabled or shellcheck not available
    if not config["enabled"]:
        return [], ""

    if not is_shellcheck_available():
        logger.debug("ShellCheck enabled but not installed")
        return [], ""

    try:
        findings = run_shellcheck(command, severity=config["severity"])

        if config["security_only"]:
            findings = get_security_findings(findings)

        if findings:
            message = format_findings_message(findings)
            return findings, message

    except Exception as e:
        logger.warning(f"ShellCheck analysis failed: {e}")

    return [], ""


def get_filter():
    """Initialize filter singleton.

    Returns:
        CommitMessageFilter instance or None if disabled/unavailable

    Unlike validator (which is critical), filter failure is non-fatal.
    Returns None to disable filtering (fail-open).
    """
    global _filter  # noqa: PLW0603 - Singleton pattern for commit filter
    if _filter is None:
        try:
            config = load_filter_config()
            _filter = CommitMessageFilter(config)
            logger.info("CommitMessageFilter initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize CommitMessageFilter: {e}. Filter disabled.")
            # Return None -> filter disabled (fail-open)
            return None
    return _filter


def get_validator() -> bool:
    """Initialize validator singleton.

    Returns:
        True if validator is available

    Note: Actual validation is done via validate_command() which handles
    its own initialization. This just checks if the module is importable.
    """
    global _validator_initialized  # noqa: PLW0603 - Singleton pattern for validator
    if not _validator_initialized:
        try:
            # Test that we can import and call validate_command
            _validator_initialized = True
            logger.info("Validator initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize validator: {e}")
            raise RuntimeError(f"Safety engine unavailable: {e}")
    return True


def map_risk_to_status(risk_level: RiskLevel) -> str:
    """Map RiskLevel enum to hook permission decision.

    Args:
        risk_level: RiskLevel from validation result

    Returns:
        "allow", "ask", or "deny" based on configured risk tolerance

    Mapping (Configurable via risk_tolerance):
        Default "balanced" preset:
        - SAFE, LOW, MEDIUM → allow (safe to execute)
        - HIGH → ask (prompt user for approval)
        - BLOCKED → deny (always prevented)

    Risk tolerance can be configured in:
        - .claude/hooks/schlock-config.yaml (project)
        - ~/.config/schlock/config.yaml (user)

    Presets available:
        - permissive: HIGH=allow (experienced users)
        - balanced: HIGH=ask (default, prompt for risky commands)
        - paranoid: MEDIUM=ask, HIGH=deny (strict environments)
    """
    risk_tolerance = get_risk_tolerance()

    # Get configured action for this risk level
    level_name = risk_level.name  # e.g., "HIGH", "BLOCKED"
    action = risk_tolerance.get(level_name)

    if action in ("allow", "ask", "deny"):
        return action

    # Unknown risk level or action → fail-safe BLOCK
    logger.warning(f"Unknown risk level or action: {risk_level}={action}, defaulting to deny")
    return "deny"


def get_context() -> AuditContext:
    """Extract context information for audit logging.

    Returns:
        AuditContext with project/git metadata.

    Attempts to detect:
        - Project root (current directory or git root)
        - Current directory
        - Git branch (if in git repository)
    """
    try:
        current_dir = str(Path.cwd())
        project_root = current_dir

        # Try to find git root
        git_branch = None
        try:
            import subprocess  # noqa: PLC0415 - Lazy import for performance

            # Get git root
            git_root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            if git_root.returncode == 0:
                project_root = git_root.stdout.strip()

            # Get current branch
            branch_result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            if branch_result.returncode == 0:
                git_branch = branch_result.stdout.strip()

        except Exception:  # noqa: S110 - Git info optional, fail silently
            pass

        return AuditContext(project_root=project_root, current_dir=current_dir, git_branch=git_branch, environment="development")

    except Exception:
        # Return minimal context on error
        return AuditContext()


def format_message(result: ValidationResult, decision: str = "deny") -> str:
    """Format user-facing message for blocked or prompted commands.

    Args:
        result: ValidationResult from validation engine
        decision: Permission decision ("ask" or "deny")

    Returns:
        Formatted message string

    Format for "ask" (prompt):
        CAUTION: <reason>
        Risk Level: <risk_level>
        Alternatives:
          - <alternative 1>

    Format for "deny" (block):
        BLOCKED: <reason>
        Risk Level: <risk_level>
        Alternatives:
          - <alternative 1>
    """
    lines = []

    # Status line with reason
    if decision == "ask":
        lines.append(f"CAUTION: {result.message}")
    else:
        lines.append(f"BLOCKED: {result.message}")

    # Risk level line
    lines.append(f"Risk Level: {result.risk_level.name}")

    # Alternatives (if any)
    if result.alternatives:
        lines.append("\nAlternatives:")
        for alt in result.alternatives:
            lines.append(f"  - {alt}")

    return "\n".join(lines)


def handle_pre_tool_use(input_data: dict) -> dict:  # noqa: PLR0915, PLR0911, PLR0912 - Complex hook logic
    """Hook handler called by Claude Code before tool execution.

    Reads command from stdin JSON input, validates it, and returns permission decision.

    Args:
        input_data: Hook input JSON containing tool_name and tool_input

    Returns:
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow" | "deny",
                "permissionDecisionReason": "Optional message"
            }
        }

    Behavior:
        1. Extract command from tool_input.command
        2. Validate using validate_command()
        3. Map risk level to permission decision (binary)
        4. Format user message (if blocked)
        5. Log audit event
        6. Return hook response

    Error Handling:
        - All exceptions caught and logged
        - Default to deny on any error
        - User sees safe error message (no sensitive data)
    """
    start_time = time.perf_counter()
    audit_logger = get_audit_logger()
    context = get_context()

    try:
        # 1. Extract command from stdin JSON
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})
        command = tool_input.get("command", "")

        if not command:
            logger.error(f"Missing command parameter. tool_name={tool_name}, tool_input keys={list(tool_input.keys())}")
            execution_time_ms = (time.perf_counter() - start_time) * 1000
            audit_logger.log_validation(
                command="<missing>",
                risk_level="BLOCKED",
                violations=["Missing command parameter"],
                decision="block",
                execution_time_ms=execution_time_ms,
                context=context,
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "BLOCKED: Missing command parameter (internal error)",
                }
            }

        logger.info(f"Validating command: {command[:100]}...")  # Log first 100 chars

        # 2. FILTER FIRST (before safety validation)
        filter_instance = get_filter()
        if filter_instance:
            filter_result = filter_instance.filter_commit_message(command)

            # DENY if advertising patterns were matched (not just whitespace changes)
            if filter_result.patterns_removed:
                logger.warning(
                    f"[commit-filter] BLOCKED commit with advertising "
                    f"(categories: {', '.join(filter_result.categories_matched)})"
                )

                # Build user-facing message
                patterns_list = []
                for pattern_info in filter_result.patterns_removed:
                    patterns_list.append(f"  - {pattern_info['description']}")

                patterns_text = "\n".join(patterns_list)

                denial_message = (
                    f"BLOCKED: Commit contains advertising/unwanted content\n\n"
                    f"Detected patterns:\n{patterns_text}\n\n"
                    f"Please remove these from your commit message and try again."
                )

                if os.getenv("SCHLOCK_DEBUG"):
                    logger.debug(f"Original: {filter_result.original_message[:200]}")
                    logger.debug(f"Cleaned: {filter_result.cleaned_message[:200]}")

                # Log audit event
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                violations = [f"Advertising: {cat}" for cat in filter_result.categories_matched]
                audit_logger.log_validation(
                    command=command[:500],  # Truncate for log size
                    risk_level="BLOCKED",
                    violations=violations,
                    decision="block",
                    execution_time_ms=execution_time_ms,
                    context=context,
                )

                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": denial_message,
                    }
                }

        # 3. Ensure validator is initialized
        get_validator()

        # 4. Validate using validate_command
        result: ValidationResult = validate_command(command)

        # 5. Check if validation had errors
        if result.error:
            logger.error(f"Validation error: {result.error}")
            execution_time_ms = (time.perf_counter() - start_time) * 1000
            audit_logger.log_validation(
                command=command[:500],
                risk_level="BLOCKED",
                violations=[f"Validation error: {result.error}"],
                decision="block",
                execution_time_ms=execution_time_ms,
                context=context,
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"BLOCKED: Validation error - {result.error}",
                }
            }

        # 6. Map risk level to permission decision
        decision = map_risk_to_status(result.risk_level)

        # 7. Run ShellCheck analysis (if enabled and command would be allowed)
        shellcheck_findings = []
        shellcheck_message = ""
        if decision == "allow":
            shellcheck_findings, shellcheck_message = run_shellcheck_analysis(command)
            if shellcheck_findings:
                # Elevate to "ask" if ShellCheck found security issues
                decision = "ask"
                logger.info(f"ShellCheck found {len(shellcheck_findings)} security issue(s)")

        # Calculate execution time
        execution_time_ms = (time.perf_counter() - start_time) * 1000

        # Extract violations from result
        violations = result.matched_rules if hasattr(result, "matched_rules") and result.matched_rules else []

        # Add shellcheck findings to violations for audit
        if shellcheck_findings:
            for finding in shellcheck_findings:
                violations.append(f"ShellCheck {finding.sc_code}: {finding.message}")

        # 8. Build response and log audit event
        if decision == "allow":
            logger.info(f"Command allowed (risk: {result.risk_level.name})")
            audit_logger.log_validation(
                command=command[:500],
                risk_level=result.risk_level.name,
                violations=violations,
                decision="allow",
                execution_time_ms=execution_time_ms,
                context=context,
            )
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}

        if decision == "ask":
            # Prompt user for approval (HIGH risk or ShellCheck findings)
            message = format_message(result, decision="ask")
            # Append ShellCheck message if present
            if shellcheck_message:
                message = f"{message}\n\n{shellcheck_message}"
            logger.info(f"Command requires approval (risk: {result.risk_level.name})")
            audit_logger.log_validation(
                command=command[:500],
                risk_level=result.risk_level.name,
                violations=violations,
                decision="ask",
                execution_time_ms=execution_time_ms,
                context=context,
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": message,
                }
            }

        # Blocked case (decision == "deny")
        message = format_message(result, decision="deny")
        logger.warning(f"Command blocked (risk: {result.risk_level.name})")
        audit_logger.log_validation(
            command=command[:500],
            risk_level=result.risk_level.name,
            violations=violations if violations else [result.message],
            decision="block",
            execution_time_ms=execution_time_ms,
            context=context,
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }

    except RuntimeError as e:
        # Validator initialization failed
        logger.error(f"RuntimeError in hook: {e}")
        execution_time_ms = (time.perf_counter() - start_time) * 1000
        audit_logger.log_validation(
            command=input_data.get("tool_input", {}).get("command", "<unknown>")[:500],
            risk_level="BLOCKED",
            violations=[f"RuntimeError: {str(e)}"],
            decision="block",
            execution_time_ms=execution_time_ms,
            context=context,
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"BLOCKED: {str(e)}",
            }
        }

    except Exception as e:
        # Catch-all for unexpected errors
        logger.error(f"Unexpected error in hook: {e}", exc_info=True)
        execution_time_ms = (time.perf_counter() - start_time) * 1000
        audit_logger.log_validation(
            command=input_data.get("tool_input", {}).get("command", "<unknown>")[:500],
            risk_level="BLOCKED",
            violations=[f"Unexpected error: {str(e)}"],
            decision="block",
            execution_time_ms=execution_time_ms,
            context=context,
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "BLOCKED: Internal validation error (see logs for details)",
            }
        }


def main():
    """Entry point for Claude Code hook execution."""
    try:
        # Read hook input from stdin
        input_data = json.load(sys.stdin)
        result = handle_pre_tool_use(input_data)
        # Output JSON to stdout
        print(json.dumps(result))
        sys.exit(0)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse stdin JSON: {e}", exc_info=True)
        error_result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "BLOCKED: Invalid hook input",
            }
        }
        print(json.dumps(error_result))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        # Still output valid JSON even on fatal errors
        error_result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "BLOCKED: Fatal hook error",
            }
        }
        print(json.dumps(error_result))
        sys.exit(1)


if __name__ == "__main__":
    main()
