"""Configuration file writer for schlock setup wizard.

Generates and writes validated YAML configuration files with atomic operations,
timestamped backups, and metadata tracking.
"""

import logging
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# Default config path (relative to project root)
DEFAULT_CONFIG_PATH = Path(".claude/hooks/schlock-config.yaml")

# File permissions (Unix only - ignored on Windows)
CONFIG_DIR_PERMS = 0o755  # rwxr-xr-x
CONFIG_FILE_PERMS = 0o644  # rw-r--r--


def safe_mkdir(path: Path, mode: int = CONFIG_DIR_PERMS) -> None:
    """Create directory with platform-appropriate permissions.

    On Unix/Linux/macOS, applies specified mode.
    On Windows, creates directory with default ACLs (mode is ignored).

    Args:
        path: Directory path to create
        mode: Unix permission bits (ignored on Windows)
    """
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        # Permission setting failed - not critical for config files
        with suppress(OSError, NotImplementedError):
            path.chmod(mode)


def safe_chmod(path: Path, mode: int) -> None:
    """Set file permissions (Unix only).

    On Unix/Linux/macOS, applies specified mode.
    On Windows, no-op (ACLs control permissions).

    Args:
        path: File path to set permissions on
        mode: Unix permission bits (ignored on Windows)
    """
    if sys.platform != "win32":
        # Permission setting failed - not critical for config files
        with suppress(OSError, NotImplementedError):
            path.chmod(mode)


# Risk tolerance presets
RISK_PRESETS: dict[str, dict[str, Any]] = {
    "permissive": {
        "description": "Allow most commands, only block critical threats",
        "hint": "Best for: experienced users, local dev",
        "settings": {
            "SAFE": "allow",
            "LOW": "allow",
            "MEDIUM": "allow",
            "HIGH": "allow",
            "BLOCKED": "deny",
        },
    },
    "balanced": {
        "description": "Prompt for HIGH-risk, block critical threats",
        "hint": "Best for: most users",
        "settings": {
            "SAFE": "allow",
            "LOW": "allow",
            "MEDIUM": "allow",
            "HIGH": "ask",
            "BLOCKED": "deny",
        },
    },
    "paranoid": {
        "description": "Prompt for MEDIUM+, block HIGH and critical",
        "hint": "Best for: production environments, compliance",
        "settings": {
            "SAFE": "allow",
            "LOW": "allow",
            "MEDIUM": "ask",
            "HIGH": "deny",
            "BLOCKED": "deny",
        },
    },
}

DEFAULT_RISK_PRESET = "balanced"


@dataclass(frozen=True)
class WizardChoices:
    """User selections from wizard flow.

    Attributes:
        ad_blocker_enabled: Enable advertising blocker
        risk_preset: Risk tolerance preset name ("permissive", "balanced", "paranoid")
        shellcheck_enabled: Enable ShellCheck integration (if available)
    """

    ad_blocker_enabled: bool
    risk_preset: str = DEFAULT_RISK_PRESET
    shellcheck_enabled: bool = False


@dataclass(frozen=True)
class WriteResult:
    """Result of config file write operation.

    Attributes:
        success: Whether write completed successfully
        config_path: Path where config was written
        backup_path: Path to backup file (None if no backup created)
        error: Error message if write failed (None on success)
        validation_errors: List of YAML validation errors (empty on success)
    """

    success: bool
    config_path: Path
    backup_path: Optional[Path]
    error: Optional[str]
    validation_errors: list[str] = field(default_factory=list)


def write_config(
    choices: WizardChoices,
    config_path: Optional[Path] = None,
    create_backup_flag: bool = True,
) -> WriteResult:
    """Write configuration file from wizard choices.

    Args:
        choices: User selections from wizard
        config_path: Path to write config (default: .claude/hooks/schlock-config.yaml)
        create_backup_flag: Whether to backup existing config

    Returns:
        WriteResult with success status and paths

    Example:
        >>> choices = WizardChoices(ad_blocker_enabled=True)
        >>> result = write_config(choices)
        >>> if result.success:
        ...     print(f"Config saved to {result.config_path}")
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    backup_path: Optional[Path] = None

    try:
        # Phase 1: Generate config dict
        config_dict = generate_config_yaml(choices)

        # Phase 2: Validate config structure
        validation_errors = validate_config_yaml(config_dict)
        if validation_errors:
            return WriteResult(
                success=False,
                config_path=config_path,
                backup_path=None,
                error="Config validation failed",
                validation_errors=validation_errors,
            )

        # Phase 3: Create backup if file exists
        if create_backup_flag and config_path.exists():
            backup_path = create_backup(config_path)
            if backup_path:
                logger.info(f"Created backup: {backup_path}")

        # Phase 4: Ensure parent directory exists
        safe_mkdir(config_path.parent, CONFIG_DIR_PERMS)

        # Phase 5: Write config file atomically
        write_yaml_atomic(config_path, config_dict)
        logger.info(f"Config written to {config_path}")

        return WriteResult(
            success=True,
            config_path=config_path,
            backup_path=backup_path,
            error=None,
            validation_errors=[],
        )

    except Exception as e:
        logger.error(f"Failed to write config: {e}")
        return WriteResult(
            success=False,
            config_path=config_path,
            backup_path=backup_path,
            error=str(e),
            validation_errors=[],
        )


def create_backup(config_path: Path) -> Optional[Path]:
    """Create timestamped backup of existing config file.

    Args:
        config_path: Path to config file to backup

    Returns:
        Path to backup file, or None if backup failed

    Example:
        >>> backup = create_backup(Path(".claude/hooks/schlock-config.yaml"))
        >>> print(backup)  # .claude/hooks/schlock-config.yaml.backup.20250107_120530
    """
    if not config_path.exists():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f"{config_path.suffix}.backup.{timestamp}")

    try:
        backup_path.write_text(config_path.read_text(), encoding="utf-8")
        return backup_path
    except Exception as e:
        logger.warning(f"Failed to create backup: {e}")
        return None


def write_yaml_atomic(path: Path, data: dict[str, Any]) -> None:
    """Write YAML file atomically using temp file + rename.

    Args:
        path: Destination path
        data: Dict to serialize as YAML

    Raises:
        OSError: If write or rename fails
        yaml.YAMLError: If serialization fails
    """
    # Write to temp file first
    temp_path = path.with_suffix(path.suffix + ".tmp")

    try:
        with temp_path.open("w", encoding="utf-8") as f:
            yaml.dump(
                data,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

        # Set permissions before rename
        safe_chmod(temp_path, CONFIG_FILE_PERMS)

        # Atomic rename
        temp_path.replace(path)
    except Exception:
        # Clean up temp file on failure
        if temp_path.exists():
            temp_path.unlink()
        raise


def generate_config_yaml(choices: WizardChoices) -> dict[str, Any]:
    """Generate config dict from wizard choices.

    Args:
        choices: User selections from wizard

    Returns:
        Dict representing YAML structure

    Notes:
        - Includes metadata (_metadata section with timestamps)
        - Includes risk_tolerance from preset selection
        - Includes ad blocker configuration
    """
    config: dict[str, Any] = {}

    # Metadata section (tracking wizard generation)
    config["_metadata"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "wizard_version": "0.1.0",
        "last_modified_by": "setup-wizard",
    }

    # Risk tolerance configuration
    preset = RISK_PRESETS.get(choices.risk_preset, RISK_PRESETS[DEFAULT_RISK_PRESET])
    config["risk_tolerance"] = {
        "preset": choices.risk_preset,
        "levels": preset["settings"].copy(),
    }

    # Claude advertising blocker configuration
    if choices.ad_blocker_enabled:
        config["commit_filter"] = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                }
            },
        }

    # ShellCheck integration (optional enhancement)
    config["shellcheck"] = {
        "enabled": choices.shellcheck_enabled,
        "severity": "info",  # Minimum severity to report (error, warning, info, style)
        "security_only": True,  # Only report security-relevant findings
    }

    return config


def validate_config_yaml(config_dict: dict[str, Any]) -> list[str]:  # noqa: PLR0912 - Validation logic
    """Validate config structure before writing.

    Args:
        config_dict: Config dictionary to validate

    Returns:
        List of validation errors (empty if valid)

    Checks:
        - Required keys present (_metadata, risk_tolerance)
        - Boolean flags are bool type
        - Risk tolerance levels are valid
        - At least one feature enabled (commit_filter)
    """
    errors: list[str] = []

    # Check required metadata
    if "_metadata" not in config_dict:
        errors.append("Missing required _metadata section")
    else:
        metadata = config_dict["_metadata"]
        required_fields = ["generated_at", "wizard_version", "last_modified_by"]
        for fld in required_fields:
            if fld not in metadata:
                errors.append(f"Missing _metadata.{fld}")

    # Check risk_tolerance is present and valid
    if "risk_tolerance" not in config_dict:
        errors.append("risk_tolerance must be present")
    else:
        risk_tol = config_dict["risk_tolerance"]
        if "preset" not in risk_tol:
            errors.append("risk_tolerance.preset required")
        elif risk_tol["preset"] not in RISK_PRESETS:
            errors.append(f"Invalid risk_tolerance.preset: {risk_tol['preset']}")

        if "levels" not in risk_tol:
            errors.append("risk_tolerance.levels required")
        else:
            levels = risk_tol["levels"]
            valid_actions = {"allow", "ask", "deny"}
            required_levels = {"SAFE", "LOW", "MEDIUM", "HIGH", "BLOCKED"}

            for level in required_levels:
                if level not in levels:
                    errors.append(f"risk_tolerance.levels.{level} required")
                elif levels[level] not in valid_actions:
                    errors.append(f"risk_tolerance.levels.{level} must be allow/ask/deny")

            # BLOCKED must always be "deny"
            if levels.get("BLOCKED") != "deny":
                errors.append("risk_tolerance.levels.BLOCKED must always be 'deny'")

    # Check commit_filter is present (only feature now)
    if "commit_filter" not in config_dict:
        errors.append("commit_filter must be present")

    # Validate commit_filter structure
    if "commit_filter" in config_dict:
        commit_filter = config_dict["commit_filter"]

        if not isinstance(commit_filter.get("enabled"), bool):
            errors.append("commit_filter.enabled must be boolean")

        if "rules" not in commit_filter:
            errors.append("commit_filter.rules section required")
        elif "advertising" not in commit_filter["rules"]:
            errors.append("commit_filter.rules.advertising required")

    return errors
