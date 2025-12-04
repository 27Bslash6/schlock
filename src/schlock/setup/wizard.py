"""Wizard helper utilities for schlock setup command.

Provides display formatting and validation functions for the wizard flow.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .config_writer import DEFAULT_RISK_PRESET, RISK_PRESETS, WizardChoices


def find_schlock_root() -> Path:  # noqa: PLR0912
    """Find schlock plugin root directory.

    Works in both development mode (running from repo) and installed mode
    (plugin installed via Claude Code marketplace).

    Returns:
        Path to schlock plugin root directory

    Raises:
        RuntimeError: If schlock installation cannot be found

    Search order:
        1. Current working directory (development mode)
        2. Claude Code plugin registry (~/.claude/plugins/installed_plugins.json)
        3. Claude Code marketplaces directory (~/.claude/plugins/marketplaces/)

    Cross-platform:
        - Windows: Checks APPDATA, LOCALAPPDATA, and home directory
        - POSIX: Checks home directory
    """
    # Try 1: Development mode (cwd is schlock repo)
    if (Path.cwd() / "src" / "schlock").exists():
        return Path.cwd()

    # Determine Claude plugins directory (cross-platform)
    if os.name == "nt":
        base_dirs = []
        if appdata := os.environ.get("APPDATA"):
            base_dirs.append(Path(appdata) / ".claude" / "plugins")
        if localappdata := os.environ.get("LOCALAPPDATA"):
            base_dirs.append(Path(localappdata) / ".claude" / "plugins")
        base_dirs.append(Path.home() / ".claude" / "plugins")
    else:
        base_dirs = [Path.home() / ".claude" / "plugins"]

    # Try 2: Check installed plugins registry
    for base in base_dirs:
        registry = base / "installed_plugins.json"
        if registry.exists():
            try:
                data = json.loads(registry.read_text(encoding="utf-8"))
                for plugin_id, info in data.get("plugins", {}).items():
                    if plugin_id.startswith("schlock@"):
                        install_path = Path(info.get("installPath", ""))
                        # Security: Validate path is within expected directories
                        try:
                            resolved = install_path.resolve()
                            if any(resolved.is_relative_to(b.resolve()) for b in base_dirs if b.exists()):
                                if (resolved / "src" / "schlock").exists():
                                    return resolved
                        except (ValueError, OSError):
                            continue
            except (OSError, json.JSONDecodeError):
                continue

    # Try 3: Search marketplaces directories
    for base in base_dirs:
        marketplaces = base / "marketplaces"
        if marketplaces.exists():
            try:
                for marketplace in marketplaces.iterdir():
                    if (marketplace / "src" / "schlock").exists():
                        # Security: Validate path is within expected directories (symlink protection)
                        try:
                            resolved = marketplace.resolve()
                            if any(resolved.is_relative_to(b.resolve()) for b in base_dirs if b.exists()):
                                return resolved
                        except (ValueError, OSError):
                            continue
            except OSError:
                continue

    raise RuntimeError(
        "Could not find schlock installation. Is the plugin installed? Run: /plugin marketplace add 27Bslash6/schlock"
    )


def setup_schlock_imports() -> Path:
    """Configure sys.path for schlock imports and return plugin root.

    This is a convenience function for setup command code blocks.
    Call this at the start of any Python code that needs schlock imports.

    Returns:
        Path to schlock plugin root directory

    Example:
        >>> plugin_root = setup_schlock_imports()
        >>> from schlock.setup.config_writer import WizardChoices
    """
    plugin_root = find_schlock_root()
    vendor_path = str(plugin_root / ".claude-plugin" / "vendor")
    src_path = str(plugin_root / "src")

    # Add paths if not already present
    if vendor_path not in sys.path:
        sys.path.insert(0, vendor_path)
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    return plugin_root


def format_risk_preset_menu() -> str:
    """Format the risk tolerance preset selection menu.

    Returns:
        Formatted menu string for risk tolerance selection

    Examples:
        >>> menu = format_risk_preset_menu()
        >>> "How do you want to handle risky commands?" in menu
        True
        >>> "[1] Permissive" in menu
        True
        >>> "[2] Balanced" in menu
        True
        >>> "[3] Paranoid" in menu
        True
        >>> "[DEFAULT]" in menu
        True
    """
    lines = ["How do you want to handle risky commands?", ""]

    preset_order = ["permissive", "balanced", "paranoid"]
    for i, preset_name in enumerate(preset_order, 1):
        preset = RISK_PRESETS[preset_name]
        default_marker = " [DEFAULT]" if preset_name == DEFAULT_RISK_PRESET else ""

        lines.append(f"[{i}] {preset_name.capitalize():10} - {preset['description']}")
        lines.append(f"               ({preset['hint']}){default_marker}")
        lines.append("")

    return "\n".join(lines)


def get_preset_from_choice(choice: int) -> str:
    """Convert menu choice number to preset name.

    Args:
        choice: Menu selection (1, 2, or 3)

    Returns:
        Preset name string

    Raises:
        ValueError: If choice is out of range

    Examples:
        >>> get_preset_from_choice(1)
        'permissive'
        >>> get_preset_from_choice(2)
        'balanced'
        >>> get_preset_from_choice(3)
        'paranoid'
        >>> get_preset_from_choice(0)
        Traceback (most recent call last):
            ...
        ValueError: Invalid choice: 0. Must be 1, 2, or 3.
        >>> get_preset_from_choice(4)
        Traceback (most recent call last):
            ...
        ValueError: Invalid choice: 4. Must be 1, 2, or 3.
    """
    preset_order = ["permissive", "balanced", "paranoid"]
    if 1 <= choice <= 3:
        return preset_order[choice - 1]
    raise ValueError(f"Invalid choice: {choice}. Must be 1, 2, or 3.")


def format_config_review(choices: WizardChoices) -> str:
    """Format config choices for review step.

    Args:
        choices: User selections from wizard

    Returns:
        Formatted summary of configuration

    Examples:
        >>> from schlock.setup.config_writer import WizardChoices
        >>> choices = WizardChoices(ad_blocker_enabled=True, risk_preset="balanced", shellcheck_enabled=True)
        >>> review = format_config_review(choices)
        >>> "Configuration Summary:" in review
        True
        >>> "Risk Tolerance: balanced" in review
        True
        >>> "Claude Advertising Blocker: Enabled" in review
        True
        >>> "ShellCheck Integration: Enabled" in review
        True

        >>> choices_disabled = WizardChoices(ad_blocker_enabled=False, risk_preset="paranoid", shellcheck_enabled=False)
        >>> review = format_config_review(choices_disabled)
        >>> "Risk Tolerance: paranoid" in review
        True
        >>> "Advertising Blocker: Disabled" in review
        True
        >>> "ShellCheck Integration: Disabled" in review
        True
    """
    lines = ["Configuration Summary:"]

    # Risk tolerance preset
    preset = RISK_PRESETS.get(choices.risk_preset, RISK_PRESETS[DEFAULT_RISK_PRESET])
    lines.append(f"✓ Risk Tolerance: {choices.risk_preset} ({preset['description']})")

    # Advertising blocker status
    ad_blocker_status = "Enabled" if choices.ad_blocker_enabled else "Disabled"
    symbol = "✓" if choices.ad_blocker_enabled else "✗"
    lines.append(f"{symbol} Claude Advertising Blocker: {ad_blocker_status}")

    # ShellCheck integration status
    shellcheck_status = "Enabled" if choices.shellcheck_enabled else "Disabled"
    symbol = "✓" if choices.shellcheck_enabled else "✗"
    lines.append(f"{symbol} ShellCheck Integration: {shellcheck_status}")

    # Config destination
    lines.append("")
    lines.append("Config will be written to: .claude/hooks/schlock-config.yaml")

    return "\n".join(lines)


def validate_wizard_choices(choices: WizardChoices) -> list[str]:
    """Validate wizard choices before config write.

    Args:
        choices: User selections to validate

    Returns:
        List of validation errors (empty if valid)

    Checks:
        - Risk preset must be valid
        - At least ad blocker must be enabled (it's still required for commit filtering)

    Examples:
        >>> from schlock.setup.config_writer import WizardChoices

        Valid configuration returns empty list:
        >>> choices = WizardChoices(ad_blocker_enabled=True, risk_preset="balanced")
        >>> validate_wizard_choices(choices)
        []

        Invalid risk preset:
        >>> choices = WizardChoices(ad_blocker_enabled=True, risk_preset="invalid")
        >>> errors = validate_wizard_choices(choices)
        >>> len(errors) == 1
        True
        >>> "Invalid risk preset" in errors[0]
        True

        Ad blocker disabled (required):
        >>> choices = WizardChoices(ad_blocker_enabled=False, risk_preset="balanced")
        >>> errors = validate_wizard_choices(choices)
        >>> len(errors) == 1
        True
        >>> "must be enabled" in errors[0]
        True

        Multiple errors:
        >>> choices = WizardChoices(ad_blocker_enabled=False, risk_preset="invalid")
        >>> errors = validate_wizard_choices(choices)
        >>> len(errors) == 2
        True
    """
    errors: list[str] = []

    # Validate risk preset
    if choices.risk_preset not in RISK_PRESETS:
        errors.append(f"Invalid risk preset: {choices.risk_preset}. Must be one of: {', '.join(RISK_PRESETS.keys())}")

    # Ad blocker must be enabled (required for commit filtering feature)
    if not choices.ad_blocker_enabled:
        errors.append(
            "Advertising Blocker must be enabled. This is schlock's commit filtering feature. "
            "For code formatting, use pre-commit hooks (industry standard)."
        )

    return errors
