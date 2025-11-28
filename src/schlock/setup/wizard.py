"""Wizard helper utilities for schlock setup command.

Provides display formatting and validation functions for the wizard flow.
All functions are pure (no I/O, no state) for testability.
"""

from .config_writer import DEFAULT_RISK_PRESET, RISK_PRESETS, WizardChoices


def format_risk_preset_menu() -> str:
    """Format the risk tolerance preset selection menu.

    Returns:
        Formatted menu string for risk tolerance selection

    Example:
        "How do you want to handle risky commands?

         [1] Permissive  - Allow most commands, only block critical threats
                           (Best for: experienced users, local dev)

         [2] Balanced    - Prompt for HIGH-risk, block critical threats
                           (Best for: most users) [DEFAULT]

         [3] Paranoid    - Prompt for MEDIUM+, block HIGH and critical
                           (Best for: production environments, compliance)"
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

    Example:
        "Configuration Summary:
         ✓ Risk Tolerance: balanced (Prompt for HIGH-risk)
         ✓ Claude Advertising Blocker: Enabled
         ✓ ShellCheck Integration: Enabled

         Config will be written to: .claude/hooks/schlock-config.yaml"
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
