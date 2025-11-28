#!/usr/bin/env python3
"""Session start hook for schlock plugin.

Checks if schlock is configured and suggests setup if not.
Outputs additionalContext for Claude to see.
"""

import json
import os
import sys
from pathlib import Path


def check_config_exists() -> tuple[bool, str]:
    """Check if schlock configuration exists.

    Returns:
        Tuple of (config_exists, config_location)
    """
    # Check project config first
    project_config = Path.cwd() / ".claude" / "hooks" / "schlock-config.yaml"
    if project_config.exists():
        return True, "project"

    # Check user config
    user_config = Path.home() / ".config" / "schlock" / "config.yaml"
    if user_config.exists():
        return True, "user"

    # Check XDG config
    xdg_config = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg_config:
        xdg_path = Path(xdg_config) / "schlock" / "config.yaml"
        if xdg_path.exists():
            return True, "xdg"

    return False, ""


def main():
    """Main entry point."""
    try:
        # Read input (required even if we don't use it)
        _input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        _input_data = {}  # noqa: F841 - Required by hook interface

    config_exists, location = check_config_exists()

    if config_exists:
        # Config exists - output minimal context
        output = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": f"[schlock] Safety validation active ({location} config)",
            }
        }
    else:
        # No config - show message to user and add context for Claude
        output = {
            "systemMessage": "[schlock] Run /schlock:setup to customize settings",
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": "[schlock] Safety validation active with default settings.",
            },
        }

    print(json.dumps(output))
    sys.exit(0)


if __name__ == "__main__":
    main()
