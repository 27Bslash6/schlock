"""Configuration and setup utilities.

This module contains configuration management and setup wizard:
- config_writer: YAML config file generation
- wizard: Interactive setup wizard helpers
- env_detector: Environment detection utilities
"""

from schlock.setup.config_writer import WizardChoices, WriteResult, write_config
from schlock.setup.env_detector import DetectionResult, ToolInfo, detect_tools
from schlock.setup.wizard import format_config_review, validate_wizard_choices

__all__ = [
    # Config writer
    "WizardChoices",
    "WriteResult",
    "write_config",
    # Wizard
    "format_config_review",
    "validate_wizard_choices",
    # Environment detection
    "DetectionResult",
    "ToolInfo",
    "detect_tools",
]
