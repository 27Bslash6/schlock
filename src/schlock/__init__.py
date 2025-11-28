"""
schlock - Claude Code plugin for LLM command safety validation.

Package structure:
- schlock.core: Validation engine (parser, rules, validator, cache)
- schlock.integrations: Optional features (audit, commit_filter, shellcheck)
- schlock.setup: Configuration and wizard utilities

Public API:
- validate_command(): Main validation function
- ValidationResult: Validation outcome dataclass
- RiskLevel: Risk categorization enum
"""

from schlock.core.rules import RiskLevel
from schlock.core.validator import ValidationResult, validate_command

__version__ = "0.1.0"
__author__ = "27B.io"

__all__ = [
    "validate_command",
    "ValidationResult",
    "RiskLevel",
]
