"""Optional feature integrations.

This module contains optional features that enhance the core validation:
- audit: Audit logging for compliance/security analysis
- commit_filter: Claude advertising blocker
- shellcheck: ShellCheck integration for enhanced analysis
"""

from schlock.integrations.audit import AuditContext, AuditEvent, AuditLogger, get_audit_logger
from schlock.integrations.commit_filter import CommitMessageFilter, FilterResult, load_filter_config
from schlock.integrations.shellcheck import (
    get_install_instructions,
    get_shellcheck_version,
    is_shellcheck_available,
)

__all__ = [
    # Audit
    "AuditContext",
    "AuditEvent",
    "AuditLogger",
    "get_audit_logger",
    # Commit filter
    "CommitMessageFilter",
    "FilterResult",
    "load_filter_config",
    # ShellCheck
    "is_shellcheck_available",
    "get_shellcheck_version",
    "get_install_instructions",
]
