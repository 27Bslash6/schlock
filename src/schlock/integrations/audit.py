"""Audit logging for security events.

This module provides persistent audit trail logging for all hook validation events.
Logs are written in JSONL (JSON Lines) format for easy parsing and analysis.

Log Location:
    Default (daily timestamped files):
        Unix/Linux/macOS: ~/.local/share/27b.io/schlock/audit-YYYY-MM-DD.jsonl
        Windows: %LOCALAPPDATA%/27b.io/schlock/audit-YYYY-MM-DD.jsonl
    Can be overridden via SCHLOCK_AUDIT_LOG environment variable (single file)

Log Format (JSONL):
    Each line is a JSON object with:
    - timestamp: ISO 8601 UTC timestamp
    - event_type: "validation" | "block" | "allow" | "warn"
    - command: The bash command that was validated (secrets redacted)
    - risk_level: Risk level (SAFE, LOW, MEDIUM, HIGH, BLOCKED)
    - violations: List of rule violations (if any)
    - decision: "allow" | "block" | "warn"
    - context: Project/environment metadata
    - execution_time_ms: Validation duration

Security:
    Secrets (passwords, tokens, API keys) are automatically redacted before logging.
    Patterns like password=secret, --token VALUE, Authorization: Bearer TOKEN are scrubbed.

Thread Safety:
    File writes are atomic (append mode with single write call).
    Safe for concurrent Claude Code sessions.

Retention:
    Daily timestamped files prevent unbounded growth.
    No automatic cleanup (user responsibility).
    Cleanup example (Unix): rm ~/.local/share/27b.io/schlock/audit-2024-*.jsonl
    Cleanup example (Windows): Remove-Item "$env:LOCALAPPDATA/27b.io/schlock/audit-2024-*.jsonl"
"""

import json
import os
import re
import sys
import threading
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from platformdirs import user_data_dir


def get_null_device() -> str:
    """Get platform-specific null device.

    Returns:
        "/dev/null" on Unix/Linux/macOS, "NUL" on Windows.
    """
    return "NUL" if sys.platform == "win32" else "/dev/null"


@dataclass
class AuditContext:
    """Context metadata for audit events."""

    project_root: Optional[str] = None
    current_dir: Optional[str] = None
    git_branch: Optional[str] = None
    environment: str = "development"


@dataclass
class AuditEvent:
    """Security audit event."""

    timestamp: str
    event_type: str  # "validation", "block", "allow", "warn"
    command: str
    risk_level: str
    violations: list[str]
    decision: str  # "allow", "block", "warn"
    context: dict[str, Any]
    execution_time_ms: Optional[float] = None

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self))


class AuditLogger:
    """Persistent audit logger for security events.

    Writes all validation events to JSONL file for compliance and debugging.
    Automatically redacts secrets before logging.

    Example:
        logger = AuditLogger()
        logger.log_validation(
            command="rm -rf /tmp/test",
            risk_level="HIGH",
            violations=["Recursive delete"],
            decision="block",
            execution_time_ms=45.2
        )
    """

    # Secret patterns to redact (compiled once for performance)
    SECRET_PATTERNS = [
        # password=VALUE, token=VALUE, api-key=VALUE, secret=VALUE
        (re.compile(r"(password|passwd|pwd|token|secret|api[-_]?key)=\S+", re.I), r"\1=***REDACTED***"),
        # Authorization: Bearer TOKEN
        (re.compile(r"(Authorization:\s*Bearer\s+)\S+", re.I), r"\1***REDACTED***"),
        # --password VALUE, --token VALUE, --api-key VALUE
        (re.compile(r"(--(password|passwd|token|secret|api[-_]?key)\s+)\S+", re.I), r"\1***REDACTED***"),
        # -p PASSWORD (but not -p in other contexts like docker -p for ports)
        # Only match if followed by something that looks like a password (not a number/port)
        (re.compile(r"(-p\s+)(?![0-9:]+\b)(\S+)", re.I), r"\1***REDACTED***"),
    ]

    def __init__(self, log_file: Optional[Path] = None):
        """Initialize audit logger.

        Args:
            log_file: Path to audit log file. If None, uses default location.
        """
        if log_file is None:
            log_file = self._get_default_log_path()

        self.log_file = log_file
        self._ensure_log_directory()

    def _scrub_secrets(self, command: str) -> str:
        """Redact secrets from command before logging.

        Args:
            command: Original command string

        Returns:
            Command with secrets redacted as ***REDACTED***

        Example:
            >>> logger._scrub_secrets("mysql --password=secret123")
            "mysql --password=***REDACTED***"
        """
        scrubbed = command
        for pattern, replacement in self.SECRET_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed

    def _get_default_log_path(self) -> Path:
        """Get default audit log path.

        Returns:
            Path to audit log file.

        Logic:
        - If SCHLOCK_AUDIT_LOG is set and ends in .jsonl: use as-is (single file)
        - If SCHLOCK_AUDIT_LOG is set but is a directory: append timestamped filename
        - Otherwise: Platform-specific data dir with timestamped filename

        Platform-specific defaults:
        - Unix/Linux/macOS: ~/.local/share/27b.io/schlock/audit-YYYY-MM-DD.jsonl
        - Windows: %LOCALAPPDATA%/27b.io/schlock/audit-YYYY-MM-DD.jsonl
        """
        env_path = os.environ.get("SCHLOCK_AUDIT_LOG")
        if env_path:
            path = Path(env_path).expanduser()
            # Special case: null device is always a file (platform-specific)
            null_dev = get_null_device()
            if str(path) == null_dev or str(path).upper() == "NUL":
                return path
            # If it ends in .jsonl, treat as explicit file path
            if path.suffix == ".jsonl":
                return path
            # Otherwise treat as directory and append timestamped filename
            today = datetime.now().strftime("%Y-%m-%d")
            return path / f"audit-{today}.jsonl"

        # Default: Platform-specific data directory with timestamped filename
        # Unix/macOS: ~/.local/share/27b.io/schlock
        # Windows: %LOCALAPPDATA%\27b.io\schlock
        data_dir = Path(user_data_dir("schlock", "27b.io"))
        today = datetime.now().strftime("%Y-%m-%d")
        return data_dir / f"audit-{today}.jsonl"

    def _ensure_log_directory(self):
        """Create log directory if it doesn't exist."""
        # Parent already exists (e.g., /dev on Unix, C:\ on Windows, NUL device)
        # or permission denied. Fail silently - actual write will fail if path is truly invalid.
        with suppress(FileExistsError, OSError):
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event: AuditEvent):
        """Write audit event to log file.

        Args:
            event: AuditEvent to log.

        Writes single line of JSON to audit log (append mode).
        Fails silently on I/O errors (audit logging is non-critical).
        """
        # Fail silently - audit logging shouldn't break the hook
        with suppress(Exception), open(self.log_file, "a") as f:
            f.write(event.to_json() + "\n")

    def log_validation(
        self,
        command: str,
        risk_level: str,
        violations: list[str],
        decision: str,
        execution_time_ms: Optional[float] = None,
        context: Optional[AuditContext] = None,
    ):
        """Log a command validation event.

        Args:
            command: The bash command that was validated (will be scrubbed)
            risk_level: Risk level (SAFE, LOW, MEDIUM, HIGH, BLOCKED)
            violations: List of rule violations
            decision: "allow", "block", or "warn"
            execution_time_ms: Validation duration in milliseconds
            context: Optional context metadata
        """
        if context is None:
            context = AuditContext()

        # Determine event type from decision
        event_type_map = {"allow": "allow", "block": "block", "warn": "warn"}
        event_type = event_type_map.get(decision, "validation")

        # Scrub secrets before logging
        scrubbed_command = self._scrub_secrets(command)

        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            command=scrubbed_command,  # Use scrubbed version
            risk_level=risk_level,
            violations=violations,
            decision=decision,
            context={
                "project_root": context.project_root,
                "current_dir": context.current_dir,
                "git_branch": context.git_branch,
                "environment": context.environment,
            },
            execution_time_ms=execution_time_ms,
        )

        self.log_event(event)


# Global audit logger singleton (lazy-loaded with thread-safe initialization)
_audit_logger: Optional[AuditLogger] = None
_audit_logger_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger singleton.

    Returns:
        AuditLogger instance.

    Thread-safe via double-check locking pattern.
    Prevents race condition when multiple threads initialize simultaneously.
    """
    global _audit_logger  # noqa: PLW0603 - Singleton pattern for audit logger

    # First check (fast path, no lock needed if already initialized)
    if _audit_logger is None:
        # Acquire lock for initialization
        with _audit_logger_lock:
            # Second check (another thread may have initialized while we waited)
            if _audit_logger is None:
                _audit_logger = AuditLogger()

    return _audit_logger
