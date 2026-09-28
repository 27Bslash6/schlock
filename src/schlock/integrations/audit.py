"""Audit logging for security events.

This module provides persistent audit trail logging for all hook validation events.
Logs are written in JSONL (JSON Lines) format for easy parsing and analysis.

Log Location:
    Default (daily timestamped files):
        Linux: ~/.local/share/schlock/audit-YYYY-MM-DD.jsonl
        macOS: ~/Library/Application Support/schlock/audit-YYYY-MM-DD.jsonl
        Windows: %LOCALAPPDATA%/27b.io/schlock/audit-YYYY-MM-DD.jsonl
    Can be overridden by an absolute SCHLOCK_AUDIT_LOG in the `env` block of the user's own
    ~/.claude/settings.json. The process environment is not consulted (see
    schlock.core.user_settings), so a shell `export` or a project settings file has no effect.

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
    Patterns like password=secret, --token VALUE, Authorization: Bearer TOKEN are scrubbed,
    as are HTTP credentials in curl -u/--user user:pass and URL userinfo (scheme://user:pass@host).

Thread Safety:
    File writes are atomic (append mode with single write call).
    Safe for concurrent Claude Code sessions.

Retention:
    Daily timestamped files prevent unbounded growth.
    No automatic cleanup (user responsibility).
    Cleanup example (Linux): rm ~/.local/share/schlock/audit-2024-*.jsonl
    Cleanup example (Windows): Remove-Item "$env:LOCALAPPDATA/27b.io/schlock/audit-2024-*.jsonl"
"""

import json
import logging
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

from schlock.core.user_settings import user_settings_env

logger = logging.getLogger(__name__)


def get_null_device() -> str:
    """Get platform-specific null device.

    Returns:
        "/dev/null" on Unix/Linux/macOS, "NUL" on Windows.
    """
    return "NUL" if sys.platform == "win32" else "/dev/null"


def _configured_log_path(value: Any, today: str) -> Optional[Path]:
    """The log file named by the user's SCHLOCK_AUDIT_LOG value, or None when it is unusable."""
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    if value == get_null_device() or (sys.platform == "win32" and value.upper() == "NUL"):
        return Path(value)
    try:
        os.fsencode(value)  # a lone surrogate would raise later, inside mkdir or open
        path = Path(value).expanduser()  # "~unknown-user/..." raises RuntimeError
    except (RuntimeError, ValueError):
        return None
    if not path.is_absolute():
        return None
    return path if path.suffix == ".jsonl" else path / f"audit-{today}.jsonl"


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
        # `(?!-)` keeps it off a following flag: `curl -p -u user:pass` must leave `-u` for the pattern below.
        (re.compile(r"(-p\s+)(?![0-9:]+\b)(?!-)(\S+)", re.I), r"\1***REDACTED***"),
        # -u/-U/--user/--proxy-user user:pass, also bundled (`curl -sSu user:pass`) and `--user=user:pass` (curl HTTP auth).
        # The value must contain a colon so `sort -u file`, `python -u x.py`, `useradd -u 1001 bob` pass through.
        # A value holding `://` is a URL (`pip install -U git+https://…`): left for the userinfo pattern below.
        # No numeric carve-out: `-u 12345:67890` is a credential shape too, so `docker run -u 1000:1000` over-redacts.
        # ponytail: shape heuristic; `docker run -u node:node`, `date -u +%H:%M`, `rsync -u host:/p` over-redact.
        # A shell-word tokeniser is the upgrade.
        (
            re.compile(r"(?<!\S)(-[a-z]*u|--user|--proxy-user)(\s+|=)(?!\S*://)[^\s:]*:\S+", re.I),
            r"\1\2***REDACTED***",
        ),
        # scheme://user:pass@host and scheme://token@host (GitHub PATs ride as a bare username).
        # Authority ends at `/`, `?` or `#` (RFC 3986), so `https://host/a:b` and `?x=a@b` never match;
        # greedy up to the last `@` before that boundary keeps an unencoded `@` in the password redacted too.
        (re.compile(r"(://)[^\s/?#]+@"), r"\1***REDACTED***@"),
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
        - SCHLOCK_AUDIT_LOG is read from the `env` block of ~/.claude/settings.json only, never
          from the process environment (see schlock.core.user_settings).
        - If the value is the null device: use it (logging disabled)
        - If the value is not an absolute path after `~` expansion: ignore it. A relative path
          resolves against the working directory, which is whatever checkout is open.
        - If the value ends in .jsonl: use as-is (single file)
        - Any other absolute value: treat as a directory and append a timestamped filename
        - A missing or unusable value falls back to the platform default, with a warning when
          a value was present. This runs before the hook's error handling, so it never raises.

        Platform-specific defaults (platformdirs user_data_dir):
        - Linux: ~/.local/share/schlock/audit-YYYY-MM-DD.jsonl
        - macOS: ~/Library/Application Support/schlock/audit-YYYY-MM-DD.jsonl
        - Windows: %LOCALAPPDATA%/27b.io/schlock/audit-YYYY-MM-DD.jsonl
        """
        today = datetime.now().strftime("%Y-%m-%d")
        configured = user_settings_env("SCHLOCK_AUDIT_LOG")
        path = _configured_log_path(configured, today)
        if path is not None:
            return path
        if configured is not None:
            logger.warning(f"Ignoring SCHLOCK_AUDIT_LOG={configured!r} in user settings; using the default audit log")
        return Path(user_data_dir("schlock", "27b.io")) / f"audit-{today}.jsonl"

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
