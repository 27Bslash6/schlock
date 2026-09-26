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
    - command: The bash command that was validated (secrets redacted, size-capped)
    - command_truncated: true when the cap cut the command (false = logged in full)
    - risk_level: Risk level (SAFE, LOW, MEDIUM, HIGH, BLOCKED)
    - violations: List of rule violations (if any)
    - decision: "allow" | "block" | "warn"
    - context: Project/environment metadata
    - execution_time_ms: Validation duration

Security:
    Secrets (passwords, tokens, API keys) are automatically redacted before logging.
    Patterns like password=secret, "password": "secret" JSON fields, --token VALUE and
    Authorization: <scheme> CREDENTIAL are scrubbed, as are HTTP credentials in curl -u/--user user:pass
    and URL userinfo (scheme://user:pass@host).

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

from schlock.integrations.commit_filter import MAX_COMMAND_SIZE

# How many of the command's own bytes an entry logs, redacted - a marker longer than the secret it replaced
# makes the entry longer. Entries the commit filter judged keep the whole command up to the filter's own
# bound (MAX_COMMAND_SIZE, 64 KiB) so the log shows what the filter saw - a `git commit -F - <<'EOF'` body
# lives past byte 500 and is the very part that after-the-fact analysis needs. Everything else keeps this.
COMMAND_LOG_LIMIT = 500

# Key names that mark the following value as a secret, shared by the key=value and JSON-field scrub rules.
_CREDENTIAL_KEY_NAMES = r"(?:password|passwd|pwd|token|secret|api[-_]?key)"


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
    command_truncated: bool = False

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
        # Authorization: <scheme> <credential>. Digest and AWS4-HMAC-SHA256 carry the secret in a later parameter
        # (response=, Signature=), not the first token, so a quoted header is redacted to its closing quote, through
        # escaped characters and backslash-newline continuations. These run before the token=/secret= rule, whose
        # \S+ would otherwise eat a closing quote and shift the boundary onto the next argument.
        # Quote before the header - the curl form, -H "Authorization: Bearer x".
        (re.compile(r"""(["'])(Authorization:\s*[\w-]+\s+)(?:\\[\s\S]|(?!\1|\\).)*""", re.I), r"\1\2***REDACTED***"),
        # Quote after the colon - bash word concatenation and YAML in heredocs, Authorization:"Bearer x".
        (re.compile(r"""(Authorization:\s*)(["'])([\w-]+\s+)(?:\\[\s\S]|(?!\2|\\).)*""", re.I), r"\1\2\3***REDACTED***"),
        # Bare header, no value boundary - one token. The lookbehind skips headers the quoted rules handled.
        (re.compile(r"""(?<!["'])(Authorization:\s*[\w-]+\s+)\S+""", re.I), r"\1***REDACTED***"),
        # A quote ends a shell SEGMENT, not the value: adjacent segments concatenate into one argument, so
        # `-H 'Authorization: Basic '"$SECRET"` carries the credential past the quote the rules above stop at.
        # Consume whole segments after a header those rules already redacted, stopping at an unquoted space
        # OR shell operator - an operator ends the word too, and eating it would hide `;rm -rf /` from the log.
        # Anchored on the redacted header, never the marker alone, so a command that merely CONTAINS the
        # marker keeps its text. Alternatives stay disjoint on their first character, so the scan is linear.
        # ponytail: this now tracks quoting state in a regex. The next shape wants the bashlex word split the
        # commit filter already does, not a fifth rule - see the redaction ceiling recorded on the ticket.
        (
            re.compile(
                r"""(Authorization:\s*["']?[\w-]+\s+\*{3}REDACTED\*{3}["'])"""
                r"""(?:'[^']*'?|"(?:\\[\s\S]|[^"\\])*"?|\\[\s\S]|[^\s'"\\;|&<>()])+""",
                re.I,
            ),
            r"\1",
        ),
        # "password": "VALUE", "authToken":"VALUE" - a JSON field whose key name contains a key=value key word
        # anywhere: single-quoted request bodies and JSON written through a heredoc (JSON escaped inside a
        # double-quoted shell string waits for the tokenizer). Runs before the key=value rule, whose \S+ would eat
        # the closing quote. The value ends at its closing quote and the rule never fires without one - and never
        # crosses a single quote, a line end, `$(` or a backtick. In `grep '"token": "' f; rm -rf ~/w; echo "x"` the
        # next `"` belongs to a later shell word, and running to it would hide the chained command from the log;
        # a substitution is executed code, not a secret. The key word is found by a lookahead: Python does not
        # backtrack into one, whereas [\w.-]* on both sides of the key word re-scans the key once per repeat
        # and goes quadratic on a long run of repeated key words.
        (
            re.compile(
                rf"""("(?=[\w.-]*{_CREDENTIAL_KEY_NAMES})[\w.-]+"\s*:\s*")"""
                r"""(?:\\[^'\n]|\$(?!\()|[^"'\\\n$`])*(?=")""",
                re.I,
            ),
            r"\1***REDACTED***",
        ),
        # password=VALUE, token=VALUE, api-key=VALUE, secret=VALUE
        (re.compile(rf"({_CREDENTIAL_KEY_NAMES})=\S+", re.I), r"\1=***REDACTED***"),
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

    def _scrub_secrets(self, command: str, cut: Optional[int] = None) -> str:
        """Redact secrets from command before logging.

        Args:
            command: Original command string
            cut: Return only the redacted form of the command's first `cut` characters (default: all).
                Every rule still sees the whole command, because a rule anchored AFTER its secret - URL
                userinfo ends at `@` - cannot see a secret the cut has split from its anchor. The cut is
                carried through each pass rather than taken on the result: a marker outgrows a short
                secret, so enough of them would push a chained command inside the window out of the log.

        Returns:
            Command with secrets redacted as ***REDACTED***

        Example:
            >>> logger._scrub_secrets("mysql --password=secret123")
            "mysql --password=***REDACTED***"
        """
        scrubbed = command
        for pattern, replacement in self.SECRET_PATTERNS:
            if cut is not None:
                cut = self._follow_cut(pattern, replacement, scrubbed, cut)
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed if cut is None else scrubbed[:cut]

    @staticmethod
    def _follow_cut(pattern: re.Pattern[str], replacement: str, text: str, cut: int) -> int:
        """Where `cut` lands in `text` once `pattern.sub(replacement, text)` has run.

        It moves by the growth of every replacement before it, and stops at the first match that ends past it.
        A cut before that match, or inside text its replacement copies unchanged (a header name, a JSON key,
        whitespace - unbounded runs), maps one to one; a cut inside the redacted part moves past the whole
        replacement, so a split secret is logged as its whole marker.
        """
        growth = 0
        for match in pattern.finditer(text):
            start, end = match.span()
            replaced = match.expand(replacement)
            if end > cut:
                if cut - start <= len(os.path.commonprefix([match.group(), replaced])):
                    return cut + growth
                return start + growth + len(replaced)
            growth += len(replaced) - (end - start)
        return cut + growth

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
        *,
        is_git_commit: bool = False,
    ):
        """Log a command validation event.

        Args:
            command: The bash command that was validated (its first bytes, up to the cap, are logged redacted)
            risk_level: Risk level (SAFE, LOW, MEDIUM, HIGH, BLOCKED)
            violations: List of rule violations
            decision: "allow", "block", or "warn"
            execution_time_ms: Validation duration in milliseconds
            context: Optional context metadata
            is_git_commit: True when the command was recognized as a `git commit`; selects the
                MAX_COMMAND_SIZE cap instead of COMMAND_LOG_LIMIT.
        """
        if context is None:
            context = AuditContext()

        # Determine event type from decision
        event_type_map = {"allow": "allow", "block": "block", "warn": "warn"}
        event_type = event_type_map.get(decision, "validation")

        # The cap picks the COMMAND's first bytes and the entry is their redacted form (see _scrub_secrets), so
        # it runs past the cap by the markers' growth - a few times the cap at the adversarial worst. The scrub
        # reads the whole command; it is linear, and a command is model output, so the model's output budget
        # bounds it. Both caps bound BYTES, which is what a log line costs and what MAX_COMMAND_SIZE is named
        # for - a 40k-character CJK command is 120 KB, near twice the 64 KiB budget, and a character count let
        # all of it through; the cut backs off to a code-point boundary. "surrogatepass" is load-bearing, not
        # tidiness: these lines sit OUTSIDE log_event's suppress, so a lone surrogate under a plain encode or
        # decode would raise out of a hook that must fail open.
        cap = MAX_COMMAND_SIZE if is_git_commit else COMMAND_LOG_LIMIT
        encoded = command.encode("utf-8", "surrogatepass")
        command_truncated = len(encoded) > cap
        cut = None
        if command_truncated:
            boundary = cap
            while encoded[boundary] & 0xC0 == 0x80:  # a UTF-8 continuation byte: the cap is inside a code point
                boundary -= 1
            cut = len(encoded[:boundary].decode("utf-8", "surrogatepass"))
        scrubbed_command = self._scrub_secrets(command, cut)

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
            command_truncated=command_truncated,
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
