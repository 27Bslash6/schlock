"""ShellCheck integration for enhanced command validation.

Provides optional integration with ShellCheck (https://www.shellcheck.net/)
for additional static analysis of shell commands.

ShellCheck is an external tool - this module:
1. Detects if shellcheck is installed
2. Runs shellcheck on commands (when enabled)
3. Maps shellcheck findings to schlock risk levels
4. Caches results for performance
5. Implements circuit breaker pattern for resilience

Usage:
    from schlock.integrations.shellcheck import is_shellcheck_available, run_shellcheck

    if is_shellcheck_available():
        findings = run_shellcheck("rm -rf $HOME")
        # list of ShellCheckFinding, or None when ShellCheck gave no verdict
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)


class ShellCheckSeverity(Enum):
    """ShellCheck severity levels mapped to schlock risk."""

    ERROR = "error"  # -> HIGH risk
    WARNING = "warning"  # -> MEDIUM risk
    INFO = "info"  # -> LOW risk
    STYLE = "style"  # -> SAFE (informational)


@dataclass(frozen=True)
class ShellCheckFinding:
    """A single finding from ShellCheck analysis."""

    code: int  # SC code (e.g., 2086)
    level: ShellCheckSeverity
    message: str
    line: int
    column: int
    end_line: int
    end_column: int

    @property
    def sc_code(self) -> str:
        """Return SC-prefixed code (e.g., 'SC2086')."""
        return f"SC{self.code}"

    @property
    def wiki_url(self) -> str:
        """Return URL to ShellCheck wiki for this code."""
        return f"https://www.shellcheck.net/wiki/{self.sc_code}"


# Security-relevant SC codes that should elevate risk level
# These indicate potential command injection, code execution, or system destruction
# Reference: https://www.shellcheck.net/wiki/
#
# Selection criteria:
# - Command injection vectors (unquoted variables, substitution)
# - System destruction risks (rm /*, unset PATH)
# - Obfuscation indicators (unusual syntax that hides intent)
# - Privilege escalation vectors
SECURITY_RELEVANT_CODES = {
    # === Command injection via unquoted variables/substitutions ===
    2086,  # Double quote to prevent globbing and word splitting
    2087,  # Quote this to prevent word splitting
    2090,  # Quotes/backslashes will be treated literally
    2091,  # Remove surrounding $() to avoid executing output as commands
    2095,  # Use double quotes to prevent globbing
    2046,  # Quote command substitutions to prevent word splitting
    # === Legacy syntax with injection risks ===
    2006,  # Use $(..) instead of legacy backticks (parsing issues)
    # === System destruction prevention (the "MongoDB disaster" rules) ===
    2114,  # Warning: deletes a system directory
    2115,  # Use "${var:?}" to ensure this never expands to /*
    # === Path/filename injection ===
    2156,  # Injecting filenames is fragile and insecure. Use parameters.
    # === Format string vulnerabilities ===
    2059,  # Don't use variables in printf format string. Use %s.
    # === Privilege escalation ===
    2117,  # To run commands as another user, use su -c or sudo
    # === Obfuscation/injection indicators (added per security review) ===
    2016,  # Expressions in single quotes don't expand (can hide injection)
    2028,  # echo may not expand escape sequences (obfuscation vector)
    2116,  # Useless echo (often used in obfuscation)
    2145,  # Argument mixes string and array (injection risk)
    2162,  # read without -r interprets backslashes (injection)
    2206,  # Quote array expansion to avoid word splitting
    # === Execution hijacking ===
    2148,  # Shebang missing or corrupted (execution hijacking)
    2154,  # Variable referenced but not assigned (typosquatting risk)
}


# Circuit breaker configuration
# Prevents repeated ShellCheck failures from degrading validation performance
_CIRCUIT_BREAKER_THRESHOLD = 3  # Failures before opening circuit
_CIRCUIT_BREAKER_RESET_TIME = 60.0  # Seconds before attempting reset
_circuit_breaker_failures: list[float] = []  # Timestamps of recent failures
_circuit_breaker_open_until: float = 0.0  # When circuit can be retried

# Output size limits (defense against JSON bombs)
_MAX_OUTPUT_SIZE = 1_000_000  # 1MB max ShellCheck output; also the only bound on finding count
_MAX_MESSAGE_LENGTH = 500  # Maximum message field length


def _sanitize_message(message: str) -> str:
    """Sanitize ShellCheck message by removing control characters.

    Args:
        message: Raw message from ShellCheck

    Returns:
        Sanitized message safe for logging/display
    """
    # Remove control characters (except newline/tab)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", message)
    # Truncate to max length
    return sanitized[:_MAX_MESSAGE_LENGTH]


def _check_circuit_breaker() -> bool:
    """Check if circuit breaker allows ShellCheck execution.

    Returns:
        True if ShellCheck should be skipped (circuit open), False otherwise.
    """
    global _circuit_breaker_open_until  # noqa: PLW0602 - Read-only access to module state

    now = time.monotonic()

    # If circuit is open, check if reset time has passed
    if _circuit_breaker_open_until > now:
        return True  # Circuit still open, skip ShellCheck

    # Clean up old failures (outside reset window)
    cutoff = now - _CIRCUIT_BREAKER_RESET_TIME
    while _circuit_breaker_failures and _circuit_breaker_failures[0] < cutoff:
        _circuit_breaker_failures.pop(0)

    return False  # Circuit closed, allow ShellCheck


def _record_circuit_breaker_failure() -> None:
    """Record a ShellCheck failure for circuit breaker tracking."""
    global _circuit_breaker_open_until  # noqa: PLW0603 - Module-level state for circuit breaker

    now = time.monotonic()
    _circuit_breaker_failures.append(now)

    # Check if threshold exceeded
    if len(_circuit_breaker_failures) >= _CIRCUIT_BREAKER_THRESHOLD:
        _circuit_breaker_open_until = now + _CIRCUIT_BREAKER_RESET_TIME
        logger.warning(
            f"ShellCheck circuit breaker opened after {_CIRCUIT_BREAKER_THRESHOLD} failures. "
            f"Disabling for {_CIRCUIT_BREAKER_RESET_TIME}s."
        )
        _circuit_breaker_failures.clear()


def _reset_circuit_breaker() -> None:
    """Reset circuit breaker on successful ShellCheck execution."""
    global _circuit_breaker_open_until  # noqa: PLW0603 - Module-level state for circuit breaker
    _circuit_breaker_failures.clear()
    _circuit_breaker_open_until = 0.0


@lru_cache(maxsize=1)
def get_shellcheck_path() -> Optional[str]:
    """Find shellcheck binary path.

    Returns:
        Path to shellcheck binary, or None if not installed.

    Caches result for performance (installation status won't change mid-session).
    """
    return shutil.which("shellcheck")


def is_shellcheck_available() -> bool:
    """Check if shellcheck is installed and accessible.

    Returns:
        True if shellcheck is available, False otherwise.
    """
    return get_shellcheck_path() is not None


def get_shellcheck_version() -> Optional[str]:
    """Get installed shellcheck version.

    Returns:
        Version string (e.g., "0.11.0"), or None if not installed.
    """
    path = get_shellcheck_path()
    if not path:
        return None

    try:
        result = subprocess.run(
            [path, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Parse version from output like "ShellCheck - shell script analysis tool\nversion: 0.11.0\n..."
        for line in result.stdout.splitlines():
            if line.startswith("version:"):
                return line.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass

    return None


def run_shellcheck(  # noqa: PLR0911 - Multiple exit points for error handling
    command: str,
    shell: str = "bash",
    severity: str = "info",
    timeout: float = 2.0,  # Reduced from 5.0 per security review
) -> Optional[list[ShellCheckFinding]]:
    """Run shellcheck on a command string.

    Args:
        command: Shell command to analyze
        shell: Shell dialect (bash, sh, dash, ksh)
        severity: Minimum severity to report (error, warning, info, style)
        timeout: Maximum time to wait for shellcheck (seconds)

    Returns:
        List of ShellCheckFinding objects - empty when ShellCheck ran and found nothing,
        or is not installed. None when ShellCheck delivered no verdict: circuit open,
        timeout, oversized output, error exit, unreadable output. None is not "clean";
        a caller that reads it as [] turns each of those into a bypass (LAB-4586: a
        slow input switched the control off). Each caller picks fail-open or
        fail-closed for its own surface.

    Note:
        This function never raises - it fails silently to avoid breaking
        the validation pipeline if shellcheck has issues.

    Security:
        - Circuit breaker pattern prevents repeated failures from degrading performance
        - Output size limited to 1MB to prevent JSON bombs
        - Message fields sanitized to prevent log injection
        - No findings cap: every finding is returned, so none can be pushed off the
          list by inert padding (LAB-4586); _MAX_OUTPUT_SIZE is the bound
    """
    # Check circuit breaker first
    if _check_circuit_breaker():
        return None

    path = get_shellcheck_path()
    if not path:
        return []

    # The checkout and the environment must not choose which codes ShellCheck reports,
    # or how long it takes (LAB-5084). Without --norc it reads .shellcheckrc from the cwd,
    # every parent dir and ~, so `disable=SC2086` in an ordinary repo switches a security
    # code off, and a .shellcheckrc symlinked to /dev/zero runs every call into the
    # timeout. SHELLCHECK_OPTS is prepended to argv, so it could --exclude the same codes.
    #
    # Minimum supported ShellCheck is 0.7.0: it added --norc along with .shellcheckrc
    # itself. An older binary rejects the flag (exit 3), which is "no verdict" below, so a
    # quoted heredoc or a `bash -c` payload is BLOCKED and nothing gets findings. We do
    # not gate the flag on get_shellcheck_version(), which would cost a second spawn per
    # hook call, just to support releases from before 2019.
    child_env = {k: v for k, v in os.environ.items() if k != "SHELLCHECK_OPTS"}

    try:
        # Run shellcheck with JSON output, reading from stdin
        result = subprocess.run(
            [
                path,
                "--norc",
                f"--shell={shell}",
                "--format=json",
                f"--severity={severity}",
                "-",  # Read from stdin
            ],
            check=False,
            input=command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=child_env,
        )

        # Exit 0 or 1 is a verdict (1 = findings). Anything else - exit 2+, or a negative
        # code for death by signal - is not, and neither is empty stdout: --format=json
        # prints `[]` for a clean run, so nothing on stdout means ShellCheck died before it
        # answered. Reading either as clean is the LAB-4586 bypass in another coat.
        if result.returncode not in (0, 1) or not result.stdout.strip():
            logger.warning(f"ShellCheck exit {result.returncode} with no verdict: {_sanitize_message(result.stderr)[:200]!r}")
            _record_circuit_breaker_failure()
            return None

        # SECURITY: Limit output size to prevent JSON bombs
        if len(result.stdout) > _MAX_OUTPUT_SIZE:
            logger.warning(f"ShellCheck output exceeds {_MAX_OUTPUT_SIZE} bytes, refusing")
            _record_circuit_breaker_failure()
            return None

        findings_json = json.loads(result.stdout)
        if not isinstance(findings_json, list):
            logger.warning(f"ShellCheck output is not a JSON array: {type(findings_json).__name__}")
            _record_circuit_breaker_failure()
            return None

        findings = []

        for f in findings_json:
            try:
                # Validate code is reasonable integer
                code = f.get("code", 0)
                if not isinstance(code, int) or code < 1000 or code > 9999:
                    continue  # Skip invalid codes

                level = ShellCheckSeverity(f.get("level", "info"))

                # SECURITY: Sanitize message to prevent log injection
                raw_message = f.get("message", "")
                safe_message = _sanitize_message(str(raw_message))

                finding = ShellCheckFinding(
                    code=code,
                    level=level,
                    message=safe_message,
                    line=f.get("line", 1),
                    column=f.get("column", 1),
                    end_line=f.get("endLine", 1),
                    end_column=f.get("endColumn", 1),
                )
                findings.append(finding)
            except (ValueError, KeyError, TypeError):
                # Skip malformed findings
                continue

        # No findings cap here, on purpose. _MAX_OUTPUT_SIZE already bounds this loop
        # (1MB is at most ~5k findings, ~20ms), and a cap applied before callers filter
        # to SECURITY_RELEVANT_CODES let 100 inert SC2034s push an SC2114 off the list,
        # which the caller read as clean (LAB-4586). If one is ever needed it must run
        # AFTER that filter, never before.
        _reset_circuit_breaker()  # Success
        return findings

    except subprocess.TimeoutExpired:
        logger.warning(f"ShellCheck timeout after {timeout}s on command: {command[:50]}...")
        _record_circuit_breaker_failure()
        return None

    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as e:
        logger.warning(f"ShellCheck error, no verdict: {e}")
        _record_circuit_breaker_failure()
        return None


def has_security_relevant_findings(findings: list[ShellCheckFinding]) -> bool:
    """Check if any findings are security-relevant.

    Args:
        findings: List of ShellCheckFinding objects

    Returns:
        True if any finding has a security-relevant SC code.
    """
    return any(f.code in SECURITY_RELEVANT_CODES for f in findings)


def get_security_findings(findings: list[ShellCheckFinding]) -> list[ShellCheckFinding]:
    """Filter to only security-relevant findings.

    Args:
        findings: List of ShellCheckFinding objects

    Returns:
        List of findings with security-relevant SC codes.
    """
    return [f for f in findings if f.code in SECURITY_RELEVANT_CODES]


def format_findings_message(findings: list[ShellCheckFinding], max_findings: int = 3) -> str:
    """Format findings for user display.

    Args:
        findings: List of ShellCheckFinding objects
        max_findings: Maximum number of findings to include

    Returns:
        Formatted message string for display.
    """
    if not findings:
        return ""

    lines = ["ShellCheck warnings:"]
    for f in findings[:max_findings]:
        lines.append(f"  - {f.sc_code}: {f.message}")

    if len(findings) > max_findings:
        lines.append(f"  ... and {len(findings) - max_findings} more")

    return "\n".join(lines)


# Installation instructions by platform
INSTALL_INSTRUCTIONS = {
    "darwin": "brew install shellcheck",
    "linux": "apt-get install shellcheck  # or: dnf install ShellCheck",
    "win32": "scoop install shellcheck  # or: choco install shellcheck",
}


def get_install_instructions() -> str:
    """Get platform-appropriate installation instructions.

    Returns:
        Installation command for the current platform.
    """
    platform = sys.platform
    if platform.startswith("linux"):
        platform = "linux"

    return INSTALL_INSTRUCTIONS.get(platform, "See https://www.shellcheck.net/#install")
