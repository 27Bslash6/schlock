"""ShellCheck integration for enhanced command validation.

Provides optional integration with ShellCheck (https://www.shellcheck.net/)
for additional static analysis of shell commands.

ShellCheck is an external tool - this module:
1. Detects if shellcheck is installed
2. Runs shellcheck on commands (when enabled)
3. Maps shellcheck findings to schlock risk levels
4. Caches results for performance

Usage:
    from schlock.integrations.shellcheck import is_shellcheck_available, run_shellcheck

    if is_shellcheck_available():
        findings = run_shellcheck("rm -rf $HOME")
        # Returns list of ShellCheckFinding objects
"""

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Optional


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
SECURITY_RELEVANT_CODES = {
    # Command injection via unquoted variables/substitutions
    2086,  # Double quote to prevent globbing and word splitting
    2087,  # Quote this to prevent word splitting
    2090,  # Quotes/backslashes will be treated literally
    2091,  # Remove surrounding $() to avoid executing output as commands
    2095,  # Use double quotes to prevent globbing
    2046,  # Quote command substitutions to prevent word splitting
    # Legacy syntax with injection risks
    2006,  # Use $(..) instead of legacy backticks (parsing issues)
    # System destruction prevention (the "MongoDB disaster" rules)
    2114,  # Warning: deletes a system directory
    2115,  # Use "${var:?}" to ensure this never expands to /*
    # Path/filename injection
    2156,  # Injecting filenames is fragile and insecure. Use parameters.
    # Format string vulnerabilities
    2059,  # Don't use variables in printf format string. Use %s.
    # Privilege escalation
    2117,  # To run commands as another user, use su -c or sudo
}


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


def run_shellcheck(
    command: str,
    shell: str = "bash",
    severity: str = "info",
    timeout: float = 5.0,
) -> list[ShellCheckFinding]:
    """Run shellcheck on a command string.

    Args:
        command: Shell command to analyze
        shell: Shell dialect (bash, sh, dash, ksh)
        severity: Minimum severity to report (error, warning, info, style)
        timeout: Maximum time to wait for shellcheck (seconds)

    Returns:
        List of ShellCheckFinding objects, empty if shellcheck unavailable or error.

    Note:
        This function never raises - it fails silently to avoid breaking
        the validation pipeline if shellcheck has issues.
    """
    path = get_shellcheck_path()
    if not path:
        return []

    try:
        # Run shellcheck with JSON output, reading from stdin
        result = subprocess.run(
            [
                path,
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
        )

        # ShellCheck returns exit code 1 if it finds issues (not an error)
        # Exit code 2+ indicates actual errors
        if result.returncode > 1:
            return []

        # Parse JSON output
        if not result.stdout.strip():
            return []

        findings_json = json.loads(result.stdout)
        findings = []

        for f in findings_json:
            try:
                level = ShellCheckSeverity(f.get("level", "info"))
                finding = ShellCheckFinding(
                    code=f.get("code", 0),
                    level=level,
                    message=f.get("message", ""),
                    line=f.get("line", 1),
                    column=f.get("column", 1),
                    end_line=f.get("endLine", 1),
                    end_column=f.get("endColumn", 1),
                )
                findings.append(finding)
            except (ValueError, KeyError):
                # Skip malformed findings
                continue

        return findings

    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError, json.JSONDecodeError):
        # Fail silently - shellcheck is optional enhancement
        return []


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
