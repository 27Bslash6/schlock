"""Environment detection module for schlock setup wizard.

Detects installed formatter tools (ruff, cargo, prettier) with version information.
Uses shutil.which() for cross-platform PATH detection and subprocess for version
checking with timeout protection.
"""

import logging
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Supported formatter tools
SUPPORTED_TOOLS = ["ruff", "cargo", "prettier"]

# Version check timeout (seconds)
VERSION_CHECK_TIMEOUT = 2.0


@dataclass(frozen=True)
class ToolInfo:
    """Information about a detected formatter tool.

    Attributes:
        name: Tool name (ruff, cargo, prettier)
        found: Whether tool exists in PATH
        path: Absolute path to tool executable (None if not found)
        version: Version string (None if not found or parse failed)
        check_time_ms: Time taken to detect (for performance monitoring)
    """

    name: str
    found: bool
    path: Optional[str]
    version: Optional[str]
    check_time_ms: float


@dataclass(frozen=True)
class DetectionResult:
    """Result of environment detection.

    Attributes:
        tools: Dict mapping tool name to ToolInfo
        total_found: Count of found tools
        total_checked: Count of tools checked
        detection_time_ms: Total time for all checks
    """

    tools: dict[str, ToolInfo]
    total_found: int
    total_checked: int
    detection_time_ms: float


def detect_tools(tool_names: Optional[list[str]] = None) -> DetectionResult:
    """Detect which formatter tools are available.

    Args:
        tool_names: Tools to check (defaults to SUPPORTED_TOOLS)

    Returns:
        DetectionResult with availability and versions

    Example:
        >>> result = detect_tools()
        >>> if result.tools["ruff"].found:
        ...     print(f"ruff {result.tools['ruff'].version}")
    """
    start_time = time.perf_counter()

    if tool_names is None:
        tool_names = SUPPORTED_TOOLS.copy()

    # Validate tool names against whitelist
    for name in tool_names:
        if name not in SUPPORTED_TOOLS:
            logger.warning(f"Unknown tool name: {name} (not in {SUPPORTED_TOOLS})")

    tools: dict[str, ToolInfo] = {}

    # Detect tools in parallel for performance (<500ms target)
    with ThreadPoolExecutor(max_workers=len(tool_names)) as executor:
        futures = {executor.submit(_detect_single_tool, name): name for name in tool_names}

        for future in as_completed(futures):
            tool_info = future.result()
            tools[tool_info.name] = tool_info

    end_time = time.perf_counter()
    detection_time_ms = (end_time - start_time) * 1000

    total_found = sum(1 for tool in tools.values() if tool.found)
    total_checked = len(tools)

    return DetectionResult(
        tools=tools,
        total_found=total_found,
        total_checked=total_checked,
        detection_time_ms=detection_time_ms,
    )


def _detect_single_tool(tool_name: str) -> ToolInfo:
    """Detect a single tool (internal helper for parallel execution).

    Args:
        tool_name: Tool name to detect

    Returns:
        ToolInfo for the tool
    """
    start_time = time.perf_counter()

    try:
        # Use shutil.which to detect tool in PATH (same pattern as formatter.py)
        tool_path = shutil.which(tool_name)

        if tool_path is None:
            # Tool not found in PATH
            check_time = (time.perf_counter() - start_time) * 1000
            return ToolInfo(
                name=tool_name,
                found=False,
                path=None,
                version=None,
                check_time_ms=check_time,
            )

        # Tool found - get version
        version = get_tool_version(tool_name, tool_path)
        check_time = (time.perf_counter() - start_time) * 1000

        logger.debug(f"Found {tool_name} at {tool_path}" + (f" (version {version})" if version else " (version unknown)"))

        return ToolInfo(
            name=tool_name,
            found=True,
            path=tool_path,
            version=version,
            check_time_ms=check_time,
        )

    except Exception as e:
        # Graceful degradation - log warning and mark as not found
        check_time = (time.perf_counter() - start_time) * 1000
        logger.warning(f"Error detecting {tool_name}: {e}")
        return ToolInfo(
            name=tool_name,
            found=False,
            path=None,
            version=None,
            check_time_ms=check_time,
        )


def get_tool_version(tool_name: str, tool_path: str) -> Optional[str]:
    """Get version string for a tool.

    Args:
        tool_name: Tool name (for determining version flag)
        tool_path: Path to tool executable

    Returns:
        Version string (e.g., "0.1.9") or None if failed

    Notes:
        - Runs `{tool} --version` with 2s timeout
        - Parses version from output (different format per tool)
        - Returns None on timeout, error, or parse failure
    """
    try:
        # Run version command with timeout (shell=False for security)
        result = subprocess.run(
            [tool_path, "--version"],
            capture_output=True,
            text=True,
            timeout=VERSION_CHECK_TIMEOUT,
            check=False,  # Don't raise on non-zero exit
        )

        if result.returncode != 0:
            logger.debug(f"{tool_name} --version returned non-zero exit: {result.returncode}")
            return None

        # Parse version from stdout
        output = result.stdout.strip()
        version = _parse_version_string(tool_name, output)

        if version is None:
            logger.debug(f"Could not parse version from {tool_name} output: {output}")

        return version

    except subprocess.TimeoutExpired:
        logger.warning(f"{tool_name} --version timed out after {VERSION_CHECK_TIMEOUT}s")
        return None
    except Exception as e:
        logger.warning(f"Error getting {tool_name} version: {e}")
        return None


def _parse_version_string(tool_name: str, output: str) -> Optional[str]:
    """Parse version string from tool output.

    Args:
        tool_name: Tool name (determines parsing strategy)
        output: Raw output from --version command

    Returns:
        Version string or None if parse failed

    Examples:
        ruff: "ruff 0.1.9" -> "0.1.9"
        cargo: "cargo 1.75.0" -> "1.75.0"
        prettier: "3.2.1" -> "3.2.1"
    """
    if not output:
        return None

    # Common version pattern: semantic versioning (x.y.z)
    # Matches: "0.1.9", "1.75.0", "3.2.1", "1.0.0-beta.1"
    version_pattern = r"(\d+\.\d+\.\d+(?:[.-]\S+)?)"

    match = re.search(version_pattern, output)
    if match:
        return match.group(1)

    # Fallback: try to extract just the first line (prettier format)
    first_line = output.split("\n")[0].strip()
    if re.match(r"^\d+\.\d+\.\d+", first_line):
        return first_line

    return None
