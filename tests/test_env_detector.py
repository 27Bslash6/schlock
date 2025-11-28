"""Tests for environment detector module."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from schlock.setup.env_detector import (
    SUPPORTED_TOOLS,
    DetectionResult,
    ToolInfo,
    _parse_version_string,
    detect_tools,
    get_tool_version,
)


class TestToolInfo:
    """Test suite for ToolInfo dataclass."""

    def test_tool_info_immutable(self):
        """ToolInfo should be immutable (frozen)."""
        tool = ToolInfo(
            name="ruff",
            found=True,
            path="/usr/local/bin/ruff",
            version="0.1.9",
            check_time_ms=45.2,
        )

        with pytest.raises(AttributeError):
            tool.found = False  # Should raise (frozen dataclass)

    def test_tool_info_not_found(self):
        """ToolInfo correctly represents missing tool."""
        tool = ToolInfo(
            name="cargo",
            found=False,
            path=None,
            version=None,
            check_time_ms=12.1,
        )

        assert tool.name == "cargo"
        assert tool.found is False
        assert tool.path is None
        assert tool.version is None
        assert tool.check_time_ms > 0


class TestDetectionResult:
    """Test suite for DetectionResult dataclass."""

    def test_detection_result_immutable(self):
        """DetectionResult should be immutable (frozen)."""
        result = DetectionResult(
            tools={"ruff": ToolInfo("ruff", True, "/usr/bin/ruff", "0.1.9", 10.0)},
            total_found=1,
            total_checked=1,
            detection_time_ms=15.0,
        )

        with pytest.raises(AttributeError):
            result.total_found = 2  # Should raise (frozen dataclass)


class TestDetectTools:
    """Test suite for detect_tools function."""

    @patch("schlock.setup.env_detector.shutil.which")
    @patch("schlock.setup.env_detector.get_tool_version")
    def test_detect_all_tools_found(self, mock_get_version, mock_which):
        """All tools found in PATH with versions."""
        # Mock shutil.which to return paths
        mock_which.side_effect = lambda tool: f"/usr/local/bin/{tool}"

        # Mock version detection
        mock_get_version.side_effect = lambda name, path: {
            "ruff": "0.1.9",
            "cargo": "1.75.0",
            "prettier": "3.2.1",
        }[name]

        result = detect_tools()

        assert result.total_checked == 3
        assert result.total_found == 3
        assert result.detection_time_ms < 1000  # Should be fast with mocks

        # Verify all tools found
        assert result.tools["ruff"].found is True
        assert result.tools["ruff"].version == "0.1.9"
        assert result.tools["cargo"].found is True
        assert result.tools["cargo"].version == "1.75.0"
        assert result.tools["prettier"].found is True
        assert result.tools["prettier"].version == "3.2.1"

    @patch("schlock.setup.env_detector.shutil.which")
    def test_detect_no_tools_found(self, mock_which):
        """No tools found in PATH."""
        # Mock shutil.which to return None (not found)
        mock_which.return_value = None

        result = detect_tools()

        assert result.total_checked == 3
        assert result.total_found == 0

        # Verify all tools not found
        for tool_name in SUPPORTED_TOOLS:
            assert result.tools[tool_name].found is False
            assert result.tools[tool_name].path is None
            assert result.tools[tool_name].version is None

    @patch("schlock.setup.env_detector.shutil.which")
    @patch("schlock.setup.env_detector.get_tool_version")
    def test_detect_mixed_tools(self, mock_get_version, mock_which):
        """Some tools found, some missing."""

        def which_side_effect(tool):
            if tool == "ruff":
                return "/usr/local/bin/ruff"
            if tool == "prettier":
                return "/usr/local/bin/prettier"
            return None  # cargo not found

        mock_which.side_effect = which_side_effect
        mock_get_version.side_effect = lambda name, path: {
            "ruff": "0.1.9",
            "prettier": "3.2.1",
        }[name]

        result = detect_tools()

        assert result.total_checked == 3
        assert result.total_found == 2

        assert result.tools["ruff"].found is True
        assert result.tools["cargo"].found is False
        assert result.tools["prettier"].found is True

    @patch("schlock.setup.env_detector.shutil.which")
    def test_detect_tools_custom_list(self, mock_which):
        """Detect custom subset of tools."""
        mock_which.side_effect = lambda tool: f"/usr/bin/{tool}" if tool == "ruff" else None

        result = detect_tools(tool_names=["ruff"])

        assert result.total_checked == 1
        assert result.total_found == 1
        assert "ruff" in result.tools
        assert "cargo" not in result.tools

    @patch("schlock.setup.env_detector.shutil.which")
    def test_detect_tools_graceful_degradation(self, mock_which):
        """Detection continues even if one tool check fails."""

        # Simulate exception for cargo, but ruff succeeds
        def which_side_effect(tool):
            if tool == "cargo":
                raise Exception("Simulated failure")
            return f"/usr/bin/{tool}"

        mock_which.side_effect = which_side_effect

        result = detect_tools()

        # Should still complete despite error
        assert result.total_checked == 3
        # cargo marked as not found due to exception
        assert result.tools["cargo"].found is False
        # Other tools detected
        assert result.tools["ruff"].found is True
        assert result.tools["prettier"].found is True

    @patch("schlock.setup.env_detector.shutil.which")
    @patch("schlock.setup.env_detector.get_tool_version")
    def test_detect_tools_performance(self, mock_get_version, mock_which):
        """Detection should complete quickly with parallel execution."""
        mock_which.return_value = "/usr/bin/tool"
        mock_get_version.return_value = "1.0.0"

        result = detect_tools()

        # Should be fast (parallel execution, mocked I/O)
        # Target is <500ms for real execution, mocked should be much faster
        assert result.detection_time_ms < 1000


class TestGetToolVersion:
    """Test suite for get_tool_version function."""

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_ruff(self, mock_run):
        """Parse ruff version correctly."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ruff 0.1.9\n",
        )

        version = get_tool_version("ruff", "/usr/local/bin/ruff")

        assert version == "0.1.9"
        mock_run.assert_called_once()
        # Verify shell=False (security - default is False if not specified)
        call_args = mock_run.call_args
        assert call_args.kwargs.get("shell", False) is False

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_cargo(self, mock_run):
        """Parse cargo version correctly."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="cargo 1.75.0 (1d8b05cdd 2023-11-20)\n",
        )

        version = get_tool_version("cargo", "/usr/bin/cargo")

        assert version == "1.75.0"

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_prettier(self, mock_run):
        """Parse prettier version correctly."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="3.2.1\n",
        )

        version = get_tool_version("prettier", "/usr/local/bin/prettier")

        assert version == "3.2.1"

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_non_zero_exit(self, mock_run):
        """Handle non-zero exit code gracefully."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
        )

        version = get_tool_version("ruff", "/usr/bin/ruff")

        assert version is None

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_timeout(self, mock_run):
        """Handle timeout gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired("ruff", 2.0)

        version = get_tool_version("ruff", "/usr/bin/ruff")

        assert version is None

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_exception(self, mock_run):
        """Handle subprocess exception gracefully."""
        mock_run.side_effect = Exception("Simulated error")

        version = get_tool_version("ruff", "/usr/bin/ruff")

        assert version is None

    @patch("schlock.setup.env_detector.subprocess.run")
    def test_get_version_unparseable_output(self, mock_run):
        """Handle unparseable version output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Invalid output without version\n",
        )

        version = get_tool_version("ruff", "/usr/bin/ruff")

        assert version is None


class TestParseVersionString:
    """Test suite for _parse_version_string function."""

    def test_parse_ruff_format(self):
        """Parse ruff version format."""
        assert _parse_version_string("ruff", "ruff 0.1.9") == "0.1.9"
        assert _parse_version_string("ruff", "ruff 0.2.0-beta.1") == "0.2.0-beta.1"

    def test_parse_cargo_format(self):
        """Parse cargo version format."""
        assert _parse_version_string("cargo", "cargo 1.75.0 (1d8b05cdd 2023-11-20)") == "1.75.0"

    def test_parse_prettier_format(self):
        """Parse prettier version format."""
        assert _parse_version_string("prettier", "3.2.1") == "3.2.1"

    def test_parse_empty_string(self):
        """Handle empty output."""
        assert _parse_version_string("ruff", "") is None

    def test_parse_no_version(self):
        """Handle output without version."""
        assert _parse_version_string("ruff", "No version found here") is None

    def test_parse_multiline_output(self):
        """Extract version from multiline output."""
        output = "Tool info\nversion 1.2.3\nmore info"
        assert _parse_version_string("tool", output) == "1.2.3"
