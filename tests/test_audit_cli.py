"""Tests for audit log analysis CLI."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# Add tests directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent))

from audit_cli import (
    AuditEntry,
    cmd_blocked,
    cmd_patterns,
    cmd_search,
    cmd_summary,
    read_entries,
)


@pytest.fixture
def sample_audit_data():
    """Generate sample audit entries."""
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp": (now - timedelta(hours=i)).isoformat(),
            "event_type": "validation",
            "command": f"test command {i}",
            "risk_level": ["SAFE", "LOW", "MEDIUM", "HIGH", "BLOCKED"][i % 5],
            "violations": [f"rule_{i}"] if i % 3 == 0 else [],
            "decision": "block" if i % 5 == 4 else "allow",
            "execution_time_ms": 10.0 + i,
        }
        for i in range(20)
    ]


@pytest.fixture
def audit_dir(sample_audit_data, tmp_path):
    """Create temporary audit directory with sample data."""
    audit_path = tmp_path / "schlock"
    audit_path.mkdir(parents=True)

    # Write audit file for today
    today = datetime.now().strftime("%Y-%m-%d")
    audit_file = audit_path / f"audit-{today}.jsonl"

    with open(audit_file, "w") as f:
        for entry in sample_audit_data:
            f.write(json.dumps(entry) + "\n")

    return audit_path


class TestAuditEntry:
    """Test AuditEntry parsing."""

    def test_from_json_valid(self):
        """Test parsing valid JSON."""
        line = json.dumps(
            {
                "timestamp": "2025-01-01T12:00:00+00:00",
                "event_type": "validation",
                "command": "ls -la",
                "risk_level": "SAFE",
                "violations": [],
                "decision": "allow",
                "execution_time_ms": 5.0,
            }
        )
        entry = AuditEntry.from_json(line)
        assert entry is not None
        assert entry.command == "ls -la"
        assert entry.risk_level == "SAFE"
        assert entry.decision == "allow"

    def test_from_json_invalid(self):
        """Test parsing invalid JSON returns None."""
        assert AuditEntry.from_json("not valid json") is None
        assert AuditEntry.from_json("{}") is None  # Missing required fields


class TestReadEntries:
    """Test audit entry reading."""

    def test_read_entries_from_dir(self, audit_dir):
        """Test reading entries from audit directory."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            entries = list(read_entries(days=1))
            assert len(entries) == 20

    def test_read_entries_empty_dir(self, tmp_path):
        """Test reading from empty directory."""
        with patch("audit_cli.get_audit_dir", return_value=tmp_path):
            entries = list(read_entries(days=1))
            assert len(entries) == 0


class TestSummaryCommand:
    """Test summary command."""

    def test_summary_with_data(self, audit_dir, capsys):
        """Test summary with audit data."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            args = type("Args", (), {"days": 7})()
            result = cmd_summary(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Total events: 20" in captured.out
            assert "By Risk Level:" in captured.out
            assert "SAFE" in captured.out
            assert "BLOCKED" in captured.out

    def test_summary_empty(self, tmp_path, capsys):
        """Test summary with no data."""
        with patch("audit_cli.get_audit_dir", return_value=tmp_path):
            args = type("Args", (), {"days": 7})()
            result = cmd_summary(args)
            assert result == 0
            captured = capsys.readouterr()
            assert "No audit entries found" in captured.out


class TestBlockedCommand:
    """Test blocked command."""

    def test_blocked_with_data(self, audit_dir, capsys):
        """Test blocked command with data."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            args = type("Args", (), {"days": 7, "limit": 10})()
            result = cmd_blocked(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Blocked Commands" in captured.out


class TestPatternsCommand:
    """Test patterns command."""

    def test_patterns_with_data(self, audit_dir, capsys):
        """Test patterns command with data."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            args = type("Args", (), {"days": 7})()
            result = cmd_patterns(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Command Patterns" in captured.out
            assert "Anomaly Detection" in captured.out


class TestSearchCommand:
    """Test search command."""

    def test_search_matching(self, audit_dir, capsys):
        """Test search with matching pattern."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            args = type("Args", (), {"days": 7, "pattern": "test command", "limit": 50})()
            result = cmd_search(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Search Results" in captured.out
            assert "matching entries" in captured.out

    def test_search_no_match(self, audit_dir, capsys):
        """Test search with no matches."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            args = type("Args", (), {"days": 7, "pattern": "nonexistent", "limit": 50})()
            result = cmd_search(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "No commands matching" in captured.out

    def test_search_invalid_regex(self, audit_dir, capsys):
        """Test search with invalid regex."""
        with patch("audit_cli.get_audit_dir", return_value=audit_dir):
            args = type("Args", (), {"days": 7, "pattern": "[invalid", "limit": 50})()
            result = cmd_search(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "Invalid regex" in captured.err


class TestIntegration:
    """Integration tests."""

    def test_cli_main_help(self):
        """Test CLI main with --help."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/audit_cli.py", "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Analyze schlock audit logs" in result.stdout

    def test_cli_summary_subcommand(self):
        """Test CLI summary subcommand."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/audit_cli.py", "summary", "--days", "1"],
            check=False,
            capture_output=True,
            text=True,
        )
        # Should succeed even with no data
        assert result.returncode == 0
