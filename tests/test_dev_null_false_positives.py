"""Test for /dev/null and stderr redirect false positives.

Regression test for issue where safe commands like:
- cat file 2>/dev/null (stderr redirect)
- cat file > /dev/null (safe device)
- paths containing 'dev' like /dev-marketplace/

Were incorrectly flagged as HIGH risk by system_critical_writes rule.
"""

from schlock.core.rules import RiskLevel
from schlock.core.validator import validate_command


class TestDevNullFalsePositives:
    """Test that /dev/null and stderr redirects are not flagged."""

    def test_stderr_redirect_to_dev_null_safe(self, safety_rules_path):
        """Stderr redirects to /dev/null should be SAFE."""
        safe_commands = [
            "cat file.txt 2>/dev/null",
            "ls -la 2>/dev/null",
            "grep pattern file 2>/dev/null",
            "cat /Users/foo/dev-marketplace/plugin.json 2>/dev/null",
            "python script.py 2>/dev/null",
            "command 2>/dev/null || echo 'failed'",
        ]

        for cmd in safe_commands:
            result = validate_command(cmd, config_path=safety_rules_path)
            assert result.allowed, f"Safe stderr redirect blocked: {cmd}"
            assert result.risk_level != RiskLevel.HIGH, f"Stderr redirect incorrectly flagged as HIGH: {cmd}"
            assert result.risk_level != RiskLevel.BLOCKED, f"Stderr redirect incorrectly flagged as BLOCKED: {cmd}"

    def test_stdout_redirect_to_dev_null_safe(self, safety_rules_path):
        """Stdout redirects to /dev/null should be SAFE."""
        safe_commands = [
            "cat file.txt > /dev/null",
            "echo test > /dev/null",
            "ls -la > /dev/null",
            "grep pattern file > /dev/null",
        ]

        for cmd in safe_commands:
            result = validate_command(cmd, config_path=safety_rules_path)
            assert result.allowed, f"Safe /dev/null redirect blocked: {cmd}"
            assert result.risk_level != RiskLevel.HIGH, f"/dev/null redirect incorrectly flagged as HIGH: {cmd}"
            assert result.risk_level != RiskLevel.BLOCKED, f"/dev/null redirect incorrectly flagged as BLOCKED: {cmd}"

    def test_paths_containing_dev_safe(self, safety_rules_path):
        """Paths containing 'dev' in directory names should be safe."""
        safe_commands = [
            "cat /Users/foo/dev-marketplace/file.json",
            "ls /opt/development/configs",
            "grep pattern /var/www/dev/app.py",
            "cat /home/user/dev-tools/config.yaml 2>/dev/null",
        ]

        for cmd in safe_commands:
            result = validate_command(cmd, config_path=safety_rules_path)
            assert result.allowed, f"Safe path with 'dev' blocked: {cmd}"
            assert result.risk_level != RiskLevel.HIGH, f"Path with 'dev' incorrectly flagged as HIGH: {cmd}"
            assert result.risk_level != RiskLevel.BLOCKED, f"Path with 'dev' incorrectly flagged as BLOCKED: {cmd}"

    def test_dangerous_dev_writes_still_blocked(self, safety_rules_path):
        """Dangerous writes to actual disk devices must still be blocked."""
        dangerous_commands = [
            "cat file > /dev/sda",
            "cat file > /dev/sdb1",
            "cat file > /dev/nvme0n1",
            "echo data > /dev/sda",
            "cat backup.img > /dev/sdc",
        ]

        for cmd in dangerous_commands:
            result = validate_command(cmd, config_path=safety_rules_path)
            assert not result.allowed, f"Dangerous disk write not blocked: {cmd}"
            assert result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED), f"Disk write not flagged as dangerous: {cmd}"

    def test_both_redirects_safe(self, safety_rules_path):
        """Commands with both stdout and stderr redirects."""
        safe_commands = [
            "command > /dev/null 2>&1",
            "cat file 2>/dev/null >/dev/null",
            "grep pattern file >/dev/null 2>/dev/null",
        ]

        for cmd in safe_commands:
            result = validate_command(cmd, config_path=safety_rules_path)
            assert result.allowed, f"Safe redirect combination blocked: {cmd}"
            assert result.risk_level != RiskLevel.HIGH, f"Safe redirect flagged as HIGH: {cmd}"
            assert result.risk_level != RiskLevel.BLOCKED, f"Safe redirect flagged as BLOCKED: {cmd}"
