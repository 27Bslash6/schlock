"""Tests for audit log secret scrubbing.

FIX 4: Secrets in Audit Logs
Bug: audit.py logged full commands containing passwords, tokens, API keys in
plaintext - compliance violation (GDPR, PCI-DSS, SOC2).

Fix: Added _scrub_secrets() method with SECRET_PATTERNS to redact before logging.
"""

import json
import tempfile
from pathlib import Path

from schlock.integrations.audit import AuditLogger


class TestSecretScrubbing:
    """Test that secrets are redacted from audit logs."""

    def test_password_equals_redacted(self):
        """password=VALUE should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("mysql -u root password=secret123 -e 'SELECT 1'")
        assert "secret123" not in scrubbed
        assert "password=***REDACTED***" in scrubbed

    def test_token_equals_redacted(self):
        """token=VALUE should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("curl -H 'token=abc123def456' https://api.example.com")
        assert "abc123def456" not in scrubbed
        assert "token=***REDACTED***" in scrubbed

    def test_api_key_equals_redacted(self):
        """api-key=VALUE and api_key=VALUE should be redacted."""
        logger = AuditLogger()

        scrubbed1 = logger._scrub_secrets("curl --header 'api-key=sk-1234567890'")
        assert "sk-1234567890" not in scrubbed1
        assert "api-key=***REDACTED***" in scrubbed1

        scrubbed2 = logger._scrub_secrets("export API_KEY=sk-9876543210")
        assert "sk-9876543210" not in scrubbed2
        assert "API_KEY=***REDACTED***" in scrubbed2

    def test_bearer_token_redacted(self):
        """Authorization: Bearer TOKEN should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets('curl -H "Authorization: Bearer sk-1234567890abcdef"')
        assert "sk-1234567890abcdef" not in scrubbed
        assert "Authorization: Bearer ***REDACTED***" in scrubbed

    def test_long_flag_password_redacted(self):
        """--password VALUE should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("mysql -u root --password secret123 -e 'SELECT 1'")
        assert "secret123" not in scrubbed
        assert "--password ***REDACTED***" in scrubbed

    def test_long_flag_token_redacted(self):
        """--token VALUE should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("gh auth login --token ghp_1234567890abcdef")
        assert "ghp_1234567890abcdef" not in scrubbed
        assert "--token ***REDACTED***" in scrubbed

    def test_short_flag_p_redacted(self):
        """-p PASSWORD should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("mysql -u root -p secret123")
        assert "secret123" not in scrubbed
        assert "-p ***REDACTED***" in scrubbed

    def test_short_flag_p_with_non_numeric(self):
        """-p with non-numeric value should be redacted (password)."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("command -p secretpass123")
        assert "secretpass123" not in scrubbed
        assert "-p ***REDACTED***" in scrubbed

    def test_case_insensitive_matching(self):
        """Pattern matching should be case-insensitive."""
        logger = AuditLogger()

        scrubbed1 = logger._scrub_secrets("export PASSWORD=secret")
        assert "PASSWORD=***REDACTED***" in scrubbed1

        scrubbed2 = logger._scrub_secrets("export Password=secret")
        assert "Password=***REDACTED***" in scrubbed2

        scrubbed3 = logger._scrub_secrets("--TOKEN value123")
        assert "--TOKEN ***REDACTED***" in scrubbed3

    def test_multiple_secrets_redacted(self):
        """Multiple secrets in one command should all be redacted."""
        logger = AuditLogger()
        cmd = "curl -H 'token=abc' -H 'api-key=xyz' --password secret123"
        scrubbed = logger._scrub_secrets(cmd)

        assert "abc" not in scrubbed
        assert "xyz" not in scrubbed
        assert "secret123" not in scrubbed
        assert scrubbed.count("***REDACTED***") == 3

    def test_safe_commands_unchanged(self):
        """Commands without secrets should pass through unchanged."""
        logger = AuditLogger()

        safe_commands = [
            "git status",
            "ls -la /tmp",
            "echo 'hello world'",
            "find . -name '*.py'",
            "docker build -t myapp .",
            "docker run -p 8080:80 nginx",  # -p with port numbers should not be redacted
            "mysql -P 3306 -h localhost",  # -P with port should not be redacted
        ]

        for cmd in safe_commands:
            scrubbed = logger._scrub_secrets(cmd)
            assert scrubbed == cmd, f"Safe command was modified: {cmd}"


class TestAuditLogIntegration:
    """Test that scrubbing is integrated into log_validation()."""

    def test_secrets_scrubbed_in_audit_log(self):
        """Secrets should be scrubbed when logging to file."""
        # Use temp file for testing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)

        try:
            logger = AuditLogger(log_file=log_path)

            # Log a command with secrets
            logger.log_validation(
                command="mysql -u root --password secret123 -e 'DROP DATABASE prod'",
                risk_level="BLOCKED",
                violations=["database_drop"],
                decision="block",
            )

            # Read the log file
            with open(log_path) as f:
                log_line = f.read().strip()

            log_data = json.loads(log_line)

            # Secret should be redacted in the log
            assert "secret123" not in log_data["command"]
            assert "--password ***REDACTED***" in log_data["command"]

            # Rest of log should be intact
            assert log_data["risk_level"] == "BLOCKED"
            assert log_data["decision"] == "block"

        finally:
            # Cleanup
            log_path.unlink(missing_ok=True)

    def test_bearer_token_scrubbed_in_log(self):
        """Bearer tokens should be scrubbed in audit logs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)

        try:
            logger = AuditLogger(log_file=log_path)

            logger.log_validation(
                command='curl -H "Authorization: Bearer sk-abc123def456"',
                risk_level="LOW",
                violations=[],
                decision="allow",
            )

            with open(log_path) as f:
                log_data = json.loads(f.read().strip())

            assert "sk-abc123def456" not in log_data["command"]
            assert "Authorization: Bearer ***REDACTED***" in log_data["command"]

        finally:
            log_path.unlink(missing_ok=True)


class TestEdgeCases:
    """Test edge cases in secret scrubbing."""

    def test_secret_at_end_of_command(self):
        """Secret at end of command should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("export API_KEY=secret")
        assert "secret" not in scrubbed
        assert "API_KEY=***REDACTED***" in scrubbed

    def test_secret_with_special_chars(self):
        """Secrets with special characters should be redacted."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("token=abc!@#$%^&*()123")
        # \S+ should match non-whitespace, so special chars are included
        assert "abc!@#$%^&*()123" not in scrubbed

    def test_no_false_positives_on_filenames(self):
        """Filenames like password.txt should not trigger redaction."""
        logger = AuditLogger()
        # This shouldn't match because it's not password=VALUE pattern
        scrubbed = logger._scrub_secrets("cat password.txt")
        assert scrubbed == "cat password.txt"

    def test_multiple_same_pattern(self):
        """Multiple occurrences of same pattern should all be redacted."""
        logger = AuditLogger()
        cmd = "password=abc password=def password=ghi"
        scrubbed = logger._scrub_secrets(cmd)
        assert "abc" not in scrubbed
        assert "def" not in scrubbed
        assert "ghi" not in scrubbed
        assert scrubbed.count("password=***REDACTED***") == 3

    def test_empty_command(self):
        """Empty commands should not crash."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("")
        assert scrubbed == ""

    def test_command_with_only_flag_no_value(self):
        """Flags without values should not crash."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("mysql --password")
        # --password with no following value shouldn't match \S+
        assert scrubbed == "mysql --password"
