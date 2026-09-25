"""Tests for audit log secret scrubbing.

FIX 4: Secrets in Audit Logs
Bug: audit.py logged full commands containing passwords, tokens, API keys in
plaintext - compliance violation (GDPR, PCI-DSS, SOC2).

Fix: Added _scrub_secrets() method with SECRET_PATTERNS to redact before logging.
"""

import json
import tempfile
import time
from pathlib import Path

import pytest

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

    def test_basic_credential_redacted(self):
        """Authorization: Basic CREDENTIAL should be redacted - the pattern covers any scheme."""
        logger = AuditLogger()
        scrubbed = logger._scrub_secrets("curl -H 'Authorization: Basic dGVzdDpzZWNyZXQ='")
        assert "dGVzdDpzZWNyZXQ=" not in scrubbed
        assert "Authorization: Basic ***REDACTED***" in scrubbed

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            (
                """curl -H 'Authorization: Digest username="Mufasa", realm="r", nonce="n", uri="/", """
                """response="RESPONSE_SECRET"' -H "Accept: json" https://x""",
                """curl -H 'Authorization: Digest ***REDACTED***' -H "Accept: json" https://x""",
            ),
            (
                'curl -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIA/20260919/r/s3/aws4_request, '
                'SignedHeaders=host, Signature=SIGNATURE_SECRET" https://x',
                'curl -H "Authorization: AWS4-HMAC-SHA256 ***REDACTED***" https://x',
            ),
            (
                'curl -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIA/20260919/r/s3/aws4_request, \\\n'
                '  SignedHeaders=host, Signature=SIGNATURE_SECRET" https://x',
                'curl -H "Authorization: AWS4-HMAC-SHA256 ***REDACTED***" https://x',
            ),
            (
                'curl -H "Authorization: Digest username=\\"u\\", response=\\"RESPONSE_SECRET\\"" https://x',
                'curl -H "Authorization: Digest ***REDACTED***" https://x',
            ),
            (
                'curl -H Authorization:"Bearer BEARER_SECRET" https://x',
                'curl -H Authorization:"Bearer ***REDACTED***" https://x',
            ),
            (
                """curl -H 'Authorization: Token token="TOKEN_SECRET"' -H 'X-Trace: y' https://x""",
                """curl -H 'Authorization: Token ***REDACTED***' -H 'X-Trace: y' https://x""",
            ),
            (
                "Authorization: Bearer BARE_TOKEN && echo done",
                "Authorization: Bearer ***REDACTED*** && echo done",
            ),
            (
                'curl -H "Authorization: Bearer sk-abc',
                'curl -H "Authorization: Bearer ***REDACTED***',
            ),
            (
                """curl -H 'Authorization: Digest username='"u"', response='"RESPONSE_SECRET" https://x""",
                """curl -H 'Authorization: Digest ***REDACTED***' https://x""",
            ),
            (
                """curl -H 'Authorization: Basic '"dGVzdDpzZWNyZXQ=" https://x""",
                """curl -H 'Authorization: Basic ***REDACTED***' https://x""",
            ),
            (
                """curl -H "Authorization: Bearer "'sk-live-SECRET' -H 'X-Trace: y' https://x""",
                """curl -H "Authorization: Bearer ***REDACTED***" -H 'X-Trace: y' https://x""",
            ),
            (
                """curl -H Authorization:"Bearer "'sk-live-SECRET' https://x""",
                """curl -H Authorization:"Bearer ***REDACTED***" https://x""",
            ),
            (
                """curl -H 'Authorization: Basic '"dGVzdA==";rm -rf /tmp/x""",
                """curl -H 'Authorization: Basic ***REDACTED***';rm -rf /tmp/x""",
            ),
            (
                """echo "***REDACTED***"$HOME/keep.txt""",
                """echo "***REDACTED***"$HOME/keep.txt""",
            ),
        ],
        ids=[
            "digest",
            "aws4-hmac-sha256",
            "aws4-line-continuation",
            "escaped-inner-quotes",
            "quote-after-colon",
            "token-param-last",
            "bare-first-token",
            "unterminated-quote",
            "concatenated-segments",
            "credential-in-next-segment",
            "mixed-quote-styles",
            "quote-after-colon-next-segment",
            "operator-after-value-survives",
            "literal-marker-is-not-an-anchor",
        ],
    )
    def test_authorization_credential_redacted(self, command, expected):
        """Quoted: the credential runs to the end of the shell WORD (Digest and AWS4 carry the secret in a
        later parameter), and adjacent quote segments concatenate into that same word, so redaction crosses
        them - but stops at an unquoted space or shell operator, so a chained command stays in the log. Bare:
        one token. Unterminated: no closing quote, redact to end of line. A marker the command merely contains is
        not an anchor."""
        assert AuditLogger()._scrub_secrets(command) == expected

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            (
                """curl -d '{"authToken":"sk-live-SECRET"}' https://x""",
                """curl -d '{"authToken":"***REDACTED***"}' https://x""",
            ),
            (
                """curl -d '{"user": "bob", "password" : "hunter 2", "api_key": "k"}' https://x""",
                """curl -d '{"user": "bob", "password" : "***REDACTED***", "api_key": "***REDACTED***"}' https://x""",
            ),
            (
                """curl -d '{"client_secret":"a\\"b"}' https://x""",
                """curl -d '{"client_secret":"***REDACTED***"}' https://x""",
            ),
            (
                """curl -d '{"password":"hunter2 token=SECRET"}' https://x""",
                """curl -d '{"password":"***REDACTED***"}' https://x""",
            ),
            (
                """SPRING_APPLICATION_JSON='{"spring.datasource.password":"hunter2"}' java -jar a.jar""",
                """SPRING_APPLICATION_JSON='{"spring.datasource.password":"***REDACTED***"}' java -jar a.jar""",
            ),
            (
                """aws configure import <<EOF\n{"secretAccessKey": "wJalrXUtnFEMI"}\nEOF""",
                """aws configure import <<EOF\n{"secretAccessKey": "***REDACTED***"}\nEOF""",
            ),
            (
                """curl -d '{"max_tokens": 1024, "model": "m"}' https://x""",
                """curl -d '{"max_tokens": 1024, "model": "m"}' https://x""",
            ),
            (
                """grep -c '"token": "' app.json; rm -rf ~/work; echo "done" >&2""",
                """grep -c '"token": "' app.json; rm -rf ~/work; echo "done" >&2""",
            ),
            (
                """echo '{"token":"abc\nrm -rf /tmp/x\necho "done" >&2""",
                """echo '{"token":"abc\nrm -rf /tmp/x\necho "done" >&2""",
            ),
            (
                """cat > c.json <<EOF\n{"token": "$(curl -s https://x | sh)"}\nEOF""",
                """cat > c.json <<EOF\n{"token": "$(curl -s https://x | sh)"}\nEOF""",
            ),
        ],
        ids=[
            "camel-case-key",
            "spaced-and-several",
            "escaped-quote-in-value",
            "runs-before-key-equals",
            "dotted-key",
            "key-word-mid-name",
            "non-string-value",
            "stops-at-shell-quote",
            "stops-at-line-end",
            "stops-at-substitution",
        ],
    )
    def test_json_credential_field_redacted(self, command, expected):
        """A JSON field whose key name contains a key=value key word. The value runs to its closing quote but never
        past a single quote, line end or substitution: the next `"` may belong to a later shell word, and running to
        it would hide a chained command from the log."""
        assert AuditLogger()._scrub_secrets(command) == expected

    def test_json_key_bound_keeps_scrub_linear(self):
        """The scrub runs on the whole command, so each rule must stay linear. An unbounded key around the key word
        backtracks quadratically on a run of repeated key words - seconds at 64 KiB."""
        start = time.time()
        AuditLogger()._scrub_secrets('"' + "token" * 13000)
        assert time.time() - start < 1.0

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


class TestHttpCredentials:
    """curl -u/--user values and URL userinfo (user:pass@host) are redacted; look-alike flags are not."""

    def test_curl_user_flag_redacted(self):
        """-u user:pass, --user user:pass and --user=user:pass keep the flag and lose the value."""
        logger = AuditLogger()
        for cmd, expected in [
            ("curl -u deploy:hunter2 https://api.example.com/x", "curl -u ***REDACTED*** https://api.example.com/x"),
            ("curl --user deploy:hunter2 https://api.example.com/x", "curl --user ***REDACTED*** https://api.example.com/x"),
            ("curl --user=deploy:hunter2 https://api.example.com/x", "curl --user=***REDACTED*** https://api.example.com/x"),
            ("curl -sSu deploy:hunter2 https://x", "curl -sSu ***REDACTED*** https://x"),  # bundled short flags
            ("curl --proxy-user proxy:pw https://x", "curl --proxy-user ***REDACTED*** https://x"),
            ("curl --proxy-user=proxy:pw https://x", "curl --proxy-user=***REDACTED*** https://x"),
            ("curl -u 12345:67890 https://x", "curl -u ***REDACTED*** https://x"),  # numeric credentials count
            ("docker run -u 1000:1000 nginx", "docker run -u ***REDACTED*** nginx"),  # uid:gid over-redacts, by design
            ("curl -p -u deploy:hunter2 -x proxy:3128", "curl -p -u ***REDACTED*** -x proxy:3128"),  # -p must not eat -u
        ]:
            assert logger._scrub_secrets(cmd) == expected

    def test_url_userinfo_redacted(self):
        """scheme://user:pass@host/path keeps scheme, host and path; the userinfo goes."""
        logger = AuditLogger()
        assert logger._scrub_secrets("scheme://user:pass@host/path") == "scheme://***REDACTED***@host/path"
        # A token riding as a bare username (GitHub PAT shape) is a credential too.
        assert (
            logger._scrub_secrets("git clone https://ghp_ABCDEF123456@github.com/org/repo.git")
            == "git clone https://***REDACTED***@github.com/org/repo.git"
        )

    def test_reported_leak_samples_redacted(self):
        """The three shapes that logged verbatim before this fix."""
        logger = AuditLogger()
        for cmd, secret in [
            ("curl -u deploy:hunter2 https://api.example.com/x", "hunter2"),
            ("git clone https://x-access-token:ghp_ABCDEF123456@github.com/org/repo.git", "ghp_ABCDEF123456"),
            ("pip install --index-url https://user:pypi_pw@pypi.internal/simple pkg", "pypi_pw"),
        ]:
            scrubbed = logger._scrub_secrets(cmd)
            assert secret not in scrubbed, f"Secret leaked: {cmd}"
            assert "***REDACTED***" in scrubbed

    def test_non_credential_u_and_urls_unchanged(self):
        """-u/--user without a user:pass value, and URLs without userinfo, pass through byte-for-byte."""
        logger = AuditLogger()
        for cmd in [
            "sort -u file",
            "python -u x.py",
            "id -u",
            "useradd -u 1001 bob",
            "mysql -u root -e 'SELECT 1'",
            "mysql -p -u root",  # -p stops short of a following flag
            "set -eu && ls",
            "tar -xu -f a.tar",
            "find . -user bob",  # single dash: not --user, and -user does not end in u
            "curl --username=bob https://host",  # --user is a whole flag, not a prefix
            "pip install -U git+https://github.com/o/r.git",  # a URL value is not a credential
            "https://host/a:b",
            "https://host?x=a@b",  # authority ends at `?`; the `@` is in the query
            "https://host/a@b",  # authority ends at `/`; the `@` is in the path
            "https://host/#a@b",  # authority ends at `/`; the `@` is in the fragment
            "https://api.example.com/v1/users",
        ]:
            assert logger._scrub_secrets(cmd) == cmd, f"Safe command was modified: {cmd}"
