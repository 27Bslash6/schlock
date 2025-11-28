"""Tests for audit logging module."""

import json
import os
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from platformdirs import user_data_dir

from schlock.integrations.audit import (
    AuditContext,
    AuditEvent,
    AuditLogger,
    get_audit_logger,
    get_null_device,
)


class TestAuditContext:
    """Test AuditContext dataclass."""

    def test_default_context(self):
        """Default context has reasonable defaults."""
        ctx = AuditContext()
        assert ctx.project_root is None
        assert ctx.current_dir is None
        assert ctx.git_branch is None
        assert ctx.environment == "development"

    def test_custom_context(self):
        """Custom context values work."""
        ctx = AuditContext(
            project_root="/home/user/project",
            current_dir="/home/user/project/src",
            git_branch="feature/test",
            environment="production",
        )
        assert ctx.project_root == "/home/user/project"
        assert ctx.current_dir == "/home/user/project/src"
        assert ctx.git_branch == "feature/test"
        assert ctx.environment == "production"


class TestAuditEvent:
    """Test AuditEvent dataclass."""

    def test_event_creation(self):
        """AuditEvent can be created with required fields."""
        event = AuditEvent(
            timestamp="2025-11-07T10:00:00Z",
            event_type="validation",
            command="rm -rf /tmp/test",
            risk_level="HIGH",
            violations=["Recursive delete"],
            decision="block",
            context={"project_root": "/home/user"},
            execution_time_ms=45.2,
        )
        assert event.timestamp == "2025-11-07T10:00:00Z"
        assert event.event_type == "validation"
        assert event.command == "rm -rf /tmp/test"
        assert event.risk_level == "HIGH"
        assert event.violations == ["Recursive delete"]
        assert event.decision == "block"
        assert event.context == {"project_root": "/home/user"}
        assert event.execution_time_ms == 45.2

    def test_event_to_json(self):
        """AuditEvent serializes to valid JSON."""
        event = AuditEvent(
            timestamp="2025-11-07T10:00:00Z",
            event_type="block",
            command="rm -rf /",
            risk_level="BLOCKED",
            violations=["System-wide recursive delete"],
            decision="block",
            context={"environment": "production"},
            execution_time_ms=12.5,
        )
        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["timestamp"] == "2025-11-07T10:00:00Z"
        assert parsed["event_type"] == "block"
        assert parsed["command"] == "rm -rf /"
        assert parsed["risk_level"] == "BLOCKED"
        assert parsed["violations"] == ["System-wide recursive delete"]
        assert parsed["decision"] == "block"
        assert parsed["context"] == {"environment": "production"}
        assert parsed["execution_time_ms"] == 12.5

    def test_event_without_execution_time(self):
        """AuditEvent works with optional execution_time_ms."""
        event = AuditEvent(
            timestamp="2025-11-07T10:00:00Z",
            event_type="allow",
            command="git status",
            risk_level="SAFE",
            violations=[],
            decision="allow",
            context={},
        )
        json_str = event.to_json()
        parsed = json.loads(json_str)
        assert parsed["execution_time_ms"] is None


class TestAuditLogger:
    """Test AuditLogger class."""

    def test_logger_creation_with_custom_path(self):
        """AuditLogger can be created with custom log path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)
            assert logger.log_file == log_file

    def test_logger_creation_with_default_path(self):
        """AuditLogger uses default timestamped path when none provided."""
        logger = AuditLogger()
        today = datetime.now().strftime("%Y-%m-%d")
        expected_path = Path(user_data_dir("schlock", "27b.io")) / f"audit-{today}.jsonl"
        assert logger.log_file == expected_path

    def test_logger_respects_env_variable_file(self):
        """AuditLogger respects SCHLOCK_AUDIT_LOG for .jsonl files (single file)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = str(Path(tmpdir) / "custom_audit.jsonl")
            os.environ["SCHLOCK_AUDIT_LOG"] = custom_path
            try:
                logger = AuditLogger()
                assert str(logger.log_file) == custom_path
            finally:
                del os.environ["SCHLOCK_AUDIT_LOG"]

    def test_logger_respects_env_variable_directory(self):
        """AuditLogger creates timestamped files in custom directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["SCHLOCK_AUDIT_LOG"] = tmpdir
            try:
                logger = AuditLogger()
                today = datetime.now().strftime("%Y-%m-%d")
                expected_path = Path(tmpdir) / f"audit-{today}.jsonl"
                assert logger.log_file == expected_path
            finally:
                del os.environ["SCHLOCK_AUDIT_LOG"]

    def test_logger_env_variable_null_device(self):
        """AuditLogger handles platform-specific null device for disabling logs."""
        null_dev = get_null_device()
        os.environ["SCHLOCK_AUDIT_LOG"] = null_dev
        try:
            logger = AuditLogger()
            assert str(logger.log_file) == null_dev
        finally:
            del os.environ["SCHLOCK_AUDIT_LOG"]

    def test_logger_creates_log_directory(self):
        """AuditLogger creates log directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "nested" / "dir" / "audit.jsonl"
            _logger = AuditLogger(log_file=log_file)  # Creates directory as side effect
            assert log_file.parent.exists()
            assert log_file.parent.is_dir()

    def test_log_event_writes_to_file(self):
        """log_event writes JSON line to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            event = AuditEvent(
                timestamp="2025-11-07T10:00:00Z",
                event_type="allow",
                command="echo hello",
                risk_level="SAFE",
                violations=[],
                decision="allow",
                context={},
            )

            logger.log_event(event)

            # Verify file contents
            with open(log_file) as f:
                lines = f.readlines()
            assert len(lines) == 1

            parsed = json.loads(lines[0])
            assert parsed["command"] == "echo hello"
            assert parsed["risk_level"] == "SAFE"

    def test_log_event_appends_to_existing_file(self):
        """log_event appends to existing log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            # Write multiple events
            for i in range(3):
                event = AuditEvent(
                    timestamp=f"2025-11-07T10:00:0{i}Z",
                    event_type="allow",
                    command=f"echo test{i}",
                    risk_level="SAFE",
                    violations=[],
                    decision="allow",
                    context={},
                )
                logger.log_event(event)

            # Verify all events written
            with open(log_file) as f:
                lines = f.readlines()
            assert len(lines) == 3

            for i, line in enumerate(lines):
                parsed = json.loads(line)
                assert parsed["command"] == f"echo test{i}"

    def test_log_event_fails_silently_on_io_error(self):
        """log_event doesn't raise on I/O errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a valid logger first
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            # Then make the file path invalid (simulate permission error)
            logger.log_file = Path("/dev/null/impossible/audit.jsonl")

            event = AuditEvent(
                timestamp="2025-11-07T10:00:00Z",
                event_type="allow",
                command="echo test",
                risk_level="SAFE",
                violations=[],
                decision="allow",
                context={},
            )

            # Should not raise - log_event fails silently
            logger.log_event(event)

    def test_log_validation_with_context(self):
        """log_validation writes validation event with context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            context = AuditContext(
                project_root="/home/user/project",
                current_dir="/home/user/project/src",
                git_branch="main",
                environment="production",
            )

            logger.log_validation(
                command="rm -rf /tmp/test",
                risk_level="HIGH",
                violations=["Recursive delete"],
                decision="block",
                execution_time_ms=45.2,
                context=context,
            )

            # Verify log contents
            with open(log_file) as f:
                line = f.readline()
            parsed = json.loads(line)

            assert parsed["event_type"] == "block"
            assert parsed["command"] == "rm -rf /tmp/test"
            assert parsed["risk_level"] == "HIGH"
            assert parsed["violations"] == ["Recursive delete"]
            assert parsed["decision"] == "block"
            assert parsed["execution_time_ms"] == 45.2
            assert parsed["context"]["project_root"] == "/home/user/project"
            assert parsed["context"]["git_branch"] == "main"
            assert parsed["context"]["environment"] == "production"

    def test_log_validation_without_context(self):
        """log_validation works without explicit context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            logger.log_validation(
                command="git status",
                risk_level="SAFE",
                violations=[],
                decision="allow",
            )

            # Verify log contents
            with open(log_file) as f:
                line = f.readline()
            parsed = json.loads(line)

            assert parsed["command"] == "git status"
            assert parsed["context"]["environment"] == "development"
            assert parsed["execution_time_ms"] is None

    def test_log_validation_event_type_mapping(self):
        """log_validation maps decision to correct event_type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            # Test allow decision
            logger.log_validation(
                command="echo hello",
                risk_level="SAFE",
                violations=[],
                decision="allow",
            )

            # Test block decision
            logger.log_validation(
                command="rm -rf /",
                risk_level="BLOCKED",
                violations=["Dangerous"],
                decision="block",
            )

            # Test warn decision
            logger.log_validation(
                command="chmod 777 file",
                risk_level="MEDIUM",
                violations=["Insecure permissions"],
                decision="warn",
            )

            # Verify event types
            with open(log_file) as f:
                lines = f.readlines()

            events = [json.loads(line) for line in lines]
            assert events[0]["event_type"] == "allow"
            assert events[1]["event_type"] == "block"
            assert events[2]["event_type"] == "warn"

    def test_log_validation_with_multiple_violations(self):
        """log_validation handles multiple violations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            logger.log_validation(
                command="rm -rf /tmp && curl http://evil.com",
                risk_level="BLOCKED",
                violations=[
                    "Recursive delete",
                    "Network request",
                    "Command chaining",
                ],
                decision="block",
            )

            with open(log_file) as f:
                line = f.readline()
            parsed = json.loads(line)

            assert len(parsed["violations"]) == 3
            assert "Recursive delete" in parsed["violations"]
            assert "Network request" in parsed["violations"]


class TestGetAuditLogger:
    """Test get_audit_logger singleton."""

    def test_get_audit_logger_returns_singleton(self):
        """get_audit_logger returns same instance."""
        logger1 = get_audit_logger()
        logger2 = get_audit_logger()
        assert logger1 is logger2

    def test_get_audit_logger_creates_instance(self):
        """get_audit_logger creates AuditLogger instance."""
        logger = get_audit_logger()
        assert isinstance(logger, AuditLogger)


class TestAuditLoggerThreadSafety:
    """Test thread safety properties."""

    def test_concurrent_writes_dont_corrupt_log(self):
        """Multiple concurrent writes create valid JSONL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_file=log_file)

            def write_events(thread_id: int, count: int):
                for i in range(count):
                    logger.log_validation(
                        command=f"echo thread{thread_id}_event{i}",
                        risk_level="SAFE",
                        violations=[],
                        decision="allow",
                    )

            # Create multiple threads writing concurrently
            threads = []
            for tid in range(5):
                t = threading.Thread(target=write_events, args=(tid, 10))
                threads.append(t)
                t.start()

            # Wait for all threads
            for t in threads:
                t.join()

            # Verify log integrity
            with open(log_file) as f:
                lines = f.readlines()

            # Should have 50 total events (5 threads × 10 events)
            assert len(lines) == 50

            # Verify all lines are valid JSON
            for line in lines:
                parsed = json.loads(line)
                assert "command" in parsed
                assert parsed["command"].startswith("echo thread")
