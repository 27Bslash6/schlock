"""Tests for audit logging module."""

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path

import pytest
from platformdirs import user_data_dir

from schlock.integrations.audit import (
    AuditContext,
    AuditEvent,
    AuditLogger,
    get_audit_logger,
    get_null_device,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolated_user_settings(tmp_path, monkeypatch):
    """Give every test an empty HOME, so a developer's own ~/.claude/settings.json cannot steer it."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("SCHLOCK_AUDIT_LOG", raising=False)
    return home


def _user_settings(home: Path, value) -> Path:
    """Write `value` as SCHLOCK_AUDIT_LOG into the `env` block of `home`/.claude/settings.json."""
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"SCHLOCK_AUDIT_LOG": value}}), encoding="utf-8")
    return settings


def _default_log_dir() -> Path:
    return Path(user_data_dir("schlock", "27b.io"))


def _default_log_file() -> Path:
    return _default_log_dir() / f"audit-{datetime.now().strftime('%Y-%m-%d')}.jsonl"


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

    def test_logger_respects_user_settings_file(self, tmp_path):
        """A `.jsonl` SCHLOCK_AUDIT_LOG in the user settings `env` block is used as the log file."""
        custom_path = tmp_path / "custom_audit.jsonl"
        _user_settings(Path.home(), str(custom_path))
        assert AuditLogger().log_file == custom_path

    def test_logger_respects_user_settings_directory(self, tmp_path):
        """Any other value is a directory that gets a timestamped file."""
        _user_settings(Path.home(), str(tmp_path))
        today = datetime.now().strftime("%Y-%m-%d")
        assert AuditLogger().log_file == tmp_path / f"audit-{today}.jsonl"

    def test_logger_user_settings_null_device(self, tmp_path, monkeypatch):
        """The platform null device disables logging: nothing is written anywhere."""
        # Windows platformdirs asks the shell API, not HOME or LOCALAPPDATA, so point the fallback here instead.
        default_dir = tmp_path / "default"
        monkeypatch.setattr("schlock.integrations.audit.user_data_dir", lambda *_: str(default_dir))
        null_dev = get_null_device()
        _user_settings(Path.home(), null_dev)
        logger = AuditLogger()
        assert str(logger.log_file) == null_dev
        logger.log_event(
            AuditEvent(
                timestamp="t", event_type="allow", command="ls", risk_level="SAFE", violations=[], decision="allow", context={}
            )
        )
        assert not default_dir.exists()

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


class TestAuditLogPathProvenance:
    """SCHLOCK_AUDIT_LOG comes from the user's own settings file, never the process environment.

    Claude Code applies a checkout's .claude/settings.json `env` block to the hook's environment,
    so an environment value would let a checkout pick the file every audit line is appended to.
    """

    def test_process_environment_alone_is_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SCHLOCK_AUDIT_LOG", str(tmp_path / "project.jsonl"))
        assert AuditLogger().log_file == _default_log_file()

    def test_user_settings_win_over_process_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SCHLOCK_AUDIT_LOG", str(tmp_path / "project.jsonl"))
        _user_settings(Path.home(), str(tmp_path / "user.jsonl"))
        assert AuditLogger().log_file == tmp_path / "user.jsonl"

    def test_user_settings_value_expands_home(self):
        _user_settings(Path.home(), "~/logs/audit.jsonl")
        assert AuditLogger().log_file == Path.home() / "logs" / "audit.jsonl"

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(b"{not json", id="malformed"),
            pytest.param(b"\xff\xfe", id="not-utf8"),
            pytest.param(b"[1, 2]", id="non-object"),
            pytest.param(b'{"env": ["SCHLOCK_AUDIT_LOG"]}', id="env-not-object"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": 1}}', id="non-string"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": null}}', id="null"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": ""}}', id="empty"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": "~no-such-user-zz/a.jsonl"}}', id="unknown-user"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": "/x\\u0000y"}}', id="nul-character"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": "/tmp/\\ud800"}}', id="lone-surrogate"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": "audit.jsonl"}}', id="relative-file"),
            pytest.param(b'{"env": {"SCHLOCK_AUDIT_LOG": "logs"}}', id="relative-directory"),
        ],
    )
    def test_unusable_user_settings_fall_back_to_default(self, content):
        settings = Path.home() / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(content)
        assert AuditLogger().log_file == _default_log_file()

    @pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, non-root")
    def test_unreadable_user_settings_fall_back_to_default(self):
        settings = _user_settings(Path.home(), "/elsewhere/audit.jsonl")
        settings.chmod(0)
        try:
            assert AuditLogger().log_file == _default_log_file()
        finally:
            settings.chmod(0o600)

    @pytest.mark.skipif(sys.platform == "win32", reason="NUL is the null device on Windows")
    def test_windows_null_device_name_is_not_a_relative_file_elsewhere(self):
        # Outside Windows "NUL" is a relative path, so it would name a file in the open checkout.
        _user_settings(Path.home(), "NUL")
        assert AuditLogger().log_file == _default_log_file()

    def test_ignored_value_is_reported(self, caplog):
        _user_settings(Path.home(), "relative/audit.jsonl")
        with caplog.at_level(logging.WARNING, logger="schlock.integrations.audit"):
            AuditLogger()
        assert any("relative/audit.jsonl" in r.getMessage() for r in caplog.records)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks and POSIX HOME")
class TestProjectScopedAuditLogThroughTheHook:
    """The real hook, as a subprocess, with SCHLOCK_AUDIT_LOG delivered the way a project delivers it."""

    COMMAND = "rm -rf / $(touch M)"

    def _run_hook(self, home: Path, project: Path, audit_env: str) -> dict:
        env = {"HOME": str(home), "PATH": os.environ["PATH"], "SCHLOCK_AUDIT_LOG": audit_env}
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "hooks" / "pre_tool_use.py")],
            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": self.COMMAND}}),
            capture_output=True,
            text=True,
            cwd=project,
            env=env,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)["hookSpecificOutput"]

    def _assert_audited_at_default(self, home: Path) -> None:
        logs = list(_default_log_dir().glob("audit-*.jsonl"))
        assert len(logs) == 1
        assert self.COMMAND in logs[0].read_text(encoding="utf-8")

    def test_symlinked_audit_path_writes_nothing_to_the_target(self, tmp_path, _isolated_user_settings):
        home = _isolated_user_settings
        target = home / ".bashrc"
        target.write_bytes(b"# rc\n")
        project = tmp_path / "project"
        project.mkdir()
        (project / "x.jsonl").symlink_to(target)

        out = self._run_hook(home, project, "x.jsonl")

        assert out["permissionDecision"] == "deny"
        assert target.read_bytes() == b"# rc\n"
        self._assert_audited_at_default(home)

    def test_directory_audit_path_creates_and_writes_nothing(self, tmp_path, _isolated_user_settings):
        home = _isolated_user_settings
        sourced_dir = home / ".bashrc.d"
        project = tmp_path / "project"
        project.mkdir()

        out = self._run_hook(home, project, str(sourced_dir))

        assert out["permissionDecision"] == "deny"
        assert not sourced_dir.exists()
        self._assert_audited_at_default(home)

    def test_user_settings_value_is_honoured(self, tmp_path, _isolated_user_settings):
        home = _isolated_user_settings
        user_log = tmp_path / "user-audit.jsonl"
        _user_settings(home, str(user_log))
        project = tmp_path / "project"
        project.mkdir()

        self._run_hook(home, project, str(tmp_path / "ignored.jsonl"))

        assert self.COMMAND in user_log.read_text(encoding="utf-8")
        assert not (tmp_path / "ignored.jsonl").exists()


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
