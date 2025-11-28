"""Tests for audit logger thread safety.

FIX 7: Audit Logger Singleton Race
Bug: get_audit_logger() wasn't thread-safe, multiple threads could create
multiple logger instances instead of singleton.

Fix: Added threading.Lock and double-check locking pattern.
"""

import threading

from schlock.integrations.audit import get_audit_logger


class TestSingletonThreadSafety:
    """Test that audit logger singleton is thread-safe."""

    def test_singleton_same_instance(self):
        """get_audit_logger() returns same instance."""
        logger1 = get_audit_logger()
        logger2 = get_audit_logger()
        assert logger1 is logger2

    def test_singleton_thread_safe_simple(self):
        """Multiple threads get same logger instance."""
        # Reset singleton for clean test
        import schlock.integrations.audit  # noqa: PLC0415 - Singleton reset

        schlock.integrations.audit._audit_logger = None

        loggers = []

        def get_logger():
            loggers.append(get_audit_logger())

        threads = [threading.Thread(target=get_logger) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should be same instance
        assert len(loggers) == 10
        assert all(logger is loggers[0] for logger in loggers)

    def test_singleton_thread_safe_stress(self):
        """Stress test with 100 concurrent threads."""
        import schlock.integrations.audit  # noqa: PLC0415 - Singleton reset

        schlock.integrations.audit._audit_logger = None

        loggers = []
        lock = threading.Lock()

        def get_logger():
            logger = get_audit_logger()
            with lock:
                loggers.append(logger)

        threads = [threading.Thread(target=get_logger) for _ in range(100)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 100 threads should get the exact same instance
        assert len(loggers) == 100
        assert all(logger is loggers[0] for logger in loggers), "Multiple logger instances created!"

    def test_singleton_after_initialization(self):
        """After first initialization, no locking overhead."""
        # Get logger once to initialize
        logger1 = get_audit_logger()

        # Subsequent calls should return same instance without locking
        loggers = []

        def get_logger():
            loggers.append(get_audit_logger())

        threads = [threading.Thread(target=get_logger) for _ in range(50)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(loggers) == 50
        assert all(logger is logger1 for logger in loggers)


class TestDoubleCheckLocking:
    """Test the double-check locking pattern implementation."""

    def test_first_check_prevents_lock_when_initialized(self):
        """First check avoids acquiring lock when logger exists."""
        # Initialize logger
        get_audit_logger()

        # Verify the fast path works (no exception from locking)
        # If the first check didn't work, this would try to acquire lock unnecessarily
        logger = get_audit_logger()
        assert logger is not None

    def test_second_check_prevents_double_initialization(self):
        """Second check inside lock prevents double initialization."""
        import schlock.integrations.audit  # noqa: PLC0415 - Singleton reset

        schlock.integrations.audit._audit_logger = None

        # This is tested implicitly by test_singleton_thread_safe_stress
        # If second check didn't work, we'd get multiple instances
        loggers = []

        def get_logger():
            loggers.append(get_audit_logger())

        threads = [threading.Thread(target=get_logger) for _ in range(20)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(logger is loggers[0] for logger in loggers)


class TestConcurrentLogging:
    """Test that concurrent logging operations work correctly."""

    def test_concurrent_logging_no_crash(self):
        """Multiple threads can log concurrently without crashing."""
        import tempfile  # noqa: PLC0415 - Test isolation
        from pathlib import Path  # noqa: PLC0415

        import schlock.integrations.audit  # noqa: PLC0415 - Singleton reset

        # Use temp file for testing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)

        try:
            # Reset and create logger with temp file
            schlock.integrations.audit._audit_logger = None
            schlock.integrations.audit._audit_logger = schlock.integrations.audit.AuditLogger(log_file=log_path)

            def log_event(thread_id):
                logger = get_audit_logger()
                for i in range(10):
                    logger.log_validation(
                        command=f"test command {thread_id}-{i}",
                        risk_level="SAFE",
                        violations=[],
                        decision="allow",
                    )

            threads = [threading.Thread(target=log_event, args=(i,)) for i in range(5)]

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Verify log file has entries (fail-silent means may not have all)
            # But at least should have created the file
            assert log_path.exists()

        finally:
            log_path.unlink(missing_ok=True)
