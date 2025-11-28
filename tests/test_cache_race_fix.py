"""Test fix for Bug #2: Cache Race Condition.

Verify that cache.set() handles concurrent updates atomically without TOCTOU races.
"""

import threading
import time

from schlock.core.cache import ValidationCache


class TestCacheRaceFix:
    """Test that cache race condition is fixed."""

    def test_concurrent_set_different_keys(self):
        """Concurrent sets with different keys should not corrupt cache."""
        cache = ValidationCache(max_size=100)
        errors = []

        def worker(key, value, count=100):
            try:
                for i in range(count):
                    cache.set(f"{key}_{i}", value)
            except Exception as e:
                errors.append(e)

        # Run multiple threads setting different keys
        threads = [threading.Thread(target=worker, args=(f"thread{i}", f"value{i}")) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no errors
        assert not errors, f"Concurrent sets caused errors: {errors}"

        # Cache should have entries (might be less than 1000 due to max_size)
        assert cache.size() > 0

    def test_concurrent_set_same_key(self):
        """Concurrent sets with same key should not corrupt cache."""
        cache = ValidationCache(max_size=100)
        errors = []
        key = "shared_key"

        def worker(thread_id, count=100):
            try:
                for i in range(count):
                    cache.set(key, f"thread{thread_id}_value{i}")
                    # Also read to increase contention
                    cache.get(key)
            except Exception as e:
                errors.append(e)

        # Run multiple threads updating same key
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no errors
        assert not errors, f"Concurrent sets on same key caused errors: {errors}"

        # Key should exist with some value
        result = cache.get(key)
        assert result is not None
        assert result.startswith("thread")

    def test_concurrent_set_at_capacity(self):
        """Concurrent sets at capacity should not corrupt cache."""
        max_size = 10
        cache = ValidationCache(max_size=max_size)
        errors = []

        # Pre-fill cache to capacity
        for i in range(max_size):
            cache.set(f"initial_{i}", f"value_{i}")

        assert cache.size() == max_size

        def worker(thread_id, count=50):
            try:
                for i in range(count):
                    # Each set might trigger eviction
                    cache.set(f"thread{thread_id}_{i}", f"value{i}")
            except Exception as e:
                errors.append(e)

        # Run multiple threads, each adding entries (will cause evictions)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no errors
        assert not errors, f"Concurrent sets at capacity caused errors: {errors}"

        # Cache should still respect max_size
        assert cache.size() <= max_size, f"Cache exceeded max_size: {cache.size()} > {max_size}"

    def test_toctou_race_prevented(self):
        """TOCTOU race between check and insert should not occur."""
        max_size = 2
        cache = ValidationCache(max_size=max_size)

        # Pre-fill to capacity
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert cache.size() == max_size

        errors = []
        results = []

        def racer(thread_id):
            """Try to exploit TOCTOU by inserting at exact same moment."""
            try:
                # Wait for all threads to be ready
                time.sleep(0.001)
                # All threads try to insert at once
                cache.set(f"race_key_{thread_id}", f"race_value_{thread_id}")
                results.append(thread_id)
            except Exception as e:
                errors.append(e)

        # Launch multiple threads simultaneously
        threads = [threading.Thread(target=racer, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should occur
        assert not errors, f"TOCTOU race caused errors: {errors}"

        # Cache should still respect max_size (CRITICAL)
        current_size = cache.size()
        assert current_size <= max_size, f"TOCTOU race allowed cache overflow: {current_size} > {max_size}"

        # All threads should have succeeded (recorded in results)
        assert len(results) == 10, "Some threads failed silently"

    def test_atomic_update_existing_key(self):
        """Updating existing key should be atomic."""
        cache = ValidationCache(max_size=10)
        cache.set("key", "initial")

        errors = []

        def updater(thread_id, count=100):
            try:
                for i in range(count):
                    cache.set("key", f"thread{thread_id}_update{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=updater, args=(i,)) for i in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent updates caused errors: {errors}"

        # Should still have exactly one entry for this key
        assert cache.size() <= 10
        result = cache.get("key")
        assert result is not None
