"""Tests for ValidationCache."""

import time

import pytest

from schlock.core.cache import ValidationCache
from tests.conftest import MockResult


class TestValidationCache:
    """Test suite for ValidationCache."""

    def test_cache_hit(self, cache, mock_result):
        """Cache returns stored result."""
        result = mock_result("test")
        cache.set("cmd", result)
        assert cache.get("cmd") == result

    def test_cache_miss(self, cache):
        """Cache returns None for unknown key."""
        assert cache.get("unknown") is None

    @pytest.mark.parametrize(
        "operations",
        [
            [("a", "a"), ("b", "b"), ("c", "c"), ("d", "d")],
        ],
    )
    def test_cache_eviction_lru(self, operations):
        """LRU eviction when max_size reached."""
        cache = ValidationCache(max_size=3)
        for key, value in operations:
            cache.set(key, MockResult(value))
        # After 4 insertions with max_size=3, first entry should be evicted
        assert cache.get("a") is None
        assert cache.get("d") is not None

    def test_cache_clear(self, cache, mock_result):
        """Clear removes all entries."""
        cache.set("a", mock_result("a"))
        cache.clear()
        assert cache.size() == 0
        assert cache.get("a") is None

    def test_cache_performance(self):
        """Cache hits are fast (<100ms for 100 lookups)."""
        cache = ValidationCache(max_size=100)
        for i in range(100):
            cache.set(f"cmd{i}", MockResult(f"{i}"))

        start = time.perf_counter()
        for i in range(100):
            cache.get(f"cmd{i}")
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 100  # 100 lookups < 100ms

    def test_cache_invalid_max_size(self):
        """Raise ValueError for non-positive max_size."""
        with pytest.raises(ValueError) as exc:
            ValidationCache(max_size=0)
        assert "must be positive" in str(exc.value)

        with pytest.raises(ValueError) as exc:
            ValidationCache(max_size=-10)
        assert "must be positive" in str(exc.value)

    def test_cache_update_existing_entry(self, cache, mock_result):
        """Updating existing entry moves it to end (MRU)."""
        cache.set("a", mock_result("a1"))
        cache.set("b", mock_result("b"))
        cache.set("c", mock_result("c"))
        # Update 'a' - should move to end
        cache.set("a", mock_result("a2"))
        # Fill cache to trigger eviction
        cache = ValidationCache(max_size=3)
        cache.set("a", mock_result("a"))
        cache.set("b", mock_result("b"))
        cache.set("c", mock_result("c"))
        # Update 'a' again - moves to end
        cache.set("a", mock_result("a_updated"))
        # Add new entry - should evict 'b' (oldest)
        cache.set("d", mock_result("d"))
        assert cache.get("a") is not None  # Still present
        assert cache.get("b") is None  # Evicted
        assert cache.get("c") is not None
        assert cache.get("d") is not None
