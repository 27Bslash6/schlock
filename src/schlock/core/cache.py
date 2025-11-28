"""LRU cache for validation results.

This module provides caching for validation results to avoid re-parsing
and re-validating repeated commands. Uses LRU eviction policy.
"""

import threading
from collections import OrderedDict
from typing import Any, Optional


class ValidationCache:
    """Thread-safe LRU cache for validation results.

    Caches validation results with least-recently-used eviction policy.
    Cache keys are exact command strings (no normalization).

    Example:
        >>> cache = ValidationCache(max_size=100)
        >>> result = ValidationResult(...)
        >>> cache.set("git status", result)
        >>> cached = cache.get("git status")
        >>> cached == result  # True
    """

    def __init__(self, max_size: int = 1000):
        """Initialize ValidationCache with configurable size.

        Args:
            max_size: Maximum number of entries to cache (must be > 0)

        Raises:
            ValueError: If max_size is not positive
        """
        if max_size <= 0:
            raise ValueError(f"max_size must be positive, got {max_size}")

        self.max_size = max_size
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, command: str) -> Optional[Any]:
        """Retrieve cached validation result.

        Moves accessed item to end (marks as recently used).

        Args:
            command: Exact command string (cache key)

        Returns:
            Cached ValidationResult if found, None otherwise

        Example:
            >>> result = cache.get("git status")
            >>> if result:
            ...     print("Cache hit!")
        """
        with self._lock:
            if command in self._cache:
                # Move to end (mark as recently used)
                self._cache.move_to_end(command)
                return self._cache[command]
            return None

    def set(self, command: str, result: Any) -> None:
        """Store validation result in cache.

        Implements LRU eviction when cache is full.

        SECURITY: Atomic operation - check and update happen together under lock
        to prevent TOCTOU race conditions.

        Args:
            command: Exact command string (cache key)
            result: ValidationResult to cache

        Example:
            >>> cache.set("git status", result)
        """
        with self._lock:
            # Atomic update: If key exists, move to end. Otherwise, check capacity and evict if needed.
            # This prevents race conditions between check and insert.
            if command in self._cache:
                # Move to end (mark as recently used)
                self._cache.move_to_end(command)
                # Update value
                self._cache[command] = result
            else:
                # Evict oldest if at capacity BEFORE inserting new entry
                if len(self._cache) >= self.max_size:
                    self._cache.popitem(last=False)  # Remove oldest (first)
                # Now insert new entry
                self._cache[command] = result

    def clear(self) -> None:
        """Clear all cached entries.

        Example:
            >>> cache.clear()
            >>> cache.get("git status")  # None
        """
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return current number of cached entries.

        Returns:
            Number of entries in cache

        Example:
            >>> cache.size()
            42
        """
        with self._lock:
            return len(self._cache)
