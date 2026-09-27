"""Performance benchmarks for schlock validation pipeline.

Uses pytest-benchmark for statistically sound measurements:
- Multiple iterations with warmup
- Statistical analysis (mean, stddev, outlier detection)
- GIL-safe timing via time.perf_counter
- Configurable rounds and iterations

Run with: pytest tests/test_performance.py -v --benchmark-only

The whole module is marked `slow`, so the local fast gate (`-m "not slow"`)
skips it. Run it with `pytest tests/test_performance.py` or `make test`.
"""

import os

import pytest

from schlock.core.cache import ValidationCache
from schlock.core.rules import RuleEngine
from schlock.core.validator import validate_command

# Check if pytest-benchmark is available
try:
    import pytest_benchmark  # noqa: F401

    HAS_BENCHMARK = True
except ImportError:
    HAS_BENCHMARK = False

# Skip decorator for benchmark tests
requires_benchmark = pytest.mark.skipif(
    not HAS_BENCHMARK,
    reason="pytest-benchmark not installed (pip install pytest-benchmark)",
)

pytestmark = pytest.mark.slow


def stats_median_ms(benchmark) -> float:
    """Extract median from benchmark stats in milliseconds.

    pytest-benchmark structure:
    - benchmark.stats is Metadata object
    - benchmark.stats.stats is the actual Stats object with median
    - stats.stats.median is in seconds
    """
    return benchmark.stats.stats.median * 1000


# An absolute millisecond budget only means something on a machine whose speed we
# control, and a shared CI runner is not one. `test_rule_matching` measured 0.22ms
# against its 0.2ms budget on Python 3.9 and turned main red while the *same commit*
# passed the identical assertion in its own PR run minutes earlier -- the runner
# moved, the code did not. The benchmarks still execute in CI, so a crash in the
# measured code still fails the build and the timing table still lands in the log;
# only the verdict on the clock is withheld, because there it grades the runner.
_IN_CI = os.environ.get("CI", "").lower() == "true" or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"


def assert_median_under(benchmark, budget_ms: float, what: str) -> None:
    """Fail when `what`'s median misses its budget -- outside CI only.

    The median is read either way, so a change in pytest-benchmark's stats shape
    still breaks the build in CI rather than silently reporting nothing.
    """
    median_ms = stats_median_ms(benchmark)
    if _IN_CI:
        return
    assert median_ms < budget_ms, f"{what} median too slow: {median_ms:.4f}ms (budget: {budget_ms}ms)"


@requires_benchmark
class TestCachePerformance:
    """Benchmark cache operations with statistical rigor."""

    @pytest.fixture
    def populated_cache(self):
        """Pre-populated cache for lookup benchmarks."""
        cache = ValidationCache(max_size=1000)
        for i in range(1000):
            cache.set(f"cmd{i}", {"result": i})
        return cache

    def test_cache_lookup_performance(self, benchmark, populated_cache):
        """Cache hits should be sub-millisecond.

        Target: median < 0.05ms (50μs) - tightened after caching optimization, with CI headroom
        """
        result = benchmark(populated_cache.get, "cmd500")
        assert result is not None

        assert_median_under(benchmark, 0.05, "Cache lookup")

    def test_cache_set_performance(self, benchmark):
        """Cache writes should be sub-millisecond."""
        cache = ValidationCache(max_size=1000)
        counter = [0]

        def cache_write():
            cache.set(f"cmd{counter[0]}", {"result": counter[0]})
            counter[0] += 1

        benchmark(cache_write)

        assert_median_under(benchmark, 0.05, "Cache write")

    @pytest.mark.parametrize("cache_size", [100, 1000, 10000])
    def test_cache_scaling(self, benchmark, cache_size):
        """Cache performance should scale sub-linearly with size."""
        cache = ValidationCache(max_size=cache_size)
        for i in range(cache_size):
            cache.set(f"cmd{i}", {"result": i})

        # Lookup from middle of cache
        key = f"cmd{cache_size // 2}"
        result = benchmark(cache.get, key)
        assert result is not None

        # LRU dict is O(1), so even 10k stays flat.
        assert_median_under(benchmark, 0.05, f"Cache size {cache_size}")


@requires_benchmark
class TestParserPerformance:
    """Benchmark bashlex parser performance."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo hello",
            "ls -la",
            "git status",
            "cat file.txt",
            "pwd",
        ],
        ids=lambda x: x[:20],
    )
    def test_simple_command_parsing(self, benchmark, parser, cmd):
        """Simple commands should parse in < 0.25ms median."""
        benchmark(parser.parse, cmd)

        assert_median_under(benchmark, 0.25, f"Parser on {cmd!r}")

    @pytest.mark.parametrize(
        "cmd",
        [
            "find . -name '*.py' | xargs grep pattern",
            "ps aux | grep python | awk '{print $2}'",
            "cat file.txt | grep pattern | sort | uniq -c",
        ],
        ids=["find_pipe", "ps_pipe", "cat_pipe"],
    )
    def test_complex_command_parsing(self, benchmark, parser, cmd):
        """Complex pipelines should parse in < 0.75ms median."""
        benchmark(parser.parse, cmd)

        assert_median_under(benchmark, 0.75, f"Parser on complex {cmd!r}")


@requires_benchmark
class TestRuleEnginePerformance:
    """Benchmark rule matching performance."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "git status",
            "rm -rf /",
            "chmod 777 file",
            "docker run image",
            "kubectl delete pod",
        ],
        ids=lambda x: x.split()[0],
    )
    def test_rule_matching(self, benchmark, safety_rules_path, cmd):
        """Rule matching should complete in < 0.2ms median."""
        engine = RuleEngine(safety_rules_path)
        benchmark(engine.match_command, cmd)

        assert_median_under(benchmark, 0.2, f"Rule matching on {cmd!r}")


@requires_benchmark
class TestEndToEndPerformance:
    """Benchmark full validation pipeline."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo hello",
            "git status",
            "ls -la /tmp",
            "cat /etc/hosts",
        ],
        ids=lambda x: x.split()[0],
    )
    def test_validation_pipeline(self, benchmark, safety_rules_path, cmd):
        """Full validation should complete in < 0.01ms median (warm/cached)."""
        # Warmup - run once to populate caches, load modules
        validate_command(cmd, config_path=safety_rules_path)

        # Benchmark warm path
        benchmark(validate_command, cmd, config_path=safety_rules_path)

        # Warm validation (cached) should be very fast after caching optimization.
        assert_median_under(benchmark, 0.01, f"Warm validation of {cmd!r}")

    def test_cold_validation_performance(self, benchmark, safety_rules_path):
        """Cold validation (uncached) should complete in < 75ms median."""
        counter = [0]

        def cold_validate():
            # Use unique command each time to avoid cache
            cmd = f"echo unique_test_{counter[0]}"
            counter[0] += 1
            return validate_command(cmd, config_path=safety_rules_path)

        benchmark(cold_validate)

        # Cold path includes parsing + rule matching; ~28ms typical.
        assert_median_under(benchmark, 75.0, "Cold validation")

    def test_cached_validation_performance(self, benchmark, safety_rules_path):
        """Cached validation should complete in < 0.01ms median."""
        cmd = "git status"
        # Warmup - populate cache
        validate_command(cmd, config_path=safety_rules_path)

        benchmark(validate_command, cmd, config_path=safety_rules_path)

        assert_median_under(benchmark, 0.01, "Cached validation")


@requires_benchmark
class TestThroughput:
    """Benchmark throughput for bulk operations."""

    def test_bulk_validation_throughput(self, benchmark, safety_rules_path):
        """Measure validations per second.

        Target: > 1000 validations/sec (tightened after caching optimization)
        """
        commands = [f"echo test_{i}" for i in range(100)]

        def validate_batch():
            for cmd in commands:
                validate_command(cmd, config_path=safety_rules_path)

        benchmark(validate_batch)

        # Calculate throughput from median time for 100 commands
        median_sec = benchmark.stats.stats.median
        throughput = 100 / median_sec if median_sec > 0 else float("inf")

        # Log throughput for visibility
        print(f"\nThroughput: {throughput:.0f} validations/sec")

        # ~2600/sec typical. Withheld in CI for the same reason as the median
        # budgets above: on a shared runner this grades the runner.
        if not _IN_CI:
            assert throughput > 1000, f"Throughput too low: {throughput:.0f} validations/sec"


class TestMemoryEfficiency:
    """Verify memory efficiency of caching."""

    def test_cache_eviction_prevents_unbounded_growth(self):
        """Cache respects max_size limit."""
        cache = ValidationCache(max_size=100)

        # Add 1000 entries
        for i in range(1000):
            cache.set(f"cmd{i}", {"result": i})

        # Verify size stayed at limit
        assert cache.size() == 100, f"Cache grew beyond limit: {cache.size()}"

    def test_cache_lru_behavior(self):
        """Least recently used entries are evicted."""
        cache = ValidationCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        # Access 'a' to make it recently used
        cache.get("a")

        # Add new entry - should evict 'b' (oldest non-accessed)
        cache.set("d", 4)

        assert cache.get("a") is not None
        assert cache.get("b") is None  # Evicted
        assert cache.get("c") is not None
        assert cache.get("d") is not None
