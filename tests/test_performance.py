"""Performance benchmarks for schlock validation pipeline.

Uses pytest-benchmark for statistically sound measurements:
- Multiple iterations with warmup
- Statistical analysis (mean, stddev, outlier detection)
- GIL-safe timing via time.perf_counter
- Configurable rounds and iterations

Run with: pytest tests/test_performance.py -v --benchmark-only

Note: Tests gracefully skip when pytest-benchmark is not installed.
Install with: uv add --dev pytest-benchmark
"""

import pytest

from schlock.core.cache import ValidationCache
from schlock.core.rules import RuleEngine
from schlock.core.validator import validate_command

# Check if pytest-benchmark is available
try:
    import pytest_benchmark  # noqa: F401  # pyright: ignore[reportMissingImports]

    HAS_BENCHMARK = True
except ImportError:
    HAS_BENCHMARK = False

# Skip decorator for benchmark tests
requires_benchmark = pytest.mark.skipif(
    not HAS_BENCHMARK,
    reason="pytest-benchmark not installed (pip install pytest-benchmark)",
)


def stats_median_ms(benchmark) -> float:
    """Extract median from benchmark stats in milliseconds.

    pytest-benchmark structure:
    - benchmark.stats is Metadata object
    - benchmark.stats.stats is the actual Stats object with median
    - stats.stats.median is in seconds
    """
    return benchmark.stats.stats.median * 1000


def grade_median(benchmark, budget_ms: float, what: str) -> None:
    """Fail when `what`'s median misses its budget.

    Calibrate these on the CI runner, not on a dev box: it is the slowest machine
    they run on and the only one that gates merges. A dev-box calibration is what
    left three of them BELOW 1.0x there -- `test_rule_matching` turned main red at
    0.22ms against a 0.2ms budget while the same commit had passed the identical
    assertion minutes earlier in its own PR run. The runner moved; the code did not.

    The budgets raised for that reason carry ~3x over the median measured on the 3.9
    leg, so they read as "not 3x slower than this was measured" rather than as an
    absolute latency claim -- which is what a regression gate wants, and what
    survives a runner that varies: across two CI runs on identical code
    `rule_matching[kubectl]` moved 1.65x. The ones left alone had 7.6x-117x there
    already; only the families inside that noise band were touched.
    """
    median_ms = stats_median_ms(benchmark)
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

        grade_median(benchmark, 0.05, "Cache lookup")

    def test_cache_set_performance(self, benchmark):
        """Cache writes should be sub-millisecond."""
        cache = ValidationCache(max_size=1000)
        counter = [0]

        def cache_write():
            cache.set(f"cmd{counter[0]}", {"result": counter[0]})
            counter[0] += 1

        benchmark(cache_write)

        grade_median(benchmark, 0.05, "Cache write")

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
        grade_median(benchmark, 0.05, f"Cache size {cache_size}")


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
        """Simple commands parse in ~0.17ms median on the 3.9 CI leg."""
        benchmark(parser.parse, cmd)

        grade_median(benchmark, 0.6, f"Parser on {cmd!r}")

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
        """Complex pipelines parse in ~0.55ms median on the 3.9 CI leg."""
        benchmark(parser.parse, cmd)

        grade_median(benchmark, 2.0, f"Parser on complex {cmd!r}")


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
        """Rule matching completes in ~0.23ms median on the 3.9 CI leg."""
        engine = RuleEngine(safety_rules_path)
        benchmark(engine.match_command, cmd)

        grade_median(benchmark, 0.75, f"Rule matching on {cmd!r}")


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
        grade_median(benchmark, 0.01, f"Warm validation of {cmd!r}")

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
        grade_median(benchmark, 75.0, "Cold validation")

    def test_cached_validation_performance(self, benchmark, safety_rules_path):
        """Cached validation should complete in < 0.01ms median."""
        cmd = "git status"
        # Warmup - populate cache
        validate_command(cmd, config_path=safety_rules_path)

        benchmark(validate_command, cmd, config_path=safety_rules_path)

        grade_median(benchmark, 0.01, "Cached validation")


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

        # An absent or zero median divides into `inf` above and would sail straight
        # past the throughput assertion.
        assert median_sec > 0, "benchmark reported a zero median; throughput is meaningless"
        # ~2600/sec typical on CI, so this keeps ~2.6x.
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
