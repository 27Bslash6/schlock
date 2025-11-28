"""Tests for security benchmark suite."""

import sys
from pathlib import Path

# Add tests directory to path for benchmark import
sys.path.insert(0, str(Path(__file__).parent))

from benchmark import (
    BENCHMARK_CASES,
    BenchmarkCase,
    BenchmarkResult,
    CategoryResult,
    run_all_benchmarks,
    run_benchmark,
)
from schlock.core.rules import RiskLevel


class TestBenchmarkCase:
    """Test BenchmarkCase structure."""

    def test_all_cases_have_required_fields(self):
        """All benchmark cases should have required fields."""
        for case in BENCHMARK_CASES:
            assert case.name, "Case missing name"
            assert case.command, "Case missing command"
            assert case.category, "Case missing category"
            assert isinstance(case.expected_blocked, bool)

    def test_cases_have_unique_names(self):
        """All case names should be unique."""
        names = [c.name for c in BENCHMARK_CASES]
        assert len(names) == len(set(names)), "Duplicate case names found"

    def test_minimum_case_count(self):
        """Should have a reasonable number of test cases."""
        assert len(BENCHMARK_CASES) >= 20, "Need at least 20 benchmark cases"


class TestRunBenchmark:
    """Test individual benchmark execution."""

    def test_run_benchmark_returns_result(self):
        """run_benchmark should return BenchmarkResult."""
        case = BenchmarkCase(
            name="test_case",
            command="echo hello",
            expected_blocked=False,
            category="test",
        )
        result = run_benchmark(case)
        assert isinstance(result, BenchmarkResult)
        assert result.case == case
        assert isinstance(result.risk_level, RiskLevel)
        assert result.execution_time_ms >= 0

    def test_run_benchmark_detects_dangerous(self):
        """Dangerous commands should be detected."""
        case = BenchmarkCase(
            name="test_dangerous",
            command="rm -rf /",
            expected_blocked=True,
            category="test",
        )
        result = run_benchmark(case)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED)
        assert result.passed

    def test_run_benchmark_allows_safe(self):
        """Safe commands should be allowed."""
        case = BenchmarkCase(
            name="test_safe",
            command="ls -la",
            expected_blocked=False,
            category="test",
        )
        result = run_benchmark(case)
        assert result.risk_level in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM)
        assert result.passed


class TestRunAllBenchmarks:
    """Test full benchmark suite execution."""

    def test_run_all_returns_dict(self):
        """run_all_benchmarks should return dict of categories."""
        results = run_all_benchmarks()
        assert isinstance(results, dict)
        assert len(results) > 0

    def test_run_all_categories_have_results(self):
        """Each category should have results."""
        results = run_all_benchmarks()
        for cat_result in results.values():
            assert isinstance(cat_result, CategoryResult)
            assert cat_result.total > 0
            assert len(cat_result.results) == cat_result.total

    def test_filter_by_category(self):
        """Can filter benchmarks by category."""
        results = run_all_benchmarks(category_filter="legitimate")
        assert len(results) == 1
        assert "legitimate" in results

    def test_nonexistent_category_returns_empty(self):
        """Nonexistent category filter returns empty."""
        results = run_all_benchmarks(category_filter="nonexistent")
        assert len(results) == 0


class TestCategoryResult:
    """Test CategoryResult calculations."""

    def test_pass_rate_calculation(self):
        """Pass rate should be calculated correctly."""
        cat = CategoryResult(name="test", total=10, passed=8)
        assert cat.pass_rate == 80.0

    def test_pass_rate_empty(self):
        """Pass rate for empty category should be 0."""
        cat = CategoryResult(name="test", total=0, passed=0)
        assert cat.pass_rate == 0


class TestBenchmarkCLI:
    """Test CLI functionality."""

    def test_cli_runs(self):
        """CLI should run without error."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/benchmark.py"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert "SCHLOCK SECURITY BENCHMARK" in result.stdout

    def test_cli_list_categories(self):
        """CLI --list-categories should work."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/benchmark.py", "--list-categories"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Available categories:" in result.stdout

    def test_cli_verbose(self):
        """CLI --verbose should show details."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/benchmark.py", "--verbose", "-c", "legitimate"],
            check=False,
            capture_output=True,
            text=True,
        )
        # Should show individual test results
        assert "ls_simple" in result.stdout or "git_status" in result.stdout


class TestBenchmarkQuality:
    """Test benchmark quality metrics."""

    def test_detection_rate_above_threshold(self):
        """Detection rate should be above minimum threshold."""
        results = run_all_benchmarks()

        all_results = [r for cat in results.values() for r in cat.results]
        attack_cases = [r for r in all_results if r.case.expected_blocked]

        if attack_cases:
            detected = sum(1 for r in attack_cases if r.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED))
            rate = detected / len(attack_cases)
            # Should detect at least 80% of attacks
            assert rate >= 0.80, f"Detection rate {rate:.1%} below 80% threshold"

    def test_false_positive_rate_below_threshold(self):
        """False positive rate should be below maximum threshold."""
        results = run_all_benchmarks()

        all_results = [r for cat in results.values() for r in cat.results]
        legitimate_cases = [r for r in all_results if not r.case.expected_blocked]

        if legitimate_cases:
            false_positives = sum(1 for r in legitimate_cases if r.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED))
            rate = false_positives / len(legitimate_cases)
            # False positive rate should be under 10%
            assert rate <= 0.10, f"False positive rate {rate:.1%} above 10% threshold"
