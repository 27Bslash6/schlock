"""Tests for rule coverage analyzer."""

import sys
from pathlib import Path

# Add tests directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent))

from rule_coverage import (
    Rule,
    analyze_coverage,
    find_rule_tests,
    get_project_root,
    load_all_rules,
)


class TestLoadRules:
    """Test rule loading."""

    def test_load_all_rules_returns_list(self):
        """Test that load_all_rules returns a list."""
        rules = load_all_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_rules_have_required_fields(self):
        """Test that all rules have required fields."""
        rules = load_all_rules()
        for rule in rules:
            assert rule.name, f"Rule missing name: {rule}"
            assert rule.risk_level, f"Rule {rule.name} missing risk_level"
            assert rule.patterns, f"Rule {rule.name} has no patterns"
            assert rule.category, f"Rule {rule.name} missing category"

    def test_rules_have_valid_risk_levels(self):
        """Test that all rules have valid risk levels."""
        valid_levels = {"SAFE", "LOW", "MEDIUM", "HIGH", "BLOCKED"}
        rules = load_all_rules()
        for rule in rules:
            assert rule.risk_level in valid_levels, f"Rule {rule.name} has invalid risk level: {rule.risk_level}"


class TestFindRuleTests:
    """Test rule test finding."""

    def test_find_tests_for_rule_by_name(self, tmp_path):
        """Test finding tests by rule name mention."""
        rule = Rule(
            name="test_rule_xyz",
            description="Test rule",
            risk_level="HIGH",
            patterns=["pattern1", "pattern2"],
            category="test",
            file_path="test.yaml",
        )

        # Create test file that mentions the rule
        test_file = tmp_path / "test_example.py"
        test_file.write_text("def test_test_rule_xyz(): pass")

        coverage = find_rule_tests(rule, [test_file])
        assert coverage.test_files
        assert "test_example.py" in coverage.test_files

    def test_no_tests_found(self, tmp_path):
        """Test when no tests are found."""
        rule = Rule(
            name="unique_rule_name_9999",
            description="Test rule",
            risk_level="HIGH",
            patterns=["very_specific_pattern"],
            category="test",
            file_path="test.yaml",
        )

        # Create test file that doesn't mention the rule
        test_file = tmp_path / "test_other.py"
        test_file.write_text("def test_something_else(): pass")

        coverage = find_rule_tests(rule, [test_file])
        assert not coverage.test_files


class TestAnalyzeCoverage:
    """Test coverage analysis."""

    def test_analyze_returns_dict(self):
        """Test that analyze_coverage returns a dict."""
        coverage = analyze_coverage()
        assert isinstance(coverage, dict)
        assert len(coverage) > 0

    def test_coverage_map_has_all_rules(self):
        """Test that coverage map includes all rules."""
        rules = load_all_rules()
        coverage = analyze_coverage()

        rule_names = {r.name for r in rules}
        coverage_names = set(coverage.keys())

        assert rule_names == coverage_names, f"Missing rules: {rule_names - coverage_names}"


class TestCLI:
    """Test CLI functionality."""

    def test_cli_runs(self):
        """Test CLI runs without error."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/rule_coverage.py"],
            check=False,
            capture_output=True,
            text=True,
        )
        # Should produce output
        assert "RULE TEST COVERAGE REPORT" in result.stdout

    def test_cli_verbose_flag(self):
        """Test CLI verbose flag."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/rule_coverage.py", "--verbose"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode in (0, 1)  # 1 if missing critical coverage

    def test_cli_missing_only_flag(self):
        """Test CLI missing-only flag."""
        import subprocess  # noqa: PLC0415 - Test isolation

        result = subprocess.run(
            ["python", "tests/rule_coverage.py", "--missing-only"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode in (0, 1)


class TestProjectRoot:
    """Test project root detection."""

    def test_get_project_root(self):
        """Test project root is detected correctly."""
        root = get_project_root()
        assert root.exists()
        assert (root / "data" / "rules").exists()
        assert (root / "tests").exists()
