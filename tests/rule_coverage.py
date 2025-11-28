"""Rule test coverage analyzer.

Analyzes which security rules have test coverage and which don't.

Usage:
    python tests/rule_coverage.py
    python tests/rule_coverage.py --verbose
    python tests/rule_coverage.py --missing-only
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Add project root to path for vendored imports
sys.path.insert(0, str(Path(__file__).parent.parent / ".claude-plugin" / "vendor"))
import yaml


@dataclass
class Rule:
    """Security rule definition."""

    name: str
    description: str
    risk_level: str
    patterns: list[str]
    category: str
    file_path: str


@dataclass
class RuleCoverage:
    """Coverage info for a rule."""

    rule: Rule
    test_files: set[str] = field(default_factory=set)
    test_count: int = 0
    test_commands: list[str] = field(default_factory=list)


def get_project_root() -> Path:
    """Get project root directory."""
    return Path(__file__).parent.parent


def load_all_rules() -> list[Rule]:
    """Load all rules from yaml files."""
    rules_dir = get_project_root() / "data" / "rules"
    rules = []

    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        # Extract category from filename (e.g., 05_code_execution.yaml -> code_execution)
        category = yaml_file.stem.split("_", 1)[-1] if "_" in yaml_file.stem else yaml_file.stem

        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        for rule_data in data.get("rules", []):
            rules.append(
                Rule(
                    name=rule_data["name"],
                    description=rule_data.get("description", ""),
                    risk_level=rule_data.get("risk_level", "UNKNOWN"),
                    patterns=rule_data.get("patterns", []),
                    category=category,
                    file_path=str(yaml_file.relative_to(get_project_root())),
                )
            )

    return rules


def find_rule_tests(rule: Rule, test_files: list[Path]) -> RuleCoverage:
    """Find tests that cover a specific rule."""
    coverage = RuleCoverage(rule=rule)

    # Patterns to look for in test files
    # Use simple string containment - \b doesn't work well with underscored names
    rule_name_lower = rule.name.lower()

    # Also look for pattern fragments (first few chars of each pattern)
    pattern_fragments = []
    for p in rule.patterns[:3]:  # Check first 3 patterns
        # Extract a meaningful substring from the pattern
        # Remove regex metacharacters for plain text search
        fragment = re.sub(r"[\[\]{}()*+?\\^$.|]", "", p)[:20]
        if len(fragment) >= 5:
            pattern_fragments.append(fragment)

    for test_file in test_files:
        try:
            content = test_file.read_text()
            content_lower = content.lower()

            # Check if rule name is mentioned (case-insensitive)
            if rule_name_lower in content_lower:
                coverage.test_files.add(str(test_file.name))
                coverage.test_count += content_lower.count(rule_name_lower)
                continue

            # Check for pattern fragments in test commands
            for fragment in pattern_fragments:
                if fragment in content:
                    coverage.test_files.add(str(test_file.name))
                    coverage.test_count += 1
                    break

        except Exception:  # noqa: S110 - Ignore test file parsing errors
            pass

    return coverage


def analyze_coverage() -> dict[str, RuleCoverage]:
    """Analyze test coverage for all rules."""
    rules = load_all_rules()
    test_dir = get_project_root() / "tests"
    test_files = list(test_dir.glob("test_*.py"))

    coverage_map = {}
    for rule in rules:
        coverage = find_rule_tests(rule, test_files)
        coverage_map[rule.name] = coverage

    return coverage_map


def print_report(  # noqa: PLR0912 - Report logic
    coverage_map: dict[str, RuleCoverage],
    verbose: bool = False,
    missing_only: bool = False,
) -> None:
    """Print coverage report."""
    # Group by category
    by_category: dict[str, list[RuleCoverage]] = {}
    for cov in coverage_map.values():
        category = cov.rule.category
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(cov)

    total_rules = len(coverage_map)
    covered_rules = sum(1 for c in coverage_map.values() if c.test_files)
    coverage_pct = (covered_rules / total_rules * 100) if total_rules else 0

    print("=" * 70)
    print("SCHLOCK RULE TEST COVERAGE REPORT")
    print("=" * 70)
    print(f"\nOverall: {covered_rules}/{total_rules} rules have tests ({coverage_pct:.1f}%)\n")

    # Summary by risk level
    by_risk: dict[str, tuple] = {}
    for cov in coverage_map.values():
        level = cov.rule.risk_level
        if level not in by_risk:
            by_risk[level] = [0, 0]
        by_risk[level][0] += 1
        if cov.test_files:
            by_risk[level][1] += 1

    print("By Risk Level:")
    for level in ["BLOCKED", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        if level in by_risk:
            total, covered = by_risk[level]
            pct = (covered / total * 100) if total else 0
            status = "✅" if pct >= 80 else "⚠️" if pct >= 50 else "❌"
            print(f"  {status} {level:8} {covered:3}/{total:<3} ({pct:5.1f}%)")

    print("\n" + "-" * 70)

    # Detail by category
    for category in sorted(by_category.keys()):
        rules = by_category[category]
        cat_covered = sum(1 for c in rules if c.test_files)

        print(f"\n### {category.upper().replace('_', ' ')} ({cat_covered}/{len(rules)})")

        for cov in sorted(rules, key=lambda c: (not c.test_files, c.rule.name)):
            if missing_only and cov.test_files:
                continue

            status = "✅" if cov.test_files else "❌"
            level_tag = f"[{cov.rule.risk_level}]"

            print(f"  {status} {level_tag:10} {cov.rule.name}")

            if verbose and cov.test_files:
                print(f"       Files: {', '.join(sorted(cov.test_files))}")

    # Missing high-priority rules
    missing_critical = [c for c in coverage_map.values() if not c.test_files and c.rule.risk_level in ("BLOCKED", "HIGH")]

    if missing_critical:
        print("\n" + "=" * 70)
        print("⚠️  CRITICAL: BLOCKED/HIGH rules without tests:")
        print("=" * 70)
        for cov in sorted(missing_critical, key=lambda c: c.rule.name):
            print(f"  ❌ [{cov.rule.risk_level}] {cov.rule.name}")
            print(f"       {cov.rule.file_path}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Analyze rule test coverage")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show test file details")
    parser.add_argument("-m", "--missing-only", action="store_true", help="Only show rules without tests")

    args = parser.parse_args()

    coverage_map = analyze_coverage()
    print_report(coverage_map, verbose=args.verbose, missing_only=args.missing_only)

    # Return non-zero if critical rules lack coverage
    missing_critical = sum(1 for c in coverage_map.values() if not c.test_files and c.rule.risk_level in ("BLOCKED", "HIGH"))

    return 1 if missing_critical > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
