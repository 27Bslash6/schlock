"""Real integration tests using actual components (NO MOCKS).

These tests verify the complete validation pipeline works end-to-end:
- Load ACTUAL data/rules/ directory
- Parse with ACTUAL bashlex (no mocks)
- Test full validation pipeline
- Verify dangerous commands blocked, safe commands allowed
"""

from pathlib import Path

from schlock.core.cache import ValidationCache
from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import validate_command


class TestRealIntegration:
    """Integration tests with real components."""

    def test_real_rules_load(self):
        """Verify actual data/rules/ directory loads successfully."""
        project_root = Path(__file__).parent.parent
        rules_dir = project_root / "data" / "rules"

        assert rules_dir.exists(), f"Rules directory not found: {rules_dir}"

        # Load with RuleEngine from directory (no mocks)
        engine = RuleEngine.from_directory(rules_dir)

        # Should have loaded rules
        assert len(engine.rules) > 0, "No rules loaded"
        assert len(engine.compiled_patterns) > 0, "No patterns compiled"

        # Verify we have rules at each risk level
        risk_levels = {rule.risk_level for rule in engine.rules}
        assert RiskLevel.BLOCKED in risk_levels, "No BLOCKED rules"
        assert RiskLevel.HIGH in risk_levels, "No HIGH rules"
        assert RiskLevel.SAFE in risk_levels, "No SAFE rules"

    def test_real_bashlex_parsing(self):
        """Verify actual bashlex parses commands correctly."""
        parser = BashCommandParser()

        # Parse various real commands
        commands = [
            "git status",
            "rm -rf /tmp/test",
            'echo "Hello world"',
            "git push origin main --force",
            "sudo rm -rf /",
        ]

        for command in commands:
            # Should parse without errors
            ast = parser.parse(command)
            assert ast is not None, f"Failed to parse: {command}"

            # Should extract string literals
            literals = parser.extract_string_literals(command, ast)
            assert isinstance(literals, list), f"String literals not a list: {command}"

    def test_real_full_pipeline_dangerous_commands(self):
        """Test complete validation pipeline blocks dangerous commands."""
        dangerous_commands = [
            ("rm -rf /", RiskLevel.BLOCKED, "System destruction"),
            ("sudo rm file", RiskLevel.BLOCKED, "Sudo use"),
            ("dd if=/dev/zero of=/dev/sda", RiskLevel.BLOCKED, "Disk destruction"),
            ("chmod 777 file", RiskLevel.HIGH, "Insecure permissions"),
            ("git push --force", RiskLevel.HIGH, "Force push"),
            ("eval 'rm -rf /'", RiskLevel.HIGH, "Eval usage"),
            ("nc -l -p 1234 -e /bin/sh", RiskLevel.BLOCKED, "Network backdoor"),
            ("echo $(rm -rf /)", RiskLevel.BLOCKED, "Command substitution"),
        ]

        for command, expected_min_risk, description in dangerous_commands:
            result = validate_command(command)

            # Should be detected as risky
            assert result.risk_level.value >= expected_min_risk.value, (
                f"{description}: Expected >= {expected_min_risk}, got {result.risk_level} for: {command}"
            )

            # BLOCKED commands must not be allowed
            if expected_min_risk == RiskLevel.BLOCKED:
                assert not result.allowed, f"{description} should be BLOCKED: {command}"

    def test_real_full_pipeline_safe_commands(self):
        """Test complete validation pipeline allows safe commands."""
        safe_commands = [
            "git status",
            "ls -la",
            "pwd",
            "git log",
            "echo 'Hello world'",
            "cat README.md",
            "npm install",
            "pip install --user package",
        ]

        for command in safe_commands:
            result = validate_command(command)

            # Should be SAFE or LOW risk
            assert result.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM], (
                f"Safe command flagged as risky: {command} -> {result.risk_level}"
            )

            # Should be allowed
            assert result.allowed, f"Safe command blocked: {command}"

    def test_real_string_literal_context(self):
        """Test that string literals are properly handled in real pipeline."""
        test_cases = [
            # Dangerous patterns in strings should be SAFE
            ('echo "rm -rf /"', True, "Just echoing"),
            ('git commit -m "Fixed rm -rf issue"', True, "Commit message"),
            # Actual dangerous commands should be BLOCKED
            ("rm -rf /", False, "Actual destruction"),
            ('eval "rm -rf /"', False, "Eval executes"),
        ]

        for command, should_allow, description in test_cases:
            result = validate_command(command)

            if should_allow:
                assert result.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM], (
                    f"False positive: {description} -> {result.risk_level}"
                )
            else:
                assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
                    f"Failed to detect: {description} -> {result.risk_level}"
                )

    def test_real_cache_integration(self):
        """Test that caching works in real pipeline."""
        cache = ValidationCache(max_size=100)

        # First validation
        command = "git status"
        result1 = validate_command(command)

        # Manually cache it
        cache.set(command, result1)

        # Second validation (should hit cache)
        cached = cache.get(command)
        assert cached is not None, "Cache miss"
        assert cached.risk_level == result1.risk_level, "Cached result mismatch"

    def test_real_multiple_pattern_matching(self):
        """Test commands matching multiple patterns return highest risk."""
        # sudo + rm -rf / should be BLOCKED (both patterns match)
        result = validate_command("sudo rm -rf /")

        assert result.risk_level == RiskLevel.BLOCKED, f"Multiple patterns should return highest risk: got {result.risk_level}"
        assert not result.allowed, "sudo rm -rf / must be blocked"

    def test_real_whitelisted_operations(self):
        """Test that whitelisted operations work."""
        # These should be whitelisted per safety_rules.yaml
        whitelisted = [
            "rm -rf node_modules",
            "rm -rf .next",
            "chmod 755 /tmp/test",
        ]

        for command in whitelisted:
            result = validate_command(command)

            # Should be SAFE or low risk (whitelisted)
            assert result.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM], (
                f"Whitelisted command should be safe: {command} -> {result.risk_level}"
            )

    def test_real_error_handling(self):
        """Test that parse errors are handled gracefully."""
        # Invalid bash syntax
        invalid_commands = [
            "",  # Empty
            "   ",  # Whitespace only
            "echo 'unclosed string",  # Unclosed quote
        ]

        for command in invalid_commands:
            result = validate_command(command)

            # Should return error, not crash
            assert result.error is not None or result.risk_level == RiskLevel.BLOCKED, (
                f"Invalid command should error or block: {command}"
            )

    def test_real_pattern_count(self):
        """Verify we have comprehensive rule coverage."""
        project_root = Path(__file__).parent.parent
        rules_dir = project_root / "data" / "rules"

        engine = RuleEngine.from_directory(rules_dir)

        # Count rules by risk level
        blocked_rules = [r for r in engine.rules if r.risk_level == RiskLevel.BLOCKED]
        high_rules = [r for r in engine.rules if r.risk_level == RiskLevel.HIGH]
        medium_rules = [r for r in engine.rules if r.risk_level == RiskLevel.MEDIUM]
        low_rules = [r for r in engine.rules if r.risk_level == RiskLevel.LOW]
        safe_rules = [r for r in engine.rules if r.risk_level == RiskLevel.SAFE]

        # Verify we have good coverage
        assert len(blocked_rules) >= 7, f"Need more BLOCKED rules: {len(blocked_rules)}"
        assert len(high_rules) >= 12, f"Need more HIGH rules: {len(high_rules)}"
        assert len(medium_rules) >= 6, f"Need more MEDIUM rules: {len(medium_rules)}"
        assert len(low_rules) >= 5, f"Need more LOW rules: {len(low_rules)}"
        assert len(safe_rules) >= 3, f"Need more SAFE rules: {len(safe_rules)}"

        # Total rules
        total = len(engine.rules)
        assert total >= 40, f"Need at least 40 rules, have {total}"
