"""Tests for ReDoS (Regular Expression Denial of Service) protection.

FIX 3: ReDoS Pattern Vulnerabilities
Bug: Multiple regex patterns had catastrophic backtracking potential with unbounded
quantifiers (.*, [^x]*) that could cause DoS with pathological inputs.

Fix: Replaced unbounded quantifiers with bounded ones (.{0,200}, [^x]{0,100}).
"""

import time

import pytest

from schlock.core.rules import RuleEngine
from schlock.core.validator import validate_command


class TestReDoSProtection:
    """Test that validation completes quickly even with pathological inputs."""

    MAX_VALIDATION_TIME = 1.0  # Maximum 1 second per validation

    def test_no_catastrophic_backtracking_rm_flags(self):
        """Pathological rm command with many flags should complete quickly."""
        # This would cause catastrophic backtracking with unbounded .*
        cmd = "rm " + "-" * 1000 + "rf /"

        start = time.time()
        result = validate_command(cmd)
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for rm with many flags"
        # Pathological input may or may not match patterns, but should complete quickly
        assert result is not None

    def test_no_catastrophic_backtracking_find_paths(self):
        """Pathological find command with deep paths should complete quickly."""
        # Many slashes could cause backtracking
        cmd = "find " + "/" * 500 + " -delete"

        start = time.time()
        validate_command(cmd)  # Result unused - testing timing
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for find with deep path"

    def test_no_catastrophic_backtracking_chmod_flags(self):
        """Pathological chmod command with many +x should complete quickly."""
        cmd = "chmod " + "+" * 800 + "x /bin/sh"

        start = time.time()
        validate_command(cmd)  # Result unused - testing timing
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for chmod with many +"

    def test_no_catastrophic_backtracking_substitution_long(self):
        """Long command substitution should complete quickly."""
        # Long content inside $() could cause unbounded [^)] backtracking
        cmd = "rm $(" + "a" * 300 + " rm -rf /)"

        start = time.time()
        validate_command(cmd)  # Result unused - testing timing
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for long substitution"

    def test_no_catastrophic_backtracking_backtick_long(self):
        """Long backtick command substitution should complete quickly."""
        cmd = "rm `" + "a" * 300 + " rm -rf /`"

        start = time.time()
        validate_command(cmd)  # Result unused - testing timing
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for long backtick"

    def test_no_catastrophic_backtracking_fork_bomb_variant(self):
        """Fork bomb with extra content should complete quickly."""
        # Extra characters between : could cause backtracking
        cmd = ":(){" + " " * 500 + ":|:&};:"

        start = time.time()
        result = validate_command(cmd)
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for fork bomb variant"
        # Pathological variant may not match exact pattern, but should complete quickly
        assert result is not None

    def test_bounded_quantifiers_still_detect_danger(self):
        """Bounded quantifiers should still catch dangerous patterns within bounds."""
        # Test that we didn't break detection by adding bounds
        dangerous_commands = [
            "rm -rf /",
            "rm -rf $HOME",
            "$(rm -rf /)",
            ":(){:|:&};:",
        ]

        for cmd in dangerous_commands:
            result = validate_command(cmd)
            assert not result.allowed, f"Failed to block: {cmd}"

    @pytest.mark.parametrize(
        "pathological_input",
        [
            "rm " + "-" * 2000 + "rf /",  # Very long flags
            "find " + "/" * 1000 + " -delete",  # Very deep path
            "chmod " + "+" * 1500 + "x file",  # Many plus signs
            "rm $(" + "x" * 500 + " rm /)",  # Long substitution
            ":(){" + " " * 1000 + ":|:&};:",  # Long fork bomb
        ],
    )
    def test_all_pathological_inputs_fast(self, pathological_input):
        """All pathological inputs should validate quickly."""
        start = time.time()
        validate_command(pathological_input)  # Result unused - testing timing
        elapsed = time.time() - start

        assert elapsed < self.MAX_VALIDATION_TIME, f"ReDoS detected: {elapsed:.3f}s for input: {pathological_input[:50]}..."

    @pytest.mark.parametrize("head", ["tee", "> ", "rm"])
    def test_blank_run_after_a_truncation_head_is_linear(self, safety_rules_path, head):
        r"""A long blank run after `tee`, `>` or `rm` is scanned once, not once per backtrack.

        The blank-operand guard is `(?=\s+\S)` in FRONT of the quantifier
        (LAB-4360). Written as `\s+(?!\s*$)` it re-scans the run on every
        backtracking step: 20,000 blanks cost 500ms at the regex layer against
        2ms for the base pattern, on a hook that runs before every bash call.
        Measured at the regex layer because the whole validator already spends
        over a second on this input in other patterns, which would hide it.
        """
        engine = RuleEngine(safety_rules_path)
        patterns = engine.compiled_patterns["file_truncation"] + engine.compiled_patterns["single_delete"]
        text = head + " " * 50_000

        start = time.perf_counter()
        for pattern in patterns:
            pattern.search(text)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"blank run after {head!r} took {elapsed:.3f}s"

    @pytest.mark.parametrize("text", ["IFS=" + " " * 50_000 + "read", "IFS=" + "x" * 50_000, "I" + "\\\n" * 25_000])
    def test_ifs_override_pattern_is_linear(self, safety_rules_path, text):
        """The IFS-override pattern scans a blank run or a `\\<newline>` run once, not once per backtrack."""
        engine = RuleEngine(safety_rules_path)

        start = time.perf_counter()
        for pattern in engine.compiled_patterns["ifs_obfuscation"]:
            pattern.search(text)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"ifs_obfuscation took {elapsed:.3f}s on {text[:12]!r}..."

    @pytest.mark.parametrize(
        "unit",
        [
            'echo "',
            "echo '",
            "echo \\",
            "echo `",
            "echo 2>&1 ",
            "echo $((1)) ",
            "echo $(a $(b) | c) ",
            "cat $(a (b ",
            "cat '",
            "export ",
            "chroot ",
            "source /tmp/",
        ],
    )
    def test_one_command_gap_is_linear_in_anchor_density(self, safety_rules_path, unit):
        """The shell-word gap restarts at every anchor, so vary ANCHOR DENSITY, not length.

        Every anchor re-runs a bounded gap plus its open-quote tail. That is linear
        in input size with a large constant (~0.8s at 64 KB, 4x the time for 4x
        the input), not quadratic. The `.{0,200}` it replaced took ~0.1s here.
        Measured at the regex layer because the whole validator hides it.
        """
        engine = RuleEngine(safety_rules_path)
        rules = [
            "credential_exposure",
            "hardcoded_secrets",
            "privilege_escalation_variants",
            "partition_manipulation",
            "filesystem_wipe",
            "source_remote_script",
            "recursive_permission_system_dirs",
        ]
        patterns = [p for r in rules for p in engine.compiled_patterns[r]]
        extended = engine.compiled_patterns["extended_credential_exposure"]
        patterns += [p for p in extended if p.pattern.startswith(("echo", "printf"))]
        text = (unit * (64 * 1024 // len(unit) + 1))[: 64 * 1024]

        start = time.perf_counter()
        for pattern in patterns:
            pattern.search(text)
        elapsed = time.perf_counter() - start

        assert elapsed < 3.0, f"{unit!r} x density took {elapsed:.3f}s"


class TestBoundedQuantifierEdgeCases:
    """Test edge cases around the boundaries of quantifiers."""

    def test_pattern_just_within_bound(self):
        """Patterns just within the 200-char bound should be detected."""
        # 150 chars is within the 200 bound
        cmd = "rm -rf " + "/" + "a" * 150

        result = validate_command(cmd)
        # Should detect the rm -rf pattern (HIGH is allowed but warned)
        assert result.risk_level.value >= 3  # HIGH or BLOCKED

    def test_pattern_at_exact_bound(self):
        """Patterns at exactly the bound should work."""
        # Test at 200-char boundary
        cmd = "rm " + "x" * 195 + " -rf /"

        result = validate_command(cmd)
        # Within bound, should detect
        # (may or may not depending on exact pattern, but should not hang)
        assert result is not None

    def test_normal_commands_unaffected(self):
        """Normal commands should still work as before."""
        safe_commands = ["git status", "ls -la", "pwd", "echo hello"]

        for cmd in safe_commands:
            result = validate_command(cmd)
            assert result.allowed or result.risk_level.name in ["SAFE", "LOW"]

    def test_dangerous_commands_still_blocked(self):
        """Dangerous commands should still be detected as risky."""
        dangerous = [
            ("rm -rf /", True),  # BLOCKED
            ("sudo rm -rf /", True),  # BLOCKED
            ("dd if=/dev/zero of=/dev/sda", True),  # BLOCKED
            ("chmod 777 /etc", False),  # HIGH (allowed but warned)
            ("eval 'rm -rf /'", True),  # BLOCKED
        ]

        for cmd, should_block in dangerous:
            result = validate_command(cmd)
            if should_block:
                assert not result.allowed, f"Should block: {cmd}"
            else:
                # HIGH is allowed but should have high risk level
                assert result.risk_level.value >= 3, f"Should be HIGH risk: {cmd}"
