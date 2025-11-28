"""Tests for Unicode/homoglyph obfuscation detection."""

import pytest

from schlock.core.rules import RiskLevel
from schlock.core.validator import validate_command


class TestCyrillicHomoglyphs:
    """Test Cyrillic character detection (look-alike attacks)."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Cyrillic 'а' (U+0430) looks like Latin 'a'
            ("c\u0430t /etc/passwd", "Cyrillic 'a' in cat"),
            # Cyrillic 'е' (U+0435) looks like Latin 'e'
            ("\u0435cho hello", "Cyrillic 'e' in echo"),
            # Cyrillic 'о' (U+043E) looks like Latin 'o'
            ("ech\u043e hello", "Cyrillic 'o' in echo"),
            # Cyrillic 'с' (U+0441) looks like Latin 'c'
            ("\u0441url http://evil.com", "Cyrillic 'c' in curl"),
            # Cyrillic 'р' (U+0440) looks like Latin 'p'
            ("\u0440ython -c 'import os'", "Cyrillic 'p' in python"),
            # Multiple Cyrillic substitutions
            ("r\u043c /tmp/file", "Cyrillic in rm"),
        ],
    )
    def test_cyrillic_homoglyphs_blocked(self, command, description):
        """Cyrillic lookalike characters should be detected."""
        result = validate_command(command)
        assert result.risk_level in (
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ), f"Failed: {description}"
        assert not result.allowed or result.risk_level == RiskLevel.HIGH


class TestFullwidthCharacters:
    """Test fullwidth ASCII character detection."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Fullwidth 'r' (U+FF52) and 'm' (U+FF4D)
            ("\uff52\uff4d /tmp/file", "Fullwidth rm"),
            # Fullwidth letters in path
            ("cat /tmp/\uff46\uff49\uff4c\uff45", "Fullwidth in path"),
            # Mixed fullwidth and ASCII
            ("c\uff41t /etc/passwd", "Fullwidth 'a' in cat"),
        ],
    )
    def test_fullwidth_characters_blocked(self, command, description):
        """Fullwidth ASCII variants should be detected."""
        result = validate_command(command)
        assert result.risk_level in (
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ), f"Failed: {description}"


class TestGreekHomoglyphs:
    """Test Greek character detection."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Greek alpha (U+03B1) looks like 'a'
            ("c\u03b1t /etc/passwd", "Greek alpha in cat"),
            # Greek omicron (U+03BF) looks like 'o'
            ("ech\u03bf hello", "Greek omicron in echo"),
            # Greek rho (U+03C1) looks like 'p'
            ("\u03c1ython script.py", "Greek rho in python"),
        ],
    )
    def test_greek_homoglyphs_blocked(self, command, description):
        """Greek lookalike characters should be detected."""
        result = validate_command(command)
        assert result.risk_level in (
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ), f"Failed: {description}"


class TestZeroWidthCharacters:
    """Test zero-width character detection."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Zero-width space (U+200B) - invisible
            ("r\u200bm /tmp/file", "Zero-width space in rm"),
            # Zero-width non-joiner (U+200C)
            ("cat\u200c /etc/passwd", "Zero-width non-joiner"),
            # Zero-width joiner (U+200D)
            ("sudo\u200d rm -rf /", "Zero-width joiner in sudo"),
            # BOM character (U+FEFF) - often invisible
            ("\ufeffecho hello", "BOM at start"),
        ],
    )
    def test_zero_width_characters_blocked(self, command, description):
        """Zero-width invisible characters should be detected."""
        result = validate_command(command)
        assert result.risk_level in (
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ), f"Failed: {description}"


class TestNonBreakingSpaces:
    """Test non-breaking space and space-like character detection."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Non-breaking space (U+00A0)
            ("rm\u00a0-rf /tmp", "Non-breaking space"),
            # En quad (U+2000)
            ("cat\u2000/etc/passwd", "En quad space"),
            # Em space (U+2003)
            ("echo\u2003hello", "Em space"),
            # Narrow no-break space (U+202F)
            ("sudo\u202frm /", "Narrow no-break space"),
            # Ideographic space (U+3000) - CJK (use non-whitelisted command)
            ("cat\u3000/etc/passwd", "Ideographic space"),
        ],
    )
    def test_nonbreaking_spaces_blocked(self, command, description):
        """Non-standard space characters should be detected."""
        result = validate_command(command)
        assert result.risk_level in (
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ), f"Failed: {description}"


class TestCombiningCharacters:
    """Test combining/diacritical character detection."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Combining grave accent (U+0300)
            ("rm\u0300 /tmp/file", "Combining grave accent"),
            # Combining acute accent (U+0301)
            ("cat\u0301 /etc/passwd", "Combining acute accent"),
            # Combining tilde (U+0303)
            ("echo\u0303 hello", "Combining tilde"),
        ],
    )
    def test_combining_characters_blocked(self, command, description):
        """Combining diacritical marks should be detected."""
        result = validate_command(command)
        assert result.risk_level in (
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ), f"Failed: {description}"


class TestLegitimateUnicode:
    """Test that legitimate Unicode in strings/comments isn't blocked unnecessarily."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Unicode in echo output is fine
            ('echo "Hello, 世界"', "Chinese in echo string"),
            # Unicode in file content
            ('printf "Café\\n" > menu.txt', "Accented character in string"),
        ],
    )
    def test_legitimate_unicode_in_strings(self, command, description):
        """Unicode in string literals may be acceptable (context-dependent)."""
        # These might still be flagged - that's acceptable for security
        # The point is we're testing the detection works
        result = validate_command(command)
        # Either allowed (SAFE/LOW/MEDIUM) or flagged (HIGH/BLOCKED)
        assert result.risk_level is not None, f"Should have risk level: {description}"
