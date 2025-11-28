"""Security rule engine and risk assessment.

This module defines the risk categorization system, rule data structures,
and the rule matching engine for command validation.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from re import Pattern
from typing import Optional, Union

import yaml

from schlock.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for command validation.

    Commands are categorized by risk level from SAFE (0) to BLOCKED (4).
    Higher numeric values indicate higher risk.

    Levels:
        SAFE: No risk, always allowed (e.g., git status, ls, pwd)
        LOW: Minimal risk, typically allowed (e.g., git commit, npm install)
        MEDIUM: Moderate risk, requires attention (e.g., rm single file, git push)
        HIGH: High risk, should be reviewed (e.g., rm -r, sudo, curl|bash)
        BLOCKED: Critical risk, always blocked (e.g., rm -rf /, eval, chmod 777)

    Example:
        >>> RiskLevel.BLOCKED.value > RiskLevel.HIGH.value
        True
        >>> RiskLevel.SAFE.value == 0
        True
    """

    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    BLOCKED = 4

    def __lt__(self, other):
        """Enable comparison for risk prioritization."""
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def __le__(self, other):
        """Enable comparison for risk prioritization."""
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __gt__(self, other):
        """Enable comparison for risk prioritization."""
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __ge__(self, other):
        """Enable comparison for risk prioritization."""
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented


@dataclass(frozen=True)
class SecurityRule:
    r"""Security rule definition for command validation.

    Defines a single security rule with patterns to match against commands.
    Rules are immutable to prevent accidental modification.

    Attributes:
        name: Unique rule identifier (e.g., "recursive-delete")
        description: Human-readable explanation of why this rule exists
        risk_level: Risk level for commands matching this rule
        patterns: List of regex patterns to match against commands
        alternatives: List of safer alternative approaches (for HIGH/BLOCKED)

    Example:
        >>> rule = SecurityRule(
        ...     name="force-push",
        ...     description="Force push can overwrite remote history",
        ...     risk_level=RiskLevel.HIGH,
        ...     patterns=[r"git\s+push\s+.*--force"],
        ...     alternatives=["Use git push --force-with-lease instead"]
        ... )
    """

    name: str
    description: str
    risk_level: RiskLevel
    patterns: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate rule structure after initialization."""
        if not self.name:
            raise ValueError("Rule name cannot be empty")
        if not self.description:
            raise ValueError("Rule description cannot be empty")
        if not isinstance(self.risk_level, RiskLevel):
            raise ValueError(f"risk_level must be RiskLevel enum, got {type(self.risk_level)}")


@dataclass(frozen=True)
class RuleMatch:
    """Result of matching a command against security rules.

    Immutable dataclass representing the outcome of rule matching.

    Attributes:
        matched: Whether any rule matched the command
        rule: The matched SecurityRule (if any)
        risk_level: Risk level of the match (SAFE if no match)
        message: Human-readable message about the match
        alternatives: Safer alternatives (from rule if available)

    Example:
        >>> match = RuleMatch(
        ...     matched=True,
        ...     rule=some_rule,
        ...     risk_level=RiskLevel.HIGH,
        ...     message="Recursive delete detected",
        ...     alternatives=["Use rm -ri for interactive delete"]
        ... )
    """

    matched: bool
    rule: Optional[SecurityRule]
    risk_level: RiskLevel
    message: str
    alternatives: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate match structure after initialization."""
        if self.matched and self.rule is None:
            raise ValueError("If matched is True, rule must be provided")
        if not self.matched and self.rule is not None:
            raise ValueError("If matched is False, rule must be None")


class RuleEngine:
    """Load and match security rules from YAML configuration.

    The RuleEngine loads security rules from a YAML file or directory,
    compiles regex patterns once at initialization, and provides efficient
    pattern matching against commands.

    YAML Structure:
        ```yaml
        whitelist:
          - pattern1
          - pattern2
        rules:
          - name: rule-name
            description: Why this is dangerous
            risk_level: BLOCKED  # or HIGH, MEDIUM, LOW, SAFE
            patterns:
              - regex_pattern_1
              - regex_pattern_2
            alternatives:
              - Safer approach 1
              - Safer approach 2
        ```

    Example:
        >>> engine = RuleEngine("/path/to/safety_rules.yaml")
        >>> match = engine.match_command("rm -rf /")
        >>> print(match.risk_level)  # RiskLevel.BLOCKED
    """

    def __init__(self, rules_yaml_path: Union[str, Path]):
        """Initialize RuleEngine and load rules from YAML.

        Args:
            rules_yaml_path: Path to YAML file containing security rules

        Raises:
            ConfigurationError: If YAML is invalid or patterns don't compile
        """
        self.rules_path = Path(rules_yaml_path)
        self.rules: list[SecurityRule] = []
        self.compiled_patterns: dict[str, list[Pattern]] = {}
        self.whitelist_patterns: list[Pattern] = []

        self._load_rules()

    @classmethod
    def from_directory(cls, rules_dir: Path) -> "RuleEngine":
        """Create RuleEngine from directory of YAML files.

        Loads all .yaml files in the directory in sorted order (alphabetical),
        which respects the NN_ numbering convention for deterministic ordering.

        Args:
            rules_dir: Path to directory containing rule YAML files

        Returns:
            RuleEngine instance with rules from all files

        Raises:
            ConfigurationError: If directory doesn't exist or files are invalid
        """
        if not rules_dir.exists() or not rules_dir.is_dir():
            raise ConfigurationError(
                f"Rules directory not found: {rules_dir}",
                file_path=str(rules_dir),
            )

        # Create instance without calling __init__
        engine = cls.__new__(cls)
        engine.rules_path = rules_dir
        engine.rules = []
        engine.compiled_patterns = {}
        engine.whitelist_patterns = []

        # Load rules from all YAML files in directory
        engine._load_rules_from_directory(rules_dir)

        return engine

    def _load_rules(self) -> None:
        """Load and validate rules from YAML file.

        Raises:
            ConfigurationError: If file doesn't exist, YAML is invalid,
                                or regex patterns don't compile
        """
        if not self.rules_path.exists():
            raise ConfigurationError(
                f"Rules file not found: {self.rules_path}",
                file_path=str(self.rules_path),
            )

        try:
            with open(self.rules_path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML syntax: {e}",
                file_path=str(self.rules_path),
            )
        except Exception as e:
            raise ConfigurationError(
                f"Failed to read rules file: {e}",
                file_path=str(self.rules_path),
            )

        if not isinstance(data, dict):
            raise ConfigurationError(
                "YAML root must be a dictionary",
                file_path=str(self.rules_path),
            )

        # Load whitelist patterns
        whitelist = data.get("whitelist", [])
        if whitelist:
            self._compile_whitelist(whitelist)

        # Load security rules
        rules_data = data.get("rules", [])
        if not rules_data:
            logger.warning(f"No rules found in {self.rules_path}")
            return

        for idx, rule_data in enumerate(rules_data):
            try:
                self._load_rule(rule_data, idx)
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to load rule at index {idx}: {e}",
                    file_path=str(self.rules_path),
                )

    def _compile_whitelist(self, patterns: list[str]) -> None:
        """Compile whitelist patterns.

        Args:
            patterns: List of regex pattern strings

        Raises:
            ConfigurationError: If pattern doesn't compile
        """
        for pattern_str in patterns:
            try:
                compiled = re.compile(pattern_str, re.MULTILINE)
                self.whitelist_patterns.append(compiled)
            except re.error as e:
                raise ConfigurationError(
                    f"Invalid whitelist regex pattern: {pattern_str!r} - {e}",
                    file_path=str(self.rules_path),
                )

    def _load_rule(self, rule_data: dict, index: int) -> None:
        """Load a single rule from YAML data.

        Args:
            rule_data: Dictionary containing rule configuration
            index: Rule index in YAML (for error messages)

        Raises:
            ConfigurationError: If rule structure is invalid or patterns don't compile
        """
        if not isinstance(rule_data, dict):
            raise ConfigurationError(
                f"Rule at index {index} must be a dictionary",
                file_path=str(self.rules_path),
            )

        # Convert risk_level string to enum
        if "risk_level" in rule_data:
            risk_str = str(rule_data["risk_level"]).upper()
            try:
                rule_data["risk_level"] = RiskLevel[risk_str]
            except KeyError:
                raise ConfigurationError(
                    f"Invalid risk_level: {risk_str}. Must be one of: {', '.join(r.name for r in RiskLevel)}",
                    file_path=str(self.rules_path),
                )

        # Create SecurityRule (this validates required fields)
        try:
            rule = SecurityRule(**rule_data)
        except (TypeError, ValueError) as e:
            raise ConfigurationError(
                f"Invalid rule structure at index {index}: {e}",
                file_path=str(self.rules_path),
            )

        # Compile and store regex patterns
        compiled_patterns = []
        for pattern_str in rule.patterns:
            try:
                # Use MULTILINE but NOT IGNORECASE (security requirement)
                compiled = re.compile(pattern_str, re.MULTILINE)
                compiled_patterns.append(compiled)
            except re.error as e:
                raise ConfigurationError(
                    f"Invalid regex pattern in rule '{rule.name}': {pattern_str!r} - {e}",
                    file_path=str(self.rules_path),
                )

        self.rules.append(rule)
        self.compiled_patterns[rule.name] = compiled_patterns

    def _load_rules_from_directory(self, rules_dir: Path) -> None:
        """Load and merge rules from all YAML files in directory.

        Files are loaded in sorted order (alphabetical), which respects
        the NN_ numbering convention for deterministic ordering.

        Args:
            rules_dir: Path to directory containing rule YAML files

        Raises:
            ConfigurationError: If directory doesn't exist or files are invalid
        """
        yaml_files = sorted(rules_dir.glob("*.yaml"))

        if not yaml_files:
            raise ConfigurationError(
                f"No YAML files found in rules directory: {rules_dir}",
                file_path=str(rules_dir),
            )

        logger.info(f"Loading rules from {len(yaml_files)} files in {rules_dir}")

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data:
                    # Skip empty files
                    continue

                if not isinstance(data, dict):
                    raise ConfigurationError(
                        f"YAML root must be a dictionary in {yaml_file.name}",
                        file_path=str(yaml_file),
                    )

                # Load whitelist patterns (merge from all files)
                whitelist = data.get("whitelist", [])
                if whitelist:
                    self._compile_whitelist(whitelist)

                # Load security rules (merge from all files)
                rules_data = data.get("rules", [])
                if not rules_data:
                    # File may only contain whitelist, skip
                    continue

                for idx, rule_data in enumerate(rules_data):
                    try:
                        self._load_rule(rule_data, idx)
                    except Exception as e:
                        raise ConfigurationError(
                            f"Failed to load rule at index {idx} in {yaml_file.name}: {e}",
                            file_path=str(yaml_file),
                        ) from e

            except yaml.YAMLError as e:
                raise ConfigurationError(
                    f"Invalid YAML syntax in {yaml_file.name}: {e}",
                    file_path=str(yaml_file),
                )
            except ConfigurationError:
                # Re-raise ConfigurationErrors as-is
                raise
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to read rules file {yaml_file.name}: {e}",
                    file_path=str(yaml_file),
                )

        logger.info(f"Loaded {len(self.rules)} rules from {len(yaml_files)} files")

    def is_whitelisted(self, command: str) -> bool:
        """Check if command matches whitelist patterns.

        Whitelisted commands always return SAFE regardless of other rules.

        Args:
            command: Command string to check

        Returns:
            True if command matches any whitelist pattern
        """
        return any(pattern.search(command) for pattern in self.whitelist_patterns)

    def match_command(self, command: str, string_literals: Optional[list[tuple]] = None) -> RuleMatch:
        """Match command against all rules, return highest risk.

        Matching algorithm:
        1. Check whitelist first (returns SAFE if matched)
        2. Match against all rules, collect all matches
        3. Skip matches that fall inside quoted string literals (AST context)
        4. Return highest risk level match

        Args:
            command: Command string to validate
            string_literals: Optional list of (start, end) positions for quoted strings
                           from AST analysis. Matches inside these ranges are ignored.

        Returns:
            RuleMatch with highest risk level from all matching rules

        Example:
            >>> engine = RuleEngine("rules.yaml")
            >>> match = engine.match_command("rm -rf /tmp/test")
            >>> if not match.matched:
            ...     print("Command is safe")

            >>> # With AST context to avoid false positives
            >>> match = engine.match_command('echo "rm -rf /"', string_literals=[(6, 15)])
            >>> # Pattern match at position 11-18 is inside string literal, ignored
        """
        # Whitelist override
        if self.is_whitelisted(command):
            return RuleMatch(
                matched=False,
                rule=None,
                risk_level=RiskLevel.SAFE,
                message="Command is whitelisted",
                alternatives=[],
            )

        # Match against all rules, track highest risk
        highest_match: Optional[RuleMatch] = None
        highest_risk = RiskLevel.SAFE

        for rule in self.rules:
            patterns = self.compiled_patterns.get(rule.name, [])
            for pattern in patterns:
                match = pattern.search(command)
                if match:
                    # Check if match is inside a quoted string literal
                    if string_literals and self._is_in_string_literal(match, string_literals):
                        # Skip this match - it's in a quoted string that won't execute
                        continue

                    # Rule matched - check if higher risk than current
                    if rule.risk_level > highest_risk:
                        highest_risk = rule.risk_level
                        highest_match = RuleMatch(
                            matched=True,
                            rule=rule,
                            risk_level=rule.risk_level,
                            message=rule.description,
                            alternatives=rule.alternatives,
                        )
                    break  # Don't check other patterns for this rule

        # Return highest risk match or SAFE if no match
        if highest_match:
            return highest_match
        return RuleMatch(
            matched=False,
            rule=None,
            risk_level=RiskLevel.SAFE,
            message="No security rules matched",
            alternatives=[],
        )

    def _is_in_string_literal(self, match: re.Match, string_literals: list[tuple]) -> bool:
        """Check if a regex match falls within a quoted string literal.

        SECURITY CRITICAL: Must check that ENTIRE match (start AND end) is within
        string literal bounds. Checking only start position allows bypass:
        Example: echo 'safe" rm -rf / "more' - match starts in string but ends outside.

        Args:
            match: Regex match object
            string_literals: List of (start, end) positions for quoted strings

        Returns:
            True if the match is ENTIRELY inside a string literal, False otherwise
        """
        match_start = match.start()
        match_end = match.end()

        # Both start AND end must be within the same string literal
        return any(literal_start <= match_start and match_end <= literal_end for literal_start, literal_end in string_literals)
