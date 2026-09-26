"""Security rule engine and risk assessment.

This module defines the risk categorization system, rule data structures,
and the rule matching engine for command validation.
"""

import logging
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from re import Pattern
from typing import Optional, Union

import yaml

from schlock.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

# A whitelist entry vouches for the command it DESCRIBES; the match is a prefix
# by design (issue #66, so "^ls\b" keeps covering "ls -la"), which means whatever
# the entry's tail never described rides along on its authority. Three constructs
# turn that from a convenience into a hole, and none is visible to a pattern
# that only describes the head of the command:
#
#   ".."  walks out of the directory the entry names. "chmod -R 777 /tmp/../.."
#         is not LIKE "chmod -R 777 /", it IS it.
#   "<>"  redirects. "ls -la > ~/.ssh/authorized_keys" is a whitelisted reader
#         being used as an arbitrary-file writer; "ls <(curl ...|sh)" runs a
#         second command the entry never mentioned.
#   "\n"  separates commands. Every "\s" in a whitelist pattern matches a
#         newline, so a "$"-anchored entry spans a string bash runs as SEVERAL
#         commands: "chmod\n-R\n777\n/tmp/evil.sh" satisfies the /tmp chmod
#         entry end to end, and the last line is an executable, not an operand.
#         A bare newline like that is split by the parser before is_whitelisted()
#         sees it, and is_whitelisted_whole() counts the pieces. This half is for
#         text that still arrives as ONE command with a newline inside: a
#         backslash continuation, a quoted string, a substitution body, and the
#         quote-stripped reconstructions match_command() also tries, where a
#         quoted newline becomes a bare one. Checked against command.rstrip() so
#         one TRAILING newline still whitelists.
#
# Refusing the whitelist is NOT refusing the command. The whitelist is an
# override that short-circuits to SAFE; declining it only sends the command to
# the ordinary rules to be judged on its merits, so this guard can over-fire
# (a filename containing ">", a harmless "ls ../src") without blocking anything
# that was not already blocked. That asymmetry is what makes one coarse
# string-level test the right size here: is_whitelisted() takes a bare str with
# no AST, and a guard whose worst case is "evaluate normally" does not need one.
#
# Deliberately in the engine rather than in each YAML entry: the per-entry
# version is this rule written once per pattern and re-written on every pattern
# added, which is the failure this file has already had three tickets for.
_WHITELIST_DISQUALIFIER = re.compile(r"\.\.|[<>\n\r]")
# is_whitelisted_whole()'s share of it: the same two escapes, without the line breaks. That
# gate counts the commands bash will find, so a newline that adds one is refused there
# already, and a newline after a pipe -- a continuation, one pipeline to bash -- has to stay
# legal. A bare \r is refused there by _NON_BASH_BLANK.
_WHOLE_LINE_DISQUALIFIER = re.compile(r"\.\.|[<>]")

# One token of a whitelist pattern's SOURCE: an escape, a bracket expression, or one character.
_SOURCE_TOKEN = re.compile(r"\\.|\[\^?\]?(?:\\.|[^\]\\])*\]|.", re.DOTALL)
# The tokens that write a command separator, so `is_whitelisted_whole` can ask how many commands
# an entry claims to describe. A literal pipe is matched as a regex spells it (`\|` or `[|]`);
# `&` and `;` are not metacharacters and mean themselves. A BARE `|` is deliberately absent: it
# is alternation, which is what `(node_modules|dist)` uses and what must NOT count. A bracket
# expression is one character SLOT, so `[^;]` or `[\w;]` mentions `;` without writing a boundary
# -- only a class holding nothing but the separator writes one. Ceiling: a pipe spelled `\x7c` or
# `\174` is not recognised, so such an entry is read as describing fewer commands and clears no
# line -- the fail-closed direction, costing a false positive on an exotic spelling, never a
# denial.
_SEPARATOR_TOKENS = frozenset({"\\|", "[|]", ";", "\\;", "[;]", "&", "\\&", "[&]"})
# Whitespace that `\s` and `str.strip` accept but bash does not treat as blank: \r, \v, \f,
# \x1c-\x1f and the Unicode spaces are WORD characters to bash. Only space, tab and newline aren't.
_NON_BASH_BLANK = re.compile(r"[^\S \t\n]")


def _declared_separators(source: str) -> int:
    """Count the command separators a whitelist pattern's source writes.

    Adjacent separator tokens are one separator: `&&`, `\\|\\|` and `\\|&` each join two commands.
    """
    count, previous = 0, False
    for token in _SOURCE_TOKEN.findall(source):
        current = token in _SEPARATOR_TOKENS
        if current and not previous:
            count += 1
        previous = current
    return count


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
    category: str = ""

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
        self._original_risk_levels: dict[str, RiskLevel] = {}

        self._load_rules()

        # Capture original risk levels for idempotent override application
        for rule in self.rules:
            self._original_risk_levels[rule.name] = rule.risk_level

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
        engine._original_risk_levels = {}

        # Load rules from all YAML files in directory
        engine._load_rules_from_directory(rules_dir)

        # Capture original risk levels for idempotent override application
        for rule in engine.rules:
            engine._original_risk_levels[rule.name] = rule.risk_level

        return engine

    def apply_overrides(
        self,
        rule_overrides: dict[str, dict],
        category_overrides: dict[str, dict],
    ) -> None:
        """Apply user/project overrides to loaded rules.

        Two-tier override system:
        1. Category overrides applied first (broad brush)
        2. Rule overrides applied second (fine-grained, wins over category)

        Security constraint: BLOCKED rules cannot be downgraded or disabled.

        Args:
            rule_overrides: Per-rule overrides keyed by rule name.
                Each value is a dict with optional keys: risk_level (str), enabled (bool).
            category_overrides: Per-category overrides keyed by category name.
                Each value is a dict with optional keys: risk_level (str), enabled (bool).
        """
        if not rule_overrides and not category_overrides:
            return

        # Phase 1: Apply category overrides
        updated_rules: list[SecurityRule] = []
        disabled_rules: set[str] = set()

        for rule in self.rules:
            new_rule = rule
            cat_override = category_overrides.get(rule.category) if rule.category else None
            original_level = self._original_risk_levels.get(rule.name, rule.risk_level)

            if cat_override and isinstance(cat_override, dict):
                new_rule = self._apply_single_override(new_rule, cat_override, source=f"category:{rule.category}")

            # Phase 2: Rule overrides take precedence
            # Pass original risk level so rule-level can override category upgrades
            rule_override = rule_overrides.get(rule.name)
            if rule_override and isinstance(rule_override, dict):
                new_rule = self._apply_single_override(
                    new_rule,
                    rule_override,
                    source=f"rule:{rule.name}",
                    original_risk_level=original_level,
                    allow_escape_hatch=True,
                )

            # Check if rule was disabled (only originally-BLOCKED rules are protected)
            # Uses original_level so that rules upgraded to BLOCKED by overrides
            # can still be disabled.
            if not self._is_rule_enabled(original_level, cat_override, rule_override, rule.name):
                disabled_rules.add(rule.name)
                continue

            updated_rules.append(new_rule)

        # Warn about unknown rule names
        known_names = {r.name for r in self.rules}
        for name in rule_overrides:
            if name not in known_names:
                logger.warning(f"Rule override references unknown rule: {name!r}")

        # Warn about unknown categories
        known_categories = {r.category for r in self.rules if r.category}
        for name in category_overrides:
            if name not in known_categories:
                logger.warning(f"Category override references unknown category: {name!r}")

        # Replace rules and clean up compiled patterns for disabled rules
        self.rules = updated_rules
        for rule_name in disabled_rules:
            self.compiled_patterns.pop(rule_name, None)

    _IMMUTABLE_CATEGORIES: frozenset[str] = frozenset({"self_protection"})

    def _apply_single_override(
        self,
        rule: SecurityRule,
        override: dict,
        source: str,
        original_risk_level: Optional["RiskLevel"] = None,
        allow_escape_hatch: bool = False,
    ) -> SecurityRule:
        """Apply a single override dict to a rule, respecting BLOCKED floor.

        Args:
            rule: The rule to potentially modify.
            override: Override dict with optional risk_level/enabled/allow_blocked_override keys.
            source: Human-readable source for log messages.
            original_risk_level: If provided, use this for the BLOCKED floor check
                instead of rule.risk_level. This allows rule-level overrides to
                downgrade a rule that was upgraded to BLOCKED by a category override,
                as long as the original rule was not BLOCKED.
            allow_escape_hatch: If True, allow_blocked_override in the override dict
                is honoured. Only rule-level overrides should pass True here.

        Returns:
            The original or replaced SecurityRule.
        """
        risk_str = override.get("risk_level")
        if risk_str is None:
            return rule

        risk_str = str(risk_str).upper()
        try:
            new_level = RiskLevel[risk_str]
        except KeyError:
            logger.warning(f"Invalid risk_level {risk_str!r} in {source}, skipping")
            return rule

        # BLOCKED floor: cannot downgrade originally-BLOCKED rules
        floor_level = original_risk_level if original_risk_level is not None else rule.risk_level
        if floor_level == RiskLevel.BLOCKED and new_level < RiskLevel.BLOCKED:
            # Self-protection rules are always immutable — no escape hatch
            if rule.category in self._IMMUTABLE_CATEGORIES:
                logger.warning(
                    f"Cannot downgrade self-protection rule {rule.name!r} via {source} — "
                    "self-protection rules are always immutable"
                )
                return rule

            # allow_blocked_override: true is the explicit opt-in escape hatch (rule-level only)
            if allow_escape_hatch and override.get("allow_blocked_override") is True:
                logger.warning(
                    f"SECURITY OVERRIDE: BLOCKED rule {rule.name!r} downgraded to "
                    f"{new_level.name} via {source}. Ensure this is intentional and audited."
                )
            else:
                logger.warning(f"Cannot downgrade BLOCKED rule {rule.name!r} via {source}")
                return rule

        if new_level != rule.risk_level:
            return replace(rule, risk_level=new_level)
        return rule

    def _is_rule_enabled(
        self,
        original_risk_level: "RiskLevel",
        category_override: Optional[dict],
        rule_override: Optional[dict],
        rule_name: str = "",
    ) -> bool:
        """Determine if a rule should remain enabled after overrides.

        Rule-level `enabled` takes precedence over category-level.
        Only originally-BLOCKED rules cannot be disabled (rules upgraded
        to BLOCKED by overrides can still be disabled).

        Args:
            original_risk_level: The rule's risk level from initial load.
            category_override: Category-level override dict (if any).
            rule_override: Rule-level override dict (if any).
            rule_name: Rule name for log messages.

        Returns:
            True if rule should remain enabled.
        """
        # Rule-level enabled takes precedence
        if rule_override and isinstance(rule_override, dict) and "enabled" in rule_override:
            if not rule_override["enabled"]:
                if original_risk_level == RiskLevel.BLOCKED:
                    logger.warning(f"Cannot disable BLOCKED rule {rule_name!r}")
                    return True
                return False
            return True

        # Category-level enabled
        if category_override and isinstance(category_override, dict) and "enabled" in category_override:
            if not category_override["enabled"]:
                if original_risk_level == RiskLevel.BLOCKED:
                    logger.warning(f"Cannot disable BLOCKED rule {rule_name!r} via category override")
                    return True
                return False

        return True

    def _load_rules(self) -> None:
        """Load and validate rules from YAML file or directory.

        Automatically detects if path is a directory and loads all YAML files,
        or loads a single file if path points to a file.

        Raises:
            ConfigurationError: If path doesn't exist, YAML is invalid,
                                or regex patterns don't compile
        """
        if not self.rules_path.exists():
            raise ConfigurationError(
                f"Rules path not found: {self.rules_path}",
                file_path=str(self.rules_path),
            )

        # Auto-detect directory vs file
        if self.rules_path.is_dir():
            self._load_rules_from_directory(self.rules_path)
            return

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
                # No re.MULTILINE: whitelist uses match() which anchors at start.
                # MULTILINE would change $ to match at line boundaries, not string end.
                compiled = re.compile(pattern_str)
                # Both whitelist checks refuse a command carrying ".." or a redirection
                # before consulting a pattern, and is_whitelisted() a line break too, so
                # an entry that describes one may never match and would otherwise fail
                # silently - the user writes a whitelist
                # rule for "psql db < schema.sql", sees it ignored, and has nothing to
                # go on. Advisory, not fatal: the source is a regex, so "\.\." here is
                # a literal ".." but a bare ".." is two wildcards and may be harmless.
                if _WHITELIST_DISQUALIFIER.search(pattern_str):
                    logger.warning(
                        f"Whitelist pattern {pattern_str!r} describes '..', a redirection or a "
                        f"newline; such commands are refused before patterns are consulted, so "
                        f"this entry may never match."
                    )
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

                # Derive category from filename: "02_file_destruction.yaml" -> "file_destruction"
                category = re.sub(r"^\d+_", "", yaml_file.stem)

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
                        rule_data["category"] = category
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
        """Check if a whitelist pattern matches the START of one command.

        Whitelisted commands always return SAFE regardless of other rules.

        This is a PREFIX test (`re.match`), which is what a single command needs — `^ls\\b`
        has to clear `ls -la`. It is therefore the WRONG test for anything that may hold more
        than one command: it would clear `ls && rm -rf /` on two characters. Use
        `is_whitelisted_whole` for a full command line. Pass this one a single command, and
        remember it reads only the front of it — a shipped entry with no trailing anchor also
        clears whatever trails the part it matched.

        Args:
            command: Command string to check

        Returns:
            True if command starts with any whitelist pattern and carries none of the
            _WHITELIST_DISQUALIFIER constructs
        """
        if _WHITELIST_DISQUALIFIER.search(command.rstrip()):
            return False
        return any(pattern.match(command) for pattern in self.whitelist_patterns)

    def is_whitelisted_whole(self, command: str, segment_count: int) -> bool:
        """Check if a whitelist entry describes this command line, commands and all.

        `is_whitelisted` is a prefix test, which is what a single command needs: `^ls\\b` is
        meant to clear `ls -la`. Applied to a line with several commands it clears the ones the
        author never wrote down — `^ls\\b` matches `ls && rm -rf /` on its first two characters,
        whitelisting the `rm`. So a line with several commands needs a different question.

        The question is whether the entry describes THIS MANY commands. An entry declares its
        count by writing separators: `^ls\\b` writes none and so speaks for one command and can
        never clear a line; the gh/docker entry writes one `\\|` and so speaks for exactly two.
        If bash finds more commands than the entry declared, the extra ones are not the author's
        and the entry does not cover them.

        Counting is what makes this hold for entries nobody has vetted -- a user's own included,
        where the two weaker tests do not:

        * Consuming the line is not sufficient. A pattern can be anchored AND open-ended -- an
          entry ending `(/.*)?$` has a `.*` that eats `&& rm -rf /` quite legitimately. It
          declares no separator, so it speaks for one command and clears no line.
        * Writing a separator is not sufficient either. Had the gh/docker entry's user slot been
          `\\S+`, which matches `;`, `docker login ghcr.io -u foo;sudo;true --password-stdin`
          would satisfy it end to end while bash runs four commands. Declared two, found four:
          refused.
        * And a newline is a separator to bash while `\\s` matches one, so an entry's own
          whitespace could span a line break its author never wrote. Counting sees through that
          too -- and, unlike rejecting newlines outright, it still clears the LEGAL multi-line
          spelling, `gh auth token |` + newline + `docker login ...`, which bash reads as one
          two-command pipeline because the newline follows a pipe.

        `\\s` also matches characters bash does NOT treat as blank (\\r, \\v, \\f, \\x1c-\\x1f,
        Unicode spaces), and the parser drops a line made only of them without counting it, so
        a line holding one is never cleared here. Refusing the whitelist is not refusing the
        command: the line is then judged one command at a time.

        A redirection is not a command, so it leaves the count unchanged, and a `\\S+` slot accepts
        `>/path` as readily as a user name. So this gate also refuses a line carrying `..` or a
        redirection (_WHOLE_LINE_DISQUALIFIER, for the reasons at _WHITELIST_DISQUALIFIER), but
        not a line break, which the count already judges. Beyond those, how loose a single
        command's arguments are is the entry's own shape to fix, not this gate's.

        Args:
            command: Full command line being validated
            segment_count: How many commands the parser found in it

        Returns:
            True if a whitelist entry declares exactly this many commands and matches them all,
            and the line carries neither `..` nor a redirection
        """
        if _NON_BASH_BLANK.search(command) or _WHOLE_LINE_DISQUALIFIER.search(command):
            return False
        # Surrounding blank space is not executable content, and `$` matches BEFORE a trailing
        # newline while `fullmatch` would have to consume it -- without this, a trailing "\n"
        # unseats the anchored entry and lands the pipeline on BLOCKED. After the guard above,
        # only space, tab and newline are left for this to strip.
        command = command.strip()
        for pattern in self.whitelist_patterns:
            declared = _declared_separators(pattern.pattern)
            if declared and declared + 1 == segment_count and pattern.fullmatch(command):
                return True
        return False

    def match_command(
        self,
        command: str,
        string_literals: Optional[list[tuple]] = None,
        heredoc_ranges: Optional[list[tuple]] = None,
        use_whitelist: bool = True,
    ) -> RuleMatch:
        """Match command against all rules, return highest risk.

        Matching algorithm:
        1. Check whitelist first (returns SAFE if matched)
        2. Match against all rules, collect all matches
        3. Skip OCCURRENCES that fall inside quoted string literals (AST context)
        4. Skip OCCURRENCES inside non-shell heredocs (text, not executed)
        5. Return highest risk level match

        A pattern only fails to match when EVERY one of its occurrences is
        suppressed - a quoted decoy does not excuse an unquoted occurrence
        later in the same command (LAB-4321).

        Args:
            command: Command string to validate
            string_literals: Optional list of (start, end) positions for quoted strings
                           from AST analysis. Matches inside these ranges are ignored.
            heredoc_ranges: Optional list of (start, end, is_shell) tuples for heredocs.
                          Matches inside non-shell heredocs are ignored (just text).
            use_whitelist: Consult the whitelist before matching rules. Pass False when
                          the caller has already settled the whitelist question — the
                          multi-segment path does, with the whole-line
                          is_whitelisted_whole() where this check is prefix-based.

        Returns:
            RuleMatch with highest risk level from all matching rules

        Example:
            >>> engine = RuleEngine("rules.yaml")
            >>> match = engine.match_command("rm -rf /tmp/test")
            >>> if not match.matched:
            ...     print("Command is safe")

            >>> # With AST context to avoid false positives
            >>> match = engine.match_command('echo "rm -rf /"', string_literals=[(6, 15)])
            >>> # The match at 6-11 is inside the string literal (6, 15), so it is ignored
        """
        # Whitelist override
        if use_whitelist and self.is_whitelisted(command):
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
                match = self._first_executable_match(pattern, command, string_literals, heredoc_ranges)
                if match:
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

    def _first_executable_match(
        self,
        pattern: "re.Pattern",
        command: str,
        string_literals: Optional[list[tuple]],
        heredoc_ranges: Optional[list[tuple]],
    ) -> Optional["re.Match"]:
        """First match of `pattern` that is not inert text, or None.

        SECURITY CRITICAL: keep scanning past a suppressed match. Stopping at the
        first one lets an inert decoy hide a real hit from the SAME pattern --
        `cat \':(){ :|:& };:\'` followed by a newline and the same fork bomb unquoted
        rated SAFE, because the quoted decoy consumed the rule\'s only search.
        Pick the example carefully: `rm -rf /` hides the leak, because
        `system_destruction`'s `[^;|&]` run crosses the newline, so its first match
        starts inside the decoy, ends at the payload, and is never suppressed.

        Advances by one character rather than to match.end() so a later match that
        overlaps the suppressed one is still found.

        The scan is EXACT - it never gives up early. A bound here looks like cheap
        insurance and is not: reporting anything other than "first executable match,
        or none" on exhaustion is wrong in one direction or the other. Reporting the
        last suppressed match denies benign text (a quoted doc listing 32 `sudo`
        lines) under a rule that never matched, which the ask prompt and the audit
        log then repeat. Returning None instead lets padding silence the rule.
        Measured, the bound bought ~1%; the superlinearity lives elsewhere.
        Termination is structural: `pos` strictly increases every iteration.
        """
        pos = 0
        while True:
            match = pattern.search(command, pos)
            if match is None:
                return None
            in_literal = bool(string_literals) and self._is_in_string_literal(match, string_literals)
            in_heredoc = bool(heredoc_ranges) and self._is_in_non_shell_heredoc(match, heredoc_ranges)
            if not (in_literal or in_heredoc):
                return match
            pos = match.start() + 1

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

    def _is_in_non_shell_heredoc(self, match: re.Match, heredoc_ranges: list[tuple]) -> bool:
        """Check if a regex match falls within a non-shell heredoc.

        SECURITY: Heredoc content going to non-shell commands (like cat, echo) is just
        text output - it won't be executed. Only heredocs going to shells (bash, sh, etc.)
        should trigger pattern matches.

        Args:
            match: Regex match object
            heredoc_ranges: List of (start, end, is_shell) tuples for heredocs

        Returns:
            True if match is inside a heredoc going to a NON-shell command (safe to ignore)
        """
        match_start = match.start()
        match_end = match.end()

        for start, end, is_shell in heredoc_ranges:
            # If match is inside this heredoc range
            if start <= match_start and match_end <= end:
                # If it's NOT going to a shell, we can safely ignore this match
                if not is_shell:
                    return True
        return False
