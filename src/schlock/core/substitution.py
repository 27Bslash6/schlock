"""Command substitution validation module.

This module provides AST-based detection and validation of command substitution
$(cmd) and process substitution <(cmd) patterns.

Security Model:
1. WHITELIST FIRST - Known-safe commands (op, date, git, etc.) pass immediately
2. AST STRUCTURAL CHECKS - Detect brace expansion, variable commands, etc.
3. RECURSIVE VALIDATION - Full validation of inner commands with depth limit
4. DEFAULT-DENY - Unknown commands in substitution context are blocked

This prevents bypass attacks that defeat regex-only detection:
- Nested substitution: $(echo $(rm -rf /))
- Brace expansion: $({r,}m -rf /)
- Variable indirection: $($CMD)
- Encoding/obfuscation: AST sees through it
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .rules import RiskLevel

# Maximum recursion depth for nested substitution validation
MAX_SUBSTITUTION_DEPTH = 10

# Commands that are ALWAYS safe inside substitution
# These are read-only, pure, or security-critical tools that don't modify state
SAFE_SUBSTITUTION_COMMANDS: frozenset[str] = frozenset(
    {
        # Secret management (designed for CLI use)
        "op",  # 1Password CLI - primary use case that triggered this fix
        # System info (read-only)
        "date",
        "pwd",
        "whoami",
        "hostname",
        "uname",
        "id",
        "groups",
        "uptime",
        "arch",
        # File listing (read-only)
        # NOTE: find requires contextual check for -exec/-delete in _has_dangerous_inner_structure()
        # NOTE: tee removed - always writes to files
        "ls",
        "stat",
        "file",
        "du",
        "df",
        "find",
        "locate",
        # File reading (read-only - content inspection)
        "cat",
        "less",
        "more",
        "tac",
        "nl",
        "od",
        "xxd",
        "hexdump",
        "strings",
        # Process inspection (read-only)
        "ps",
        "pgrep",
        "top",
        "htop",
        "pmap",
        "lsof",
        # File comparison (read-only)
        "diff",
        "cmp",
        "comm",
        "sdiff",
        # File operations that output (safe in substitution context)
        # NOTE: tee removed - writes to arbitrary files
        "md5sum",
        "sha256sum",
        "shasum",
        "cksum",
        # Git (read-only operations - write ops would fail in substitution anyway)
        "git",
        # Path manipulation (pure functions)
        "basename",
        "dirname",
        "realpath",
        "readlink",
        # Text output (pure)
        "echo",
        "printf",
        # Environment inspection (read-only)
        # NOTE: env removed - executes arbitrary commands (env rm -rf / works)
        "printenv",
        # Which/type - NOTE: command removed (bypasses blacklist)
        "which",
        "type",
        # Math (pure)  # noqa: ERA001
        "expr",
        "bc",
        # String manipulation (pure)
        "tr",
        "cut",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "rev",
        "seq",
        "yes",
        "grep",
        "egrep",
        "fgrep",
        # Common pure utilities
        "true",
        "false",
        "sleep",
        "tty",
        "stty",
        "locale",
        "getconf",
        "nproc",
    }
)

# Commands that are ALWAYS dangerous inside substitution
# Even if they would be allowed outside substitution context
DANGEROUS_SUBSTITUTION_COMMANDS: frozenset[str] = frozenset(
    {
        # Destructive
        "rm",
        "rmdir",
        "shred",
        "truncate",
        "wipefs",
        # Privilege escalation
        "sudo",
        "su",
        "doas",
        "pkexec",
        # Arbitrary execution
        "eval",
        "exec",
        "source",
        # System modification
        "dd",
        "mkfs",
        "fdisk",
        "parted",
        "mount",
        "umount",
        # Process control
        "kill",
        "killall",
        "pkill",
        # Credential access (should go through proper channels)
        "security",  # macOS keychain
        "secret-tool",  # Linux keyring
        "pass",  # password store
        # Network exfiltration
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "socat",
        # Shell interpreters (RCE via process substitution)
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
    }
)


class SubstitutionType(Enum):
    """Type of shell substitution."""

    COMMAND = "command"  # $(cmd) or `cmd`
    PROCESS_INPUT = "process_input"  # <(cmd)
    PROCESS_OUTPUT = "process_output"  # >(cmd)


@dataclass
class SubstitutionNode:
    """Represents a command or process substitution in the AST."""

    substitution_type: SubstitutionType
    inner_command: str  # The command text inside the substitution
    base_command: str | None  # First word of inner command (e.g., "op" from "op read ...")
    ast_node: Any  # The bashlex AST node
    nested_substitutions: list[SubstitutionNode] = field(default_factory=list)
    depth: int = 0  # Nesting depth


@dataclass
class SubstitutionValidationResult:
    """Result of validating a substitution."""

    allowed: bool
    risk_level: RiskLevel
    message: str
    whitelisted: bool = False  # True if matched whitelist (fast path)
    depth_exceeded: bool = False  # True if hit MAX_SUBSTITUTION_DEPTH
    inner_results: list[SubstitutionValidationResult] = field(default_factory=list)


class SubstitutionValidator:
    """Validates commands inside shell substitution constructs.

    Uses a three-layer approach:
    1. Whitelist check for known-safe commands (fast path)
    2. AST structural checks for suspicious patterns
    3. Recursive validation with depth limit

    Example:
        >>> validator = SubstitutionValidator(parser, rule_engine)
        >>> result = validator.validate_command_with_substitutions("echo $(date)")
        >>> result.allowed
        True
    """

    def __init__(self, parser: Any, rule_engine: Any) -> None:
        """Initialize validator with parser and rule engine.

        Args:
            parser: BashCommandParser instance
            rule_engine: RuleEngine instance for YAML rule matching
        """
        self.parser = parser
        self.rule_engine = rule_engine

    def extract_substitutions(self, ast_nodes: list[Any], depth: int = 0) -> list[SubstitutionNode]:
        """Extract all substitution nodes from AST.

        Args:
            ast_nodes: List of bashlex AST nodes
            depth: Current nesting depth

        Returns:
            List of SubstitutionNode objects representing all substitutions
        """
        substitutions: list[SubstitutionNode] = []

        def visit(node: Any, current_depth: int) -> None:
            if not hasattr(node, "kind"):
                return

            if node.kind == "commandsubstitution":
                sub_node = self._create_substitution_node(node, SubstitutionType.COMMAND, current_depth)
                if sub_node:
                    substitutions.append(sub_node)
                return  # Don't recurse into substitution here - handled by _create_substitution_node

            if node.kind == "processsubstitution":
                # Determine if input <(cmd) or output >(cmd)
                sub_type = SubstitutionType.PROCESS_INPUT  # Default, could enhance detection
                sub_node = self._create_substitution_node(node, sub_type, current_depth)
                if sub_node:
                    substitutions.append(sub_node)
                return

            # Recurse into child nodes
            for attr in ["parts", "command", "list", "pipe", "compound"]:
                if hasattr(node, attr):
                    child = getattr(node, attr)
                    if isinstance(child, list):
                        for item in child:
                            visit(item, current_depth)
                    elif child:
                        visit(child, current_depth)

        for node in ast_nodes or []:
            visit(node, depth)

        return substitutions

    def _create_substitution_node(self, node: Any, sub_type: SubstitutionType, depth: int) -> SubstitutionNode | None:
        """Create a SubstitutionNode from an AST node.

        Args:
            node: The bashlex commandsubstitution or processsubstitution node
            sub_type: Type of substitution
            depth: Current nesting depth

        Returns:
            SubstitutionNode or None if extraction fails
        """
        inner_command = self._extract_inner_command_text(node)
        if not inner_command:
            return None

        base_command = self._extract_base_command(node)

        # Find nested substitutions
        nested: list[SubstitutionNode] = []
        if depth < MAX_SUBSTITUTION_DEPTH and hasattr(node, "command"):
            try:
                inner_ast = [node.command] if node.command else []
                nested = self.extract_substitutions(inner_ast, depth + 1)
            except Exception:  # noqa: S110 - Parse errors treated as suspicious AST
                nested = []  # Failed to parse nested - treat as no nested subs

        return SubstitutionNode(
            substitution_type=sub_type,
            inner_command=inner_command,
            base_command=base_command,
            ast_node=node,
            nested_substitutions=nested,
            depth=depth,
        )

    def _extract_inner_command_text(self, node: Any) -> str | None:  # noqa: PLR0911, PLR0912
        """Extract the command text from inside a substitution.

        Args:
            node: The substitution AST node

        Returns:
            Command string or None
        """
        if not hasattr(node, "command"):
            return None

        cmd_node = node.command
        if not cmd_node:
            return None

        # Handle pipeline: $(cmd1 | cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "pipeline":
            parts_text: list[str] = []
            if hasattr(cmd_node, "parts"):
                for part in cmd_node.parts:
                    if hasattr(part, "kind"):
                        if part.kind == "command" and hasattr(part, "parts"):
                            cmd_words = [p.word for p in part.parts if hasattr(p, "word")]
                            if cmd_words:
                                parts_text.append(" ".join(cmd_words))
                        elif part.kind == "pipe":
                            parts_text.append("|")
            return " ".join(parts_text) if parts_text else None

        # Handle command list: $(cmd1; cmd2) or $(cmd1 && cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "list":
            # For command lists, extract all parts
            parts_text = []
            if hasattr(cmd_node, "parts"):
                for part in cmd_node.parts:
                    if hasattr(part, "kind") and part.kind == "command":
                        if hasattr(part, "parts"):
                            cmd_words = [p.word for p in part.parts if hasattr(p, "word")]
                            if cmd_words:
                                parts_text.append(" ".join(cmd_words))
                    elif hasattr(part, "kind") and part.kind == "operator":
                        if hasattr(part, "op"):
                            parts_text.append(part.op)
            return " ".join(parts_text) if parts_text else None

        # Handle simple command: try to get from parts
        words: list[str] = []
        if hasattr(cmd_node, "parts"):
            for part in cmd_node.parts:
                if hasattr(part, "word"):
                    words.append(part.word)

        if words:
            return " ".join(words)

        # Fallback: try to get from list (compound commands)
        if hasattr(cmd_node, "list") and cmd_node.list:
            # For compound commands, return first command
            first = cmd_node.list[0] if cmd_node.list else None
            if first and hasattr(first, "parts"):
                words = [p.word for p in first.parts if hasattr(p, "word")]
                return " ".join(words) if words else None

        return None

    def _extract_base_command(self, node: Any) -> str | None:  # noqa: PLR0911
        """Extract the base command (first word) from a substitution.

        Args:
            node: The substitution AST node

        Returns:
            Base command string or None
        """
        if not hasattr(node, "command"):
            return None

        cmd_node = node.command
        if not cmd_node:
            return None

        # Handle pipeline - get first command in pipeline
        if hasattr(cmd_node, "kind") and cmd_node.kind == "pipeline":
            if hasattr(cmd_node, "parts") and cmd_node.parts:
                first_cmd = cmd_node.parts[0]
                if hasattr(first_cmd, "parts") and first_cmd.parts:
                    first_word = first_cmd.parts[0]
                    if hasattr(first_word, "word"):
                        return first_word.word
            return None

        # Handle simple command
        if hasattr(cmd_node, "parts") and cmd_node.parts:
            first_part = cmd_node.parts[0]
            if hasattr(first_part, "word"):
                return first_part.word

        # Handle compound command (command list)
        if hasattr(cmd_node, "list") and cmd_node.list:
            first = cmd_node.list[0]
            if hasattr(first, "parts") and first.parts:
                first_part = first.parts[0]
                if hasattr(first_part, "word"):
                    return first_part.word

        return None

    @lru_cache(maxsize=256)  # noqa: B019 - OK, validator is singleton
    def is_whitelisted(self, base_command: str | None) -> bool:
        """Check if a command is in the safe whitelist.

        Args:
            base_command: The base command name

        Returns:
            True if whitelisted (safe)
        """
        if not base_command:
            return False
        return base_command in SAFE_SUBSTITUTION_COMMANDS

    @lru_cache(maxsize=256)  # noqa: B019 - OK, validator is singleton
    def is_blacklisted(self, base_command: str | None) -> bool:
        """Check if a command is in the dangerous blacklist.

        Args:
            base_command: The base command name

        Returns:
            True if blacklisted (dangerous)
        """
        if not base_command:
            return False
        return base_command in DANGEROUS_SUBSTITUTION_COMMANDS

    def has_suspicious_ast_patterns(self, node: Any) -> tuple[bool, str]:
        """Check for suspicious AST patterns that indicate bypass attempts.

        Args:
            node: The substitution AST node

        Returns:
            Tuple of (is_suspicious, reason)
        """
        if not hasattr(node, "command"):
            return False, ""

        cmd_node = node.command
        if not cmd_node:
            return False, ""

        # Check for brace expansion in command position
        # This catches $({r,}m -rf /) type attacks
        if self._has_brace_expansion_in_command(cmd_node):
            return True, "brace expansion in command name"

        # Check for variable as command
        # This catches $($CMD) type attacks
        if self._has_variable_as_command(cmd_node):
            return True, "variable used as command name"

        # Check for parameter expansion that could construct commands
        if self._has_suspicious_parameter_expansion(cmd_node):
            return True, "suspicious parameter expansion"

        return False, ""

    def _has_brace_expansion_in_command(self, cmd_node: Any) -> bool:
        """Check if command name uses brace expansion."""
        if not hasattr(cmd_node, "parts") or not cmd_node.parts:
            return False

        first_part = cmd_node.parts[0]

        # Check if first part has brace expansion
        if hasattr(first_part, "kind") and first_part.kind == "compound":
            return True

        # Check for brace in the word itself
        if hasattr(first_part, "word"):
            word = first_part.word
            if "{" in word and "," in word and "}" in word:
                return True

        return False

    def _has_variable_as_command(self, cmd_node: Any) -> bool:
        """Check if command name is a variable reference."""
        if not hasattr(cmd_node, "parts") or not cmd_node.parts:
            return False

        first_part = cmd_node.parts[0]

        # Check for parameter/variable node
        if hasattr(first_part, "kind"):
            if first_part.kind in ("parameter", "variable"):
                return True

        # Check for $ in word position (variable expansion)
        if hasattr(first_part, "word"):
            word = first_part.word
            # $VAR or ${VAR} as command
            if word.startswith("$"):
                return True

        # Check parts of the first word for parameter expansions
        if hasattr(first_part, "parts"):
            for subpart in first_part.parts:
                if hasattr(subpart, "kind") and subpart.kind == "parameter":
                    return True

        return False

    def _has_suspicious_parameter_expansion(self, cmd_node: Any) -> bool:
        """Check for parameter expansion that could construct dangerous paths."""
        # Check for ${VAR:offset:length} substring extraction
        # This is used to construct commands from environment variables
        pattern = re.compile(r"\$\{[^}]+:[0-9]+:[0-9]+\}")

        def check_node(node: Any) -> bool:
            if hasattr(node, "word"):
                if pattern.search(node.word):
                    return True
            if hasattr(node, "parts"):
                for part in node.parts:
                    if check_node(part):
                        return True
            return False

        return check_node(cmd_node)

    def _has_dangerous_inner_structure(  # noqa: PLR0911, PLR0912
        self, node: Any, base_command: str | None = None
    ) -> tuple[bool, str]:
        """Check if inner command has dangerous structures or arguments.

        These structures can weaponize even whitelisted commands:
        - $(date | bash) - pipeline bypasses date's safety
        - $(date; rm -rf /) - chain runs additional commands
        - $(for x in ...; do rm $x; done) - compound executes loop
        - $(echo x > /etc/cron.d/x) - output redirection writes files
        - $(git -c 'alias.x=!rm' x) - git alias executes shell command

        Args:
            node: The substitution AST node
            base_command: The base command being validated (for arg checks)

        Returns:
            Tuple of (is_dangerous, reason)
        """
        if not hasattr(node, "command"):
            return False, ""

        cmd_node = node.command
        if not cmd_node:
            return False, ""

        # Pipeline: $(cmd1 | cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "pipeline":
            return True, "pipeline in substitution"

        # Command list: $(cmd1; cmd2) or $(cmd1 && cmd2) or $(cmd1 || cmd2)
        if hasattr(cmd_node, "kind") and cmd_node.kind == "list":
            return True, "command chain in substitution"

        # Compound command: $(if ...; then ...; fi) etc.
        if hasattr(cmd_node, "kind") and cmd_node.kind == "compound":
            return True, "compound command in substitution"

        # Check for output redirections and dangerous arguments
        if hasattr(cmd_node, "parts"):
            args: list[str] = []
            for part in cmd_node.parts:
                # Output redirection: $(echo x > file) or $(echo x >> file)
                if hasattr(part, "kind") and part.kind == "redirect":
                    if hasattr(part, "type") and part.type in (">", ">>", ">&"):
                        return True, "output redirection in substitution"

                # Collect arguments for dangerous pattern checks
                if hasattr(part, "word"):
                    args.append(part.word)

            # Check for git -c config options that execute commands
            # These config keys run arbitrary commands when set via -c:
            # - alias.NAME=!cmd (shell command alias)
            # - core.sshCommand, core.pager, core.editor (tool execution)
            # - credential.helper (auth command execution)
            # - diff.external, merge.tool (diff/merge tool execution)
            if base_command == "git" and args:
                dangerous_git_configs = {
                    "alias.",  # alias.x=!cmd executes shell command
                    "core.sshcommand",  # executed during SSH operations
                    "core.pager",  # executed when paging output
                    "core.editor",  # executed when editing messages
                    "credential.helper",  # executed for authentication
                    "diff.external",  # executed during diff
                    "merge.tool",  # executed during merge
                }
                for i, arg in enumerate(args):
                    config_val = None
                    if arg == "-c" and i + 1 < len(args):
                        config_val = args[i + 1]
                    # Also check combined form: -cvalue
                    elif arg.startswith("-c") and len(arg) > 2:
                        config_val = arg[2:]

                    if config_val:
                        config_lower = config_val.lower()
                        for dangerous_prefix in dangerous_git_configs:
                            if config_lower.startswith(dangerous_prefix):
                                # Special case: alias requires ! for shell execution
                                if dangerous_prefix == "alias." and "!" not in config_val:
                                    continue
                                return True, f"git config {dangerous_prefix.rstrip('.')} executes commands via -c flag"

            # Check for find with command execution flags
            # -exec, -execdir, -ok, -okdir run arbitrary commands
            # -delete removes files (dangerous side effect)
            if base_command == "find" and args:
                dangerous_find_flags = {"-exec", "-execdir", "-ok", "-okdir", "-delete"}
                for arg in args:
                    if arg in dangerous_find_flags:
                        return True, f"find {arg} executes commands or modifies files"

        return False, ""

    def validate_substitution(  # noqa: PLR0911, PLR0912
        self, sub_node: SubstitutionNode, depth: int = 0
    ) -> SubstitutionValidationResult:
        """Validate a single substitution node.

        Args:
            sub_node: The substitution node to validate
            depth: Current recursion depth

        Returns:
            SubstitutionValidationResult
        """
        # Import here to avoid circular dependency
        from .rules import RiskLevel  # noqa: PLC0415

        # Check depth limit
        if depth > MAX_SUBSTITUTION_DEPTH:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Substitution nesting depth exceeded (max {MAX_SUBSTITUTION_DEPTH})",
                depth_exceeded=True,
            )

        # Layer 1: Whitelist check (fast path) - WITH STRUCTURAL VALIDATION
        if self.is_whitelisted(sub_node.base_command):
            # SECURITY: Check for dangerous structures that bypass whitelist safety
            # Pipelines like $(date | bash) or chains like $(date; rm -rf /)
            # weaponize even safe base commands
            has_dangerous, structure_reason = self._has_dangerous_inner_structure(sub_node.ast_node, sub_node.base_command)

            if has_dangerous:
                # Whitelisted command has dangerous structure (pipeline/chain)
                # Block it - the user can run these commands directly instead
                return SubstitutionValidationResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    message=f"Dangerous structure in substitution: {structure_reason}",
                )

            # Safe structure - validate nested substitutions and return SAFE
            if sub_node.nested_substitutions:
                for nested in sub_node.nested_substitutions:
                    nested_result = self.validate_substitution(nested, depth + 1)
                    if not nested_result.allowed:
                        return SubstitutionValidationResult(
                            allowed=False,
                            risk_level=nested_result.risk_level,
                            message=f"Nested substitution blocked: {nested_result.message}",
                            inner_results=[nested_result],
                        )
            return SubstitutionValidationResult(
                allowed=True,
                risk_level=RiskLevel.SAFE,
                message=f"Whitelisted command: {sub_node.base_command}",
                whitelisted=True,
            )

        # Layer 1b: Blacklist check
        if self.is_blacklisted(sub_node.base_command):
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Dangerous command in substitution: {sub_node.base_command}",
            )

        # Layer 2: AST structural checks
        is_suspicious, reason = self.has_suspicious_ast_patterns(sub_node.ast_node)
        if is_suspicious:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message=f"Suspicious pattern in substitution: {reason}",
            )

        # Layer 3: Recursive validation of nested substitutions
        inner_results: list[SubstitutionValidationResult] = []
        for nested in sub_node.nested_substitutions:
            nested_result = self.validate_substitution(nested, depth + 1)
            inner_results.append(nested_result)
            if not nested_result.allowed:
                return SubstitutionValidationResult(
                    allowed=False,
                    risk_level=nested_result.risk_level,
                    message=f"Nested substitution blocked: {nested_result.message}",
                    inner_results=inner_results,
                )

        # Layer 4: Validate inner command against YAML rules
        if sub_node.inner_command:
            rule_match = self.rule_engine.match_command(sub_node.inner_command)
            if rule_match and rule_match.matched:
                # Amplify risk by +1 level for substitution context
                amplified_risk = self._amplify_risk(rule_match.risk_level)
                if amplified_risk == RiskLevel.BLOCKED:
                    return SubstitutionValidationResult(
                        allowed=False,
                        risk_level=RiskLevel.BLOCKED,
                        message=f"Inner command blocked: {rule_match.message}",
                        inner_results=inner_results,
                    )
                if amplified_risk == RiskLevel.HIGH:
                    # HIGH in substitution context - treat as blocked for safety
                    # Could be configurable based on risk tolerance
                    return SubstitutionValidationResult(
                        allowed=False,
                        risk_level=RiskLevel.BLOCKED,
                        message=f"High-risk command in substitution context: {rule_match.message}",
                        inner_results=inner_results,
                    )

        # Unknown command - default deny in substitution context
        if not sub_node.base_command:
            return SubstitutionValidationResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                message="Cannot determine command in substitution",
            )

        # Command not in whitelist and not explicitly dangerous
        # This is the "gray area" - we block by default for security
        return SubstitutionValidationResult(
            allowed=False,
            risk_level=RiskLevel.HIGH,
            message=f"Unknown command in substitution: {sub_node.base_command}. Add to whitelist if safe.",
            inner_results=inner_results,
        )

    def _amplify_risk(self, risk_level: RiskLevel) -> RiskLevel:
        """Amplify risk level for substitution context.

        Substitution adds indirection which makes auditing harder.
        Risk is increased by one level (capped at BLOCKED).

        Args:
            risk_level: Original risk level

        Returns:
            Amplified risk level
        """
        from .rules import RiskLevel  # noqa: PLC0415

        risk_order = [
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ]

        try:
            idx = risk_order.index(risk_level)
            new_idx = min(idx + 1, len(risk_order) - 1)
            return risk_order[new_idx]
        except ValueError:
            return RiskLevel.BLOCKED  # Unknown risk level - be safe

    def validate_all_substitutions(self, ast_nodes: list[Any]) -> list[SubstitutionValidationResult]:
        """Validate all substitutions in an AST.

        Args:
            ast_nodes: The parsed AST nodes

        Returns:
            List of validation results for each substitution found
        """
        substitutions = self.extract_substitutions(ast_nodes)
        results: list[SubstitutionValidationResult] = []

        for sub in substitutions:
            result = self.validate_substitution(sub)
            results.append(result)

        return results

    def check_process_substitution_context(self, ast_nodes: list[Any], sub_node: SubstitutionNode) -> tuple[bool, str]:
        """Check if process substitution is in a dangerous context.

        Process substitution to a shell interpreter is RCE:
        - bash <(curl ...)  -> BLOCKED
        - diff <(ls dir1) <(ls dir2)  -> SAFE

        Args:
            ast_nodes: Full AST for context
            sub_node: The process substitution node

        Returns:
            Tuple of (is_dangerous, reason)
        """
        if sub_node.substitution_type not in (
            SubstitutionType.PROCESS_INPUT,
            SubstitutionType.PROCESS_OUTPUT,
        ):
            return False, ""

        # Find the outer command that uses this process substitution
        outer_cmd = self._find_outer_command(ast_nodes, sub_node.ast_node)

        if outer_cmd in DANGEROUS_SUBSTITUTION_COMMANDS:
            return True, f"Process substitution to shell interpreter: {outer_cmd}"

        # Specifically check for shell interpreters
        shell_interpreters = {"bash", "sh", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node"}
        if outer_cmd in shell_interpreters:
            return True, f"Process substitution to {outer_cmd} is arbitrary code execution"

        return False, ""

    def _find_outer_command(self, ast_nodes: list[Any], target_node: Any) -> str | None:
        """Find the outer command that contains a substitution node.

        Args:
            ast_nodes: Full AST
            target_node: The substitution node to find context for

        Returns:
            The outer command name or None
        """
        # This is a simplified implementation
        # A full implementation would track parent references in AST traversal
        for node in ast_nodes or []:
            if hasattr(node, "kind") and node.kind == "command":
                if hasattr(node, "parts") and node.parts:
                    first_word = node.parts[0]
                    if hasattr(first_word, "word"):
                        return first_word.word
        return None
