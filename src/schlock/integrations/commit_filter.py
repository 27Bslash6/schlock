"""Commit message content filtering.

This module provides optional filtering of commit messages to remove unwanted
content (advertising, profanity, policy violations) based on configurable
pattern-based rules.

The filter is designed to be fail-open - if filtering encounters errors,
the original commit is allowed (usability over perfection, not security-critical).

ARCHITECTURE NOTE: Commit Filter vs Security Validator
=======================================================
This module uses bashlex parsing for commit message extraction.
It is INTENTIONALLY SEPARATE from core/parser.py (security validator).

KEY DIFFERENCES:
1. Failure Mode:
   - commit_filter.py: FAIL-OPEN (pass through on error)
   - core/parser.py: FAIL-CLOSED (block on error)

2. Purpose:
   - commit_filter.py: Cosmetic filtering (advertising removal)
   - core/parser.py: Safety validation (prevent dangerous commands)

3. Error Handling:
   - commit_filter.py: Catch exceptions, return None, allow command
   - core/parser.py: Raise ParseError, deny command execution

DO NOT merge these parsers. Different failure semantics require separate code paths.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import bashlex
import bashlex.errors

logger = logging.getLogger(__name__)

# Size limit to prevent DoS via huge commands (64KB is generous for commit messages)
MAX_COMMAND_SIZE = 64 * 1024


@dataclass(frozen=True)
class FilterResult:
    """Result of commit message filtering.

    Attributes:
        cleaned_command: Git command with filtered message (or original if no changes)
        original_message: Original commit message extracted from command
        cleaned_message: Message after filtering (or original if no changes)
        was_modified: True if filtering changed the message
        patterns_removed: List of patterns that matched (with category info)
        categories_matched: List of category names that had matches
        error: Error message if filtering failed (None on success)
        message_delivery: How the message reaches git ("scannable" | "unscannable" | "none").
            See CommitMessageFilter.classify_message_delivery.
        unscannable_decision: Decision for an unscannable content-bearing commit (issue #76):
            None (not applicable, or policy is "off"), "warn", or "block". Distinct from the
            filter's configured policy CommitMessageFilter.unscannable_action ("off" maps here
            to None); this field is the per-command outcome the hook acts on.
        unscannable_reason: Human-readable explanation when unscannable_decision is set.
    """

    cleaned_command: str
    original_message: str
    cleaned_message: str
    was_modified: bool
    patterns_removed: list[dict[str, str]] = field(default_factory=list)
    categories_matched: list[str] = field(default_factory=list)
    error: Optional[str] = None
    message_delivery: str = "none"
    unscannable_decision: Optional[str] = None
    unscannable_reason: str = ""


class CommitMessageFilter:
    """Filter commit messages based on configurable pattern rules.

    The filter operates in three phases:
    1. Extract: Parse git command to get commit message
    2. Filter: Apply enabled rule categories, remove matched patterns
    3. Rewrite: Reconstruct git command with cleaned message

    Example:
        >>> filter = CommitMessageFilter(config)
        >>> result = filter.filter_commit_message('git commit -m "Add feature\\n\\nGenerated with Claude Code"')
        >>> print(result.was_modified)  # True
        >>> print(result.cleaned_message)  # "Add feature"
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize filter with configuration.

        Args:
            config: Configuration dict with structure:
                {
                    "enabled": bool,  # Master enable/disable
                    "rules": {
                        "category_name": {
                            "enabled": bool,
                            "patterns": [
                                {"pattern": str, "description": str, "replacement": str},
                                ...
                            ]
                        },
                        ...
                    },
                    "custom_patterns": [...]  # User-defined patterns
                }

        Raises:
            ValueError: If configuration is invalid
        """
        self.config = config
        self.enabled = config.get("enabled", True)  # Default: enabled

        # Policy for commit messages whose content is NOT in argv (issue #76): file/stdin
        # delivery or unevaluated substitution. "warn" is the safe default — non-destructive
        # but not silent. Invalid values fall back to "warn" rather than raising.
        action = str(config.get("unscannable_message_action", "warn")).strip().lower()
        self.unscannable_action = action if action in ("off", "warn", "block") else "warn"

        # Compile patterns from enabled categories
        self._compiled_patterns: list[tuple[re.Pattern, str, str, str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns from enabled categories.

        Builds self._compiled_patterns list with tuples:
        (compiled_regex, category, description, replacement)
        """
        if not self.enabled:
            return  # Skip compilation if filter disabled

        rules = self.config.get("rules", {})
        for category, category_config in rules.items():
            if not category_config.get("enabled", False):
                continue  # Skip disabled categories

            patterns = category_config.get("patterns", [])
            for pattern_def in patterns:
                try:
                    pattern_str = pattern_def["pattern"]
                    description = pattern_def.get("description", "")
                    replacement = pattern_def.get("replacement", "")

                    # Compile with DOTALL | MULTILINE for cross-line matching
                    compiled = re.compile(pattern_str, re.DOTALL | re.MULTILINE)
                    self._compiled_patterns.append((compiled, category, description, replacement))
                except (KeyError, re.error) as e:
                    logger.warning(f"Invalid pattern in category '{category}': {e}. Skipping.")
                    continue  # Skip invalid patterns, continue with valid ones

        # Add custom patterns (if any)
        custom_patterns = self.config.get("custom_patterns", [])
        for pattern_def in custom_patterns:
            try:
                pattern_str = pattern_def["pattern"]
                description = pattern_def.get("description", "Custom pattern")
                replacement = pattern_def.get("replacement", "")

                compiled = re.compile(pattern_str, re.DOTALL | re.MULTILINE)
                self._compiled_patterns.append((compiled, "custom", description, replacement))
            except (KeyError, re.error) as e:
                logger.warning(f"Invalid custom pattern: {e}. Skipping.")
                continue

    def is_git_commit_command(self, command: str) -> bool:
        """Check if command contains a git commit.

        Handles compound commands like:
        - git commit -m "msg"
        - git add . && git commit -m "msg"
        - cd project && git add -A && git commit -m "msg"
        - git add .; git commit -m "msg"

        Args:
            command: Bash command string

        Returns:
            True if command contains 'git commit'
        """
        # Check for 'git commit' anywhere in the command
        # Use word boundary to avoid matching 'git-commit' or 'git_commit'
        return bool(re.search(r"\bgit\s+commit\b", command))

    def extract_commit_message(self, command: str) -> Optional[str]:
        """Extract commit message from git command using dual-mode parsing.

        Uses bashlex AST parsing as primary method with regex fallback.
        This hybrid approach provides robustness while maintaining backward
        compatibility with edge cases bashlex can't handle (e.g., heredocs).

        Supports formats:
        - git commit -m "message"
        - git commit -m 'message'
        - git commit -m "message" -m "another paragraph"
        - git commit -m "$(cat <<'EOF'\\nmessage\\nEOF\\n)"
        - git add && git commit -m "message" (compound commands)

        Args:
            command: Git commit command

        Returns:
            Extracted message or None if not found (fail-open signal)

        Implementation:
            1. Check size limit (DoS prevention)
            2. Try bashlex extraction (handles compound commands robustly)
            3. Fall back to regex (handles heredoc and edge cases)
            4. Return None if both fail (fail-open)
        """
        # Size limit check (DoS prevention per Security Specialist)
        if len(command) > MAX_COMMAND_SIZE:
            logger.warning(
                f"Command exceeds size limit ({len(command)} > {MAX_COMMAND_SIZE} bytes). Skipping extraction (fail-open)."
            )
            return None

        # Try bashlex first (handles compound commands, proper AST parsing)
        try:
            message = self._extract_via_bashlex(command)
            if message is not None:
                logger.debug("Extracted message via bashlex")
                return message
        except bashlex.errors.ParsingError as e:
            logger.debug(f"Bashlex parse failed: {e}. Trying regex fallback.")
        except (AttributeError, KeyError, IndexError) as e:
            logger.warning(f"Bashlex AST traversal error: {e}. Trying regex fallback.")
        except Exception as e:
            logger.warning(f"Unexpected bashlex error: {e}. Trying regex fallback.")

        # Fallback to regex (handles heredoc and other edge cases)
        try:
            message = self._extract_via_regex(command)
            if message is not None:
                logger.debug("Extracted message via regex fallback")
                return message
        except Exception as e:
            logger.warning(f"Regex extraction failed: {e}")

        # Both methods failed → fail-open (return None)
        return None

    def classify_message_delivery(self, command: str) -> str:
        """Classify how a git commit command delivers its message.

        Returns one of:
            "scannable"   - a message was extracted from argv (any ``-m "..."`` form). Its
                            literal bytes are in the command, so it is scanned as-is - an
                            incidental ``$(...)`` does not stop the literal parts (including a
                            trailer) from being matched and stripped.
            "unscannable" - the message is delivered from OUTSIDE argv: ``-F`` / ``--file``
                            (a file, or ``-`` for stdin). There is nothing in the command to
                            scan, so the filter can only warn or block - it cannot strip.
            "none"        - no NEW author-supplied message content (bare ``git commit``,
                            ``--amend --no-edit``, ``-C`` / ``-c`` / ``--squash`` /
                            ``--fixup`` / ``--template`` message reuse or editor deferral).

        WHY THIS EXISTS: ``extract_commit_message`` returns ``None`` for BOTH legitimate
        message reuse (``--amend --no-edit``, ``-C HEAD``) and the issue #76 file bypass
        (``-F file``). Acting on the bare ``None`` signal would block every amend/reuse, so
        this method separates "content we structurally cannot see" from "no new content".

        NOTE: ``-m "$(cat externalfile)"`` (the WHOLE message is a substitution) is treated as
        ``scannable`` - its literal ``$(...)`` text is scanned and matches nothing, so it slips
        pre-execution. Catching that reliably needs the ACTUAL committed message (a post-commit
        check), not argv inspection - argv genuinely does not contain the bytes. Pure and
        side-effect free. Public entry point used by tests; ``filter_commit_message`` shares the
        core decision via ``_classify_from_extraction``.
        """
        if not self.is_git_commit_command(command):
            return "none"
        return self._classify_from_extraction(command, self.extract_commit_message(command))

    def _classify_from_extraction(self, command: str, extracted: Optional[str]) -> str:
        """Classify delivery given an already-extracted message (shared with filtering).

        Split out so ``filter_commit_message`` can extract once and classify rather than
        extracting twice. ``extracted`` is ``extract_commit_message``'s result for a command
        already known to be a git commit.

        A file/stdin flag in ANY git commit segment means part of the command is content not
        in argv -> ``unscannable`` (checked FIRST: a compound `git commit -m x && git commit -F
        y` must not be masked as scannable by the earlier inline message). Otherwise an extracted
        message is literally in argv -> ``scannable`` (scan it, incidental substitutions and all);
        anything else is reuse/editor deferral -> ``none``.
        """
        if self._command_has_file_content_flag(command):
            return "unscannable"
        if extracted is not None:
            return "scannable"
        return "none"

    def _command_has_file_content_flag(self, command: str) -> bool:
        """True if any git commit segment delivers its message from a file or stdin (-F/--file)."""
        for words in self._git_commit_word_lists(command):
            for word in words[2:]:  # skip "git commit"; flags follow the subcommand
                if word == "--":
                    break  # everything after the option terminator is a pathspec, not a flag
                if word == "--file" or word.startswith("--file="):
                    return True
                # Single-dash short-flag cluster: -F, attached -Fpath, or clustered -aF / -aFpath.
                if word.startswith("-") and not word.startswith("--") and self._short_cluster_has_file_flag(word):
                    return True
        return False

    @staticmethod
    def _short_cluster_has_file_flag(token: str) -> bool:
        """True if a single-dash short-flag cluster uses -F (commit message from a file/stdin).

        Walks the cluster letters: -m/-C/-c also take arguments, so reaching one of THOSE first
        means the remainder is that flag's value (e.g. -mFix is message "Fix", not a file flag).
        Reaching 'F' first means file delivery (handles -F, -Fpath, -aF, -aFpath).
        """
        for ch in token[1:]:
            if ch == "F":
                return True
            if ch in "mCc":  # argument-taking flag; the rest of the token is its value, not flags
                return False
        return False

    # Explanation surfaced when an unscannable commit is warned/blocked. Unscannable always
    # means file/stdin delivery (-F/--file), so a single static message suffices.
    _UNSCANNABLE_REASON = (
        "Commit message supplied via a file or stdin (-F/--file); its content is not in the "
        "command and was not scanned for advertising. Inline the message with -m to enable "
        "scanning, or remove any unwanted trailer manually."
    )

    def _git_commit_word_lists(self, command: str) -> list[list[str]]:
        """Return the argv word lists of every ``git commit`` invocation in the command.

        Uses bashlex to isolate the git commit segment(s) of a compound command. On parse
        failure (or an oversized command) falls back to splitting the whole command -
        over-detecting a file flag and warning is safer than silently missing it for this
        fail-open filter, and never parsing an oversized string avoids a DoS on the hook.
        """
        if len(command) > MAX_COMMAND_SIZE:  # DoS guard: never run bashlex on an oversized command
            return [command.split()]
        try:
            parts = bashlex.parse(command)
        except Exception:  # noqa: BLE001 - bashlex raises various types; fail-open to split
            return [command.split()]

        results: list[list[str]] = []

        def visit(node: Any) -> None:
            if getattr(node, "kind", None) == "command":
                words = [p.word for p in getattr(node, "parts", []) if hasattr(p, "word")]
                if len(words) >= 2 and words[0] == "git" and words[1] == "commit":
                    results.append(words)
            for attr in ("parts", "list", "command"):
                child = getattr(node, attr, None)
                if child is None:
                    continue
                for item in child if isinstance(child, list) else [child]:
                    visit(item)

        for part in parts:
            visit(part)

        return results if results else [command.split()]

    def _extract_via_bashlex(self, command: str) -> Optional[str]:
        """Extract commit message using bashlex AST parsing.

        Parses the command into an AST and finds -m arguments within
        git commit command nodes. Handles compound commands correctly.

        Args:
            command: Git commit command

        Returns:
            Extracted message or None if not found

        Raises:
            bashlex.errors.ParsingError: If bashlex can't parse the command

        Note:
            bashlex handles escape sequences differently than expected.
            When it sees `\\n` in double quotes, it strips the backslash.
            We use position info to extract the RAW message from the original
            command, then handle `\\n` → newline conversion ourselves.
        """
        parts = bashlex.parse(command)
        messages: list[str] = []

        def extract_msg_from_node(msg_node: Any) -> str:
            """Extract message from AST node using position info."""
            if hasattr(msg_node, "pos"):
                start, end = msg_node.pos
                raw_msg = command[start:end]
                # Strip quotes if present
                if raw_msg and raw_msg[0] in "\"'" and raw_msg[-1] == raw_msg[0]:
                    raw_msg = raw_msg[1:-1]
                return raw_msg.replace("\\n", "\n")
            # Fallback to bashlex-parsed word
            return msg_node.word.replace("\\n", "\n")

        def visit(node: Any) -> None:
            """Recursively visit AST nodes to find git commit messages."""
            if hasattr(node, "kind") and node.kind == "command":
                words = [p for p in getattr(node, "parts", []) if hasattr(p, "word")]

                # Check if this is 'git commit'
                if len(words) >= 2 and words[0].word == "git" and words[1].word == "commit":
                    i = 0
                    while i < len(words):
                        word_node = words[i]
                        if word_node.word == "-m" and i + 1 < len(words):
                            messages.append(extract_msg_from_node(words[i + 1]))
                            i += 2  # Skip past -m and message
                        else:
                            i += 1

            # Recurse into compound commands (&&, ||, ;, |)
            for attr in ["parts", "list", "command"]:
                child = getattr(node, attr, None)
                if child is None:
                    continue
                for item in child if isinstance(child, list) else [child]:
                    visit(item)

        for part in parts:
            visit(part)

        if not messages:
            return None

        # Combine all messages with paragraph breaks
        return "\n\n".join(messages)

    def _extract_via_regex(self, command: str) -> Optional[str]:
        """Extract commit message using regex patterns (fallback method).

        Handles formats that bashlex can't parse, including heredocs.

        Args:
            command: Git commit command

        Returns:
            Extracted message or None if not found
        """
        # Pattern 1: Heredoc format (check FIRST - more specific pattern)
        # Match: -m "$(cat <<'EOF'\nMESSAGE\nEOF\n)"
        heredoc_match = re.search(r'-m\s+"?\$\(cat\s+<<\'EOF\'\n(.+?)\nEOF\n\)"?', command, re.DOTALL)
        if heredoc_match:
            return heredoc_match.group(1)

        # Pattern 2: Standard -m "message" or -m 'message'
        # Use finditer to get ALL -m flags (prevents bypass via multiple -m)
        # Note: This pattern doesn't handle escaped quotes well - bashlex is preferred
        matches = list(re.finditer(r'-m\s+(["\'])(.+?)\1', command, re.DOTALL))

        if matches:
            # Extract all messages and combine with paragraph breaks
            messages = [m.group(2).replace("\\n", "\n") for m in matches]
            return "\n\n".join(messages)

        # Pattern 3: Empty message -m ""
        empty_match = re.search(r'-m\s+(["\'])\1', command)
        if empty_match:
            return ""

        # No message found
        return None

    def clean_message(self, message: str) -> tuple[str, list[dict[str, str]], list[str]]:
        """Apply filtering patterns to message.

        Args:
            message: Original commit message

        Returns:
            Tuple of:
            - Cleaned message
            - List of patterns removed (dicts with pattern, category, description)
            - List of categories that had matches

        Algorithm:
            1. Apply each compiled pattern with sub()
            2. Track which patterns matched
            3. Trim excessive whitespace (collapse multiple newlines)
            4. Strip trailing whitespace from each line
        """
        cleaned = message
        patterns_removed = []
        categories_matched = set()

        # Apply each pattern
        for compiled, category, description, replacement in self._compiled_patterns:
            # Check if pattern matches before replacing
            if compiled.search(cleaned):
                cleaned = compiled.sub(replacement, cleaned)
                patterns_removed.append({"pattern": compiled.pattern, "category": category, "description": description})
                categories_matched.add(category)

        # Trim excessive whitespace (collapse 3+ newlines to 2)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)

        # Strip trailing whitespace from each line
        lines = cleaned.split("\n")
        lines = [line.rstrip() for line in lines]
        cleaned = "\n".join(lines)

        # Strip leading/trailing whitespace from entire message
        cleaned = cleaned.strip()

        return cleaned, patterns_removed, sorted(categories_matched)

    def reconstruct_command(self, original_command: str, cleaned_message: str) -> str:
        """Reconstruct git command with cleaned message.

        Uses in-place replacement to preserve compound command structure.
        Handles commands like: git add && git commit -m "msg"

        Args:
            original_command: Original git commit command (may be compound)
            cleaned_message: Filtered commit message

        Returns:
            Command with cleaned message (preserves compound structure)

        Format:
            git commit -m "message with \"escaped\" quotes"

        This format:
        - Escapes double quotes and backslashes
        - Preserves newlines as literal \\n
        - Compatible with bashlex parser
        - Preserves compound command structure (&&, ||, ;)
        """
        # Escape the message for double-quote context
        escaped_message = cleaned_message.replace("\\", "\\\\").replace('"', '\\"')
        # Convert actual newlines to literal \n for bash
        escaped_message = escaped_message.replace("\n", "\\n")

        # Pattern to match -m with quoted string (double or single quotes)
        m_pattern = re.compile(r'-m\s+(["\'])(.+?)\1', re.DOTALL)

        # Find all -m arguments
        matches = list(m_pattern.finditer(original_command))

        if not matches:
            # No -m found - shouldn't happen if we got here, but failsafe
            logger.warning("No -m pattern found in command, cannot reconstruct")
            return original_command

        # Strategy: Replace first -m arg with cleaned message, remove subsequent -m args
        # Work backwards to preserve string positions
        result = original_command

        if len(matches) == 1:
            # Single -m: simple replacement
            match = matches[0]
            replacement = f'-m "{escaped_message}"'
            result = result[: match.start()] + replacement + result[match.end() :]
        else:
            # Multiple -m flags: replace first, remove rest
            # Work backwards to preserve positions
            for match in reversed(matches[1:]):
                # Remove subsequent -m args (and leading whitespace)
                start = match.start()
                # Trim leading whitespace
                while start > 0 and result[start - 1] in " \t":
                    start -= 1
                result = result[:start] + result[match.end() :]

            # Now replace the first one
            first = matches[0]
            replacement = f'-m "{escaped_message}"'
            result = result[: first.start()] + replacement + result[first.end() :]

        return result

    def filter_commit_message(self, command: str) -> FilterResult:  # noqa: PLR0911 - Multiple patterns require multiple exits
        """Filter commit message in git command.

        Main entry point for filtering. Orchestrates extraction, cleaning,
        and reconstruction.

        Args:
            command: Git commit command

        Returns:
            FilterResult with cleaned command and metadata

        Behavior:
            - If not a git commit command -> return original (no filtering)
            - If filter disabled -> return original (no filtering)
            - If message extraction fails -> return original (fail-open)
            - If no patterns match -> return original (no changes needed)
            - If patterns match -> return cleaned command

        Never raises exceptions - all errors are caught and returned
        in FilterResult.error field.
        """
        try:
            # Check if git commit
            if not self.is_git_commit_command(command):
                return FilterResult(
                    cleaned_command=command,
                    original_message="",
                    cleaned_message="",
                    was_modified=False,
                    patterns_removed=[],
                    categories_matched=[],
                )

            # Check if filter enabled
            if not self.enabled:
                return FilterResult(
                    cleaned_command=command,
                    original_message="",
                    cleaned_message="",
                    was_modified=False,
                    patterns_removed=[],
                    categories_matched=[],
                )

            # Extract once and classify how the message is delivered to git.
            message = self.extract_commit_message(command)
            delivery = self._classify_from_extraction(command, message)

            # Content-bearing but NOT in argv (file / stdin) -> #76. We cannot scan it
            # pre-execution; surface a warn/block decision per config.
            if delivery == "unscannable":
                if self.unscannable_action == "off":
                    # Opt-out: preserve historical silent pass-through. This is a deliberate
                    # skip, NOT a failure, so `error` stays None (the state is recorded by
                    # message_delivery="unscannable" + unscannable_decision=None).
                    return FilterResult(
                        cleaned_command=command,
                        original_message="",
                        cleaned_message="",
                        was_modified=False,
                        message_delivery="unscannable",
                        unscannable_decision=None,
                    )
                logger.warning("[commit-filter] Unscannable commit message (file/stdin); action=%s", self.unscannable_action)
                return FilterResult(
                    cleaned_command=command,
                    original_message="",
                    cleaned_message="",
                    was_modified=False,
                    message_delivery="unscannable",
                    unscannable_decision=self.unscannable_action,
                    unscannable_reason=self._UNSCANNABLE_REASON,
                )

            # No NEW author-supplied content (bare commit, --amend --no-edit, -C/-c/--squash/
            # --fixup/--template). Legitimate reuse/deferral -> pass through, never flag.
            if delivery == "none":
                return FilterResult(
                    cleaned_command=command,
                    original_message="",
                    cleaned_message="",
                    was_modified=False,
                    message_delivery="none",
                )

            # delivery == "scannable": by the classifier contract `message` is non-None here.

            # Clean message
            cleaned, patterns_removed, categories = self.clean_message(message)

            # Check if modified
            was_modified = cleaned != message

            if not was_modified:
                # No changes -> return original
                return FilterResult(
                    cleaned_command=command,
                    original_message=message,
                    cleaned_message=cleaned,
                    was_modified=False,
                    patterns_removed=[],
                    categories_matched=[],
                    message_delivery="scannable",
                )

            # Check if cleaned message is empty
            if not cleaned or not cleaned.strip():
                # Empty message after filtering -> error
                return FilterResult(
                    cleaned_command=command,  # Return original (don't break commit)
                    original_message=message,
                    cleaned_message=cleaned,
                    was_modified=False,  # Don't use cleaned (it's empty)
                    patterns_removed=patterns_removed,
                    categories_matched=categories,
                    message_delivery="scannable",
                    error="Commit message is empty after filtering",
                )

            # Reconstruct command with cleaned message
            cleaned_command = self.reconstruct_command(command, cleaned)

            return FilterResult(
                cleaned_command=cleaned_command,
                original_message=message,
                cleaned_message=cleaned,
                was_modified=True,
                patterns_removed=patterns_removed,
                categories_matched=categories,
                message_delivery="scannable",
            )

        except Exception as e:
            # Catch-all for unexpected errors -> fail-open
            logger.exception(f"Unexpected error in filter: {e}")
            return FilterResult(
                cleaned_command=command,  # Return original (fail-open)
                original_message="",
                cleaned_message="",
                was_modified=False,
                patterns_removed=[],
                categories_matched=[],
                error=str(e),
            )


def load_filter_config(config_path: Optional[str] = None) -> dict[str, Any]:
    """Load filter configuration with layering.

    Configuration layers (later overrides earlier):
    1. Plugin defaults: data/commit_filter_rules.yaml (required)
    2. User overrides: Platform-specific config directory (optional, future feature)
    3. Project overrides: .claude/hooks/schlock-config.yaml (optional, commit_filter section)

    For Spec 4, only layer 1 (plugin defaults) is implemented.
    Layering will follow Spec 2 patterns.

    Args:
        config_path: Optional path to rules file (for testing)

    Returns:
        Configuration dict for CommitMessageFilter

    Raises:
        FileNotFoundError: If plugin defaults are missing
        yaml.YAMLError: If YAML is malformed
    """
    import yaml  # noqa: PLC0415 - Lazy import, only needed when loading config

    if config_path:
        # Testing/override path
        try:
            with open(config_path) as f:
                return yaml.safe_load(f)
        except (FileNotFoundError, yaml.YAMLError) as e:
            logger.warning(f"Failed to load config from {config_path}: {e}. Filter disabled.")
            return {"enabled": False, "rules": {}}

    # Default: plugin defaults at data/commit_filter_rules.yaml
    # Path: integrations/commit_filter.py -> integrations -> schlock -> src -> project_root
    project_root = Path(__file__).parent.parent.parent.parent
    default_rules = project_root / "data" / "commit_filter_rules.yaml"

    if not default_rules.exists():
        # If defaults missing -> disable filter (fail-open, not critical)
        logger.warning(f"Filter rules not found: {default_rules}. Filter disabled.")
        return {"enabled": False, "rules": {}}

    try:
        with open(default_rules) as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        # If YAML invalid -> disable filter (fail-open)
        logger.warning(f"Invalid YAML in filter rules: {e}. Filter disabled.")
        return {"enabled": False, "rules": {}}
