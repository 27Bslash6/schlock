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

# git GLOBAL options that consume the FOLLOWING word as a value, in separate-word form (issue
# #82). When one precedes the subcommand (e.g. `git -C <path> commit`), the next token is its
# value, NOT the subcommand — so _commit_subcommand_index skips both. Everything else dashed is
# treated as a value-less global flag (`-p`, `--no-pager`, `--bare`, …) or an attached-value
# form (`--git-dir=…`), which consume only their own token.
_GIT_GLOBAL_VALUE_OPTS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source"}
)

# Long form of the -m commit-message flag (issue #77). The blockable content sits in argv for
# --message "msg" / --message=msg just as it does for -m, but the extractor used to key on -m
# only, so these slipped (fail-open). git ALSO accepts unambiguous prefixes (--mess, --messa);
# those are intentionally NOT handled - no agent emits abbreviated flags and this is a fail-open
# cosmetic filter, not a security boundary (see CLAUDE.md / test_abbreviated_long_flag_*).
_LONG_MESSAGE_FLAG = "--message"
_ATTACHED_LONG_PREFIX = _LONG_MESSAGE_FLAG + "="  # "--message="

# Regex fragment matching the flag+separator preceding a commit-message value. Shared by the
# regex extraction fallback and command reconstruction so the two never drift:
#   -m<ws>           kept strict with \s+ so existing -m behavior is byte-for-byte unchanged
#   --message<ws>    or   --message=
_MSG_FLAG = r"(?:-m\s+|--message(?:\s+|=))"


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

    @staticmethod
    def _commit_subcommand_index(words: list[str]) -> int:
        """Index of the ``commit`` subcommand within a git argv word list, tolerating leading git
        GLOBAL options (issue #82): ``git -C <path> commit``, ``git -c k=v commit``,
        ``git --git-dir=… commit``, ``git --work-tree … commit``, ``git --no-pager commit``.

        Returns -1 if ``words`` is not a ``git … commit`` invocation. Fail-open bias: value-taking
        globals (``-C`` etc., see _GIT_GLOBAL_VALUE_OPTS) consume their following word so a path is
        never mistaken for the subcommand; any other dashed token is treated as a value-less flag.
        """
        if len(words) < 2 or words[0] != "git":
            return -1
        i = 1
        while i < len(words):
            word = words[i]
            if word == "commit":
                return i
            if not word.startswith("-"):
                return -1  # first non-option token is some other subcommand (status, log, push…)
            if "=" in word or word not in _GIT_GLOBAL_VALUE_OPTS:
                i += 1  # attached-value (--git-dir=…) or value-less flag — consume just this token
            else:
                i += 2  # separate-word value (e.g. -C <path>) — consume the option AND its value
        return -1

    def is_git_commit_command(self, command: str) -> bool:
        """Check if the command contains a git commit invocation.

        Handles compound commands AND git GLOBAL options before the subcommand (issue #82):
        - git commit -m "msg"
        - git add . && git commit -m "msg"
        - cd project && git add -A && git commit -m "msg"
        - git -C /path commit -m "msg"      (global option between `git` and `commit`)
        - git -c key=val commit -m "msg"

        Args:
            command: Bash command string

        Returns:
            True if any segment is a ``git [global-opts] commit`` invocation.
        """
        # Fast reject: a git commit needs both "git" and a standalone "commit" token. Skips
        # parsing the overwhelming majority of commands (which contain neither).
        if "git" not in command or not re.search(r"\bcommit\b", command):
            return False
        # Oversized: skip bashlex (DoS guard) and use a tolerant regex.
        if len(command) > MAX_COMMAND_SIZE:
            return bool(re.search(r"\bgit\b.*?\bcommit\b", command, re.DOTALL))
        # Precise: bashlex AST, tolerant of global options. AST detection also avoids the old
        # `\bgit\s+commit\b` false positive on strings like `echo "git commit"`. A parse failure
        # must not silently disable detection, so fall back to a tolerant regex (over-detect-safe).
        try:
            return bool(self._commit_arg_word_lists(command))
        except Exception:  # noqa: BLE001 - bashlex raises various types; fail-open to regex
            return bool(re.search(r"\bgit\b.*?\bcommit\b", command, re.DOTALL))

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

        # Fallback: stdin heredoc feeding `git commit -F-` (issue #87). The bashlex/-m and regex
        # attempts above don't see it (the body is a redirect, not a -m value), but the bytes are
        # in the command string, so it is scannable.
        try:
            message = self._extract_heredoc_stdin_message(command)
            if message is not None:
                logger.debug("Extracted message via stdin-heredoc fallback")
                return message
        except Exception as e:  # noqa: BLE001 - fail-open cosmetic filter
            logger.warning(f"Heredoc stdin extraction failed: {e}")

        # All methods failed → fail-open (return None)
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
            # Issue #87: a `-F-`/`--file -` fed by an in-command heredoc has its bytes in argv,
            # so it is scannable, NOT unscannable. A real file (-F path), piped stdin, or no
            # heredoc returns None here and stays unscannable.
            if extracted is not None and self._extract_heredoc_stdin_message(command) is not None:
                return "scannable"
            return "unscannable"
        if extracted is not None:
            return "scannable"
        return "none"

    def _command_has_file_content_flag(self, command: str) -> bool:
        """True if any git commit segment delivers its message from a file or stdin (-F/--file)."""
        for args in self._git_commit_arg_lists(command):  # args already start AFTER `commit`
            for word in args:
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

    @staticmethod
    def _arg_targets_stdin(args: list[str]) -> bool:
        """True if a -F/--file flag in these post-``commit`` args reads the message from STDIN
        (target ``-`` or ``/dev/stdin``) rather than a real file — i.e. a heredoc-feedable
        delivery. Walks short-flag clusters like _short_cluster_has_file_flag: an argument-taking
        flag (m/C/c) reached before F means the remainder is that flag's value, not a file flag.
        """
        stdin_targets = ("-", "/dev/stdin")
        i = 0
        while i < len(args):
            word = args[i]
            if word == "--":
                break  # pathspec terminator
            if word == "--file":
                return i + 1 < len(args) and args[i + 1] in stdin_targets
            if word.startswith("--file="):
                return word[len("--file=") :] in stdin_targets
            if word.startswith("-") and not word.startswith("--"):
                rest = word[1:]
                for j, ch in enumerate(rest):
                    if ch in "mCc":
                        break  # argument-taking flag swallows the remainder as its value
                    if ch == "F":
                        attached = rest[j + 1 :]
                        if attached:
                            return attached in stdin_targets  # -F-, -F/dev/stdin, -aF-
                        return i + 1 < len(args) and args[i + 1] in stdin_targets  # -F -
            i += 1
        return False

    # Cheap, LINEAR (non-backtracking) heredoc-opener counter. Used to bail out of the more
    # expensive O(n^2)-prone body regex unless there is EXACTLY one heredoc — see
    # _extract_heredoc_stdin_message. Matches <<EOF / <<'EOF' / <<"EOF" / <<-EOF / << EOF.
    _HEREDOC_OPENER_RE = re.compile(r"<<-?[ \t]*['\"]?\w+")

    # Heredoc body feeding `git commit -F-` / `--file -`. Matches <<EOF, <<'EOF', <<"EOF",
    # <<-EOF, << EOF and arbitrary \w+ delimiter names; captures the body up to a line that is
    # the (optionally tab-indented) delimiter alone. DOTALL so the body spans lines.
    _HEREDOC_BODY_RE = re.compile(r"<<-?[ \t]*(['\"]?)(\w+)\1[^\n]*\n(.*?)\n[ \t]*\2(?:\n|$)", re.DOTALL)

    def _extract_heredoc_stdin_message(self, command: str) -> Optional[str]:
        """Commit message of a ``git commit -F-`` / ``--file -`` fed by an in-command heredoc.

        Returns the heredoc body when (a) some ``git … commit`` segment reads its message from
        stdin (``-F -`` / ``--file -`` / ``/dev/stdin``) AND (b) a heredoc body is present in the
        command string; otherwise ``None``. This reclassifies the stdin-heredoc form from
        ``unscannable`` to ``scannable`` (issue #87) — its bytes ARE in argv, unlike ``-F file``
        (on disk) or ``cat f | git commit -F-`` (in a prior pipe segment), both of which return
        ``None`` here and stay unscannable. Fail-open: any uncertainty → ``None``.

        bashlex raises on quoted-delimiter heredocs (``<<'EOF'``), so the STDIN gate reuses the
        tolerant ``_git_commit_arg_lists`` infra while the BODY is taken by regex (uniform across
        quoted and unquoted forms).
        """
        if len(command) > MAX_COMMAND_SIZE:
            return None  # DoS guard: never run the DOTALL body regex on an oversized command
        if not any(self._arg_targets_stdin(args) for args in self._git_commit_arg_lists(command)):
            return None
        # Only the UNAMBIGUOUS single-heredoc case can be bound to the stdin-fed commit segment.
        # With 0 or 2+ heredocs, binding by position would guess wrong — leaking an ad behind a
        # clean leading heredoc, or false-blocking a clean commit whose sibling heredoc contains
        # the token — so fail open to unscannable instead. The linear opener count also starves
        # the O(n^2) DOTALL body search of any multi-`<<` adversarial input within MAX_COMMAND_SIZE.
        if len(self._HEREDOC_OPENER_RE.findall(command)) != 1:
            return None
        match = self._HEREDOC_BODY_RE.search(command)
        return match.group(3) if match else None

    # Explanation surfaced when an unscannable commit is warned/blocked. Unscannable always
    # means file/stdin delivery (-F/--file), so a single static message suffices.
    _UNSCANNABLE_REASON = (
        "Commit message supplied via a file or stdin (-F/--file); its content is not in the "
        "command and was not scanned for advertising. Inline the message with -m to enable "
        "scanning, or remove any unwanted trailer manually."
    )

    def _commit_arg_word_lists(self, command: str) -> list[list[str]]:
        """For each ``git … commit`` invocation, the argument words FOLLOWING ``commit`` (the
        global options and the subcommand itself stripped). Tolerates global options between
        ``git`` and ``commit`` via _commit_subcommand_index (issue #82).

        RAISES if bashlex cannot parse — callers decide the fallback. Callers must size-guard
        before calling (no DoS check here).
        """
        results: list[list[str]] = []

        def visit(node: Any) -> None:
            if getattr(node, "kind", None) == "command":
                words = [p.word for p in getattr(node, "parts", []) if hasattr(p, "word")]
                idx = self._commit_subcommand_index(words)
                if idx != -1:
                    results.append(words[idx + 1 :])
            for attr in ("parts", "list", "command"):
                child = getattr(node, attr, None)
                if child is None:
                    continue
                for item in child if isinstance(child, list) else [child]:
                    visit(item)

        for part in bashlex.parse(command):
            visit(part)
        return results

    def _git_commit_arg_lists(self, command: str) -> list[list[str]]:
        """_commit_arg_word_lists with fail-open fallbacks for the file-flag scan: on oversized
        input, parse failure, or no match, return a single naive split of the whole command so a
        file flag (-F/--file) is over-detected rather than silently missed.
        """
        if len(command) > MAX_COMMAND_SIZE:  # DoS guard: never run bashlex on an oversized command
            return [command.split()]
        try:
            results = self._commit_arg_word_lists(command)
        except Exception:  # noqa: BLE001 - bashlex raises various types; fail-open to split
            return [command.split()]
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

        def extract_attached_message(flag_node: Any) -> str:
            """Extract the value of a single --message=VALUE token (issue #77).

            Uses raw position slicing rather than flag_node.word for the same reason
            extract_msg_from_node does: bashlex drops the backslash of a literal \\n in .word,
            which would corrupt a multi-line trailer. We slice the original command, strip the
            ``--message=`` prefix, then strip a matched surrounding quote.
            """
            if hasattr(flag_node, "pos"):
                start, end = flag_node.pos
                raw = command[start:end]
                value = raw[len(_ATTACHED_LONG_PREFIX) :] if raw.startswith(_ATTACHED_LONG_PREFIX) else ""
                if value and value[0] in "\"'" and value[-1] == value[0]:
                    value = value[1:-1]
                return value.replace("\\n", "\n")
            # Fallback: bashlex word (loses a literal \\n backslash, acceptable when pos absent)
            word = flag_node.word
            return word[len(_ATTACHED_LONG_PREFIX) :].replace("\\n", "\n") if word.startswith(_ATTACHED_LONG_PREFIX) else ""

        def visit(node: Any) -> None:
            """Recursively visit AST nodes to find git commit messages."""
            if hasattr(node, "kind") and node.kind == "command":
                words = [p for p in getattr(node, "parts", []) if hasattr(p, "word")]

                # Check if this is 'git [global-opts] commit' (issue #82: tolerate -C/-c/etc.)
                idx = self._commit_subcommand_index([w.word for w in words])
                if idx != -1:
                    i = idx + 1  # scan the commit's own args, starting AFTER the `commit` token
                    while i < len(words):
                        word = words[i].word
                        if word in ("-m", _LONG_MESSAGE_FLAG) and i + 1 < len(words):
                            # Separate-word form: -m "msg" / --message "msg". Value is next token.
                            messages.append(extract_msg_from_node(words[i + 1]))
                            i += 2  # Skip past the flag and its message
                        elif word.startswith(_ATTACHED_LONG_PREFIX):
                            # Attached form: --message="msg" / --message=word (single token).
                            messages.append(extract_attached_message(words[i]))
                            i += 1
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
        # Match: -m/--message "$(cat <<'EOF'\nMESSAGE\nEOF\n)"
        heredoc_match = re.search(rf'{_MSG_FLAG}"?\$\(cat\s+<<\'EOF\'\n(.+?)\nEOF\n\)"?', command, re.DOTALL)
        if heredoc_match:
            return heredoc_match.group(1)

        # Pattern 2: every message value, in ONE left-to-right pass so quoted AND unquoted
        # attached forms AGGREGATE in argv order. A single pass (rather than separate quoted /
        # empty / unquoted searches with early returns) is what makes mixed commands like
        # `--message="clean" --message=adtoken` keep BOTH paragraphs (#77, CodeRabbit #81) — a
        # quoted flag must not short-circuit and drop a later unquoted token. Two alternatives:
        #   - quoted (any flag):      -m "x" / --message 'x' / --message="x"  (group 2 = value;
        #     .*? also matches the empty message ""). The quoted span is consumed as a UNIT, so a
        #     literal --message= INSIDE a value cannot be re-matched as an attached flag.
        #   - unquoted attached long: --message=word (group 3). The first char is non-quote so it
        #     never swallows an empty "" (left to the quoted branch), and -m stays strict (no
        #     unquoted -m) — preserving existing -m behavior byte-for-byte.
        # Escaped quotes inside a value remain imperfect here; bashlex is preferred and tried first.
        combined = re.compile(rf'{_MSG_FLAG}(["\'])(.*?)\1' + r'|--message=([^\s"\']\S*)', re.DOTALL)
        messages = []
        for m in combined.finditer(command):
            value = m.group(2) if m.group(2) is not None else m.group(3)
            if value is not None:
                messages.append(value.replace("\\n", "\n"))
        if messages:
            return "\n\n".join(messages)

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

        # Pattern to match -m / --message / --message= with a quoted string (#77). Shares
        # _MSG_FLAG with extraction so the two recognize exactly the same flag forms.
        m_pattern = re.compile(rf'{_MSG_FLAG}(["\'])(.+?)\1', re.DOTALL)

        # KNOWN LIMITATION (CodeRabbit #81): matches are taken over the WHOLE original_command,
        # so in a contrived compound command a `-m "..."` / `--message "..."` token OUTSIDE the
        # git commit invocation could in principle be rewritten. This is deliberately NOT scoped
        # to the git-commit segment because reconstruct_command's output (FilterResult.cleaned_
        # command) is OFF the hook's block path: pre_tool_use.py denies on `patterns_removed` and
        # never executes cleaned_command. Threading the extraction span through to here to scope
        # the replacement would add machinery to a field nothing consumes (YAGNI). If a future
        # caller ever EXECUTES cleaned_command, this must be scoped to the commit segment first.
        matches = list(m_pattern.finditer(original_command))

        if not matches:
            # No message flag found - shouldn't happen if we got here, but failsafe
            logger.warning("No -m/--message pattern found in command, cannot reconstruct")
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
