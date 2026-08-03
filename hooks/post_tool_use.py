#!/usr/bin/env python3
"""PostToolUse hook: detect advertising that slipped into the actual committed message.

The PreToolUse commit filter can only scan argv. Messages delivered from outside argv
(`git commit -F <file>`, `-F -`/heredoc stdin, `-m "$(cat file)"`) materialize at exec
time, so a trailer can land on a real commit despite the pre-execution filter (issue #79,
refs #76, complements #78). Post-execution the byte-location problem vanishes: this hook
reads the message from the commit object itself (`git log -1`), so one detector covers
every delivery form.

Behavior:
- Detect-and-feedback ONLY. Never rewrites history (no auto-amend) — it injects
  `hookSpecificOutput.additionalContext` instructing the model to `git commit --amend`.
- Fail-open: any error, missing git, non-repo cwd, or stale HEAD -> silent exit 0.
  This is a cosmetic filter, not a security boundary.
- Cheap-gated: substring check on the command first (the hook runs on every Bash call;
  latency is load-bearing), then the PreToolUse filter's bashlex-backed recognizer binds
  to real `git … commit` invocations before any subprocess runs.
- Freshness-gated: the Bash tool "succeeds" even when `git commit` exits non-zero, so
  only a HEAD committed within FRESHNESS_WINDOW_SECONDS is inspected — a failed re-run
  must not re-flag a stale commit.
- Self-terminating: the amend re-fires this hook; a clean amended message produces no
  output, ending the loop. A pathological re-add of the trailer re-flags — that is the
  correct response, and since the hook only ever informs (never blocks), no state is
  needed to bound it.
- File-content scan: only added lines in the fresh HEAD~1..HEAD diff are checked for the
  exact canonical Generated with Claude Code phrase. Schlock's own checkout is skipped
  because its fixtures and docs legitimately quote the phrase.

Hook Interface:
- Input: JSON via stdin (tool_input.command, cwd, ...)
- Output: JSON with hookSpecificOutput.additionalContext on detection; nothing otherwise
"""

import json
import logging
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# Add vendored dependencies to path FIRST (pure Python packages)
vendor_path = Path(__file__).parent.parent / ".claude-plugin" / "vendor"
if vendor_path.exists():
    sys.path.insert(0, str(vendor_path))

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

logging.basicConfig(level=logging.INFO, format="[schlock-post-hook] %(levelname)s: %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)

# Only inspect a HEAD committed within this window. Wide enough for compound commands
# (`git commit -F f && make test`) where the hook fires after the whole command; narrow
# enough that a later failed/no-op `git commit` doesn't re-flag an old HEAD.
FRESHNESS_WINDOW_SECONDS = 30

# Timeout for the single git subprocess (seconds).
GIT_TIMEOUT_SECONDS = 5

# The file-content extension intentionally recognizes only the canonical phrase.
# Reusing the full commit-message rules here would make ordinary source/docs content
# containing other advertising patterns noisy.
CANONICAL_ADVERTISING_PATTERN = re.compile(r"(?i)(?<!\w)Generated with Claude Code(?!\w)")


def read_added_lines(cwd: Optional[str]) -> Optional[list[tuple[str, str]]]:
    """Return (path, line) pairs added by the current commit.

    The scan is deliberately limited to added lines in HEAD~1..HEAD. A commit
    in schlock's own checkout is excluded because the plugin contains legitimate
    fixtures and documentation that quote its advertising patterns.

    Returns None when git cannot provide a diff (for example, an initial commit
    or a non-repository cwd), preserving the hook's fail-open behavior.
    """
    try:
        root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd or None,
        )
        if root_result.returncode != 0:
            return None

        repo_root = Path(root_result.stdout.strip()).resolve()
        schlock_root = Path(__file__).resolve().parent.parent
        if repo_root == schlock_root:
            return []

        diff_result = subprocess.run(
            [
                "git",
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=0",
                "--no-renames",
                "HEAD~1",
                "HEAD",
                "--",
            ],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd or None,
        )
        if diff_result.returncode != 0:
            return None

        added_lines: list[tuple[str, str]] = []
        current_path: Optional[str] = None
        in_file_header = False
        for line in diff_result.stdout.splitlines():
            if line.startswith("diff --git "):
                current_path = None
                in_file_header = True
            elif in_file_header and line.startswith("+++ b/"):
                current_path = line[6:]
                in_file_header = False
            elif line.startswith("@@"):
                in_file_header = False
            elif current_path and line.startswith("+") and not line.startswith("+++"):
                added_lines.append((current_path, line[1:]))
        return added_lines
    except (OSError, subprocess.SubprocessError):
        return None


def find_file_advertising(cwd: Optional[str]) -> Optional[list[tuple[str, str]]]:
    """Find canonical advertising phrases in committed file additions only."""
    added_lines = read_added_lines(cwd)
    if added_lines is None:
        return None
    return [(path, line) for path, line in added_lines if CANONICAL_ADVERTISING_PATTERN.search(line)]


def read_head_commit(cwd: Optional[str]) -> Optional[tuple[int, str, str]]:
    """Read HEAD's committer timestamp, short hash, and full message.

    Returns:
        (committer_epoch, short_hash, message) or None if cwd is not a git repo,
        the repo has no commits, or git is unavailable (fail-open).

    Reads `git log`, not an attacker-supplied path — none of the TOCTOU/symlink/FIFO
    risks that ruled out reading the `-F` target pre-execution apply here.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct %h%n%B"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd or None,
        )
        if result.returncode != 0:
            return None
        first_line, _, message = result.stdout.partition("\n")
        epoch_str, _, short_hash = first_line.partition(" ")
        return int(epoch_str), short_hash, message
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def format_amend_prompt(short_hash: str, patterns_removed: list[dict]) -> str:
    """Build the additionalContext message instructing the model to amend."""
    offending = "\n".join(f"  - {p.get('description', p.get('pattern', 'advertising pattern'))}" for p in patterns_removed)
    return (
        f"schlock: advertising content landed in commit {short_hash} — the message was delivered "
        f"outside argv (e.g. -F/--file, stdin, or command substitution), so the pre-execution "
        f"filter could not scan it.\n\n"
        f"Offending content:\n{offending}\n\n"
        f"Fix it now: rewrite the message with `git commit --amend`, keeping the real message and "
        f"removing ONLY the advertising lines above. Do NOT amend if this commit has already been "
        f"pushed to a shared branch — in that case, tell the user instead of rewriting history."
    )


def format_file_amend_prompt(short_hash: str, matches: list[tuple[str, str]]) -> str:
    """Build feedback for canonical advertising found in committed file content."""
    locations = "\n".join(f"  - {path}: {line.strip()}" for path, line in matches)
    return (
        f"schlock: advertising content landed in added file content in commit {short_hash}.\n\n"
        f"Canonical phrase found on these added lines:\n{locations}\n\n"
        f"Fix it now: remove ONLY those advertising lines from the listed files, then run git commit --amend --no-edit. "
        f"Do NOT amend if this commit has already been pushed to a shared branch — in that case, tell the user instead of "
        f"rewriting history."
    )


def audit_detection(command: str, categories: list[str], cwd: Optional[str], start_time: float) -> None:
    """Record the post-commit detection in the audit log (best-effort, never raises)."""
    try:
        from schlock.integrations.audit import AuditContext, get_audit_logger  # noqa: PLC0415 - lazy, post-gate

        get_audit_logger().log_validation(
            command=command[:500],
            risk_level="LOW",
            violations=[f"commit_filter: post-commit advertising detected ({cat})" for cat in categories],
            decision="warn",
            execution_time_ms=(time.perf_counter() - start_time) * 1000,
            context=AuditContext(project_root=cwd or "", current_dir=cwd or "", environment="development"),
        )
    except Exception as e:
        logger.warning(f"Audit logging failed: {e}")


def handle_post_tool_use(input_data: dict) -> Optional[dict]:  # noqa: PLR0911 - guard-clause gates require multiple exits
    """Inspect HEAD after a git-commit-shaped Bash command; flag advertising in its message.

    Returns:
        Hook response dict with additionalContext on detection, None for silence.
    """
    start_time = time.perf_counter()

    command = input_data.get("tool_input", {}).get("command", "")
    # Cheap gate: cost is on every Bash call. Substrings (not "git commit" literal) so
    # global-option forms like `git -C <path> commit` still reach the precise recognizer.
    if "git" not in command or "commit" not in command:
        return None

    # Heavy imports only after the cheap gate passed.
    try:
        from schlock.integrations.commit_filter import CommitMessageFilter, load_filter_config  # noqa: PLC0415 - lazy

        config = load_filter_config()
        commit_filter = CommitMessageFilter(config)
        if not commit_filter.enabled:
            return None
        # Precision gate: the same bashlex-backed recognizer the PreToolUse filter uses.
        # Rejects text mentions (`echo "git commit"`) and binds to real commit invocations.
        if not commit_filter.is_git_commit_command(command):
            return None
        # A commit redirected to another repository (git -C <path> / --git-dir / --work-tree)
        # cannot be judged by THIS directory's HEAD — skip rather than flag the wrong commit.
        # (Documented limit: such commits are not inspected.)
        if commit_filter.commit_targets_external_repo(command):
            return None
    except Exception as e:
        logger.warning(f"Post-commit filter failed: {e}. Skipping (fail-open).")
        return None

    head = read_head_commit(input_data.get("cwd"))
    if head is None:
        return None
    committed_at, short_hash, message = head

    # Freshness gate: Bash "succeeds" even when `git commit` was a no-op (nothing staged,
    # hook failure, --dry-run). Only a just-created HEAD is attributable to this command.
    if time.time() - committed_at > FRESHNESS_WINDOW_SECONDS:
        return None

    try:
        _cleaned, patterns_removed, categories = commit_filter.clean_message(message)
    except Exception as e:
        logger.warning(f"Post-commit filter failed: {e}. Skipping (fail-open).")
        return None

    file_matches = find_file_advertising(input_data.get("cwd"))
    if not patterns_removed and not file_matches:
        # Clean message — also the amend-loop terminator: a successful amend lands here.
        return None

    detected_categories = categories + (["file_content"] if file_matches else [])
    logger.warning(
        f"[commit-filter] post-commit advertising detected in {short_hash} (categories: {', '.join(detected_categories)})"
    )
    audit_detection(command, detected_categories, input_data.get("cwd"), start_time)

    contexts = []
    if patterns_removed:
        contexts.append(format_amend_prompt(short_hash, patterns_removed))
    if file_matches:
        contexts.append(format_file_amend_prompt(short_hash, file_matches))

    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n\n".join(contexts),
        }
    }


def main():
    """Entry point for Claude Code hook execution. Always exits 0 (fail-open)."""
    try:
        input_data = json.load(sys.stdin)
        result = handle_post_tool_use(input_data)
        if result is not None:
            print(json.dumps(result))
    except Exception as e:
        # Cosmetic detector: never surface an error into the session (exit 2 would feed
        # stderr to the model). Log and stay silent.
        logger.error(f"Fatal error in post_tool_use hook: {e}", exc_info=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
