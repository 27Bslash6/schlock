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
- Freshness-gated by HEAD identity: the Bash tool "succeeds" even when `git commit`
  exits non-zero, so only a HEAD this detector has not already seen is inspected — a
  failed re-run must not re-flag a stale commit. The last-seen HEAD per repository is
  kept in a small state file (SCHLOCK_POST_COMMIT_STATE, default
  <user data dir>/post_commit_heads.json). Identity, not wall-clock age: the hook fires
  after the WHOLE Bash command, so `git commit && <slow test suite>` must still be
  inspected. Only on first contact with a repo (no recorded HEAD) does a wall-clock
  window decide, because an unseen stale HEAD after a failed re-run is then
  indistinguishable from a slow compound command's commit. A HEAD that changed but
  predates the last look (git pull, a commit from the user's own terminal) is
  recorded, never flagged — it is not this command's commit to amend.
- Self-terminating: the amend re-fires this hook; a clean amended message produces no
  output, ending the loop. A pathological re-add of the trailer re-flags — that is the
  correct response, and since the hook only ever informs (never blocks), no state is
  needed to bound it.
- File-content scan: only lines added by the fresh HEAD commit (`git show`, so root
  commits are scanned, merge commits are not blamed for their incoming branch, and pure
  renames stay silent) are checked for the canonical Generated with Claude Code phrase
  (case-insensitive, plain or linked-markdown form). A schlock checkout — identified by
  its own .claude-plugin/plugin.json — is skipped because its fixtures and docs
  legitimately quote the phrase.

Hook Interface:
- Input: JSON via stdin (tool_input.command, cwd, ...)
- Output: JSON with hookSpecificOutput.additionalContext on detection; nothing otherwise
"""

import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from contextlib import suppress
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

# Bootstrap-only wall-clock fallback. Freshness is normally decided by HEAD identity
# ("a commit not yet seen by this detector" — see read_last_seen_head), which a slow
# compound command (`git commit -F f && make test`) cannot age out of. This window
# applies only on first contact with a repository, where no recorded HEAD exists and a
# stale HEAD after a failed/no-op re-run is indistinguishable from a fresh commit.
FRESHNESS_WINDOW_SECONDS = 30

# Timeout for each git subprocess (seconds). Three run per fresh commit:
# rev-parse + log + show.
GIT_TIMEOUT_SECONDS = 5

# Cap on repositories tracked in the last-seen-HEAD state file (insertion-ordered,
# oldest evicted) so the file cannot grow unboundedly across a machine's lifetime.
MAX_TRACKED_REPOS = 100

# The file-content extension intentionally recognizes only the canonical phrase —
# plain ("Generated with Claude Code") or linked-markdown ("Generated with
# [Claude Code](https://claude.ai/code)") — case-insensitively, with any whitespace
# run between words (matching data/commit_filter_rules.yaml). Reusing the full
# commit-message rules here would make ordinary source/docs content containing
# other advertising patterns noisy.
CANONICAL_ADVERTISING_PATTERN = re.compile(r"(?i)\bGenerated\s+with\s+\[?Claude\s+Code\b")

# POSIX ERE mirror of CANONICAL_ADVERTISING_PATTERN for `git show -G`: restricts the
# diff to files whose patch actually mentions the phrase, so one generated bundle or
# vendored artifact cannot flood the hook (measured 7MB of diff without the bound).
# `-G` has no case-insensitivity flag, hence the per-letter classes; `[[]?` is the
# optional literal "[" of the linked-markdown form.
CANONICAL_ADVERTISING_PICKAXE = (
    "[Gg][Ee][Nn][Ee][Rr][Aa][Tt][Ee][Dd][[:space:]]+[Ww][Ii][Tt][Hh][[:space:]]+"
    "[[]?[Cc][Ll][Aa][Uu][Dd][Ee][[:space:]]+[Cc][Oo][Dd][Ee]"
)

# Unified-diff hunk header; group 1 is the new-file start line.
HUNK_HEADER_PATTERN = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)")

# Git's C-style path quoting: a backslash escape is either three octal digits
# (a control byte) or a single mnemonic character.
GIT_QUOTED_PATH_ESCAPE = re.compile(r"\\([0-7]{3}|.)")
GIT_PATH_SIMPLE_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", '"': '"', "\\": "\\"}

# Cap on locations reported in feedback — committed content is untrusted, so the
# feedback names path:line only (never the matched bytes) and stays bounded.
MAX_REPORTED_LOCATIONS = 10


def is_schlock_checkout(cwd: Optional[str]) -> bool:
    """True when cwd sits inside a schlock checkout, identified by its plugin manifest.

    Identity-keyed (not path-keyed) so contributor clones and git worktrees are
    recognized wherever they live — the hook itself runs from the plugin install
    dir, which never equals a contributor's checkout path. The nearest manifest
    on the walk up decides. Any read/parse failure means "not schlock": the
    default is to scan.
    """
    try:
        start = Path(cwd or ".").resolve()
        for directory in (start, *start.parents):
            manifest = directory / ".claude-plugin" / "plugin.json"
            if manifest.is_file():
                return json.loads(manifest.read_text()).get("name") == "schlock"
        return False
    except (OSError, ValueError):
        return False


def unquote_git_path(path: str) -> str:
    """Decode git's C-style quoted path form (`"na\\tme.md"`, `\\ooo` octal).

    `core.quotePath=false` keeps non-ASCII raw, but quotes, backslashes and
    control characters are ALWAYS quoted regardless of the setting — left
    undecoded, the `b/` prefix check would silently skip that file's lines.
    """
    if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
        return path

    def decode(match: "re.Match[str]") -> str:
        escape = match.group(1)
        if len(escape) == 3:
            return chr(int(escape, 8))
        return GIT_PATH_SIMPLE_ESCAPES.get(escape, escape)

    return GIT_QUOTED_PATH_ESCAPE.sub(decode, path[1:-1])


def escape_control_chars(text: str) -> str:
    """Escape control characters for display — a crafted filename must not inject
    line structure into the additionalContext report."""
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", text)


def find_file_advertising(cwd: Optional[str]) -> Optional[list[tuple[str, int]]]:
    """Return (path, line_number) locations of the canonical phrase added by HEAD.

    `git show HEAD` rather than `git diff HEAD~1 HEAD`: a root commit is still
    scanned (no parent to resolve), a merge commit is not blamed for lines its
    incoming branch wrote (condensed combined diff yields no `+` lines), and a
    pure rename adds nothing. The diff format is pinned (`-c core.quotePath=false`,
    `--no-color`, explicit prefixes, `--find-renames` against diff.renames=false)
    so ambient git config — diff.noprefix, color.diff=always, quoted non-ASCII
    paths, disabled rename detection — cannot silently blind or noise the parser.
    `--text` scans paths a .gitattributes `-diff` rule would otherwise hide;
    undecodable bytes in forced-text diffs are replaced, not fatal.

    Fail-open: any git failure returns None — distinct from [] (scanned clean) so
    the caller can leave the HEAD unrecorded and retry the scan next time.
    """
    if is_schlock_checkout(cwd):
        return []
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "show",
                "--format=",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--text",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                "--find-renames",
                f"-G{CANONICAL_ADVERTISING_PICKAXE}",
                "HEAD",
                "--",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd or None,
        )
        if result.returncode != 0:
            logger.warning(f"Post-commit file scan failed: git show exited {result.returncode}. Skipping (fail-open).")
            return None

        matches: list[tuple[str, int]] = []
        current_path: Optional[str] = None
        in_file_header = False
        line_number = 0
        for line in result.stdout.splitlines():
            if line.startswith("diff --git "):
                current_path = None
                in_file_header = True
            elif in_file_header and line.startswith("+++ "):
                # Path may be C-quoted (control chars/quotes/backslashes) and, when it
                # contains spaces unquoted, carries git's trailing-TAB separator.
                target = unquote_git_path(line[4:].rstrip("\t"))
                if target.startswith("b/"):
                    current_path = target[2:]
                    in_file_header = False
            elif line.startswith("@@"):
                in_file_header = False
                header = HUNK_HEADER_PATTERN.match(line)
                line_number = int(header.group(1)) if header else 0
            elif current_path and not in_file_header and line.startswith("+"):
                if CANONICAL_ADVERTISING_PATTERN.search(line[1:]):
                    matches.append((current_path, line_number))
                line_number += 1
        return matches
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Post-commit file scan failed: {e}. Skipping (fail-open).")
        return None


def read_head_commit(cwd: Optional[str]) -> Optional[tuple[int, str, str, str]]:
    """Read HEAD's committer timestamp, short hash, full hash, and full message.

    Returns:
        (committer_epoch, short_hash, full_hash, message) or None if cwd is not a
        git repo, the repo has no commits, or git is unavailable (fail-open).

    Reads `git log`, not an attacker-supplied path — none of the TOCTOU/symlink/FIFO
    risks that ruled out reading the `-F` target pre-execution apply here.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct %h %H%n%B"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd or None,
        )
        if result.returncode != 0:
            return None
        first_line, _, message = result.stdout.partition("\n")
        parts = first_line.split(" ")
        if len(parts) != 3:
            return None
        return int(parts[0]), parts[1], parts[2], message
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def get_repo_key(cwd: Optional[str]) -> Optional[str]:
    """Stable identity for the last-seen-HEAD state: the absolute git dir.

    Per-worktree (each worktree has its own HEAD) and independent of which
    subdirectory the command ran from. None on any failure — the caller then
    falls back to the bootstrap wall-clock window (fail-open).
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--absolute-git-dir"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd or None,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def state_file_path() -> Path:
    """Path of the last-seen-HEAD state file.

    SCHLOCK_POST_COMMIT_STATE overrides (tests, unusual setups); the default sits
    next to the audit log in the platform user-data dir. platformdirs is imported
    lazily — this module is imported on every Bash call, but state is only touched
    after a command has gated in as a real `git commit`.
    """
    env_path = os.environ.get("SCHLOCK_POST_COMMIT_STATE")
    if env_path:
        return Path(env_path).expanduser()
    from platformdirs import user_data_dir  # noqa: PLC0415 - lazy, post-gate

    return Path(user_data_dir("schlock", "27b.io")) / "post_commit_heads.json"


def read_last_seen(repo_key: Optional[str]) -> Optional[tuple[str, int]]:
    """(full_hash, seen_at_epoch) last recorded for this repo, or None (unknown/failed)."""
    if repo_key is None:
        return None
    try:
        state = json.loads(state_file_path().read_text())
        entry = state.get(repo_key) if isinstance(state, dict) else None
        if not isinstance(entry, dict):
            return None
        full_hash, seen_at = entry.get("hash"), entry.get("seen_at")
        if isinstance(full_hash, str) and isinstance(seen_at, (int, float)):
            return full_hash, int(seen_at)
        return None
    except (OSError, ValueError):
        return None


def record_seen_head(repo_key: Optional[str], full_hash: str) -> None:
    """Best-effort atomic record of the HEAD just seen for this repo, with the
    wall-clock time of the look (seen_at) so a later HEAD that PREDATES it can be
    recognized as externally created.

    Write failures are swallowed: with no record, the next run degrades to the
    bootstrap wall-clock window — the pre-identity behavior. No file locking: the
    read-modify-replace below leaves a microseconds-wide lost-update window
    between concurrent sessions, whose worst case is one repo dropping back to
    the bootstrap window for its next commit (a slow compound command's commit
    there is missed once); the next record self-heals. Locking is not worth that
    for a detector that informs, never blocks.
    """
    if repo_key is None:
        return
    tmp = None
    try:
        path = state_file_path()
        try:
            state = json.loads(path.read_text())
            if not isinstance(state, dict):
                state = {}
        except (OSError, ValueError):
            state = {}
        # Insertion order is recency order: re-insert, then evict the oldest.
        # seen_at is floored to whole seconds so a commit landing in the same
        # second as the look still compares as not-older (git %ct is integral).
        state.pop(repo_key, None)
        state[repo_key] = {"hash": full_hash, "seen_at": int(time.time())}
        if len(state) > MAX_TRACKED_REPOS:
            for key in list(state)[: len(state) - MAX_TRACKED_REPOS]:
                del state[key]
        path.parent.mkdir(parents=True, exist_ok=True)
        # PID-unique temp name so concurrent writers never clobber each other's
        # in-flight temp file; the atomic replace keeps the state file valid JSON.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(path)
    except OSError:
        if tmp is not None:
            with suppress(OSError):
                tmp.unlink(missing_ok=True)


def is_uninspected_commit(repo_key: Optional[str], full_hash: str, committed_at: int) -> bool:
    """True when HEAD is a commit this command may have created and the detector
    has not yet inspected.

    Records the HEADs it rules out (they are now "seen"); the caller records a HEAD
    once it is scanned clean or reported, so a transient scan failure on a clean
    commit is retried rather than permanently suppressed.
    """
    last_seen = read_last_seen(repo_key)
    if last_seen is not None and last_seen[0] == full_hash:
        return False  # no new commit since the last look — failed/no-op re-run
    if last_seen is None:
        if time.time() - committed_at > FRESHNESS_WINDOW_SECONDS:
            # Bootstrap: with no recorded HEAD for this repo (first contact, or state
            # unavailable), an old HEAD after a failed re-run is indistinguishable from
            # a slow compound command's commit — fall back to the wall-clock window
            # rather than re-flag a stale commit. Record so identity tracking starts.
            record_seen_head(repo_key, full_hash)
            return False
    elif committed_at < last_seen[1]:
        # HEAD changed but the commit predates our last look, so this command cannot
        # have created it — it moved externally (git pull, the user's own terminal).
        # Flagging it would prompt an amend of a commit that is not ours to rewrite.
        record_seen_head(repo_key, full_hash)
        return False
    return True


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


def format_file_amend_prompt(short_hash: str, matches: list[tuple[str, int]]) -> str:
    """Build feedback for canonical advertising found in committed file content.

    Reports path:line locations and the canonical phrase ONLY — never the matched
    bytes. Committed content is untrusted; echoing it verbatim into
    additionalContext would let a crafted line speak in schlock's voice (same
    rationale as format_amend_prompt emitting rule descriptions, not content).
    """
    shown = matches[:MAX_REPORTED_LOCATIONS]
    locations = "\n".join(f"  - {escape_control_chars(path)}:{line_number}" for path, line_number in shown)
    remaining = len(matches) - len(shown)
    if remaining:
        locations += f"\n  - ... and {remaining} more"
    # Stage exactly the files whose locations were shown — never a superset the
    # model was not told about, never a truncated subset of what it was told to
    # edit. Locations beyond the cap surface on the next run: the amend re-fires
    # this hook, which reports the next batch until the commit is clean.
    paths = list(dict.fromkeys(path for path, _ in shown))
    add_targets = " ".join(shlex.quote(path) for path in paths)
    rerun_note = (
        f"This report lists the first {MAX_REPORTED_LOCATIONS} locations only; the amend re-runs "
        f"this check and it will report the remaining ones.\n"
        if remaining
        else ""
    )
    return (
        f'schlock: the canonical advertising phrase ("Generated with Claude Code") landed in file '
        f"content added by commit {short_hash}.\n\n"
        f"Locations (file:line):\n{locations}\n\n"
        f"Fix it now: remove ONLY the advertising phrase at those locations, then stage and amend:\n"
        f"  git add -- {add_targets} && git commit --amend --no-edit\n"
        f"{rerun_note}"
        f"Do NOT amend if this commit has already been pushed to a shared branch, and if the phrase "
        f"is quoted deliberately (e.g. documentation discussing the phrase itself), leave it — in "
        f"either case, tell the user instead."
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
    committed_at, short_hash, full_hash, message = head

    # Freshness gate, by HEAD identity: Bash "succeeds" even when `git commit` was a
    # no-op (nothing staged, hook failure, --dry-run), so an unchanged HEAD must not be
    # re-flagged — but wall-clock age cannot decide, because the hook fires after the
    # WHOLE command and `git commit && <slow suite>` ages HEAD past any window.
    repo_key = get_repo_key(input_data.get("cwd"))
    if not is_uninspected_commit(repo_key, full_hash, committed_at):
        return None

    try:
        _cleaned, patterns_removed, categories = commit_filter.clean_message(message)
    except Exception as e:
        # NOT recorded as seen: a transient filter failure must not permanently
        # suppress this HEAD — the next commit-shaped command retries it.
        logger.warning(f"Post-commit filter failed: {e}. Skipping (fail-open).")
        return None

    # None = scan failed: leave the HEAD unrecorded so the next run retries — unless
    # message findings report it below (a reported HEAD must not be re-flagged by a
    # later failed re-run; None is falsy, so the report still fires this run).
    file_matches = find_file_advertising(input_data.get("cwd"))
    if file_matches is not None or patterns_removed:
        record_seen_head(repo_key, full_hash)

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
