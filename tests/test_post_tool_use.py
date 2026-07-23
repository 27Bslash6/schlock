"""Tests for the PostToolUse post-commit advertising detector (issue #79).

Every bypass form is exercised against a REAL git repo: the whole point of the
PostToolUse detector is that byte-location no longer matters once the message has
materialized into the commit object, so the tests commit through the same delivery
channels that evade the PreToolUse filter (-F file, stdin heredoc, $(cat file)) and
assert on what the hook sees in `git log`.
"""

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

# Add src and hooks to path BEFORE importing (same pattern as test_hook_integration.py)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

import post_tool_use
from post_tool_use import handle_post_tool_use, read_head_commit

TRAILER = "Co-Authored-By: Claude <noreply@anthropic.com>"
CLEAN_MESSAGE = "feat: add the flux capacitor"


def git_env() -> dict:
    """Environment isolating tmp repos from the user's global git config/hooks/templates."""
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "Test"
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    return env


def run_bash(command: str, cwd: Path, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """Run a command through bash, like the Bash tool does (heredocs, substitution)."""
    return subprocess.run(
        ["bash", "-c", command],
        cwd=cwd,
        env=env or git_env(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.fixture
def git_repo(tmp_path):
    """Fresh git repo with one staged file, ready to commit."""
    env = git_env()
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, env=env, check=True)
    (tmp_path / "file.txt").write_text("content\n")
    subprocess.run(["git", "add", "file.txt"], cwd=tmp_path, env=env, check=True)
    return tmp_path


def hook_input(command: str, cwd: Path) -> dict:
    """Minimal PostToolUse input payload as captured from a live Claude Code session."""
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": "", "stderr": "", "interrupted": False},
        "cwd": str(cwd),
    }


class TestBypassFormsAreDetected:
    """The three outside-argv delivery forms the PreToolUse filter cannot scan."""

    def test_trailer_via_dash_f_file(self, git_repo):
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        command = "git commit -F msg.txt"
        result = run_bash(command, git_repo)
        assert result.returncode == 0, result.stderr

        response = handle_post_tool_use(hook_input(command, git_repo))

        assert response is not None
        context = response["hookSpecificOutput"]["additionalContext"]
        assert response["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "Co-Authored-By" in context
        assert "git commit --amend" in context

    def test_trailer_via_stdin_heredoc(self, git_repo):
        command = f"git commit -F - <<'EOF'\n{CLEAN_MESSAGE}\n\n{TRAILER}\nEOF"
        result = run_bash(command, git_repo)
        assert result.returncode == 0, result.stderr

        response = handle_post_tool_use(hook_input(command, git_repo))

        assert response is not None
        assert "git commit --amend" in response["hookSpecificOutput"]["additionalContext"]

    def test_trailer_via_command_substitution(self, git_repo):
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        command = 'git commit -m "$(cat msg.txt)"'
        result = run_bash(command, git_repo)
        assert result.returncode == 0, result.stderr

        response = handle_post_tool_use(hook_input(command, git_repo))

        assert response is not None
        assert "git commit --amend" in response["hookSpecificOutput"]["additionalContext"]

    def test_detection_names_the_commit_hash(self, git_repo):
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        run_bash("git commit -F msg.txt", git_repo)
        short_hash = run_bash("git rev-parse --short HEAD", git_repo).stdout.strip()

        response = handle_post_tool_use(hook_input("git commit -F msg.txt", git_repo))

        assert short_hash in response["hookSpecificOutput"]["additionalContext"]


class TestNoFalsePositives:
    def test_clean_commit_is_silent(self, git_repo):
        command = f'git commit -m "{CLEAN_MESSAGE}"'
        result = run_bash(command, git_repo)
        assert result.returncode == 0, result.stderr

        assert handle_post_tool_use(hook_input(command, git_repo)) is None

    def test_failed_commit_does_not_reflag_stale_head(self, git_repo):
        # Land a trailer-bearing commit with a committer date well outside the window...
        env = git_env()
        env["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00 +0000"
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        assert run_bash("git commit -F msg.txt", git_repo, env=env).returncode == 0

        # ...then a no-op `git commit` (nothing staged) that the Bash tool still "succeeds" on.
        command = 'git commit -m "nothing staged"'
        result = run_bash(command, git_repo)
        assert result.returncode != 0  # the commit itself failed

        assert handle_post_tool_use(hook_input(command, git_repo)) is None

    def test_non_git_command_exits_at_cheap_gate(self, git_repo, monkeypatch):
        def boom(*args, **kwargs):
            raise AssertionError("cheap gate must prevent any subprocess")

        monkeypatch.setattr(post_tool_use.subprocess, "run", boom)
        assert handle_post_tool_use(hook_input("echo hello", git_repo)) is None

    def test_non_repo_cwd_is_silent(self, tmp_path):
        assert handle_post_tool_use(hook_input("git commit -m x", tmp_path)) is None

    def test_missing_command_is_silent(self, git_repo):
        assert handle_post_tool_use({"tool_input": {}, "cwd": str(git_repo)}) is None


class TestAmendLoopTerminates:
    def test_clean_amend_produces_silence(self, git_repo):
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        run_bash("git commit -F msg.txt", git_repo)
        assert handle_post_tool_use(hook_input("git commit -F msg.txt", git_repo)) is not None

        # The remediation the hook asks for — re-fires the hook, must self-terminate.
        amend = f'git commit --amend -m "{CLEAN_MESSAGE}"'
        assert run_bash(amend, git_repo).returncode == 0
        assert handle_post_tool_use(hook_input(amend, git_repo)) is None

    def test_pathological_readd_is_reflagged(self, git_repo):
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        run_bash("git commit -F msg.txt", git_repo)

        # Amend that re-adds the trailer via another outside-argv form: still flagged.
        amend = f"git commit --amend -F - <<'EOF'\n{CLEAN_MESSAGE}\n\n{TRAILER}\nEOF"
        assert run_bash(amend, git_repo).returncode == 0
        assert handle_post_tool_use(hook_input(amend, git_repo)) is not None


class TestGitGlobalOptionForms:
    def test_git_dash_c_before_subcommand_still_gates_in(self, git_repo):
        """`git -c foo=bar commit` has no literal "git commit" substring — must still detect."""
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        command = "git -c core.pager=cat commit -F msg.txt"
        result = run_bash(command, git_repo)
        assert result.returncode == 0, result.stderr

        assert handle_post_tool_use(hook_input(command, git_repo)) is not None


class TestHelpers:
    def test_read_head_commit_returns_none_outside_repo(self, tmp_path):
        assert read_head_commit(str(tmp_path)) is None

    def test_read_head_commit_parses_head(self, git_repo):
        run_bash(f'git commit -m "{CLEAN_MESSAGE}"', git_repo)
        epoch, short_hash, message = read_head_commit(str(git_repo))
        assert abs(time.time() - epoch) < 60
        assert len(short_hash) >= 7
        assert message.strip() == CLEAN_MESSAGE

    def test_main_emits_json_on_detection_and_exits_zero(self, git_repo, monkeypatch, capsys):
        (git_repo / "msg.txt").write_text(f"{CLEAN_MESSAGE}\n\n{TRAILER}\n")
        run_bash("git commit -F msg.txt", git_repo)

        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input("git commit -F msg.txt", git_repo))))
        with pytest.raises(SystemExit) as exc:
            post_tool_use.main()
        assert exc.value.code == 0
        parsed = json.loads(capsys.readouterr().out)
        assert "additionalContext" in parsed["hookSpecificOutput"]

    def test_main_is_silent_and_exits_zero_on_garbage_stdin(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
        with pytest.raises(SystemExit) as exc:
            post_tool_use.main()
        assert exc.value.code == 0
        assert capsys.readouterr().out == ""
