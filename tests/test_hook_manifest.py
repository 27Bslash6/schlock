"""Tests for hooks/hooks.json — the configured command line, not the hook module.

Claude Code runs a `command` hook declared without an `args` array in *shell form*: the
command string is handed to a shell (`/bin/sh -c` on POSIX, observed against Claude Code
2.1.278). Everything the hook module can do about its own failures therefore begins only
once the interpreter has started and compiled the file. A failure before that point — no
`python3` on PATH, a SyntaxError in pre_tool_use.py — exits non-zero with empty stdout,
and a non-zero exit carrying no decision lets the tool call proceed.

So the manifest carries the outermost guard, `|| exit 2`: exit 2 is the one exit code that
blocks a PreToolUse tool call on its own, whatever is or is not on stdout. These tests read
the command string out of hooks.json rather than restating it, so editing the guard away
fails them.

Windows is not covered — see the skip reason below.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
MANIFEST = HOOKS_DIR / "hooks.json"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="shell-form hook commands run under PowerShell on Windows, where `||` needs v7; no Windows CI to pin it",
)


def _hook_command(matcher: str) -> str:
    """The PreToolUse command string Claude Code would hand to the shell for one matcher."""
    entries = json.loads(MANIFEST.read_text())["hooks"]["PreToolUse"]
    matching = [e for e in entries if e.get("matcher") == matcher]
    assert len(matching) == 1, f"expected exactly one PreToolUse entry matching {matcher!r}"
    hooks = matching[0]["hooks"]
    assert len(hooks) == 1, f"expected exactly one hook under PreToolUse/{matcher}"
    assert "args" not in hooks[0], (
        "an `args` array switches Claude Code from shell form to a direct spawn, which makes "
        "`|| exit 2` inert text rather than shell syntax"
    )
    return hooks[0]["command"]


def _all_commands() -> list:
    """Every command string in the manifest, across all events."""
    events = json.loads(MANIFEST.read_text())["hooks"].values()
    return [h["command"] for entries in events for e in entries for h in e["hooks"]]


def _run(
    command: str,
    plugin_root: Path,
    payload: dict,
    *,
    home: Path,
    path: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a manifest command line the way the harness does: a POSIX shell, payload on stdin.

    `home` is also used as the working directory, and both are throwaway and distinct from
    the repo: schlock resolves its user config under HOME and its project config under the
    working directory, so without both a developer's own config would steer the result.
    """
    env = {
        "CLAUDE_PLUGIN_ROOT": str(plugin_root),
        "HOME": str(home),
        "PATH": os.environ["PATH"] if path is None else path,
    }
    return subprocess.run(
        ["/bin/sh", "-c", command],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=home,
        env=env,
        timeout=60,
        check=False,
    )


def _stub_plugin_root(directory: Path, body: str) -> Path:
    """A plugin root whose hook scripts are all `body`, for the failure-to-start cases."""
    (directory / "hooks").mkdir(parents=True, exist_ok=True)
    for script in HOOKS_DIR.glob("*.py"):
        (directory / "hooks" / script.name).write_text(body)
    return directory


BASH_PAYLOAD = {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}


class TestPreToolUseFailsClosedOnStartupFailure:
    """A schlock install that cannot start its hook must block, not wave the command through."""

    def test_missing_python3_blocks(self, tmp_path):
        """python3 absent from PATH: the shell exits 127 with no decision -> must become exit 2."""
        root = _stub_plugin_root(tmp_path, "")
        empty_bin = tmp_path / "empty-bin"
        empty_bin.mkdir()

        result = _run(_hook_command("Bash"), root, BASH_PAYLOAD, home=tmp_path, path=str(empty_bin))

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == "", "a startup failure has no decision to report"

    def test_syntax_error_in_hook_file_blocks(self, tmp_path):
        """A SyntaxError in pre_tool_use.py: no guard inside the file can exist yet -> exit 2.

        Distinct from the case above: schlock declares Python >=3.9, so a too-old interpreter
        fails here rather than at the `python3` lookup.
        """
        root = _stub_plugin_root(tmp_path, "def (\n")

        result = _run(_hook_command("Bash"), root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == "", "a file that will not compile emits no decision"


class TestEveryHookStartsFromAPathContainingASpace:
    """Every plugin-root path is quoted, so `/Users/Jane Smith/...` does not brick a tool.

    Unquoted, the shell splits the path and python3 exits 2 on its own ("can't open file") —
    and exit 2 blocks. An unquoted entry therefore does not merely fail to start, it
    hard-blocks every call its matcher covers, for the whole session.
    """

    @pytest.mark.parametrize("command", _all_commands())
    def test_command_starts(self, tmp_path, command):
        root = _stub_plugin_root(tmp_path / "plugin root", "print('{\"ok\": true}')\n")

        result = _run(command, root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 0, f"rc={result.returncode} stderr={result.stderr!r}"
        assert json.loads(result.stdout) == {"ok": True}


class TestPreToolUseStillDeliversOrdinaryDecisions:
    """`|| exit 2` fires on a non-zero exit, and allow, ask and deny all exit 0 — so it cannot
    turn a decision the validator reached into a block it did not choose. `ask` is the case
    that matters: converting a prompt the user could approve into a hard block would take the
    choice away from them, which is the opposite of what the risk presets are for.
    """

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("echo hello", "allow"),
            ("git push --force", "ask"),
            ("rm -rf /", "deny"),
        ],
    )
    def test_real_hook_exits_zero_with_the_expected_decision(self, tmp_path, command, expected):
        """Drive the real hook through the configured command line, under default settings."""
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}

        result = _run(_hook_command("Bash"), REPO_ROOT, payload, home=tmp_path)

        assert result.returncode == 0, (
            f"an ordinary decision must exit 0 or `|| exit 2` turns it into a hard block: "
            f"rc={result.returncode} stderr={result.stderr[-500:]!r}"
        )
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == expected


class TestSelfProtectStaysFailOpen:
    """The write-tool hook is deliberately fail-open and must not inherit `|| exit 2`.

    self_protect.py is a lock on schlock's own config file, not a gate. If python3 is missing
    the Bash entry already blocks every command, so guarding this one too would only remove
    the last way to repair the install from inside the session.
    """

    def test_write_tool_hook_has_no_exit_guard(self):
        assert "exit 2" not in _hook_command("Write|Edit|MultiEdit|NotebookEdit")


class TestPreToolUseFailsClosedOnNonTerminatingValidation:
    """A validation that never returns must block; Claude Code lets a timed-out hook through (LAB-4959)."""

    def test_unterminated_brace_heredoc_denies_promptly(self, tmp_path):
        """The LAB-4959 repro, through the real hook and its vendored bashlex: vanilla bashlex never returns."""
        payload = {"tool_name": "Bash", "tool_input": {"command": 'git commit -m "$(cat << EOF\n${\nEOF\n)"; echo ran'}}

        start = time.monotonic()
        result = _run(_hook_command("Bash"), REPO_ROOT, payload, home=tmp_path)

        # Well inside the 30 s soft deadline, so this pins the parse itself returning.
        assert time.monotonic() - start < 10
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_stall_the_soft_deadline_cannot_interrupt_blocks(self, tmp_path):
        """SIGALRM held off (as C code holding the GIL would): the watchdog exits and `|| exit 2` blocks."""
        stub = f"""
import signal, sys, time
sys.path.insert(0, {str(HOOKS_DIR)!r})
import pre_tool_use

def stall(command):
    signal.pthread_sigmask(signal.SIG_BLOCK, {{signal.SIGALRM}})
    time.sleep(30)

pre_tool_use.validate_command = stall
pre_tool_use.VALIDATION_DEADLINE_S = 0.1
pre_tool_use.HARD_DEADLINE_S = 1
pre_tool_use.main()
"""
        root = _stub_plugin_root(tmp_path / "plugin", stub)

        result = _run(_hook_command("Bash"), root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == ""
