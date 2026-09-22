"""Tests for hooks/hooks.json — the command line, not the hook module.

Claude Code runs a `command` hook declared without an `args` array in *shell form*: the
`command` string is handed to a shell (`/bin/sh -c` on POSIX, observed against Claude Code
2.1.278). Everything the hook module can do about its own failures therefore starts only
once the interpreter has run and compiled the file. A failure *before* that point — no
`python3` on PATH, a SyntaxError in pre_tool_use.py, the process killed — exits non-zero
with empty stdout, which Claude Code treats as a non-blocking error: the tool call proceeds.

So the manifest carries the outermost guard, `|| exit 2`: exit 2 is the one exit code that
blocks a PreToolUse tool call through the code alone. These tests drive the *configured
command line* read straight out of hooks.json, so they fail if that guard is edited away.

Windows is not covered: schlock has no Windows CI, and on Windows without Git Bash the
shell is PowerShell, where `||` is a pipeline chain operator only from PowerShell 7.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "hooks" / "hooks.json"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="shell-form hook commands run under PowerShell on Windows; no Windows CI to pin it",
)


def _hook_command(event: str, matcher: str) -> str:
    """The command string Claude Code would hand to the shell for one manifest entry."""
    entries = json.loads(MANIFEST.read_text())["hooks"][event]
    matching = [e for e in entries if e.get("matcher") == matcher]
    assert len(matching) == 1, f"expected exactly one {event} entry matching {matcher!r}"
    hooks = matching[0]["hooks"]
    assert len(hooks) == 1, f"expected exactly one hook under {event}/{matcher}"
    return hooks[0]["command"]


def _run(
    command: str,
    plugin_root: Path,
    payload: dict,
    *,
    home: Path,
    path: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a manifest command line the way the harness does: a POSIX shell, payload on stdin.

    CLAUDE_PLUGIN_ROOT is passed through the environment because shell form lets the shell
    expand it; Claude Code exports it into the hook's environment for exactly that reason.
    `home` is a throwaway directory and is always distinct from the repo, so a run of the
    real hook writes its audit log and reads its config somewhere disposable.
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
        env=env,
        timeout=60,
        check=False,
    )


def _stub_plugin_root(directory: Path, body: str) -> Path:
    """A plugin root whose hooks/pre_tool_use.py is `body`, for the failure-to-start cases."""
    (directory / "hooks").mkdir(parents=True, exist_ok=True)
    (directory / "hooks" / "pre_tool_use.py").write_text(body)
    return directory


BASH_PAYLOAD = {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}


class TestPreToolUseFailsClosedOnStartupFailure:
    """A schlock install that cannot start its hook must block, not wave the command through."""

    def test_missing_python3_blocks(self, tmp_path):
        """python3 absent from PATH: the shell exits ~127 with no decision -> must be exit 2."""
        root = _stub_plugin_root(tmp_path, "raise SystemExit(0)\n")
        empty_bin = tmp_path / "empty-bin"
        empty_bin.mkdir()

        result = _run(_hook_command("PreToolUse", "Bash"), root, BASH_PAYLOAD, home=tmp_path, path=str(empty_bin))

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == "", "a startup failure has no decision to report"

    def test_syntax_error_in_hook_file_blocks(self, tmp_path):
        """A SyntaxError in pre_tool_use.py: no guard inside the file can exist yet -> exit 2."""
        root = _stub_plugin_root(tmp_path, "def (\n")

        result = _run(_hook_command("PreToolUse", "Bash"), root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == "", "a file that will not compile emits no decision"

    def test_plugin_root_containing_a_space_still_starts(self, tmp_path):
        """The path is quoted, so a home directory like `/Users/Jane Smith` does not brick the gate.

        Unquoted, the shell would split the path and the hook would fail to start — which, with
        `|| exit 2` in place, would block every Bash command instead of silently disabling schlock.
        """
        root = _stub_plugin_root(tmp_path / "plugin root", "print('{\"ok\": true}')\n")

        result = _run(_hook_command("PreToolUse", "Bash"), root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 0, f"rc={result.returncode} stderr={result.stderr!r}"
        assert json.loads(result.stdout) == {"ok": True}


class TestPreToolUseStillDeliversOrdinaryDecisions:
    """`|| exit 2` fires on a non-zero exit — every ordinary decision must exit 0, so it never does."""

    @pytest.mark.parametrize(
        "command",
        [
            "echo hello",  # safe -> allow
            "chmod 777 /tmp/schlock-manifest-test",  # elevated risk -> ask or deny by preset
            "rm -rf /",  # blocked
        ],
    )
    def test_real_hook_exits_zero_and_emits_json(self, tmp_path, command):
        """Drive the real hook through the configured command line; the decision comes from stdout."""
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}

        result = _run(_hook_command("PreToolUse", "Bash"), REPO_ROOT, payload, home=tmp_path)

        assert result.returncode == 0, (
            f"an ordinary decision must exit 0 or `|| exit 2` turns it into a hard block: "
            f"rc={result.returncode} stderr={result.stderr[-500:]!r}"
        )
        decision = json.loads(result.stdout)["hookSpecificOutput"]
        assert decision["hookEventName"] == "PreToolUse"


class TestSelfProtectStaysFailOpen:
    """The sibling write-tool hook is deliberately fail-open; it must not inherit `|| exit 2`.

    self_protect.py is a lock on schlock's own config file, not a gate: it denies only when a
    write targets a protected path and exits 0 otherwise. If python3 is missing, the Bash gate
    above already blocks every command — adding the same guard here would also block every
    Write/Edit, leaving no way to repair the install from inside the session, in order to
    protect a config file whose validator is not running anyway.
    """

    def test_write_tool_hook_has_no_exit_guard(self):
        assert "exit 2" not in _hook_command("PreToolUse", "Write|Edit|MultiEdit|NotebookEdit")
