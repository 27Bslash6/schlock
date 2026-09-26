"""Tests for hooks/hooks.json — the configured command line, not the hook module.

Claude Code runs a `command` hook declared without an `args` array in *shell form*: the
command string is handed to a shell (`/bin/sh -c` on POSIX, observed against Claude Code
2.1.278). Everything the hook module can do about its own failures therefore begins only
once the interpreter has started and compiled the file. A failure before that point — no
`python3` on PATH, a SyntaxError in pre_tool_use.py — exits non-zero with empty stdout,
and a non-zero exit carrying no decision lets the tool call proceed.

So the manifest carries the outermost guard: exit 2 is the one exit code that blocks a
PreToolUse tool call on its own, whatever is or is not on stdout, and the command exits 2
unless the hook both exits 0 and prints a decision. Exit status alone is not proof the hook
ran — a `python3` that is not the expected binary can exit 0 having printed nothing — and
neither is a stray key name, so "a decision" means stdout is the envelope pre_tool_use.py
writes, start to end. Whatever stdout carries is passed through on every exit, so a block
keeps the reason the hook gave for it. These tests read the command string out of
hooks.json rather than restating it, so editing the guard away fails them.
"""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional, Union

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
MANIFEST = HOOKS_DIR / "hooks.json"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="exercises POSIX /bin/sh semantics",
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
        "the guard inert text rather than shell syntax"
    )
    return hooks[0]["command"]


def _all_commands() -> list:
    """Every command string in the manifest, across all events."""
    events = json.loads(MANIFEST.read_text())["hooks"].values()
    return [h["command"] for entries in events for e in entries for h in e["hooks"]]


def _envelope(decision: str) -> str:
    """The stdout pre_tool_use.py writes for one decision — the shape the guard accepts."""
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}})


def _run(
    command: str,
    plugin_root: Path,
    payload: Union[dict, str],
    *,
    home: Path,
    path: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a manifest command line the way the harness does: a POSIX shell, payload on stdin.

    A `str` payload is sent verbatim, for input the harness would never produce.

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
        input=payload if isinstance(payload, str) else json.dumps(payload),
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

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "hello",
            "{}",
            '{"permissionDecision": "allow"}',
            '{"hookSpecificOutput": {"hookEventName": "PreToolUse"}}',
            'plugin/"permissionDecision"/hooks/pre_tool_use.py',
            "banner\n" + _envelope("allow"),
            _envelope("allow") + "\nbanner",
        ],
        ids=[
            "silent",
            "not-a-decision",
            "empty-object",
            "key-outside-the-envelope",
            "envelope-without-a-decision",
            "key-name-in-other-text",
            "envelope-after-other-output",
            "envelope-before-other-output",
        ],
    )
    def test_python3_that_exits_zero_without_a_decision_blocks(self, tmp_path, stdout):
        """A shadowed `python3` that exits 0 never ran the hook: status 0 is not a decision.

        Nor is text that merely mentions one. The harness reads stdout as a single JSON object
        and proceeds when it cannot, so anything but the whole envelope must block.
        """
        root = _stub_plugin_root(tmp_path, "")
        fake_bin = tmp_path / "fake-bin"
        fake_bin.mkdir()
        fake = fake_bin / "python3"
        fake.write_text(f"#!/bin/sh\nprintf '%s' {shlex.quote(stdout)}\nexit 0\n")
        fake.chmod(0o755)

        result = _run(_hook_command("Bash"), root, BASH_PAYLOAD, home=tmp_path, path=f"{fake_bin}:/usr/bin:/bin")

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == "", "nothing the harness could read as a decision may pass through"

    @pytest.mark.parametrize("decision", ["allow", "deny"])
    def test_decision_followed_by_a_non_zero_exit_blocks_and_keeps_its_stdout(self, tmp_path, decision):
        """A hook that printed a decision and then failed is still a failed hook -> exit 2.

        Its stdout is passed through all the same, so a deny keeps the reason the model is
        shown instead of degrading to whatever the hook logged on stderr.
        """
        root = _stub_plugin_root(tmp_path, f"import sys\nprint({_envelope(decision)!r})\nsys.exit(1)\n")

        result = _run(_hook_command("Bash"), root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 2, f"expected a block, got rc={result.returncode} stdout={result.stdout!r}"
        assert result.stdout.strip() == _envelope(decision)


class TestEveryHookStartsFromAPathContainingASpace:
    """Every plugin-root path is quoted, so `/Users/Jane Smith/...` does not brick a tool.

    Unquoted, the shell splits the path and python3 exits 2 on its own ("can't open file") —
    and exit 2 blocks. An unquoted entry therefore does not merely fail to start, it
    hard-blocks every call its matcher covers, for the whole session.
    """

    @pytest.mark.parametrize("command", _all_commands())
    def test_command_starts(self, tmp_path, command):
        root = _stub_plugin_root(tmp_path / "plugin root", f"print({_envelope('allow')!r})\n")

        result = _run(command, root, BASH_PAYLOAD, home=tmp_path)

        assert result.returncode == 0, f"rc={result.returncode} stderr={result.stderr!r}"
        assert result.stdout.strip() == _envelope("allow")


class TestPreToolUseStillDeliversOrdinaryDecisions:
    """The guard fires on a non-zero exit or a missing decision, and allow, ask and deny all
    exit 0 with a decision — so it cannot turn a decision the validator reached into a block
    it did not choose. `ask` is the case that matters: converting a prompt the user could
    approve into a hard block would take the choice away from them, which is the opposite of
    what the risk presets are for.

    main()'s own error paths are the exception: they print a deny and exit 1, which the guard
    turns into exit 2 — a block either way — while forwarding the deny so its reason survives.
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
            f"an ordinary decision must exit 0 or the guard turns it into a hard block: "
            f"rc={result.returncode} stderr={result.stderr[-500:]!r}"
        )
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == expected

    def test_real_hook_error_path_deny_keeps_its_reason(self, tmp_path):
        """Unparseable stdin takes main()'s JSONDecodeError path: a deny, then exit 1."""
        result = _run(_hook_command("Bash"), REPO_ROOT, "not json", home=tmp_path)

        assert result.returncode == 2, f"rc={result.returncode} stderr={result.stderr[-500:]!r}"
        output = json.loads(result.stdout)["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"
        assert output["permissionDecisionReason"] == "BLOCKED: Invalid hook input"


class TestSelfProtectStaysFailOpen:
    """The write-tool hook is deliberately fail-open and must not inherit the exit-2 guard.

    self_protect.py is a lock on schlock's own config file, not a gate. If python3 is missing
    the Bash entry already blocks every command, so guarding this one too would only remove
    the last way to repair the install from inside the session.
    """

    def test_write_tool_hook_has_no_exit_guard(self):
        assert "exit 2" not in _hook_command("Write|Edit|MultiEdit|NotebookEdit")
