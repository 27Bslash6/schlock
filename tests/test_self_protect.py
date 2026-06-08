"""Tests for the Write/Edit self-protection hook (hooks/self_protect.py, issue #92)."""

import json
import ntpath
import posixpath
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Add src and hooks to path (mirrors tests/test_hook_integration.py).
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

import self_protect  # noqa: E402
from self_protect import decide  # noqa: E402

_HOOK = Path(__file__).parent.parent / "hooks" / "self_protect.py"


class TestSelfProtectDecide:
    """decide() blocks write-tool calls targeting schlock config, allows everything else."""

    @pytest.mark.parametrize(
        "tool_name,tool_input",
        [
            ("Write", {"file_path": "/home/user/.config/schlock/config.yaml", "content": "rule_overrides: {}"}),
            ("Write", {"file_path": ".claude/hooks/schlock-config.yaml", "content": "x"}),
            ("Write", {"file_path": "project/.claude/hooks/schlock-config.yaml", "content": "x"}),
            ("Edit", {"file_path": "/home/user/.config/schlock/config.yaml", "new_string": "x", "old_string": ""}),
            ("MultiEdit", {"file_path": ".claude/hooks/schlock-config.yaml", "edits": []}),
            ("NotebookEdit", {"notebook_path": "/x/.config/schlock/config.yaml", "new_source": "x"}),
            ("Write", {"file_path": "schlock-config.yaml", "content": "x"}),  # bare filename
            ("Write", {"file_path": "/home/user/.config/schlock/../schlock/config.yaml", "content": "x"}),  # .. traversal
            ("Write", {"file_path": ".config/schlock//config.yaml", "content": "x"}),  # double slash
        ],
    )
    def test_blocks_write_to_config(self, tool_name, tool_input):
        result = decide({"tool_name": tool_name, "tool_input": tool_input})
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "schlock" in result["hookSpecificOutput"]["permissionDecisionReason"].lower()

    @pytest.mark.parametrize(
        "tool_name,tool_input",
        [
            ("Write", {"file_path": "src/main.py", "content": "print('hi')"}),
            ("Edit", {"file_path": "README.md", "new_string": "x", "old_string": "y"}),
            ("Write", {"file_path": ".claude/hooks/other-config.yaml", "content": "x"}),
            ("Write", {"file_path": "not-schlock-config.yaml-backup", "content": "x"}),  # substring, not suffix
            ("NotebookEdit", {"notebook_path": "analysis.ipynb", "new_source": "x"}),
        ],
    )
    def test_allows_non_config_writes(self, tool_name, tool_input):
        assert decide({"tool_name": tool_name, "tool_input": tool_input}) is None

    @pytest.mark.parametrize("tool_name", ["Bash", "Read", "Grep", "Glob", "WebFetch", "file_write", ""])
    def test_allows_non_write_tools(self, tool_name):
        # Even pointing at a config path, a non-write tool is not this hook's concern.
        data = {"tool_name": tool_name, "tool_input": {"file_path": ".config/schlock/config.yaml"}}
        assert decide(data) is None

    @pytest.mark.parametrize(
        "data",
        [
            {},
            {"tool_name": "Write"},
            {"tool_name": "Write", "tool_input": None},
            {"tool_name": "Write", "tool_input": {"file_path": None}},
            {"tool_name": 123, "tool_input": "nope"},
            {"tool_input": {"file_path": ".config/schlock/config.yaml"}},  # missing tool_name
        ],
    )
    def test_malformed_input_fails_open(self, data):
        # No exception, returns None (allow).
        assert decide(data) is None


class TestSelfProtectEndToEnd:
    """Invoke the hook as a subprocess, exactly as Claude Code does."""

    def _run(self, payload: dict) -> str:
        proc = subprocess.run(
            [sys.executable, str(_HOOK)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0
        return proc.stdout.strip()

    def test_deny_write_to_config(self):
        out = self._run({"tool_name": "Write", "tool_input": {"file_path": "/x/.config/schlock/config.yaml", "content": "x"}})
        assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_allow_non_config_write_emits_nothing(self):
        out = self._run({"tool_name": "Write", "tool_input": {"file_path": "/x/main.py", "content": "x"}})
        assert out == ""  # deny-only hook: silent allow

    def test_malformed_stdin_emits_nothing(self):
        proc = subprocess.run(
            [sys.executable, str(_HOOK)], input="not json", capture_output=True, text=True, timeout=10, check=False
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""


class TestSelfProtectPathSync:
    """Drift guard: the hook's hardcoded paths must match the validator's."""

    def test_paths_match_validator(self):
        from schlock.core.validator import SELF_PROTECTION_PATHS as VALIDATOR_PATHS  # noqa: PLC0415

        assert set(self_protect.SELF_PROTECTION_PATHS) == set(VALIDATOR_PATHS)


class TestSelfProtectWindowsPaths:
    """Separator/case coverage across platforms.

    _targets_protected uses only os.path.{normpath,normcase,sep}, so swapping the
    module-local ``os`` binding to a namespace backed by ntpath / posixpath exercises
    Windows / POSIX path semantics on ANY host (both modules emulate the other platform).
    This gives real coverage on the Linux CI runner instead of a Windows-only skipif that
    never executes there. Note: backslash paths CANNOT be added to the POSIX deny-list
    (TestSelfProtectDecide) — on POSIX '\\' is a literal filename char, not a separator,
    so such a path is a genuinely different file and is correctly allowed
    (see test_posix_backslash_is_literal).
    """

    def _decide(self, monkeypatch, pathmod, file_path):
        monkeypatch.setattr(self_protect, "os", SimpleNamespace(path=pathmod))
        return decide({"tool_name": "Write", "tool_input": {"file_path": file_path, "content": "x"}})

    @pytest.mark.parametrize(
        "file_path",
        [
            r".config\schlock\config.yaml",  # relative, backslash separators
            r"C:\Users\user\.config\schlock\config.yaml",  # absolute Windows path
            r"project\.claude\hooks\schlock-config.yaml",  # project config, backslash
            ".config/schlock\\config.yaml",  # mixed forward/back separators
            r".CONFIG\SCHLOCK\CONFIG.YAML",  # case-insensitive on Windows (normcase folds)
        ],
    )
    def test_windows_paths_blocked(self, monkeypatch, file_path):
        result = self._decide(monkeypatch, ntpath, file_path)
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    @pytest.mark.parametrize(
        "file_path",
        [
            # Ends with 'schlock\config.yaml' but NOT '.config\schlock\config.yaml' — a real,
            # different file (suffix precision holds on Windows too, not just POSIX).
            r"C:\Users\user\AppData\Roaming\schlock\config.yaml",
            r"C:\Users\user\src\main.py",
            r"not-schlock-config.yaml-backup",  # substring, not suffix
        ],
    )
    def test_windows_non_config_allowed(self, monkeypatch, file_path):
        assert self._decide(monkeypatch, ntpath, file_path) is None

    def test_posix_backslash_is_literal(self, monkeypatch):
        # Documents WHY the Windows cases go through ntpath rather than the POSIX deny-list:
        # under posixpath a backslash path is one literal filename component, not the config.
        assert self._decide(monkeypatch, posixpath, r".config\schlock\config.yaml") is None
