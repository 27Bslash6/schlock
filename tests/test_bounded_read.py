"""Files the working tree or the environment can name are read with a bound.

The hook-level cases run the real hook in a child process. What they pin is that the hook
finishes, and a regression there blocks on an open or reads without end — only a child
process can be timed out and memory-capped from outside.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from schlock.core.bounded_read import MAX_CONFIG_BYTES, MAX_READ_BYTES, load_config, read_bounded

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="needs RLIMIT_AS, so a regressed read stops at MemoryError"
)

COMMAND = "git push --force"  # HIGH: the shipped preset asks

# HIGH -> allow can only come from this file, so an "allow" for COMMAND proves the user config
# loaded after the project config was skipped. It also takes the hook down the "allow" path,
# the only one that loads the ShellCheck settings.
USER_CONFIG = """\
risk_tolerance:
  levels:
    SAFE: allow
    LOW: allow
    MEDIUM: allow
    HIGH: allow
    BLOCKED: deny
"""

# The three loaders that read the project config: risk tolerance and ShellCheck settings in
# the hook, rule overrides in the validator. Each must refuse it.
PROJECT_CONFIG_LOADERS = 3


def _cap_memory() -> None:
    """Make a regressed read of /dev/urandom stop at MemoryError instead of exhausting the machine."""
    import resource  # noqa: PLC0415 - Unix-only module

    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))


def _run(argv: list, home: Path, env: dict, stdin: str = "") -> subprocess.CompletedProcess:
    """Run `argv` with `home` as HOME and cwd, memory-capped and timed out."""
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        cwd=home,
        env={"HOME": str(home), "PATH": os.environ["PATH"], **env},
        timeout=20,
        preexec_fn=_cap_memory,
        check=False,
    )


def _run_hook(home: Path, audit_log: Path) -> "tuple[subprocess.CompletedProcess, str]":
    """Run the PreToolUse hook on COMMAND; return the process and its decision."""
    proc = _run(
        [sys.executable, str(HOOKS_DIR / "pre_tool_use.py")],
        home,
        {"SCHLOCK_AUDIT_LOG": str(audit_log)},
        stdin=json.dumps({"tool_name": "Bash", "tool_input": {"command": COMMAND}}),
    )
    return proc, json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]


def _urandom(path: Path) -> None:
    path.symlink_to("/dev/urandom")


def _oversized(path: Path) -> None:
    # Sparse, so it costs no disk. An unbounded read of it would pull 16 GiB.
    with path.open("wb") as handle:
        handle.truncate(16 * 1024**3)


def _alias_bomb(path: Path) -> None:
    # Under 2 KB, but each line doubles the work of the one before it.
    lines = ["a0: &a0 {k: v}"] + [f"a{i}: &a{i} {{<<: [*a{i - 1}, *a{i - 1}]}}" for i in range(1, 40)]
    path.write_text("\n".join(lines) + "\n")


@linux_only
@pytest.mark.parametrize(
    ("make_config", "refusal"),
    [
        (_urandom, "not a regular file"),
        (os.mkfifo, "not a regular file"),
        (_oversized, "larger than"),
        (_alias_bomb, "aliases are not allowed"),
    ],
    ids=["symlink-to-urandom", "fifo", "over-cap", "alias-bomb"],
)
def test_unreadable_project_config_is_skipped(tmp_path, make_config, refusal):
    """A project config the bound refuses is skipped; the user config and the audit line survive."""
    (tmp_path / ".config" / "schlock").mkdir(parents=True)
    (tmp_path / ".config" / "schlock" / "config.yaml").write_text(USER_CONFIG)
    (tmp_path / ".claude" / "hooks").mkdir(parents=True)
    make_config(tmp_path / ".claude" / "hooks" / "schlock-config.yaml")
    audit_log = tmp_path / "audit.jsonl"

    proc, decision = _run_hook(tmp_path, audit_log)

    assert proc.returncode == 0, proc.stderr
    assert decision == "allow", proc.stderr
    # Counted, not just present: with one loader regressed the other two still log the refusal,
    # and under the memory cap a regressed read ends in a MemoryError the loaders swallow like
    # any other failure.
    assert proc.stderr.count(refusal) == PROJECT_CONFIG_LOADERS, proc.stderr
    assert [json.loads(line)["command"] for line in audit_log.read_text().splitlines()] == [COMMAND]
    assert audit_log.stat().st_mode & 0o111 == 0, "the audit log is created with builtin open()'s mode"


@linux_only
def test_audit_log_fifo_does_not_stall_the_hook(tmp_path):
    """SCHLOCK_AUDIT_LOG naming a FIFO with no reader loses the audit line, not the decision."""
    audit_log = tmp_path / "audit.jsonl"
    os.mkfifo(audit_log)

    proc, decision = _run_hook(tmp_path, audit_log)

    assert proc.returncode == 0, proc.stderr
    assert decision == "ask", proc.stderr


POST_HOOK_PROBE = """\
import sys
sys.path.insert(0, sys.argv[1])
import post_tool_use
print(post_tool_use.is_schlock_checkout("."))
print(post_tool_use.read_last_seen("repo"))
post_tool_use.record_seen_head("repo", "abc")
print(post_tool_use.read_last_seen("repo")[0])
"""


@linux_only
def test_post_commit_reads_are_bounded(tmp_path):
    """The PostToolUse hook's manifest and state reads refuse what the bound refuses."""
    (tmp_path / ".claude-plugin").mkdir()
    _oversized(tmp_path / ".claude-plugin" / "plugin.json")
    state = tmp_path / "state.json"
    os.mkfifo(state)

    proc = _run([sys.executable, "-c", POST_HOOK_PROBE, str(HOOKS_DIR)], tmp_path, {"SCHLOCK_POST_COMMIT_STATE": str(state)})

    # Not schlock, so the commit gets scanned; no state until the FIFO is replaced by a real file.
    assert proc.stdout.split() == ["False", "None", "abc"], proc.stderr


@pytest.mark.parametrize(("read", "cap"), [(read_bounded, MAX_READ_BYTES), (load_config, MAX_CONFIG_BYTES)])
def test_cap_is_inclusive(tmp_path, read, cap):
    at_cap, over_cap = tmp_path / "at", tmp_path / "over"
    at_cap.write_bytes(b"#" * cap)  # a YAML comment, so load_config accepts it too
    over_cap.write_bytes(b"#" * (cap + 1))

    read(at_cap)
    with pytest.raises(OSError, match="larger than"):
        read(over_cap)
