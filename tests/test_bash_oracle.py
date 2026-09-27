"""Tests for scripts/bash-oracle, the only sanctioned way to execute a candidate command.

Two things are pinned. The oracle really runs bash, yet a destructive line cannot reach the
caller's files. And no test spawns a real shell outside it unless the allowlist below says
why.

The destructive vectors run against a decoy HOME in tmp_path, never the developer's own.
A test that would delete the real home directory if the sandbox regressed is the very
failure the oracle exists to prevent. The real home is still checked, but only for
visibility, and a visibility probe cannot destroy anything.
"""

import ast
import os
import pwd
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import run_bash_oracle as oracle

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="bubblewrap is Linux-only")


@pytest.fixture
def sandbox(oracle_home):
    """The caller's HOME, holding the kind of files a stray `rm -rf ~` destroys."""
    (oracle_home / ".ssh").mkdir()
    (oracle_home / ".ssh" / "id_canary").write_text("canary\n")
    (oracle_home / ".config").mkdir()
    (oracle_home / ".config" / "canary").write_text("canary\n")
    return oracle_home


def assert_canaries_intact(home: Path) -> None:
    assert (home / ".ssh" / "id_canary").read_text() == "canary\n"
    assert (home / ".config" / "canary").read_text() == "canary\n"


class TestContainment:
    @pytest.mark.parametrize(
        "vector",
        [
            "$'\\u72'm -rf ~",  # ANSI-C-escaped rm: passes a substring guard for "rm -rf"
            "rm -rf {home}",  # the literal absolute path to the home directory
            "rm -rf ~/.ssh ~/.config",
            "find ~ -delete",
        ],
    )
    def test_destructive_vector_runs_and_leaves_caller_home_intact(self, sandbox, vector):
        command = vector.format(home=shlex.quote(str(sandbox)))
        # Refuse to run the vector at all if the decoy's files are visible inside.
        seen = oracle(f"test -e {shlex.quote(str(sandbox / '.ssh' / 'id_canary'))}", sandbox)
        assert seen.returncode == 1, f"caller's HOME is visible inside the sandbox:\n{seen.stderr}"

        result = oracle(f"mkdir ~/.ssh && touch ~/.ssh/witness; {command}; test -e ~/.ssh/witness || echo RAN", sandbox)

        assert "RAN" in result.stdout, f"the vector did not delete the sandbox's own home:\n{result.stderr}"
        assert result.stderr.endswith(f"bash-oracle: exit={result.returncode}\n")
        assert_canaries_intact(sandbox)

    def test_exact_evasion_string_reports_it_ran(self, sandbox):
        result = oracle("$'\\u72'm -rf ~", sandbox)

        # rm empties the tmpfs HOME, then cannot unlink its mount point: bash ran rm.
        assert re.search(r"^rm: cannot remove .*: Device or resource busy$", result.stderr, re.M), result.stderr
        assert result.stderr.endswith("bash-oracle: exit=1\n")
        assert result.returncode == 1
        assert_canaries_intact(sandbox)

    def test_host_paths_outside_the_allowlist_are_invisible(self, sandbox):
        # Non-destructive on purpose: a probe that only looks cannot hurt a regressed sandbox.
        paths = [pwd.getpwuid(os.getuid()).pw_dir, REPO_ROOT, "/home", "/mnt", "/run", "/media", "/var", "/root"]
        probe = "; ".join(f"test -e {shlex.quote(str(p))} && echo VISIBLE:{shlex.quote(str(p))}" for p in paths)
        result = oracle(f"{probe}; true", sandbox)
        assert "VISIBLE" not in result.stdout

    def test_root_is_read_only_and_home_and_tmp_are_writable(self, sandbox):
        result = oracle("touch /usr/x /etc/x /x 2>/dev/null || echo RO; touch ~/x /tmp/x && echo RW", sandbox)
        assert result.stdout.split() == ["RO", "RW"]

    def test_no_network(self, sandbox):
        result = oracle("exec 3<>/dev/tcp/1.1.1.1/80", sandbox)
        assert "Network is unreachable" in result.stderr

    def test_environment_is_cleared(self, sandbox):
        result = oracle("env", sandbox)
        assert "leak-me" not in result.stdout
        assert f"HOME={sandbox}" in result.stdout.splitlines()


class TestReporting:
    def test_stdout_stderr_and_status_pass_through(self, sandbox):
        result = oracle("echo out; echo err >&2; exit 3", sandbox)
        assert (result.returncode, result.stdout, result.stderr) == (3, "out\n", "err\nbash-oracle: exit=3\n")

    def test_runs_as_bash_dash_c(self, sandbox):
        result = oracle('echo "$0" "$#"; echo "${BASH_VERSION%%.*}"', sandbox)
        assert result.stdout.splitlines()[0] == "bash 0"

    def test_timeout_kills_the_command(self, sandbox):
        marker = "sleep 97.25"
        started = time.monotonic()
        result = oracle(marker, sandbox, "-t", "1")
        assert time.monotonic() - started < 10
        assert (result.returncode, result.stderr) == (124, "bash-oracle: timeout=1\n")
        time.sleep(0.2)
        leftover = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True, check=False)
        assert leftover.stdout == "", "the sandboxed command outlived the oracle"


class TestFailsClosed:
    def test_without_bwrap_nothing_runs(self, tmp_path):
        empty = tmp_path / "empty-bin"
        empty.mkdir()
        witness = tmp_path / "witness"

        result = oracle(f"touch {shlex.quote(str(witness))}", tmp_path, path=str(empty))

        assert result.returncode == 125
        assert "refusing to run unsandboxed" in result.stderr
        assert not witness.exists()

    @pytest.mark.parametrize(
        ("home", "reason"),
        [("/", "would hide"), ("/usr", "would hide"), ("/etc/x", "would hide"), ("relative", "must be an absolute")],
    )
    def test_rejects_a_home_it_cannot_mount_safely(self, home, reason):
        result = oracle("true", Path(home))
        assert result.returncode == 125
        assert reason in result.stderr

    def test_rejects_bad_usage(self, tmp_path):
        assert oracle("true", tmp_path, "-t", "0").returncode == 2


# --- No real shell outside the oracle -------------------------------------------------

# Test code that spawns a real shell, and why it is not executing candidate commands.
# Add to this only for fixed, test-authored commands; a candidate goes through the oracle.
REAL_SHELL_ALLOWLIST = {
    "tests/test_post_tool_use.py": "fixed git commit commands in a tmp repo; the hook reads git log",
    "tests/test_hook_manifest.py": "runs hooks.json's own command line with HOME and cwd in tmp_path",
    "tests/conftest.py": "run_bash_oracle: the oracle itself",
}

_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "busybox"}
_SPAWNERS = {"run", "call", "check_call", "check_output", "Popen"}
_STRING_TO_SHELL = {"os.system", "os.popen", "pty.spawn", "subprocess.getoutput", "subprocess.getstatusoutput"}


def _spawns_real_shell(call: ast.Call) -> bool:
    """A call that hands a string to a shell: a shell argv, shell=True, os.system and kin."""
    func = call.func
    if isinstance(func, ast.Attribute):
        owner = func.value.id if isinstance(func.value, ast.Name) else ""
        name = f"{owner}.{func.attr}"
    else:
        name = getattr(func, "id", "")
    if name in _STRING_TO_SHELL or name.startswith(("os.exec", "os.spawn", "os.posix_spawn")):
        return True
    if name.rpartition(".")[2] not in _SPAWNERS:
        return False
    if any(k.arg == "shell" and not (isinstance(k.value, ast.Constant) and k.value.value is False) for k in call.keywords):
        return True
    argv = call.args[0] if call.args else None
    if isinstance(argv, (ast.List, ast.Tuple)) and argv.elts:
        head = argv.elts[0]
        if isinstance(head, ast.Constant):
            return Path(str(head.value)).name in _SHELLS
        # Python itself is not a shell; any other program the source does not spell out may be.
        return ast.unparse(head) != "sys.executable"
    return False


def _files_spawning_a_shell():
    for root in ("tests", "tools", "scripts"):
        for source in sorted((REPO_ROOT / root).rglob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            if any(isinstance(n, ast.Call) and _spawns_real_shell(n) for n in ast.walk(tree)):
                yield source.relative_to(REPO_ROOT).as_posix()


def test_no_real_shell_outside_the_oracle():
    offenders = [f for f in _files_spawning_a_shell() if f not in REAL_SHELL_ALLOWLIST]
    assert offenders == [], f"real shell spawned outside scripts/bash-oracle: {offenders}"


def test_allowlist_has_no_stale_entries():
    assert set(REAL_SHELL_ALLOWLIST) <= set(_files_spawning_a_shell())


@pytest.mark.parametrize(
    ("source", "spawns"),
    [
        ('subprocess.run(["bash", "-c", c])', True),
        ('subprocess.Popen(["/bin/sh", "-c", c])', True),
        ("subprocess.run(argv)", False),
        ("subprocess.run([shell, script])", True),  # an unknown program may be a shell
        ('subprocess.run("x", shell=True)', True),
        ('subprocess.check_output(["git", "log"])', False),
        ('subprocess.run([sys.executable, "-c", code])', False),
        ("os.system(c)", True),
        ("os.execvp(c, [c])", True),
        ("cursor.execute(sql)", False),
        ('assert parse(("find", [".", "-exec", "bash", "-c", "x"]))', False),
    ],
)
def test_the_guard_reads_calls_not_text(source, spawns):
    call = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call))
    assert _spawns_real_shell(call) is spawns
