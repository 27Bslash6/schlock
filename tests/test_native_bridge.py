"""Tests for the native_bridge subprocess client (LAB-409 T2a).

Scope is the subprocess layer only: binary resolution, the bounded stdout read,
and the exit-code contract of tools/schlock-parse. Nothing here asserts on the
shape of the typed-JSON beyond "it decodes" — mapping it to an AstView is T2b.
"""

import json
import platform
import subprocess
from pathlib import Path

import pytest

from schlock.core.native_bridge import (
    MAX_AST_JSON_SIZE,
    MAX_COMMAND_SIZE,
    NativeBridge,
    NativeBridgeError,
    platform_dir,
    resolve_binary,
)
from schlock.exceptions import ParseError
from schlock.integrations import commit_filter

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPO_ROOT / "tools" / "schlock-parse" / "testdata" / "corpus.json"


def _load_corpus():
    if not CORPUS_PATH.exists():
        return []
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


CORPUS = _load_corpus()


def _binary_available():
    try:
        resolve_binary()
    except NativeBridgeError:
        return False
    return True


needs_binary = pytest.mark.skipif(
    not _binary_available(),
    reason="no vendored schlock-parse binary for this platform",
)


def _fake_binary(tmp_path, body):
    """Write an executable stand-in for schlock-parse that runs `body`."""
    script = tmp_path / "fake-schlock-parse"
    script.write_text("#!/usr/bin/env python3\nimport sys\n" + body, encoding="utf-8")
    script.chmod(0o755)
    return script


class TestBinaryResolution:
    """Binary resolution must fail loudly — never silently degrade to no-parser."""

    def test_platform_dir_matches_vendored_layout(self):
        assert platform_dir() in {
            "linux-amd64",
            "linux-arm64",
            "darwin-amd64",
            "darwin-arm64",
            "windows-amd64",
        }

    def test_unsupported_arch_raises(self, monkeypatch):
        monkeypatch.setattr(platform, "machine", lambda: "sparc64")
        with pytest.raises(NativeBridgeError, match="unsupported platform"):
            platform_dir()

    def test_missing_binary_raises(self, tmp_path):
        with pytest.raises(NativeBridgeError, match="not found"):
            resolve_binary(bin_root=tmp_path)

    def test_non_executable_binary_raises(self, tmp_path):
        path = tmp_path / platform_dir() / "schlock-parse"
        path.parent.mkdir(parents=True)
        path.write_text("not executable", encoding="utf-8")
        path.chmod(0o644)
        with pytest.raises(NativeBridgeError, match="not executable"):
            resolve_binary(bin_root=tmp_path)

    def test_parse_with_missing_binary_raises_not_returns(self, tmp_path):
        bridge = NativeBridge(binary_path=tmp_path / "absent")
        with pytest.raises(NativeBridgeError):
            bridge.parse_json("echo hi")


@needs_binary
class TestCorpusParseability:
    """All 24 constructs must reach exit 0 with non-empty JSON (T2a acceptance)."""

    def test_corpus_covers_the_bashlex_failing_constructs(self):
        assert len(CORPUS) == 24
        assert sum(1 for c in CORPUS if c["bashlex_fails"]) >= 7

    @pytest.mark.parametrize("case", CORPUS, ids=[c["name"] for c in CORPUS])
    def test_construct_parses(self, case):
        payload = NativeBridge().parse_json(case["script"])
        assert payload
        assert json.loads(payload)["Type"] == "File"

    def test_parse_error_raises_parse_error(self):
        with pytest.raises(ParseError):
            NativeBridge().parse_json("if; then")


class TestExitContract:
    """Exit 3/4 and crashes must never be reported as a (partial) success."""

    @pytest.mark.parametrize("code", [3, 4])
    def test_partial_output_then_error_exit_is_not_swallowed(self, tmp_path, code):
        binary = _fake_binary(
            tmp_path,
            f'sys.stdout.write(\'{{"Type":"File"\')\nsys.stdout.flush()\nsys.exit({code})\n',
        )
        with pytest.raises(NativeBridgeError, match=f"exited {code}"):
            NativeBridge(binary_path=binary).parse_json("echo hi")

    def test_unexpected_exit_code_raises(self, tmp_path):
        binary = _fake_binary(tmp_path, "sys.exit(9)\n")
        with pytest.raises(NativeBridgeError, match="exited 9"):
            NativeBridge(binary_path=binary).parse_json("echo hi")

    def test_parse_error_exit_2_carries_stderr_detail(self, tmp_path):
        binary = _fake_binary(tmp_path, 'sys.stderr.write("1:1: bad syntax")\nsys.exit(2)\n')
        with pytest.raises(ParseError, match="bad syntax"):
            NativeBridge(binary_path=binary).parse_json("if; then")

    def test_command_reaches_the_binary_on_stdin(self, tmp_path):
        binary = _fake_binary(tmp_path, "sys.stdout.write(sys.stdin.read())\n")
        assert NativeBridge(binary_path=binary).parse_json("echo unique-marker") == "echo unique-marker"


class TestBoundedRead:
    """Output guard: bound the stream, kill the process, and reap it."""

    def test_overflow_kills_and_reaps_the_process(self, tmp_path, monkeypatch):
        binary = _fake_binary(
            tmp_path,
            "while True:\n    sys.stdout.write('x' * 4096)\n    sys.stdout.flush()\n",
        )
        spawned = []
        real_popen = subprocess.Popen

        def recording_popen(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        monkeypatch.setattr(subprocess, "Popen", recording_popen)

        bridge = NativeBridge(binary_path=binary, max_ast_json_size=8192)
        with pytest.raises(NativeBridgeError, match="exceeded"):
            bridge.parse_json("echo hi")

        assert len(spawned) == 1
        # returncode set => wait() ran => no zombie left behind.
        assert spawned[0].returncode is not None

    def test_output_at_the_bound_is_accepted(self, tmp_path):
        binary = _fake_binary(tmp_path, "sys.stdout.write('y' * 4096)\n")
        payload = NativeBridge(binary_path=binary, max_ast_json_size=4096).parse_json("echo hi")
        assert len(payload) == 4096


class TestSpawnDiscipline:
    """Parse-once: exactly one Popen per call, and no unbounded capture."""

    def test_single_spawn_and_no_capture_output(self, tmp_path, monkeypatch):
        binary = _fake_binary(tmp_path, "sys.stdout.write('{}')\n")
        calls = []
        real_popen = subprocess.Popen

        def recording_popen(*args, **kwargs):
            calls.append(kwargs)
            return real_popen(*args, **kwargs)

        monkeypatch.setattr(subprocess, "Popen", recording_popen)

        assert NativeBridge(binary_path=binary).parse_json("echo hi") == "{}"
        assert len(calls) == 1
        assert "capture_output" not in calls[0]
        assert calls[0]["stdout"] is subprocess.PIPE


class TestSizeGuards:
    """Spec §5: both guards fail-closed — a trip raises NativeBridgeError before any partial work."""

    def test_default_bounds_are_the_spec_values(self):
        assert MAX_COMMAND_SIZE == 64 * 1024
        assert MAX_AST_JSON_SIZE == 12 * 1024 * 1024

    @pytest.mark.parametrize(
        "command",
        ["a" * (MAX_COMMAND_SIZE + 1), "é" * (MAX_COMMAND_SIZE // 2 + 1)],
        ids=["ascii", "multibyte-under-the-char-count"],
    )
    def test_oversized_input_never_spawns(self, monkeypatch, command):
        # Bytes, not code points: the CLI reads bytes, so a len(str) check would under-guard.
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        with pytest.raises(NativeBridgeError, match="exceeds"):
            NativeBridge().parse_json(command)

    def test_input_at_the_bound_is_accepted(self, tmp_path):
        binary = _fake_binary(tmp_path, "sys.stdout.write(str(len(sys.stdin.buffer.read())))\n")
        assert NativeBridge(binary_path=binary).parse_json("a" * MAX_COMMAND_SIZE) == str(MAX_COMMAND_SIZE)

    def test_unencodable_input_routes_to_fallback(self, monkeypatch):
        # A lone surrogate reaches the hook via a `\ud800` escape in its JSON stdin.
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        with pytest.raises(NativeBridgeError, match="not UTF-8"):
            NativeBridge().parse_json("echo \ud800")

    def test_deeply_nested_json_routes_to_fallback(self, tmp_path):
        # json.loads overflows the C scanner on deep nesting; a bare RecursionError skips T5's routing.
        binary = _fake_binary(tmp_path, "sys.stdout.write('[' * 100000 + ']' * 100000)\n")
        with pytest.raises(NativeBridgeError, match="malformed"):
            NativeBridge(binary_path=binary).parse("echo hi")

    def test_commit_filter_shares_the_core_constant(self):
        assert commit_filter.MAX_COMMAND_SIZE == MAX_COMMAND_SIZE


@needs_binary
class TestOutputBoundAtMaxInput:
    """The bound clears the spec's legitimate 64 KiB worst case and trips CLEANLY on the dense
    shapes it is sized to reject (memory budget — see MAX_AST_JSON_SIZE)."""

    def test_sparse_max_size_input_parses_on_the_native_tier(self):
        command = ("echo a;" * (MAX_COMMAND_SIZE // 7)).ljust(MAX_COMMAND_SIZE)
        assert json.loads(NativeBridge().parse_json(command))["Type"] == "File"

    def test_dense_max_size_input_trips_the_bound_and_falls_back(self):
        command = "a|b|c|d|e|f|g|h;" * (MAX_COMMAND_SIZE // 16)
        with pytest.raises(NativeBridgeError, match="exceeded"):
            NativeBridge().parse_json(command)
