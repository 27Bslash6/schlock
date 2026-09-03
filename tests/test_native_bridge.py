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

    def test_default_output_bound_is_the_spec_value(self):
        assert MAX_AST_JSON_SIZE == 32 * 1024 * 1024


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


class TestInputGuard:
    """Input guard (spec §5.1): oversized input never reaches the subprocess — fail-closed."""

    def test_default_input_bound_is_the_spec_value(self):
        assert MAX_COMMAND_SIZE == 64 * 1024

    def test_oversized_input_never_spawns(self, tmp_path, monkeypatch):
        binary = _fake_binary(tmp_path, "sys.stdout.write('{}')\n")
        spawns = []
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawns.append(a))

        with pytest.raises(NativeBridgeError, match="exceeds"):
            NativeBridge(binary_path=binary).parse_json("a" * (MAX_COMMAND_SIZE + 1))
        assert spawns == []

    def test_input_at_the_bound_is_accepted(self, tmp_path):
        binary = _fake_binary(tmp_path, "sys.stdout.write(str(len(sys.stdin.buffer.read())))\n")
        assert NativeBridge(binary_path=binary).parse_json("a" * MAX_COMMAND_SIZE) == str(MAX_COMMAND_SIZE)

    def test_bound_is_measured_in_utf8_bytes_not_code_points(self, tmp_path, monkeypatch):
        # The CLI reads bytes; a 64 KB *character* count of multibyte input is
        # far larger on the wire, so guarding on len(str) would under-guard.
        binary = _fake_binary(tmp_path, "sys.stdout.write('{}')\n")
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        with pytest.raises(NativeBridgeError, match="exceeds"):
            NativeBridge(binary_path=binary).parse_json("é" * (MAX_COMMAND_SIZE // 2 + 1))

    def test_commit_filter_shares_the_core_constant(self):
        # Relocated, not duplicated. commit_filter's own fail-open behaviour on a
        # trip is pinned by tests/test_commit_filter.py (test_size_limit_prevents_dos,
        # test_oversized_command_skips_bashlex_parse).
        assert commit_filter.MAX_COMMAND_SIZE == MAX_COMMAND_SIZE


@needs_binary
class TestOutputBoundServesLegitimateInput:
    """Output guard (spec §5.2) must trip only on subprocess pathology, never on a legitimate
    max-size command. `a|b|…;` is the densest node-per-byte shape mvdan produces (~400× JSON
    amplification measured, LAB-528); `echo a;` is the ~125× shape the original eval used."""

    @pytest.mark.parametrize("unit", ["a|b|c|d|e|f|g|h;", "a|b;", "a;", "x=1;", "echo a;"])
    def test_max_size_input_parses_on_the_native_tier(self, unit):
        command = (unit * (MAX_COMMAND_SIZE // len(unit))).ljust(MAX_COMMAND_SIZE)
        assert len(command.encode("utf-8")) == MAX_COMMAND_SIZE
        payload = NativeBridge().parse_json(command)
        assert json.loads(payload)["Type"] == "File"

    def test_output_bound_derives_from_the_input_bound(self):
        # 512× the input cap: above the ~400× measured legitimate ceiling, so a
        # bump to either constant keeps them coherent instead of silently re-opening MAJ #7.
        assert MAX_AST_JSON_SIZE == 512 * MAX_COMMAND_SIZE
