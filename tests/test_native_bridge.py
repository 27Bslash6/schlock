"""Tests for the native_bridge subprocess client (LAB-409 T2a).

Scope is the subprocess layer only: binary resolution, the bounded stdout read,
and the exit-code contract of tools/schlock-parse. Nothing here asserts on the
shape of the typed-JSON beyond "it decodes" — mapping it to an AstView is T2b.
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from schlock.core import native_bridge
from schlock.core.native_bridge import (
    BINARY_NAME,
    DEFAULT_BIN_ROOT,
    MAX_AST_JSON_SIZE,
    MAX_COMMAND_SIZE,
    NATIVE_TIMEOUT,
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


class TestBinaryIntegrity:
    """Spec §7: never exec a binary whose SHA-256 is not the one MANIFEST.json records."""

    STAND_IN = b"#!/bin/sh\necho '{}'\n"

    @needs_binary
    def test_bit_flipped_vendored_binary_raises(self, tmp_path):
        # The acceptance case on the real artefact: a copy of the shipped binary, one bit flipped.
        real = resolve_binary()
        path = tmp_path / platform_dir() / real.name
        path.parent.mkdir()
        tampered = bytearray(real.read_bytes())
        tampered[len(tampered) // 2] ^= 0x01
        path.write_bytes(bytes(tampered))
        path.chmod(0o755)
        shutil.copy(DEFAULT_BIN_ROOT / "MANIFEST.json", tmp_path / "MANIFEST.json")
        with pytest.raises(NativeBridgeError, match="SHA-256"):
            resolve_binary(bin_root=tmp_path)

    def test_missing_manifest_raises(self, tmp_path, vendored):
        vendored(self.STAND_IN)
        (tmp_path / "MANIFEST.json").unlink()
        with pytest.raises(NativeBridgeError, match="MANIFEST"):
            resolve_binary(bin_root=tmp_path)

    @pytest.mark.parametrize(
        "manifest",
        [
            '{"binaries": {"plan9-386/schlock-parse": "00"}}',  # no entry for this platform
            '{"binaries": ["schlock-parse"]}',
            "not json",
        ],
    )
    def test_manifest_without_this_platforms_digest_raises(self, tmp_path, vendored, manifest):
        # Fail closed: no recorded digest is an integrity failure, never "nothing to check".
        vendored(self.STAND_IN)
        (tmp_path / "MANIFEST.json").write_text(manifest, encoding="utf-8")
        with pytest.raises(NativeBridgeError, match="MANIFEST"):
            resolve_binary(bin_root=tmp_path)

    def test_non_string_digest_raises(self, tmp_path, vendored):
        vendored(self.STAND_IN)
        (tmp_path / "MANIFEST.json").write_text(
            json.dumps({"binaries": {f"{platform_dir()}/{BINARY_NAME}": None}}), encoding="utf-8"
        )
        with pytest.raises(NativeBridgeError, match="SHA-256"):
            resolve_binary(bin_root=tmp_path)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
    def test_fifo_manifest_raises_without_blocking(self, tmp_path, vendored):
        # The check runs before the spawn deadline: a read that waits for a writer would hold
        # the hook past its own timeout, which fails open.
        vendored(self.STAND_IN)
        (tmp_path / "MANIFEST.json").unlink()
        os.mkfifo(tmp_path / "MANIFEST.json")
        started = time.monotonic()
        with pytest.raises(NativeBridgeError, match="regular file"):
            resolve_binary(bin_root=tmp_path)
        assert time.monotonic() - started < 1

    def test_oversized_binary_raises_without_hashing(self, tmp_path, vendored):
        # Sparse: no disk cost, but hashing 1 TiB would take minutes.
        binary = vendored(self.STAND_IN)
        with binary.open("r+b") as handle:
            handle.truncate(1 << 40)
        started = time.monotonic()
        with pytest.raises(NativeBridgeError, match="regular file of at most"):
            resolve_binary(bin_root=tmp_path)
        assert time.monotonic() - started < 1

    def test_check_runs_at_first_exec_not_construction(self, tmp_path, vendored, monkeypatch, spawned):
        # The check sits in the exec path: a swap after the bridge is built is still caught.
        binary = vendored(self.STAND_IN)
        monkeypatch.setattr(native_bridge, "DEFAULT_BIN_ROOT", tmp_path)
        bridge = NativeBridge()
        binary.write_bytes(b"#!/bin/sh\necho swapped\n")
        with pytest.raises(NativeBridgeError, match="SHA-256"):
            bridge.parse_json("echo hi")
        assert spawned == []

    def test_failure_is_cached_not_rehashed_per_parse(self, tmp_path, vendored, monkeypatch):
        # A command's substitutions each parse; re-hashing a bad binary per parse multiplies the cost.
        vendored(self.STAND_IN, digest="0" * 64)
        monkeypatch.setattr(native_bridge, "DEFAULT_BIN_ROOT", tmp_path)
        calls = []
        real = native_bridge._verify_digest
        monkeypatch.setattr(native_bridge, "_verify_digest", lambda *a: calls.append(a) or real(*a))
        bridge = NativeBridge()
        for _ in range(3):
            with pytest.raises(NativeBridgeError, match="SHA-256"):
                bridge.parse_json("echo hi")
        assert len(calls) == 1

    def test_verified_binary_is_executed(self, tmp_path, vendored, monkeypatch, spawned):
        vendored(self.STAND_IN)
        monkeypatch.setattr(native_bridge, "DEFAULT_BIN_ROOT", tmp_path)
        assert NativeBridge().parse_json("echo hi").strip() == "{}"
        assert len(spawned) == 1

    def test_every_vendored_binary_matches_manifest(self):
        # Platform-independent: CI runs on one OS, and needs_binary skips on ANY resolve failure,
        # so a stale digest for another target would otherwise only surface on its users' machines
        # as a silent fall back to bashlex.
        binaries = json.loads((DEFAULT_BIN_ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["binaries"]
        on_disk = {p.relative_to(DEFAULT_BIN_ROOT).as_posix() for p in DEFAULT_BIN_ROOT.glob(f"*/{BINARY_NAME}*")}
        assert (
            set(binaries)
            == on_disk
            == {
                "darwin-amd64/schlock-parse",
                "darwin-arm64/schlock-parse",
                "linux-amd64/schlock-parse",
                "linux-arm64/schlock-parse",
                "windows-amd64/schlock-parse.exe",
            }
        )
        for key, expected in binaries.items():
            assert hashlib.sha256((DEFAULT_BIN_ROOT / key).read_bytes()).hexdigest() == expected, key


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
    def test_partial_output_then_error_exit_is_not_swallowed(self, fake_binary, code):
        binary = fake_binary(
            f'sys.stdout.write(\'{{"Type":"File"\')\nsys.stdout.flush()\nsys.exit({code})\n',
        )
        with pytest.raises(NativeBridgeError, match=f"exited {code}"):
            NativeBridge(binary_path=binary).parse_json("echo hi")

    def test_unexpected_exit_code_raises(self, fake_binary):
        binary = fake_binary("sys.exit(9)\n")
        with pytest.raises(NativeBridgeError, match="exited 9"):
            NativeBridge(binary_path=binary).parse_json("echo hi")

    def test_parse_error_exit_2_carries_stderr_detail(self, fake_binary):
        binary = fake_binary('sys.stderr.write("1:1: bad syntax")\nsys.exit(2)\n')
        with pytest.raises(ParseError, match="bad syntax"):
            NativeBridge(binary_path=binary).parse_json("if; then")

    def test_command_reaches_the_binary_on_stdin(self, fake_binary):
        binary = fake_binary("sys.stdout.write(sys.stdin.read())\n")
        assert NativeBridge(binary_path=binary).parse_json("echo unique-marker") == "echo unique-marker"


class TestBoundedRead:
    """Output guard: bound the stream, kill the process, and reap it."""

    def test_overflow_kills_and_reaps_the_process(self, fake_binary, spawned):
        binary = fake_binary(
            "while True:\n    sys.stdout.write('x' * 4096)\n    sys.stdout.flush()\n",
        )
        bridge = NativeBridge(binary_path=binary, max_ast_json_size=8192)
        with pytest.raises(NativeBridgeError, match="exceeded"):
            bridge.parse_json("echo hi")

        assert len(spawned) == 1
        # returncode set => wait() ran => no zombie left behind.
        assert spawned[0].returncode is not None

    def test_output_at_the_bound_is_accepted(self, fake_binary):
        binary = fake_binary("sys.stdout.write('y' * 4096)\n")
        payload = NativeBridge(binary_path=binary, max_ast_json_size=4096).parse_json("echo hi")
        assert len(payload) == 4096


class TestTimeout:
    """Spec §6: the deadline bounds the CALLER. A hung or pipe-holding child is killed and reaped
    (kill+wait, no zombie), never awaited."""

    def test_default_timeout_is_the_spec_value(self):
        assert NATIVE_TIMEOUT == 0.25

    def test_hung_binary_is_killed_reaped_and_reported_as_timeout(self, fake_binary, spawned):
        binary = fake_binary("import time\nsys.stdin.read()\ntime.sleep(30)\n")

        started = time.perf_counter()
        with pytest.raises(NativeBridgeError, match="timed out"):
            NativeBridge(binary_path=binary, timeout=0.1).parse_json("echo hi")

        assert time.perf_counter() - started < 5  # did not sit out the 30 s sleep
        assert len(spawned) == 1
        assert spawned[0].returncode is not None  # reaped: no zombie
        assert spawned[0].returncode != 0

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="fork-based stand-in")
    def test_forked_child_holding_stdout_cannot_outlive_the_deadline(self, fake_binary, spawned):
        # A tampered binary forks a child that keeps the stdout pipe open, then exits 0 itself.
        # Killing the (already dead) parent changes nothing and read() never sees EOF, so the
        # deadline has to bound the caller — a hook blocked past its own timeout is fail-open.
        binary = fake_binary("import os, time\nsys.stdin.read()\nif os.fork() == 0:\n    time.sleep(30)\nsys.exit(0)\n")

        started = time.perf_counter()
        with pytest.raises(NativeBridgeError, match="timed out"):
            NativeBridge(binary_path=binary, timeout=0.2).parse_json("echo hi")

        assert time.perf_counter() - started < 5
        assert spawned[0].returncode is not None

    def test_fast_binary_is_not_reported_as_timeout(self, fake_binary):
        assert NativeBridge(binary_path=fake_binary("sys.stdout.write('{}')\n"), timeout=5).parse_json("echo hi") == "{}"


class TestSpawnDiscipline:
    """Parse-once: exactly one Popen per call, and no unbounded capture."""

    def test_single_spawn_and_no_capture_output(self, fake_binary, monkeypatch):
        binary = fake_binary("sys.stdout.write('{}')\n")
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

    def test_input_at_the_bound_is_accepted(self, fake_binary):
        binary = fake_binary("sys.stdout.write(str(len(sys.stdin.buffer.read())))\n")
        assert NativeBridge(binary_path=binary).parse_json("a" * MAX_COMMAND_SIZE) == str(MAX_COMMAND_SIZE)

    def test_unencodable_input_routes_to_fallback(self, monkeypatch):
        # A lone surrogate reaches the hook via a `\ud800` escape in its JSON stdin.
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        with pytest.raises(NativeBridgeError, match="not UTF-8"):
            NativeBridge().parse_json("echo \ud800")

    def test_commit_filter_shares_the_core_constant(self):
        assert commit_filter.MAX_COMMAND_SIZE == MAX_COMMAND_SIZE


@needs_binary
class TestOutputBoundAtMaxInput:
    """The bound clears the spec's legitimate 64 KiB worst case and trips CLEANLY on the dense
    shapes it is sized to reject (memory budget — see MAX_AST_JSON_SIZE).

    The deadline is lifted here on purpose: every 64 KiB shape takes the Go side longer than
    NATIVE_TIMEOUT, so with the default the timer wins and these would measure the timeout
    (TestTimeout's job), not the bound."""

    def test_sparse_max_size_input_parses_on_the_native_tier(self):
        command = ("echo a;" * (MAX_COMMAND_SIZE // 7)).ljust(MAX_COMMAND_SIZE)
        assert json.loads(NativeBridge(timeout=30).parse_json(command))["Type"] == "File"

    def test_dense_max_size_input_trips_the_bound_and_falls_back(self):
        command = "a|b|c|d|e|f|g|h;" * (MAX_COMMAND_SIZE // 16)
        with pytest.raises(NativeBridgeError, match="exceeded"):
            NativeBridge(timeout=30).parse_json(command)
