"""Subprocess client for the vendored `schlock-parse` Go CLI.

Slice T2a of the native-parser migration (spec §3.1/§3.2): resolve the binary
for this platform, hand it a command on stdin, and read its typed-JSON AST back
under a hard output bound and a hard deadline. Turning that JSON into an
`AstView` the existing walkers can read is `ast_view.py`; the tier/fallback state
machine that decides what happens when this bridge raises is
`parser.TieredParser` (spec §6).

Two invariants carry the security weight here:

1. **Bounded read, not `capture_output`.** `subprocess.run(capture_output=True)`
   buffers stdout without limit. This bridge runs behind a PreToolUse hook on
   every bash call, so a binary streaming garbage would OOM the process that is
   supposed to be protecting the session.
2. **A failed exchange is never a partial success.** Exit 3 (stdin read) and
   exit 4 (stdout write) mean the binary saw — or emitted — only part of the
   command. Returning the bytes we did read would hand the walkers a prefix AST
   with a trailing `; rm -rf /` silently dropped, so every non-zero exit raises
   and the accumulated output is discarded (spec §3.1, §11 finding 10).
"""

import contextlib
import os
import platform
import signal
import subprocess
import threading
from pathlib import Path
from typing import Optional

from schlock.exceptions import ParseError

BINARY_NAME = "schlock-parse"

# Vendored binaries live beside the plugin manifest (spec §7); same root walk as
# validator.py's project_root.
DEFAULT_BIN_ROOT = Path(__file__).parent.parent.parent.parent / ".claude-plugin" / "bin"

# Size guards (spec §5, LAB-528). Both fail-closed: a trip raises
# NativeBridgeError and the caller falls back to bashlex.
#
# Input guard, checked on the UTF-8 byte length BEFORE spawning (the CLI reads
# bytes). Shared with integrations/commit_filter.py, which counts code points
# and fails toward skip-extraction rather than raising — see its docstring.
MAX_COMMAND_SIZE = 64 * 1024

# Anti-OOM output bound on the incremental stdout read: a memory budget against a
# runaway or tampered binary (decoded JSON costs ~40 B of Python heap per byte).
# It clears the sparse `echo a;` shape at 64 KiB (~7.9 MiB) but NOT dense ones —
# `a;`, `x=1;` and bare pipeline chains reach ~410× amplification (25.6 MiB on
# mvdan v3.13.1) and trip it → bashlex. Deliberate: those shapes also blow the
# §6 250 ms timeout, so native never serves them anyway, and a bound that admitted
# them would let one 64 KiB command cost the hook ~1 GiB.
MAX_AST_JSON_SIZE = 12 * 1024 * 1024

_READ_CHUNK_SIZE = 64 * 1024
_MAX_STDERR_BYTES = 8 * 1024

# The GOOS/GOARCH pairs T1 cross-compiles (spec §7). Anything else has no native
# tier at all — resolution raises so the caller falls back rather than guessing.
_GOOS = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
_GOARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

# Exit-code contract of tools/schlock-parse/main.go (spec §3.1).
EXIT_OK = 0
EXIT_PARSE_ERROR = 2

# Spec §6 deadline, ~50-100x a typical parse (~5 ms measured). Bounds the whole exchange —
# not just the child's lifetime: a hung binary, a dense 64 KiB shape (0.4-1.2 s on the Go
# side) or a forked grandchild holding stdout open all end here, with the process group
# killed and the child reaped, and the caller falls back to bashlex. A hook blocked past its
# own timeout is fail-OPEN (Claude Code proceeds), so this is load-bearing.
NATIVE_TIMEOUT = 0.25


class NativeBridgeError(Exception):
    """The native tier could not produce a trustworthy AST (spec §6 → fallback).

    Deliberately distinct from `ParseError`: `ParseError` means *the command* is
    unparseable (both tiers will agree, and the terminal verdict is deny), while
    `NativeBridgeError` means *the bridge* failed and bashlex should be tried.
    T5's state machine needs that distinction to route correctly.
    """


def platform_dir() -> str:
    """Return the `<goos>-<goarch>` directory name for the running platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    goos = _GOOS.get(system)
    goarch = _GOARCH.get(machine)
    if goos is None or goarch is None:
        raise NativeBridgeError(f"unsupported platform for native parser: {system}/{machine}")
    return f"{goos}-{goarch}"


def resolve_binary(bin_root: Optional[Path] = None) -> Path:
    """Locate the vendored `schlock-parse` for this platform.

    Raises:
        NativeBridgeError: platform unsupported, binary absent, or not executable.
            Never returns None — a missing parser must surface as a failure the
            fallback chain can see, not as a silent allow.
    """
    root = DEFAULT_BIN_ROOT if bin_root is None else bin_root
    suffix = ".exe" if platform.system().lower() == "windows" else ""
    path = root / platform_dir() / f"{BINARY_NAME}{suffix}"
    if not path.is_file():
        raise NativeBridgeError(f"native parser binary not found: {path}")
    if not os.access(path, os.X_OK):
        raise NativeBridgeError(f"native parser binary not executable: {path}")
    return path


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child and anything it forked (same session, see start_new_session) — no-op if gone."""
    if hasattr(os, "killpg"):
        # ProcessLookupError once reaped, PermissionError never in practice; proc.kill() covers the parent.
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
    proc.kill()  # polls first: a no-op on an exited child


def _kill_and_reap(proc: subprocess.Popen) -> None:
    """Kill the child and collect it — `kill()` alone leaves a zombie."""
    _kill_tree(proc)
    proc.wait()


class NativeBridge:
    """Runs `schlock-parse` and returns its raw typed-JSON AST.

    Args:
        binary_path: explicit binary, bypassing platform resolution (tests, and
            T5's forced-tier switch).
        max_ast_json_size: output bound in bytes; overflow kills the child.
        timeout: seconds the exchange may take before the child is killed (spec §6).
    """

    def __init__(
        self,
        binary_path: Optional[Path] = None,
        max_ast_json_size: int = MAX_AST_JSON_SIZE,
        timeout: float = NATIVE_TIMEOUT,
    ):
        self._binary_path = binary_path
        self._max_ast_json_size = max_ast_json_size
        self._timeout = timeout

    def _binary(self) -> Path:
        # Resolved lazily and cached on success only, so a machine without a
        # vendored binary keeps raising (→ fallback) instead of caching a lie.
        # T6 (binary integrity) inserts the MANIFEST SHA-256 check here, before the
        # path is cached: a mismatch raises NativeBridgeError → bashlex with a
        # warning (spec §6 row 2). The tier machine already routes and logs it.
        if self._binary_path is None:
            self._binary_path = resolve_binary()
        return self._binary_path

    def parse(self, command: str) -> "list":
        """Parse `command` into bashlex-shaped `AstView` nodes (spec §3.2).

        Raises:
            ParseError: the binary rejected the command as unparseable.
            NativeBridgeError: subprocess failure, a prefix parse, or a
                construct without an explicit mapping (→ fallback tier).
        """
        from schlock.core.ast_view import build_ast_view  # noqa: PLC0415 - avoids an import cycle

        return build_ast_view(command, self.parse_json(command))

    def parse_json(self, command: str) -> str:
        """Parse `command` and return the typed-JSON AST as text.

        Exactly one process is spawned per call: `extract_command_segments` will
        derive its segment views from this single parse (spec §3.2, parse-once).

        Raises:
            ParseError: the binary rejected the command as unparseable (exit 2).
            NativeBridgeError: any other failure — no binary, oversized input, timeout,
                output overflow, stdin/stdout error (exit 3/4), crash, or
                undecodable output.
        """
        try:
            command_bytes = command.encode("utf-8")
        except UnicodeEncodeError as exc:
            # A lone surrogate arrives via a `\ud800` escape in the hook's JSON stdin.
            raise NativeBridgeError(f"command is not UTF-8 encodable: {exc}")
        if len(command_bytes) > MAX_COMMAND_SIZE:
            raise NativeBridgeError(
                f"command exceeds native parser input bound ({len(command_bytes)} > {MAX_COMMAND_SIZE} bytes)"
            )
        binary = self._binary()
        try:
            proc = subprocess.Popen(
                [str(binary)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # own process group, so _kill_tree reaches forked children
            )
        except OSError as exc:
            raise NativeBridgeError(f"failed to spawn native parser {binary}: {exc}")

        payload, stderr, returncode = self._exchange_within_deadline(proc, command_bytes, binary)

        if returncode == EXIT_OK:
            try:
                return payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise NativeBridgeError(f"native parser emitted undecodable output: {exc}")

        detail = stderr.decode("utf-8", errors="replace").strip()
        if returncode == EXIT_PARSE_ERROR:
            raise ParseError(f"native parser could not parse the command: {detail}")
        # Exit 3 (stdin read), 4 (stdout write), signals and anything else:
        # whatever landed on stdout is a prefix, so it is dropped, not returned.
        raise NativeBridgeError(f"native parser exited {returncode}: {detail}")

    def _exchange_within_deadline(
        self, proc: subprocess.Popen, command_bytes: bytes, binary: Path
    ) -> "tuple[bytes, bytes, int]":
        """Run `_exchange` on a worker thread and wait at most `timeout` for it (spec §6).

        The deadline bounds the CALLER, not the child: a blocking `read()` cannot be
        interrupted, and killing the child does not end it when a forked grandchild still
        holds the stdout pipe open. So the exchange runs on a daemon thread; if it has not
        finished at the deadline the process group is killed, the child reaped, and the
        caller raises — whatever the pipe is doing. A worker that finishes first wins
        outright: returncode, not the clock, decides success.
        """
        outcome: dict = {}

        def run() -> None:
            try:
                outcome["result"] = self._exchange(proc, command_bytes, binary)
            except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread below
                outcome["error"] = exc

        worker = threading.Thread(target=run, name="schlock-parse-exchange", daemon=True)
        # Popen as a context manager closes the three pipes and reaps the child even on the
        # raising paths — including a worker thread that fails to start.
        with proc:
            worker.start()
            worker.join(self._timeout)
            if worker.is_alive():
                _kill_and_reap(proc)
                # Whatever reached stdout is a prefix of a parse that never finished.
                raise NativeBridgeError(f"native parser timed out after {self._timeout * 1000:.0f} ms; killed {binary}")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["result"]

    def _exchange(self, proc: subprocess.Popen, command_bytes: bytes, binary: Path) -> "tuple[bytes, bytes, int]":
        """Feed stdin, read stdout under the bound, and collect the exit code."""
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            _kill_and_reap(proc)
            raise NativeBridgeError("native parser pipes unavailable")

        try:
            proc.stdin.write(command_bytes)
            proc.stdin.close()
        except OSError as exc:
            # Child exited before consuming stdin, so it only ever saw a prefix.
            _kill_and_reap(proc)
            raise NativeBridgeError(f"failed to send command to native parser {binary}: {exc}")

        # ponytail: write-then-read is deadlock-free only because the CLI does
        # io.ReadAll(stdin) before writing a byte of stdout. A tampered binary
        # that floods stdout first could block the write above; the NATIVE_TIMEOUT
        # deadline in _exchange_within_deadline closes that window.
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = proc.stdout.read(_READ_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > self._max_ast_json_size:
                _kill_and_reap(proc)
                raise NativeBridgeError(f"native parser output exceeded {self._max_ast_json_size} bytes; killed {binary}")
            chunks.append(chunk)

        stderr = proc.stderr.read(_MAX_STDERR_BYTES) or b""
        return b"".join(chunks), stderr, proc.wait()
