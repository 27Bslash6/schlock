"""Subprocess client for the vendored `schlock-parse` Go CLI.

Slice T2a of the native-parser migration (spec §3.1/§3.2): resolve the binary
for this platform, hand it a command on stdin, and read its typed-JSON AST back
under a hard output bound. Turning that JSON into an `AstView` the existing
walkers can read is T2b; the final size constants are T4; the tier/fallback
state machine is T5.

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

import os
import platform
import subprocess
from pathlib import Path
from typing import Optional

from schlock.exceptions import ParseError

BINARY_NAME = "schlock-parse"

# Vendored binaries live beside the plugin manifest (spec §7); same root walk as
# validator.py's project_root.
DEFAULT_BIN_ROOT = Path(__file__).parent.parent.parent.parent / ".claude-plugin" / "bin"

# Anti-OOM output bound (spec §5). Deliberately above the ~8.8 MB legitimate
# worst case for a 64 KB input, so it trips only on subprocess pathology.
# T4 owns the final constants, including the pre-spawn 64 KB input guard.
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


def _kill_and_reap(proc: subprocess.Popen) -> None:
    """Kill the child and collect it — `kill()` alone leaves a zombie."""
    proc.kill()
    proc.wait()


class NativeBridge:
    """Runs `schlock-parse` and returns its raw typed-JSON AST.

    Args:
        binary_path: explicit binary, bypassing platform resolution (tests, and
            T5's forced-tier switch).
        max_ast_json_size: output bound in bytes; overflow kills the child.
    """

    def __init__(
        self,
        binary_path: Optional[Path] = None,
        max_ast_json_size: int = MAX_AST_JSON_SIZE,
    ):
        self._binary_path = binary_path
        self._max_ast_json_size = max_ast_json_size

    def _binary(self) -> Path:
        # Resolved lazily and cached on success only, so a machine without a
        # vendored binary keeps raising (→ fallback) instead of caching a lie.
        if self._binary_path is None:
            self._binary_path = resolve_binary()
        return self._binary_path

    def parse_json(self, command: str) -> str:
        """Parse `command` and return the typed-JSON AST as text.

        Exactly one process is spawned per call: `extract_command_segments` will
        derive its segment views from this single parse (spec §3.2, parse-once).

        Raises:
            ParseError: the binary rejected the command as unparseable (exit 2).
            NativeBridgeError: any other failure — spawn error, output overflow,
                stdin/stdout error (exit 3/4), crash, or undecodable output.
        """
        binary = self._binary()
        try:
            proc = subprocess.Popen(
                [str(binary)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise NativeBridgeError(f"failed to spawn native parser {binary}: {exc}")

        # Popen as a context manager closes the three pipes and reaps the child
        # even on the raising paths below.
        with proc:
            payload, stderr, returncode = self._exchange(proc, command, binary)

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

    def _exchange(self, proc: subprocess.Popen, command: str, binary: Path) -> "tuple[bytes, bytes, int]":
        """Feed stdin, read stdout under the bound, and collect the exit code."""
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            _kill_and_reap(proc)
            raise NativeBridgeError("native parser pipes unavailable")

        try:
            proc.stdin.write(command.encode("utf-8"))
            proc.stdin.close()
        except OSError as exc:
            # Child exited before consuming stdin, so it only ever saw a prefix.
            _kill_and_reap(proc)
            raise NativeBridgeError(f"failed to send command to native parser {binary}: {exc}")

        # ponytail: write-then-read is deadlock-free only because the CLI does
        # io.ReadAll(stdin) before writing a byte of stdout. A tampered binary
        # that floods stdout first could block the write above; T5's 250 ms
        # timeout (spec §6) is what closes that window.
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
