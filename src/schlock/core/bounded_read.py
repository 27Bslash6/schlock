"""Bounded file access for paths the working tree or the environment can name.

The project config lives inside the checkout, and the audit log and the post-commit state
live at paths an environment variable can set. A plain open trusts whatever sits there: a
FIFO blocks the open until its other end appears, a character device or a huge file reads
until memory runs out, inside one C call that no Python-level timeout can interrupt, and a
write to a device or a pipe goes somewhere other than a log file. So such paths are opened
with `open_regular`: reads through `read_bounded` (YAML config through `load_config`), and
the audit-log append directly.
"""

import os
import stat
from pathlib import Path
from typing import IO, Any

import yaml
from yaml.composer import ComposerError
from yaml.events import AliasEvent
from yaml.scanner import ScannerError

# The post-commit state file and the plugin manifest are JSON, which parses in C.
MAX_READ_BYTES = 64 * 1024

# A config that overrides every shipped rule and category is about 10 KB. The vendored YAML
# parser is pure Python, and with aliases refused its time grows with size, so this cap is
# what bounds the parse; the hook parses the project config up to three times per call.
MAX_CONFIG_BYTES = 16 * 1024

# Flow collections (`[...]`, `{...}`) nested deeper than this are refused. A schlock config
# needs two or three levels at most.
MAX_FLOW_DEPTH = 16


class _ConfigLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases and deep flow nesting, the two ways to outgrow the size cap.

    Each alias can double the work, so a few hundred bytes of anchors and `<<` merge keys take
    minutes to load. Each open flow collection leaves a pending key the scanner rechecks on
    every later token, so parse time grows with nesting depth times size.
    """

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise ComposerError(None, None, "aliases are not allowed in schlock config", self.peek_event().start_mark)
        return super().compose_node(parent, index)

    def fetch_flow_collection_start(self, TokenClass):  # noqa: N803 - PyYAML's parameter name
        if self.flow_level >= MAX_FLOW_DEPTH:
            raise ScannerError(
                None, None, f"flow collections nested more than {MAX_FLOW_DEPTH} deep are not allowed", self.get_mark()
            )
        super().fetch_flow_collection_start(TokenClass)


def nonblocking_opener(path: "str | os.PathLike[str]", flags: int) -> int:
    """`open(..., opener=)` hook that adds O_NONBLOCK, so a FIFO cannot block the open.

    Opening a FIFO for reading then returns at once, and opening one for writing with no
    reader fails with ENXIO. O_NONBLOCK has no effect on a regular file. Windows has neither
    the flag nor FIFOs at a filesystem path. 0o666 is the mode builtin open() creates with.
    """
    return os.open(path, flags | getattr(os, "O_NONBLOCK", 0), 0o666)


def open_regular(path: "str | os.PathLike[str]", mode: str) -> IO[Any]:
    """Open `path` in `mode` without blocking, and only if it is a regular file.

    Raises:
        OSError: `path` cannot be opened, or is not a regular file.
    """
    handle = open(path, mode, opener=nonblocking_opener)  # noqa: SIM115 - the caller closes it
    if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
        handle.close()
        raise OSError("not a regular file")
    return handle


def read_bounded(path: Path, limit: int = MAX_READ_BYTES) -> str:
    """Return `path`'s UTF-8 text if it is a regular file of at most `limit` bytes.

    Raises:
        OSError: `path` is missing or unreadable, is not a regular file, or is over `limit`.
        UnicodeDecodeError: the content is not UTF-8.
    """
    with open_regular(path, "rb") as handle:
        # `limit + 1`, never an unbounded read: a file can grow after it is opened.
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"larger than {limit} bytes; not reading it")
    return data.decode("utf-8")


def load_config(path: Path) -> Any:
    """Parse the YAML config at `path`: at most MAX_CONFIG_BYTES, read with `read_bounded`, see `_ConfigLoader`."""
    return yaml.load(read_bounded(path, MAX_CONFIG_BYTES), Loader=_ConfigLoader)  # noqa: S506 - a SafeLoader subclass
