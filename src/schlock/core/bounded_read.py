"""Bounded file access for paths the working tree or the environment can name.

The project config lives inside the checkout, and the audit log and the post-commit state
live at paths an environment variable can set. A plain open trusts whatever sits there: a
FIFO blocks the open until its other end appears, and a character device or a huge file
reads until memory runs out, inside one C call that no Python-level timeout can interrupt.
So reads of such paths go through `read_bounded` (YAML config through `load_config`), and
the audit-log append through `nonblocking_opener`.
"""

import os
import stat
from pathlib import Path
from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.events import AliasEvent

# The post-commit state file and the plugin manifest are JSON, which parses in C.
MAX_READ_BYTES = 64 * 1024

# A config that overrides every shipped rule and category is about 10 KB. The vendored YAML
# parser is pure Python, and with aliases refused its time grows with size, so this cap is
# what bounds the parse; the hook parses the project config three times per call.
MAX_CONFIG_BYTES = 16 * 1024


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases.

    Each alias can double the work, so a few hundred bytes of anchors and `<<` merge keys take
    minutes to load, whatever the size cap. No schlock config needs one.
    """

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise ComposerError(None, None, "aliases are not allowed in schlock config", self.peek_event().start_mark)
        return super().compose_node(parent, index)


def nonblocking_opener(path: "str | os.PathLike[str]", flags: int) -> int:
    """`open(..., opener=)` hook that adds O_NONBLOCK, so a FIFO cannot block the open.

    Opening a FIFO for reading then returns at once, and opening one for writing with no
    reader fails with ENXIO. O_NONBLOCK has no effect on a regular file. Windows has neither
    the flag nor FIFOs at a filesystem path. 0o666 is the mode builtin open() creates with.
    """
    return os.open(path, flags | getattr(os, "O_NONBLOCK", 0), 0o666)


def read_bounded(path: Path, limit: int = MAX_READ_BYTES) -> str:
    """Return `path`'s UTF-8 text if it is a regular file of at most `limit` bytes.

    Raises:
        OSError: `path` is missing or unreadable, is not a regular file, or is over `limit`.
        UnicodeDecodeError: the content is not UTF-8.
    """
    with open(path, "rb", opener=nonblocking_opener) as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError("not a regular file; not reading it")
        # `limit + 1`, never an unbounded read: a file can grow after it is opened.
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"larger than {limit} bytes; not reading it")
    return data.decode("utf-8")


def load_config(path: Path) -> Any:
    """Parse the YAML config at `path`: at most MAX_CONFIG_BYTES, read with `read_bounded`, no aliases."""
    return yaml.load(read_bounded(path, MAX_CONFIG_BYTES), Loader=_NoAliasLoader)  # noqa: S506 - a SafeLoader subclass
