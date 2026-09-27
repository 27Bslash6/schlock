"""Read schlock switches from the user's own Claude Code settings file.

Claude Code applies every settings file's `env` block to the session and its subprocesses,
project over user, so an environment variable carries no provenance: a checkout's committed
`.claude/settings.json` can set or override any of them. The one settings file a checkout cannot
write is the user's own `~/.claude/settings.json`, so every schlock switch that must not be
steerable by a checkout is read from that file's `env` block and never from `os.environ`.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def user_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def user_settings_env(name: str, user_settings: Optional[Path] = None) -> Any:
    """Return `name` from the `env` block of the user-scope settings file, or None.

    The key matches case-insensitively (Windows environments do, and a user's own typo is not a
    threat). The raw JSON value is returned; callers validate its type and content. A missing,
    unreadable, malformed or non-object file, or a missing or non-object `env` block, yields None,
    with one warning when the file exists but cannot be read. Never raises.
    """
    try:
        path = user_settings_path() if user_settings is None else user_settings
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - HOME unresolvable, unreadable or malformed: the value is unknowable
        logger.warning(f"Cannot read {name} from user settings ({exc})")
        return None
    env_block = data.get("env") if isinstance(data, dict) else None
    if not isinstance(env_block, dict):
        return None
    wanted = name.upper()
    return next((v for k, v in env_block.items() if str(k).upper() == wanted), None)
