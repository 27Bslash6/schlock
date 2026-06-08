#!/usr/bin/env python3
"""PreToolUse self-protection hook for Write/Edit-family tools (issue #92).

Blocks Write/Edit/MultiEdit/NotebookEdit tool calls that target schlock's own configuration
files. This is the tool-call counterpart to the Bash-command self-protection in the safety
validator (validator._check_self_protection), which only inspects Bash command strings — so
without this hook an agent could edit schlock config via the Write/Edit tool and bypass it.

Registered in hooks/hooks.json with matcher "Write|Edit|MultiEdit|NotebookEdit".

DESIGN:
- Import-light (no schlock/bashlex import) so it stays fast on the edit hot path and cannot
  fail from an import error.
- Deny-ONLY: emits a deny decision solely when a write-tool targets a protected config file;
  otherwise prints nothing and exits 0 (the tool proceeds through the normal permission flow).
- FAIL-OPEN: malformed input or any unexpected error -> allow. A glitch must never block all
  edits; this is one defense layer (Bash config-writes remain covered by the validator).

The protected-path list is intentionally duplicated here (rather than imported from
schlock.core.validator) to keep this hook import-light and independently robust;
tests/test_self_protect.py asserts it stays in sync with validator.SELF_PROTECTION_PATHS.
"""

import json
import os
import sys
from typing import Optional

# Keep in sync with schlock.core.validator.SELF_PROTECTION_PATHS (enforced by test_self_protect.py).
SELF_PROTECTION_PATHS = ("schlock-config.yaml", ".config/schlock/config.yaml")

# File-mutating tools whose target path is checked against the protected config files.
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

_DENY_REASON = (
    "BLOCKED: Modification of schlock safety configuration is not allowed.\n"
    "Edit configuration manually outside of Claude Code, "
    "or use /schlock:setup to configure interactively."
)


def _targets_protected(path: str) -> bool:
    """True if a file path resolves to a protected schlock config file.

    Normalizes BOTH sides with normcase(normpath(...)) so the suffix check is correct on
    every platform: normpath collapses '..' and '//' and (on Windows) rewrites '/' to the
    backslash separator; normcase folds case + separators on Windows and is a no-op on
    POSIX; os.path.sep is the platform separator. So a roundabout target like
    '.../schlock/../schlock/config.yaml' OR a Windows-style backslash/drive-letter path
    can't slip past — the latter previously did, because a hard-coded '/' suffix never
    matches normpath's backslash output on Windows. normpath/normcase are pure string
    manipulation — no filesystem access, so no TOCTOU. Suffix match (not substring) so
    'not-schlock-config.yaml-backup' does NOT match, while both the bare filename and an
    absolute '.../.config/schlock/config.yaml' do.
    """
    if not path:
        return False
    norm = os.path.normcase(os.path.normpath(path))
    for protected in SELF_PROTECTION_PATHS:
        protected_norm = os.path.normcase(os.path.normpath(protected))
        if norm == protected_norm or norm.endswith(os.path.sep + protected_norm):
            return True
    return False


def decide(input_data: dict) -> Optional[dict]:
    """Deny hookSpecificOutput if a write-tool targets a protected config file, else None.

    Returns None (allow) for non-write tools, non-config targets, and any malformed input.
    """
    try:
        if input_data.get("tool_name") not in WRITE_TOOLS:
            return None
        tool_input = input_data.get("tool_input") or {}
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if _targets_protected(path):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": _DENY_REASON,
                }
            }
        return None
    except Exception:  # noqa: BLE001 - fail-open: never break edits on an unexpected shape
        return None


def main() -> None:
    """Read the hook payload from stdin; emit a deny decision only when warranted."""
    try:
        data = json.load(sys.stdin)
        result = decide(data)
        if result is not None:
            print(json.dumps(result))
    except Exception:  # noqa: BLE001, S110 - fail-open: malformed stdin -> allow (no output)
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
