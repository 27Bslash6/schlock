---
description: Interactive wizard to configure schlock safety validation and advertising blocker
allowed-tools: Bash, AskUserQuestion
argument-hint: (no arguments)
---

# schlock Configuration Wizard

Welcome! I'll help you configure schlock's safety validation in 4 simple steps.

This wizard generates `.claude/hooks/schlock-config.yaml` that you can share with your team via git.

---

## Bootstrap Helper

All Python code blocks in this wizard need to import from schlock. Use this bootstrap snippet at the start of each code block:

```python
# Bootstrap: Find schlock and set up imports
import sys, json, os
from pathlib import Path

def _find_schlock():
    if (Path.cwd() / "src" / "schlock").exists():
        return Path.cwd()
    base_dirs = []
    if os.name == "nt":
        if v := os.environ.get("APPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
        if v := os.environ.get("LOCALAPPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
    base_dirs.append(Path.home() / ".claude" / "plugins")
    for base in base_dirs:
        reg = base / "installed_plugins.json"
        if reg.exists():
            try:
                for pid, info in json.loads(reg.read_text(encoding="utf-8")).get("plugins", {}).items():
                    if pid.startswith("schlock@"):
                        p = Path(info.get("installPath", ""))
                        if (p / "src" / "schlock").exists(): return p
            except: pass
    for base in base_dirs:
        mp = base / "marketplaces"
        if mp.exists():
            for m in mp.iterdir():
                if (m / "src" / "schlock").exists(): return m
    raise RuntimeError("schlock not found. Run: /plugin marketplace add 27Bslash6/schlock")

_root = _find_schlock()
sys.path.insert(0, str(_root / ".claude-plugin" / "vendor"))
sys.path.insert(0, str(_root / "src"))
```

---

## Step 1: Risk Tolerance (Step 1 of 4)

Risk tolerance controls how schlock handles commands at different risk levels:
- **SAFE/LOW/MEDIUM**: Always allowed (safe operations)
- **HIGH**: Risky commands (rm -rf, git push --force, etc.)
- **BLOCKED**: Critical threats (credential theft, system destruction) - always blocked

**Your Task**: Use the `AskUserQuestion` tool to ask:

```json
{
  "question": "How should schlock handle risky (HIGH-risk) commands?",
  "header": "Risk Tolerance",
  "multiSelect": false,
  "options": [
    {"label": "Balanced (recommended)", "description": "Prompt for approval on HIGH-risk commands. Best for most users."},
    {"label": "Permissive", "description": "Allow HIGH-risk commands without prompting. For experienced users."},
    {"label": "Paranoid", "description": "Block HIGH-risk commands entirely, prompt for MEDIUM. For production/compliance."}
  ]
}
```

**Store the user's choice** as `risk_preset`:
- "Balanced (recommended)" → `risk_preset = "balanced"`
- "Permissive" → `risk_preset = "permissive"`
- "Paranoid" → `risk_preset = "paranoid"`

---

## Step 2: Claude Advertising Blocker (Step 2 of 4)

The Claude Advertising Blocker removes unwanted messages from git commits:
- "Generated with [Claude Code](https://claude.com/claude-code)"
- "Co-Authored-By: Claude <noreply@anthropic.com>"

**This feature is enabled by default** and keeps your git history clean.

**Your Task**: Inform the user:

> "The Claude Advertising Blocker is enabled. This removes 'Generated with Claude Code' spam from your commits, keeping your git history clean and professional."

**Set** `ad_blocker_enabled = True`

---

## Step 3: ShellCheck Integration (Step 3 of 4)

**First, detect if ShellCheck is installed** by running:

```python
# Bootstrap: Find schlock and set up imports
import sys, json, os
from pathlib import Path

def _find_schlock():
    if (Path.cwd() / "src" / "schlock").exists():
        return Path.cwd()
    base_dirs = []
    if os.name == "nt":
        if v := os.environ.get("APPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
        if v := os.environ.get("LOCALAPPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
    base_dirs.append(Path.home() / ".claude" / "plugins")
    for base in base_dirs:
        reg = base / "installed_plugins.json"
        if reg.exists():
            try:
                for pid, info in json.loads(reg.read_text(encoding="utf-8")).get("plugins", {}).items():
                    if pid.startswith("schlock@"):
                        p = Path(info.get("installPath", ""))
                        if (p / "src" / "schlock").exists(): return p
            except: pass
    for base in base_dirs:
        mp = base / "marketplaces"
        if mp.exists():
            for m in mp.iterdir():
                if (m / "src" / "schlock").exists(): return m
    raise RuntimeError("schlock not found. Run: /plugin marketplace add 27Bslash6/schlock")

_root = _find_schlock()
sys.path.insert(0, str(_root / ".claude-plugin" / "vendor"))
sys.path.insert(0, str(_root / "src"))

# Actual logic
from schlock.integrations.shellcheck import is_shellcheck_available, get_shellcheck_version, get_install_instructions

if is_shellcheck_available():
    version = get_shellcheck_version()
    print(f"ShellCheck v{version} detected")
    shellcheck_available = True
else:
    print("ShellCheck not installed")
    print(f"Install with: {get_install_instructions()}")
    shellcheck_available = False
```

**If ShellCheck IS available** (`shellcheck_available = True`):

Use the `AskUserQuestion` tool to ask:

```json
{
  "question": "Enable ShellCheck integration for enhanced security analysis?",
  "header": "ShellCheck",
  "multiSelect": false,
  "options": [
    {"label": "Enable (recommended)", "description": "Run ShellCheck on commands for additional security analysis."},
    {"label": "Disable", "description": "Skip ShellCheck analysis. schlock's built-in rules still protect you."}
  ]
}
```

**Store the user's choice** as `shellcheck_enabled` (True for Enable, False for Disable).

**If ShellCheck is NOT available** (`shellcheck_available = False`):

Use the `AskUserQuestion` tool to ask:

```json
{
  "question": "ShellCheck is not installed. Would you like to install it?",
  "header": "ShellCheck",
  "multiSelect": false,
  "options": [
    {"label": "Show install command", "description": "Display the installation command for your platform."},
    {"label": "Skip for now", "description": "Continue without ShellCheck. Run /schlock:setup again after installing."}
  ]
}
```

**If user selects "Show install command"**:
- Display the installation command from `get_install_instructions()`
- Set `shellcheck_enabled = False` (they can re-run wizard after installing)

**If user selects "Skip for now"**:
- Set `shellcheck_enabled = False`

---

## Step 4: Review and Write Configuration (Step 4 of 4)

Now I'll show you a summary and save the configuration.

**Your Task (Part A - Display Review)**: Run this Python code to generate the summary:

```python
# Bootstrap: Find schlock and set up imports
import sys, json, os
from pathlib import Path

def _find_schlock():
    if (Path.cwd() / "src" / "schlock").exists():
        return Path.cwd()
    base_dirs = []
    if os.name == "nt":
        if v := os.environ.get("APPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
        if v := os.environ.get("LOCALAPPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
    base_dirs.append(Path.home() / ".claude" / "plugins")
    for base in base_dirs:
        reg = base / "installed_plugins.json"
        if reg.exists():
            try:
                for pid, info in json.loads(reg.read_text(encoding="utf-8")).get("plugins", {}).items():
                    if pid.startswith("schlock@"):
                        p = Path(info.get("installPath", ""))
                        if (p / "src" / "schlock").exists(): return p
            except: pass
    for base in base_dirs:
        mp = base / "marketplaces"
        if mp.exists():
            for m in mp.iterdir():
                if (m / "src" / "schlock").exists(): return m
    raise RuntimeError("schlock not found. Run: /plugin marketplace add 27Bslash6/schlock")

_root = _find_schlock()
sys.path.insert(0, str(_root / ".claude-plugin" / "vendor"))
sys.path.insert(0, str(_root / "src"))

# Actual logic
from schlock.setup.config_writer import WizardChoices, write_config
from schlock.setup.wizard import format_config_review, validate_wizard_choices
from schlock.integrations.shellcheck import get_install_instructions

# Build choices from Steps 1-3 (Claude substitutes actual values)
choices = WizardChoices(
    ad_blocker_enabled=ad_blocker_enabled,
    risk_preset=risk_preset,
    shellcheck_enabled=shellcheck_enabled
)

# Validate choices
validation_errors = validate_wizard_choices(choices)
if validation_errors:
    print("Configuration validation failed:")
    for error in validation_errors:
        print(f"  - {error}")
    print("\nRun /schlock:setup again to restart.")
else:
    print(format_config_review(choices))
    config_valid = True
```

**If validation errors exist**:
- Display the errors
- Exit wizard (don't write config)

**If validation passes**:

**Your Task (Part B - Confirm Write)**: Use the `AskUserQuestion` tool:

```json
{
  "question": "Save this configuration?",
  "header": "Confirm",
  "multiSelect": false,
  "options": [
    {"label": "Yes, save configuration", "description": "Write config to .claude/hooks/schlock-config.yaml."},
    {"label": "Cancel setup", "description": "Exit without saving. Run /schlock:setup again later."}
  ]
}
```

**If user selects "Cancel setup"**:
- Display: "Setup cancelled. Run `/schlock:setup` again anytime."
- Exit wizard

**If user selects "Yes, save configuration"**:

**Your Task (Part C - Write Config)**: Run this Python code:

```python
# Bootstrap: Find schlock and set up imports (REQUIRED - each code block is separate)
import sys, json, os
from pathlib import Path

def _find_schlock():
    if (Path.cwd() / "src" / "schlock").exists():
        return Path.cwd()
    base_dirs = []
    if os.name == "nt":
        if v := os.environ.get("APPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
        if v := os.environ.get("LOCALAPPDATA"): base_dirs.append(Path(v) / ".claude" / "plugins")
    base_dirs.append(Path.home() / ".claude" / "plugins")
    for base in base_dirs:
        reg = base / "installed_plugins.json"
        if reg.exists():
            try:
                for pid, info in json.loads(reg.read_text(encoding="utf-8")).get("plugins", {}).items():
                    if pid.startswith("schlock@"):
                        p = Path(info.get("installPath", ""))
                        if (p / "src" / "schlock").exists(): return p
            except: pass
    for base in base_dirs:
        mp = base / "marketplaces"
        if mp.exists():
            for m in mp.iterdir():
                if (m / "src" / "schlock").exists(): return m
    raise RuntimeError("schlock not found. Run: /plugin marketplace add 27Bslash6/schlock")

_root = _find_schlock()
sys.path.insert(0, str(_root / ".claude-plugin" / "vendor"))
sys.path.insert(0, str(_root / "src"))

# Actual logic
from schlock.setup.config_writer import WizardChoices, write_config
from schlock.integrations.shellcheck import get_install_instructions

# Reconstruct choices (Claude substitutes actual values from earlier steps)
choices = WizardChoices(
    ad_blocker_enabled=ad_blocker_enabled,
    risk_preset=risk_preset,
    shellcheck_enabled=shellcheck_enabled
)

result = write_config(choices, create_backup_flag=True)

if result.success:
    print(f"Configuration saved to {result.config_path}")
    if result.backup_path:
        print(f"(Previous config backed up to {result.backup_path})")
    print("\nNext steps:")
    print("- Config is active immediately (no restart needed)")
    print("- Share .claude/hooks/ in git for team standardization")
    print("- Run /schlock:setup again anytime to reconfigure")
    if not shellcheck_enabled:
        print(f"- Install ShellCheck for enhanced security: {get_install_instructions()}")
else:
    print(f"Failed to write configuration: {result.error}")
    if result.validation_errors:
        print("Validation errors:")
        for error in result.validation_errors:
            print(f"  - {error}")
    print("\nTroubleshooting:")
    print("- Check .claude/hooks/ directory is writable")
    print("- Ensure sufficient disk space")
    print("- Verify permissions: chmod 755 .claude/hooks/")
```

---

## Error Handling

**If AskUserQuestion tool is unavailable**:
- Fallback to text-based prompts
- Display options as numbered list
- Parse user text responses

**If config write fails**:
- Display helpful error with troubleshooting steps
- Check: permissions, disk space, path existence

**If existing config is corrupted**:
- Display: "Existing config is invalid YAML. Creating backup and generating fresh config."
- Proceed with write (backup preserves broken file)

---

## Important Notes

1. **Each code block is independent**: Python code blocks run in separate processes. Each block must include the bootstrap snippet.

2. **Variable substitution**: Claude stores user choices in context and substitutes them into Python code (e.g., `ad_blocker_enabled`, `risk_preset`, `shellcheck_enabled`).

3. **Validation is mandatory**: Always run `validate_wizard_choices()` before writing. Invalid configs must not be written.

4. **Risk tolerance presets**:
   - `permissive`: Allow HIGH-risk commands (experienced users)
   - `balanced`: Prompt for HIGH-risk commands (default, most users)
   - `paranoid`: Block HIGH-risk, prompt for MEDIUM (production/compliance)

5. **BLOCKED is always blocked**: Critical threats (credential theft, rm -rf /, etc.) are never allowed regardless of preset.

6. **ShellCheck is optional but recommended**: Even without ShellCheck, schlock provides comprehensive protection via built-in rules.

---

## Success Criteria

Wizard succeeds when:
- User completes all 4 steps without errors
- Config file exists at `.claude/hooks/schlock-config.yaml`
- Config contains valid YAML with risk_tolerance, commit_filter, and shellcheck settings
- User understands how to reconfigure later

Run `/schlock:setup` to start!
