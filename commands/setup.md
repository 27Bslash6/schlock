---
description: Interactive wizard to configure schlock safety validation and advertising blocker
allowed-tools: Bash, AskUserQuestion
argument-hint: (no arguments)
---

# schlock Configuration Wizard

Welcome! I'll help you configure schlock's safety validation in 4 simple steps.

> **schlock v0.2.0** now includes ShellCheck integration and configurable risk tolerance!

This wizard generates `.claude/hooks/schlock-config.yaml` that you can share with your team via git.

---

## Step 1: Risk Tolerance (Step 1 of 4)

Risk tolerance controls how schlock handles commands at different risk levels:
- **SAFE/LOW/MEDIUM**: Always allowed (safe operations)
- **HIGH**: Risky commands (rm -rf, git push --force, etc.)
- **BLOCKED**: Critical threats (credential theft, system destruction) - always blocked

**Your Task**: Use the `AskUserQuestion` tool to ask:

```
Question: "How should schlock handle risky (HIGH-risk) commands?"
Header: "Risk Tolerance"
MultiSelect: False
Options:
  1. "Balanced (recommended)" - Description: "Prompt for approval on HIGH-risk commands. Best for most users - you'll see a confirmation before risky operations."
  2. "Permissive" - Description: "Allow HIGH-risk commands without prompting. Best for experienced users who know what they're doing."
  3. "Paranoid" - Description: "Block HIGH-risk commands entirely, prompt for MEDIUM. Best for production environments or compliance requirements."
```

**Store the user's choice** as `risk_preset`:
- "Permissive" → `risk_preset = "permissive"`
- "Balanced" → `risk_preset = "balanced"` (default)
- "Paranoid" → `risk_preset = "paranoid"`

---

## Step 2: Claude Advertising Blocker (Step 2 of 4)

The Claude Advertising Blocker removes unwanted messages from git commits:
- "Generated with [Claude Code](https://claude.com/claude-code)"
- "Co-Authored-By: Claude <noreply@anthropic.com>"

**Recommendation**: Most users prefer clean commits without advertising.

**Your Task**: Use the `AskUserQuestion` tool to ask:

```
Question: "Enable Claude Advertising Blocker?"
Header: "Ad Blocker"
MultiSelect: False
Options:
  1. "Enable (recommended)" - Description: "Blocks 'Generated with Claude Code' spam from commits. Keeps your git history clean."
  2. "Disable" - Description: "Allow Claude advertising in commits. Only choose this if you specifically want to credit Claude."
```

**Store the user's choice** as `ad_blocker_enabled` (True for Enable, False for Disable).

---

## Step 3: ShellCheck Integration (Step 3 of 4)

**First, detect if ShellCheck is installed** by running:

```python
import sys
from pathlib import Path

project_root = Path.cwd()
sys.path.insert(0, str(project_root / "src"))

from schlock.integrations.shellcheck import is_shellcheck_available, get_shellcheck_version, get_install_instructions

if is_shellcheck_available():
    version = get_shellcheck_version()
    print(f"✓ ShellCheck v{version} detected")
    shellcheck_available = True
else:
    print("✗ ShellCheck not installed")
    print(f"  Install with: {get_install_instructions()}")
    shellcheck_available = False
```

**If ShellCheck IS available** (`shellcheck_available = True`):

Use the `AskUserQuestion` tool to ask:

```
Question: "Enable ShellCheck integration for enhanced security analysis?"
Header: "ShellCheck"
MultiSelect: False
Options:
  1. "Enable (recommended)" - Description: "Run ShellCheck on commands for additional security analysis. Catches injection vulnerabilities and unsafe patterns."
  2. "Disable" - Description: "Skip ShellCheck analysis. schlock's built-in rules will still protect you."
```

**Store the user's choice** as `shellcheck_enabled` (True for Enable, False for Disable).

**If ShellCheck is NOT available** (`shellcheck_available = False`):

Use the `AskUserQuestion` tool to ask:

```
Question: "ShellCheck is not installed. Would you like to install it?"
Header: "ShellCheck"
MultiSelect: False
Options:
  1. "Yes, show install command" - Description: "Display the installation command for your platform. You can install now or later."
  2. "Skip for now" - Description: "Continue without ShellCheck. You can enable it later by running /schlock:setup again after installing."
```

**If user selects "Yes, show install command"**:
- Display the installation command from `get_install_instructions()`
- Set `shellcheck_enabled = False` (they can re-run wizard after installing)
- Continue to Step 4

**If user selects "Skip for now"**:
- Set `shellcheck_enabled = False`
- Continue to Step 4

---

## Step 4: Review and Write Configuration (Step 4 of 4)

Now I'll show you a summary and save the configuration.

**Your Task (Part A - Display Review)**: Run this Python code to generate the summary:

```python
import sys
from pathlib import Path

# Adjust path to match actual project location
project_root = Path.cwd()
sys.path.insert(0, str(project_root / "src"))

from schlock.setup.config_writer import WizardChoices, write_config
from schlock.setup.wizard import format_config_review, validate_wizard_choices

# Build choices from Steps 1-3
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
    print("\nPlease fix these issues and try again.")
    # STOP - don't proceed
else:
    # Display review
    print(format_config_review(choices))
```

**If validation errors exist**:
- Display the errors
- Exit wizard (don't write config)

**If validation passes**:

**Your Task (Part B - Confirm Write)**: Use the `AskUserQuestion` tool:

```
Question: "Save this configuration?"
Header: "Confirm"
MultiSelect: False
Options:
  1. "Yes, save configuration" - Description: "Write config to .claude/hooks/schlock-config.yaml. Existing config will be backed up."
  2. "Cancel setup" - Description: "Exit without saving. Run /schlock:setup again later to configure."
```

**If user selects "Cancel setup"**:
- Display: "Setup cancelled. Run `/schlock:setup` again anytime."
- Exit wizard

**If user selects "Yes, save configuration"**:

**Your Task (Part C - Write Config)**: Run this Python code:

```python
result = write_config(choices, create_backup_flag=True)

if result.success:
    print(f"Configuration saved to {result.config_path}")
    if result.backup_path:
        print(f"   (Previous config backed up to {result.backup_path})")
    print("\nNext steps:")
    print("- Config is active immediately (no restart needed)")
    print("- Share .claude/hooks/ in git for team standardization")
    print("- Run /schlock:setup again anytime to reconfigure")
    if not shellcheck_enabled:
        print("- Install ShellCheck for enhanced security: " + get_install_instructions())
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

1. **Path adjustment**: The example code uses `Path.cwd()` to find project root. Adjust if needed based on environment.

2. **Validation is mandatory**: Always run `validate_wizard_choices()` before writing. Invalid configs must not be written.

3. **Progress indicators**: Show "Step X of 4" in section headers.

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
