---
description: Manually validate a bash command for safety
argument-hint: [command]
---

# schlock:validate

Validate a bash command for safety without executing it.

This command uses the same validation engine as the automatic PreToolUse hook, allowing you to test commands before running them.

## Usage

```
/schlock:validate "command to validate"
```

**Examples:**
```
/schlock:validate "rm -rf /tmp/test"
/schlock:validate "git push --force origin main"
/schlock:validate "ls -la"
```

---

## Instructions for Claude

When this command is invoked, follow these steps to validate the command:

### Step 1: Extract Command Argument

Parse the user's input to extract the command to validate.

**Expected format:** `/schlock:validate "command here"`

**If no argument provided:**
- Display usage instructions (see Usage Examples section below)
- Do NOT proceed with validation
- Exit

### Step 2: Call Validation Engine

Import and call the validation function:

```python
import sys
from pathlib import Path

# Add schlock to path
project_root = Path.cwd()
sys.path.insert(0, str(project_root))

from schlock import validate_command

# Validate the command
result = validate_command(command)
```

### Step 3: Format and Display Result

Display the validation result with this format:

**For BLOCKED commands:**
```
🚫 BLOCKED: [message]

Safer alternatives:
  • [alternative 1]
  • [alternative 2]
```

**For HIGH risk commands:**
```
⚠️  HIGH RISK: [message]

Proceed with caution. Consider:
  • [alternative 1]
  • [alternative 2]
```

**For MEDIUM risk commands:**
```
⚠️  MEDIUM RISK: [message]

[Display alternatives if available]
```

**For LOW risk commands:**
```
ℹ️  LOW RISK: [message]
```

**For SAFE commands:**
```
✅ SAFE: [message]
```

**If validation error occurred:**
```
❌ VALIDATION ERROR: [error message]

The command was blocked due to a validation error (fail-safe mode).
```

### Step 4: Display Technical Details (Optional)

After the main result, you may optionally display:
- Risk level: `result.risk_level.name`
- Exit code: `result.exit_code`
- Cached: (check if response was <50ms)

---

## Usage Examples

When user runs `/schlock:validate` without arguments, display:

```
schlock:validate - Validate bash commands for safety

Usage:
  /schlock:validate "command to validate"

Examples:
  /schlock:validate "rm -rf /tmp/test"
    → Validates recursive delete operation

  /schlock:validate "git push --force origin main"
    → Checks for dangerous git operations

  /schlock:validate "ls -la"
    → Validates safe file listing command

How it works:
  • Uses same validation engine as automatic hook
  • Analyzes command using bashlex AST parsing
  • Checks against 40+ safety rules
  • Returns risk level: SAFE, LOW, MEDIUM, HIGH, BLOCKED
  • Suggests safer alternatives when available

Risk Levels:
  🚫 BLOCKED  - Command execution prevented (destructive operations)
  ⚠️  HIGH     - Dangerous but not blocked (requires caution)
  ⚠️  MEDIUM   - Potentially risky operations
  ℹ️  LOW      - Minor concerns or best practice violations
  ✅ SAFE     - No safety concerns detected
```

---

## Error Handling

**If command extraction fails:**
- Show usage instructions
- Do not attempt validation

**If validation raises exception:**
- Display error message
- Explain that command was blocked (fail-safe)
- Suggest checking command syntax

**If import fails:**
- Display: "schlock validation engine not found. Plugin installation may be corrupted."
- Suggest: "/plugin update schlock" or reinstall

---

## Notes for Claude

1. **Path handling:** Adjust `sys.path.insert(0, ...)` to use actual project root from environment. The example uses `Path.cwd()` which should work in most cases.

2. **ValidationResult structure:** The `result` object has these fields:
   - `allowed` (bool): Whether command can execute
   - `risk_level` (RiskLevel enum): SAFE, LOW, MEDIUM, HIGH, BLOCKED
   - `message` (str): Human-readable explanation
   - `alternatives` (List[str]): Safer approaches (may be empty)
   - `exit_code` (int): 0 if allowed, 1 if blocked
   - `error` (Optional[str]): Error message if validation failed

3. **Formatting:** Use emoji indicators (🚫 ⚠️ ℹ️ ✅ ❌) for visual clarity in terminal output.

4. **Alternatives:** Only display alternatives section if `result.alternatives` list is not empty.

5. **Consistency:** Output format should match PreToolUse hook messages for familiarity.

6. **Performance:** Validation is fast (<200ms cold, <50ms cached). No need for progress indicators.

7. **No execution:** This command ONLY validates. It never executes the provided command.

---

## Success Criteria

Command is working correctly when:
- `/schlock:validate "rm -rf /"` shows BLOCKED with alternatives
- `/schlock:validate "ls -la"` shows SAFE
- `/schlock:validate "git push --force"` shows HIGH risk
- `/schlock:validate` (no args) shows usage instructions
- Output format matches PreToolUse hook messages
- Validation cache is shared (second call to same command is fast)
