# Configuration Guide

This document describes how to configure schlock features, customize safety rules, and integrate with your development workflow.

> **⚠️ Note on Code Formatting**: The `formatter` configuration options documented below are **non-functional** in v0.1.0 because Claude Code does not support PostToolUse hooks for plugins. For code formatting, use [pre-commit hooks](https://pre-commit.com/) (industry standard). The formatter configuration is documented here for reference and future compatibility.

## Table of Contents

1. [Configuration System](#configuration-system)
2. [Safety Rules Customization](#safety-rules-customization)
3. [Advertising Blocker](#advertising-blocker)
4. [Audit Logging](#audit-logging)
5. [Advanced Examples](#advanced-examples)
6. [Team-Wide Configuration](#team-wide-configuration)

**Note**: For code formatting, use [pre-commit hooks](https://pre-commit.com/) (industry standard).

## Configuration System

Schlock uses a 3-tier configuration system with clear precedence:

1. **Plugin defaults**: `data/*.yaml` (immutable, bundled with plugin)
2. **User overrides**: `~/.config/schlock/config.yaml` (optional, personal preferences)
3. **Project overrides**: `.claude/hooks/schlock-config.yaml` (team-shareable, version-controlled)

### Priority Order

```
Project config > User config > Plugin defaults
```

**Why three layers?**
- **Plugin defaults**: Production-ready security rules maintained by schlock
- **User config**: Personal preferences (e.g., disable blocker for personal projects)
- **Project config**: Team standards (version-controlled, shareable via git)

### Configuration File Format

All config files use YAML format:

```yaml
# Feature toggles
commit_filter:
  enabled: true  # Advertising blocker

formatter:
  enabled: true  # Code formatter

# Individual features can be fine-tuned below
```

## Safety Rules Customization

Safety rules are defined in `data/safety_rules.yaml`. You cannot directly edit plugin defaults, but you can override them in user/project config.

### Understanding Rule Structure

Each rule has:
- `id`: Unique identifier (e.g., `RULE_001`)
- `severity`: `BLOCKED`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`
- `pattern`: Regular expression to match commands
- `description`: Human-readable explanation
- `message`: User-facing warning message
- `alternatives`: Suggested safer alternatives (optional)

### Example Rule Override (Coming Soon)

> **Note**: Rule customization is not yet implemented in v0.1.0. This feature is planned for v0.2.0.
>
> Planned syntax:
> ```yaml
> safety_rules:
>   # Override severity for specific rule
>   RULE_042:
>     severity: LOW  # Downgrade from HIGH
>
>   # Disable rule entirely
>   RULE_013:
>     enabled: false
> ```

### Current Workarounds

For now, if you need to bypass safety checks:
1. **Run commands in terminal** (outside Claude Code)
2. **Use `/bypass` command** (if implemented by Claude Code team)
3. **Temporarily disable plugin** (not recommended)

## Safety Validation (Always On)

- **Cannot be disabled** - Core security feature
- Validates all Bash commands before execution
- Uses `data/safety_rules.yaml` ruleset
- Fail-safe design (denies on errors)

## Advertising Blocker

The advertising blocker removes unwanted Claude Code advertising from git commits.

### What It Blocks

The blocker targets these patterns:
1. **Generated with Claude Code** - Signature lines with links
2. **Co-Authored-By: Claude** - Co-author credits in commits
3. **Powered by Claude** - Similar promotional content

### Configuration

```yaml
# .claude/hooks/schlock-config.yaml
commit_filter:
  enabled: true  # Enable advertising blocker
  rules:
    advertising:
      enabled: true  # Block Claude advertising
```

### How It Works

1. **PreToolUse hook** intercepts `git commit` commands
2. **Extracts commit message** from command arguments
3. **Scans for advertising patterns** using regex rules
4. **Blocks commit** if patterns found (with clear error message)
5. **User must remove** advertising and retry

### Why Block Instead of Filter?

**Block-on-detection** (current approach):
- User awareness (you know advertising was present)
- No silent modifications (transparent behavior)
- Respects user agency (you decide what to commit)

**Silent filtering** (considered but rejected):
- Could silently modify commits without user knowledge
- Harder to debug if something goes wrong
- Users should know what's being committed

### Disabling the Blocker

To disable (e.g., for personal projects where you don't care):

```yaml
# .claude/hooks/schlock-config.yaml
commit_filter:
  enabled: false  # Disable advertising blocker
```

Or disable advertising rules only:

```yaml
commit_filter:
  enabled: true
  rules:
    advertising:
      enabled: false  # Keep filter enabled but allow advertising
```

### Custom Patterns (v0.2.0)

> **Note**: Custom pattern rules are planned for v0.2.0.
>
> Future syntax:
> ```yaml
> commit_filter:
>   enabled: true
>   custom_rules:
>     - pattern: "DO NOT COMMIT"
>       description: "Blocking development markers"
> ```

## Audit Logging

Audit logging provides a persistent security trail of all command validations.

### What Gets Logged

Every command validation creates an audit entry with:
- **Timestamp**: ISO 8601 UTC timestamp
- **Command**: The bash command that was validated (truncated to 500 chars)
- **Risk Level**: SAFE, LOW, MEDIUM, HIGH, or BLOCKED
- **Violations**: List of matched security rules
- **Decision**: allow, block, or warn
- **Context**: Project root, current directory, git branch
- **Execution Time**: Validation duration in milliseconds

### Log Location

Default: `~/.config/schlock/audit-YYYY-MM-DD.jsonl` (daily timestamped files)

Override via `SCHLOCK_AUDIT_LOG` environment variable:
```bash
# Single file (ends in .jsonl)
export SCHLOCK_AUDIT_LOG=~/my-logs/audit.jsonl

# Timestamped files in custom directory
export SCHLOCK_AUDIT_LOG=~/my-logs

# Disable logging
export SCHLOCK_AUDIT_LOG=/dev/null
```

### Log Format (JSONL)

Each line is a complete JSON object:

```json
{
  "timestamp": "2025-11-07T10:15:30.123456Z",
  "event_type": "block",
  "command": "rm -rf /tmp/dangerous",
  "risk_level": "HIGH",
  "violations": ["Recursive delete with rm -rf"],
  "decision": "block",
  "context": {
    "project_root": "/home/user/project",
    "current_dir": "/home/user/project/src",
    "git_branch": "main",
    "environment": "development"
  },
  "execution_time_ms": 12.45
}
```

### Querying Audit Logs

**Count blocked commands today:**
```bash
# Today's file
TODAY=$(date +%Y-%m-%d)
grep '"decision":"block"' ~/.config/schlock/audit-$TODAY.jsonl | wc -l
```

**Find all HIGH-risk commands (today):**
```bash
TODAY=$(date +%Y-%m-%d)
jq 'select(.risk_level == "HIGH")' ~/.config/schlock/audit-$TODAY.jsonl
```

**Commands in specific project (last 7 days):**
```bash
cat ~/.config/schlock/audit-*.jsonl | \
  jq 'select(.context.project_root == "/home/user/myproject")'
```

### Log Retention

Daily timestamped files prevent unbounded growth. Each file contains one day's logs.

**Manual cleanup (delete old logs):**
```bash
# Delete logs older than 90 days
find ~/.config/schlock -name "audit-*.jsonl" -mtime +90 -delete

# Delete specific year
rm ~/.config/schlock/audit-2024-*.jsonl

# Keep only last 30 days
ls -t ~/.config/schlock/audit-*.jsonl | tail -n +31 | xargs rm
```

**Logrotate (optional, for compression):**
```
# /etc/logrotate.d/schlock
/home/USER/.config/schlock/audit-*.jsonl {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
}
```

### Disabling Audit Logging

Audit logging is **always enabled** and cannot be disabled. This is intentional:
- **Security compliance** - Audit trails required for some environments
- **Fail-silent design** - I/O errors don't break hooks
- **Minimal overhead** - Single append write per command (<1ms)
- **Non-intrusive** - No user-facing impact

If you need to disable it, set log path to `/dev/null`:
```bash
export SCHLOCK_AUDIT_LOG=/dev/null
```

### Thread Safety

Audit logging is thread-safe:
- **Append-only writes** - Atomic at OS level
- **No file locking** - Concurrent writes won't corrupt log
- **JSON Lines format** - Each line is independent

Multiple Claude Code sessions can log to the same file safely.

## Advanced Examples

### Example 1: Strict Team Configuration

Enforce strict rules for production team:

```yaml
# .claude/hooks/schlock-config.yaml (version-controlled)
commit_filter:
  enabled: true  # Block advertising
  rules:
    advertising:
      enabled: true

formatter:
  enabled: true  # Enforce consistent formatting
  tools:
    ruff:
      enabled: true  # Python formatting required
    prettier:
      enabled: true  # JS/TS formatting required
    cargo:
      enabled: false  # No Rust in this project
```

### Example 2: Personal Relaxed Setup

Minimal config for personal projects:

```yaml
# ~/.config/schlock/config.yaml (user home)
commit_filter:
  enabled: false  # I don't mind Claude advertising

formatter:
  enabled: false  # I format manually
```

### Example 3: Python-Only Project

Configure for Python-exclusive development:

```yaml
# .claude/hooks/schlock-config.yaml
formatter:
  enabled: true
  tools:
    ruff:
      enabled: true  # Python only
    cargo:
      enabled: false  # Disable Rust
    prettier:
      enabled: false  # Disable JS/TS
```

### Example 4: Multi-Language Monorepo

Full-stack configuration:

```yaml
# .claude/hooks/schlock-config.yaml
commit_filter:
  enabled: true

formatter:
  enabled: true
  tools:
    ruff:
      enabled: true  # Backend (Python)
    cargo:
      enabled: true  # Systems code (Rust)
    prettier:
      enabled: true  # Frontend (TS/React)
```

## Team-Wide Configuration

### Version Control Integration

**Add to git:**
```bash
git add .claude/hooks/schlock-config.yaml
git commit -m "Add schlock configuration for team"
```

**Team members get config automatically:**
- Plugin reads `.claude/hooks/schlock-config.yaml` from project root
- No manual setup required
- Consistent behavior across team

### Onboarding New Developers

1. **Install schlock plugin:**
   ```
   /plugin install schlock@27b
   ```

2. **Run setup wizard:**
   ```
   /schlock:setup
   ```

3. **Config already present:**
   - Wizard detects existing `.claude/hooks/schlock-config.yaml`
   - Offers to keep or regenerate
   - Most devs keep team config

### Handling Conflicts

If user preferences conflict with team config:

**User wants to disable formatter:**
```yaml
# ~/.config/schlock/config.yaml
formatter:
  enabled: false  # Personal preference
```

**Team requires formatter:**
```yaml
# .claude/hooks/schlock-config.yaml
formatter:
  enabled: true  # Team standard
```

**Result:** Project config wins (formatter enabled). User must use project standards.

**Recommendation:** Discuss with team if you have strong preferences. Project config represents team consensus.

### Documentation for Teams

Include in your project README:

```markdown
## Development Setup

### Code Quality Tools

This project uses [schlock](https://github.com/27Bslash6/schlock) for:
- Bash command safety validation (always on)
- Automatic code formatting (Python: ruff, JS/TS: prettier)
- Clean commit history (no advertising)

Install schlock:
1. In Claude Code: `/plugin install schlock@27b`
2. Run setup: `/schlock:setup`
3. Accept project configuration

Configuration is in `.claude/hooks/schlock-config.yaml` (version-controlled).
```

### Migration Path

**Introducing schlock to existing project:**

1. **Install locally first:**
   ```
   /plugin install schlock@27b
   /schlock:setup
   ```

2. **Test with your workflows:**
   - Run typical commands
   - Verify formatter works
   - Check commit flow

3. **Create team config:**
   ```bash
   cp ~/.claude/hooks/schlock-config.yaml .claude/hooks/schlock-config.yaml
   ```

4. **Commit and announce:**
   ```bash
   git add .claude/hooks/schlock-config.yaml
   git commit -m "Add schlock plugin configuration"
   ```

5. **Document in README:**
   - Installation instructions
   - Why schlock is used
   - How to configure

---

## Troubleshooting

### Config Not Loading?

**Check file location:**
```bash
ls -la .claude/hooks/schlock-config.yaml  # Project
ls -la ~/.config/schlock/config.yaml      # User
```

**Check YAML syntax:**
```bash
python -c "import yaml; yaml.safe_load(open('.claude/hooks/schlock-config.yaml'))"
```

**Enable debug logging:**
```bash
export SCHLOCK_DEBUG=1
```

### Feature Not Working?

**Advertising blocker:**
- Check `commit_filter.enabled: true`
- Try test commit with "Generated with Claude Code"
- Should be blocked

**Formatter:**
- Check `formatter.enabled: true`
- Verify tool installed: `which ruff` / `which prettier`
- Try writing Python file
- Check stderr for formatter logs

### Getting Help

1. **Check logs:** stderr output from hooks
2. **Enable debug mode:** `export SCHLOCK_DEBUG=1`
3. **Review audit log:** `~/.config/schlock/audit.jsonl`
4. **File issue:** https://github.com/27Bslash6/schlock/issues
