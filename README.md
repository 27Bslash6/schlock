# schlock

**A safety net for Claude Code** — Intercepts dangerous bash commands before they execute.

[![Tests](https://img.shields.io/badge/tests-821_passing-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](CONTRIBUTING.md)
[![License](https://img.shields.io/badge/license-WTFPL-blue)](https://www.wtfpl.net/)

**Features**: AST-based parsing (not regex) · 60+ security rules · 3 risk presets · Audit logging · Commit ad-blocker

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Configuration](#configuration) · [Docs](#documentation)

---

## The Problem

You're using Claude Code with `Bash(*)` permissions because you want it to actually get things done. But then it does this:

```
Claude: I'll clean up those temp files for you.
Claude: Bash(`rm -rf project-*`)
```

While you're thinking: *"Wait, which directory am I in? What else matches that glob? Did I have anything important in there?"* it's already too late.

Or worse:

```
Claude: Let me fix that git history.
Claude: Bash(`git reset --hard HEAD~5`)
Claude: Bash(`git push --force origin main`)
```

By the time you've processed what happened, it's done. Your git history is rewritten. Your team is not happy.

## The Solution

**schlock** is a Claude Code plugin that intercepts every bash command and blocks the dangerous ones *before* they execute.

```
Claude: Bash(`rm -rf /`)
┌─────────────────────────────────────────────────────┐
│ 🚫 BLOCKED by schlock                               │
│                                                     │
│ Command: rm -rf /                                   │
│ Risk: BLOCKED - Recursive delete from root          │
│                                                     │
│ This command would delete your entire filesystem.   │
│ If you actually need to do this, run it manually.   │
└─────────────────────────────────────────────────────┘
```

Claude sees the rejection and adjusts. Your filesystem survives. You sleep at night.

---

## Quick Start

```bash
# In Claude Code
/plugin marketplace add 27Bslash6/schlock
/plugin install schlock@schlock

# Optional
/schlock:setup
```

That's it. Safety validation is automatic. The setup wizard configures to your liking.

**Zero friction**: <1ms validation on most commands. You won't notice it's there.

**Team installation**: Add to `.claude/settings.json` and commit — teammates get it automatically when they trust the repo. See [docs/INSTALLING.md](docs/INSTALLING.md).

---

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Claude wants │     │   schlock    │     │   Command    │
│ to run bash  │ ──▶ │  validates   │ ──▶ │   executes   │
│   command    │     │   command    │     │  (or not)    │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                     ┌──────┴──────┐
                     │             │
                 ┌───▼───┐    ┌───▼───┐
                 │ Parse │    │ Match │
                 │  AST  │    │ Rules │
                 └───────┘    └───────┘
```

1. **Hook**: schlock registers a `PreToolUse` hook with Claude Code
2. **Parse**: When Claude calls `Bash()`, schlock parses the command using [bashlex](https://github.com/idank/bashlex) (proper AST, not regex)
3. **Match**: The parsed command is checked against 40+ security rules
4. **Decide**: Commands are allowed, warned, or blocked based on risk level
5. **Log**: Every decision is logged to `~/.config/schlock/audit.jsonl`

**Why AST parsing matters**: Regex-based blockers are trivially bypassed. `rm -rf /` is easy to catch, but what about `r\m -rf /` or `$(echo rm) -rf /`? bashlex parses the actual shell semantics, not string patterns.

---

## What Gets Caught

Every command is classified into a risk level:

| Risk Level | What | Examples |
|------------|------|----------|
| 🚫 **BLOCKED** | System destruction, credential exposure | `rm -rf /`, `chmod 000 /`, `cat ~/.ssh/id_rsa` |
| ⚠️ **HIGH** | History rewriting, broad permissions | `git push --force`, `chmod 777`, `sudo rm` |
| ⚡ **MEDIUM** | Risky patterns | `curl \| sh`, `eval "$var"` |
| ℹ️ **LOW** | Potentially slow/resource-intensive | `find / -name`, `dd if=/dev` |
| ✅ **SAFE** | Read-only operations | `ls`, `git status`, `cat file.txt` |

What happens at each level depends on your [risk tolerance preset](#risk-tolerance). By default (balanced), BLOCKED commands are denied, HIGH commands prompt for confirmation, and everything else is allowed.

See [`data/rules/`](data/rules/) for the complete ruleset (60+ rules across multiple categories).

---

## Performance

schlock is designed to be invisible:

| Operation | Time |
|-----------|------|
| Cached validation | <0.5ms |
| Simple command | <1ms |
| Complex pipeline | <15ms |
| Throughput | ~100/sec |

You won't notice it's there — until it saves you.

---

## Configuration

### Risk Tolerance

Not everyone wants the same level of protection. schlock has three presets:

| Preset | BLOCKED | HIGH | MEDIUM | LOW | Best For |
|--------|---------|------|--------|-----|----------|
| **permissive** | 🚫 deny | ✅ allow | ✅ allow | ✅ allow | Experienced users, local dev |
| **balanced** *(default)* | 🚫 deny | ❓ ask | ✅ allow | ✅ allow | Most users |
| **paranoid** | 🚫 deny | 🚫 deny | ❓ ask | ✅ allow | Production, compliance |

Configure in `.claude/hooks/schlock-config.yaml`:

```yaml
risk_tolerance:
  preset: balanced  # or: permissive, paranoid
```

Or go custom:

```yaml
risk_tolerance:
  levels:
    SAFE: allow
    LOW: allow
    MEDIUM: allow
    HIGH: ask      # Prompt before allowing
    BLOCKED: deny  # Always block
```

**Actions explained:**
- `allow` — Execute without prompting
- `ask` — Prompt user for confirmation
- `deny` — Block execution, Claude must find another way

### Advertising Blocker

Optional but recommended. Blocks "Generated with Claude Code" spam from commits:

```yaml
commit_filter:
  enabled: true
  rules:
    advertising:
      enabled: true
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for advanced options and team-wide settings.

---

## Limitations

schlock is **defense-in-depth**, not a security boundary. It catches obvious mistakes and dangerous patterns. It won't stop:

- A determined attacker (or LLM) trying to bypass it
- Commands that are dangerous in context but safe in isolation
- Anything that doesn't go through Claude Code's `Bash()` tool

Think of it like a seatbelt: you should still drive carefully, but it's better than nothing.

---

## Documentation

- [**INSTALLING.md**](docs/INSTALLING.md) — Installation guide (individual, team, troubleshooting)
- [**CONFIGURATION.md**](docs/CONFIGURATION.md) — Power-user configuration
- [**CHANGELOG.md**](docs/CHANGELOG.md) — Release history
- [**CONTRIBUTING.md**](CONTRIBUTING.md) — Development workflow

---

## The Name

"Schlock" is slang for cheap, low-quality horror movies — the kind where you yell at the screen because the character is about to do something obviously stupid.

That's what this plugin does. It yells at Claude before it does something obviously stupid.

Secure Claude Hook LOCK? 💭

---

## License

[WTFPL](LICENSE) — Do what you want. Just don't blame us if Claude still finds a way to `rm -rf /` your production server.
