# CLAUDE.md

## Project Overview

**schlock** - Claude Code plugin for LLM command safety validation.

**Features**:
- **Safety validation** (always on): Bashlex AST parsing prevents dangerous commands
- **Risk tolerance presets**: permissive, balanced (default), paranoid
- **Audit logging** (always on): JSONL audit trail for compliance/security analysis
- **Claude advertising blocker** (optional): Blocks "Generated with Claude Code" spam

**Distribution**: Plugin-only (NOT PyPI). Leverages Claude Code's automatic team installation.

**Status**: v0.2.4 production. 850+ tests passing, 92%+ coverage.

## Critical Design Principles

1. **Security is Non-Negotiable**: Bashlex AST parsing is security-critical. No regex shortcuts.
   - **Approved exception — the quoted-heredoc fallback lexer.** bashlex rejects a quoted
     heredoc delimiter (`<< 'EOF'`) outright, so for those commands there is no AST to walk
     and the shell *around* the heredoc would otherwise never be validated (LAB-2765).
     `_neuter_heredocs` / `_rewrite_openers` in `src/schlock/core/validator.py` recover it
     with a hand-written lexer. This is the only sanctioned non-AST parsing path, and it holds
     only while all four constraints do:
     1. **Bounded reach** — two call sites. The fallback (`_neuter_heredocs`) runs only from
        `_validate_heredoc_command`, after bashlex has already raised a heredoc-shaped error.
        `_normalise_heredoc_delimiters` runs the same lexer *before* bashlex on any command
        containing `<<`, but its only output is a rewrite of **quoted** delimiters to their
        bare spelling (and their bodies to same-length filler, since a quoted body is
        literal): a command with no quoted delimiter reaches bashlex byte for byte. So it
        changes what bashlex sees only on the inputs that used to reach the fallback, or that
        bashlex misread (LAB-3094).
     2. **No verdicts** — it decides *where heredoc bodies begin and end*, nothing else. The
        recovered text is re-validated through `validate_command`'s front door, so rules,
        segments, substitutions and dangerous-flag checks all still run on the AST. The only
        verdicts its reading feeds are refusals when it and bashlex disagree about an opener.
     3. **Fails closed on uncertainty** — an untokenizable delimiter, a missing terminator,
        or a line that continues past an opener raises `ParseError`, which the caller turns
        into `BLOCKED`; the pre-parse rewrite answers the same uncertainty by handing the
        command back untouched, which sends it down that same route. Note what this does
        *not* cover: the dangerous failure is not the uncertain reading that raises, it is
        the confident wrong one that does not. The pre-parse rewrite shares that exposure on
        the same inputs - it blanks what it reads as a quoted body - which is why its body
        spans are pinned against an independent bash parser, not against bashlex.
     4. **Escalation is monotonic, which is not the same as safe** —
        `_escalate_past_heredoc` can worsen a verdict and never improve one, so a misread
        body *end* is bounded to a false positive. A misread body *start* is not: the
        swallowed text is deleted from the rewrite before escalation ever sees it, leaving
        the verdict pinned at the heredoc head's own floor. That asymmetry is why every
        uncertain body-*start* reading must raise, and why changes here are pinned by
        asserting the rewritten text still contains the payload rather than by asserting a
        verdict.
     Bash's tokenization is what it must match, so every behavioural change here is decided by
     running real bash first and pinned by a test that names what bash did.
2. **User Autonomy**: Risk presets let users choose their protection level. Document risks, respect decisions.
3. **Plugin-First**: Purpose-built for Claude Code. No PyPI hybrid complexity.
4. **Simplicity First**: Plugin bundles all dependencies. Three commands to install.

## SubstitutionValidator Security Model

Command/process substitution (`$(cmd)`, `<(cmd)`) requires special handling because:
1. Regex cannot parse nested/recursive structures
2. Whitelisted commands may have dangerous modes (e.g., `find -exec`)
3. Pipelines/chains after safe commands can execute arbitrary code

**Architecture**: Hybrid AST + Whitelist + Recursive Validation
- Layer 1: Whitelist check (fast path for known-safe patterns)
- Layer 2: AST-based detection of dangerous constructs
- Layer 3: Recursive validation of nested substitutions
- Layer 4: Rule engine validation of inner commands

**Contextual Validation**: Some commands are safe by default but dangerous with specific flags/options:

| Command | Safe Usage | Dangerous Flags/Options |
|---------|------------|------------------------|
| `find` | `-name`, `-type`, `-maxdepth` | `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete` |
| `git` | `status`, `log`, `diff` | `-c alias.X=!cmd`, `-c core.sshCommand`, `-c core.pager`, `-c credential.helper`, `-c diff.external`, `-c merge.tool`, `-c man.*`, `-c help.format`; writing `man.*` / `help.format` with `git config`, including a `--rename-section` into them (rated on the key, whatever the value, since they pick the program `git help` runs: HIGH at the top level, BLOCKED inside `$()`, and a worse value keeps its own verdict) |
| `grep` | Pattern matching | (generally safe) |
| `locate` | File search | (generally safe) |

**Key Security Learnings** (2025-12 hardening session):
1. Whitelist commands need ALL dangerous flag/config enumeration
2. Pipeline to shell (`date | bash`) must be blocked even for whitelisted commands
3. Command chains (`;`, `&&`, `||`) after whitelisted commands must validate all segments
4. Git `-c` config options can execute arbitrary commands via alias, core.sshCommand, core.pager
5. `env` and `command` builtins were removed from whitelist (execute arbitrary commands)

## Quick Reference

**Core Components**:
- `.claude-plugin/plugin.json` - Plugin manifest
- `hooks/pre_tool_use.py` - Safety validation + audit logging
- `src/schlock/core/` - Validation engine (parser, rules, validator, cache, substitution)
- `src/schlock/integrations/` - Optional features (audit, commit_filter, shellcheck)
- `src/schlock/setup/` - Configuration utilities (config_writer, wizard, env_detector)
- `data/rules/` - 60+ security rules (multi-file structure)
- `tests/` - 850+ tests (92%+ coverage)

**Risk Tolerance Presets**:
| Preset | BLOCKED | HIGH | MEDIUM | Use Case |
|--------|---------|------|--------|----------|
| `permissive` | deny | allow | allow | Experienced users, local dev |
| `balanced` | deny | ask | allow | Default, most users |
| `paranoid` | deny | deny | ask | Production, compliance |

**Configuration Layers** (highest priority last):
1. Plugin defaults: `data/rules/*.yaml` (immutable)
2. User overrides: `~/.config/schlock/config.yaml`
3. Project overrides: `.claude/hooks/schlock-config.yaml`

**Rule Overrides**: Per-rule and per-category overrides via `rule_overrides` and `category_overrides` YAML keys. BLOCKED rules cannot be downgraded or disabled (security floor).

**Command Whitelist**: User-level config (`~/.config/schlock/config.yaml`) supports `whitelist:` — a list of regex patterns that bypass ALL rules including BLOCKED. Project-level config cannot define whitelist patterns (privilege escalation risk). See `docs/CONFIGURATION.md`.

**Self-Protection**: Three-layer defense prevents LLM agents from modifying schlock config:
1. YAML rules (`14_self_protection.yaml`, BLOCKED) — can't be overridden
2. Hardcoded validator check (`_check_self_protection`) — independent of YAML rules
3. Dedicated PreToolUse hook (`self_protect.py`, matcher `Write|Edit|MultiEdit|NotebookEdit`) — blocks Write/Edit tool calls targeting config files

## Installation

```bash
/plugin marketplace add 27Bslash6/schlock
/plugin install schlock@schlock
/schlock:setup   # Optional - configure preferences
```

## Release Process

Uses **release-please** for automated releases:
1. Conventional commits (`feat:`, `fix:`) trigger release PRs
2. Merge release PR → GitHub release + tag created
3. Version updated in: `pyproject.toml`, `src/schlock/__init__.py`, `.claude-plugin/plugin.json`

Config files: `release-please-config.json`, `.release-please-manifest.json`

## Documentation Map

**User Documentation**:
- **README.md** - Problem/solution, how it works, installation
- **docs/INSTALLING.md** - Complete installation guide
- **docs/CONFIGURATION.md** - Power-user configuration guide
- **docs/CHANGELOG.md** - Release history

**Developer Documentation**:
- **CONTRIBUTING.md** - Development workflow, testing, contributing
- **docs/QA_TOOLING.md** - QA tools and workflow guide

## Package Metadata

- **Name**: `schlock`
- **Version**: `0.1.0`
- **Publisher**: 27B.io
- **License**: WTFPL
- **Python**: >=3.9
- **Repository**: https://github.com/27Bslash6/schlock
- **Dependencies**: `bashlex>=0.18`, `pyyaml>=6.0` (vendored)
