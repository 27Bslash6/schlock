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
| `git` | `status`, `log`, `diff` | `-c alias.X=!cmd`, `-c core.sshCommand`, `-c core.pager`, `-c credential.helper`, `-c diff.external`, `-c merge.tool` |
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
