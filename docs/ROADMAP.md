# schlock Product Roadmap

*Last Updated: 2025-12-01*

This roadmap outlines schlock's evolution. Priorities are driven by user feedback and real-world usage.

---

## Current Status: v0.2.1

**Released**: 2025-12-01

**Core Capabilities**:
- Safety validation (60+ rules, bashlex AST parsing)
- Risk tolerance presets (permissive, balanced, paranoid)
- ShellCheck integration (optional)
- Audit logging (JSONL, always-on)
- Claude advertising blocker (optional)
- Setup wizard (`/schlock:setup`)
- Manual validation (`/schlock:validate`, `safety-validator` skill)
- Layered configuration (plugin → user → project)

**Known Limitations**:
- **No per-rule overrides**: Can't customize individual rule severity
- **No code quality rules**: Only security-focused rules exist
- **Code formatter**: Non-functional (Claude Code doesn't support PostToolUse hooks)

---

## Release History

### v0.2.1 (2025-12-01)
- Fix: Commit filter bashlex AST parsing with regex fallback
- Docs: README badges, ShellCheck integration details

### v0.2.0 (2025-11-28)
- Initial public release
- 60+ security rules across 5 severity levels
- Risk tolerance presets
- ShellCheck integration
- Advertising blocker
- Audit logging
- 821 tests, 90% coverage

---

## Upcoming: v0.3.0 - Rule Customization & Code Quality

**Goal**: Enable per-rule customization and add code quality anti-pattern detection.

**Priority**: HIGH (original inspiration for the plugin)

### Features

#### 1. Rule Categories
Separate security rules from code quality rules:

```yaml
rule_categories:
  security: true      # Always on (hardcoded, non-negotiable)
  code_quality: true  # Default on, user can disable
```

- **security**: Dangerous commands (rm -rf, credential exposure, etc.)
- **code_quality**: LLM anti-patterns that bypass developer intent

#### 2. Per-Rule Overrides
Customize individual rule behavior:

```yaml
rule_overrides:
  git_bulk_staging:
    risk_level: BLOCKED  # Upgrade from HIGH
  git_commit_all:
    risk_level: MEDIUM   # Downgrade from HIGH
  some_annoying_rule:
    enabled: false       # Disable entirely
```

#### 3. Code Quality Rules
Block sloppy LLM behaviors:

| Rule | Pattern | Why |
|------|---------|-----|
| `git_bulk_staging` | `git add -A`, `git add .`, `git add --all` | Bulk staging bypasses file review |
| `git_commit_all` | `git commit -a` | Auto-staging bypasses explicit staging |
| `git_discard_all` | `git checkout .`, `git restore .` | Discards all changes without review |
| `git_clean_aggressive` | `git clean -fd` (without dry-run) | Nukes untracked without preview |
| `git_stash_all` | `git stash --all`, `git stash -u` | Stashes everything without review |

Default risk level: **HIGH** (prompts in balanced mode, users can override to BLOCKED)

### Implementation Scope

| Component | Change |
|-----------|--------|
| `src/schlock/core/rules.py` | Add `category` field to SecurityRule |
| `src/schlock/core/validator.py` | Category filtering + per-rule overrides |
| `src/schlock/setup/config_writer.py` | New config schema |
| `data/rules/13_code_quality.yaml` | New rules file |
| `hooks/pre_tool_use.py` | Load category/override config |
| `/schlock:setup` wizard | Ask about code quality preference |

**Estimated effort**: 2-3 days

---

## Future: v0.4.0 - False Positive Management

**Goal**: Build feedback loops for rule accuracy improvement.

**Features**:
- `/schlock:report-fp` command for quick feedback
- GitHub issue template with auto-filled context
- Rule accuracy tracking
- Enhanced rule documentation (rationale, known edge cases)

**Trigger**: After v0.3.0 ships and generates user feedback

---

## Future: v0.5.0 - Ruleset Versioning

**Goal**: Enable safe ruleset updates without breaking configs.

**Features**:
- Versioned ruleset schema
- Migration path documentation
- `/schlock:update-rules` command
- Breaking change notifications

**Trigger**: When rule changes would break existing configs

---

## Deferred / Not Planned

| Feature | Reason |
|---------|--------|
| Code formatter | Claude Code doesn't support PostToolUse hooks |
| Telemetry | Privacy concerns, unclear value |
| Web dashboard | CLI-first is sufficient |
| PyPI package | No demand signal yet |
| ML-based adaptive rules | Overkill for current scale |

**Revisit when**: Clear user demand + proven ROI

---

## Decision Framework

### Priority Levels

- **HIGH**: Blocks adoption, addresses core pain points, clear user demand
- **MEDIUM**: Enhances existing workflows, enables team adoption
- **LOW**: Speculative value, complex implementation

### Version Bump Triggers

- **Patch (0.x.Y)**: Bug fixes, docs, performance
- **Minor (0.X.0)**: New features, backwards compatible
- **Major (X.0.0)**: Breaking changes (not planned before 1.0)

---

## Feedback

**How to influence roadmap**:
1. GitHub Issues: Feature requests, bug reports
2. False positive reports: Help improve rule accuracy
3. Pull requests: Code contributions welcome

---

## Related Documents

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development workflow
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration guide
- [INSTALLING.md](INSTALLING.md) - Installation guide
- [CHANGELOG.md](CHANGELOG.md) - Release history
