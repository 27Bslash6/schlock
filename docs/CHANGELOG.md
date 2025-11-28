# Changelog

All notable changes to schlock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-11-28

Initial release.

### Added

**Safety Validation Engine**
- 60+ security rules across 5 severity levels (BLOCKED, HIGH, MEDIUM, LOW, SAFE)
- Bashlex AST parser for accurate command structure analysis (not regex)
- Thread-safe LRU cache with <0.1ms cache hit performance
- Fail-safe design: denies on errors, parse failures, unknown risks
- Performance: <15ms validation, <0.5ms cached

**Risk Tolerance Presets**
- `permissive`: Only block critical threats (BLOCKED level)
- `balanced` (default): Prompt for HIGH-risk commands
- `paranoid`: Deny HIGH, prompt for MEDIUM
- Custom per-level configuration (allow/ask/deny)

**ShellCheck Integration**
- Optional static analysis via ShellCheck (if installed)
- Security-focused findings surfaced in validation
- Configurable in setup wizard

**Advertising Blocker**
- Blocks "Generated with Claude Code" spam in commits
- 3 pattern categories: signatures, co-authored footers, promotional variants
- Configurable per-project or per-user
- Default enabled

**Audit Logging**
- JSONL audit trail at `~/.config/schlock/audit.jsonl`
- Captures: timestamp, command, risk level, violations, decision, execution time
- Always enabled, fail-silent design
- Thread-safe concurrent writes
- Customizable location via `SCHLOCK_AUDIT_LOG` environment variable

**Setup & Commands**
- `/schlock:setup` — Interactive configuration wizard
- `/schlock:validate` — Manual command validation
- `safety-validator` skill for AI-assisted safety analysis

**Plugin Infrastructure**
- Claude Code plugin manifest
- Vendored dependencies: bashlex, pyyaml, platformdirs
- PreToolUse hook for validation
- Zero external dependencies at runtime
- Python 3.8+ support

**Documentation**
- README.md: Problem/solution narrative, installation, configuration
- CONFIGURATION.md: Power-user guide (risk presets, layered config, team setup)
- INSTALLING.md: Individual and team installation
- CONTRIBUTING.md: Development workflow

### Security

- No external network calls, all processing local
- No telemetry or usage tracking
- Fail-safe: exceptions → deny
- Thread-safe concurrent execution

**Rule Categories**:
- Privilege escalation (sudo, su, pkexec)
- File destruction (rm -rf, shred, find -delete)
- Credential exposure (env vars, SSH keys, cloud configs)
- Disk operations (dd, mkfs, fdisk)
- Code execution (eval, curl|sh, python -c)
- Network security (telnet, unencrypted transfers)
- Container security (docker --privileged, kubectl exec)
- Git safety (force push, hard reset, history rewriting)
- Cloud CLI (AWS, GCP, Azure destructive operations)

### Quality

- 821 tests, 90% coverage
- Core modules 95%+ coverage
- Performance benchmarks verified
- ReDoS protection on all regex patterns

---

## Installation

```bash
/plugin marketplace add 27Bslash6/schlock
/plugin install schlock@schlock
/schlock:setup
```

---

## Links

- [Repository](https://github.com/27Bslash6/schlock)
- [Issues](https://github.com/27Bslash6/schlock/issues)

[Unreleased]: https://github.com/27Bslash6/schlock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/27Bslash6/schlock/releases/tag/v0.1.0
