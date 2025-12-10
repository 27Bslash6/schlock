# Changelog

All notable changes to schlock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.6...schlock-v0.3.0) (2025-12-10)


### Features

* **parser:** enhance command name extraction and eval/exec detection ([#41](https://github.com/27Bslash6/schlock/issues/41)) ([edb2631](https://github.com/27Bslash6/schlock/commit/edb2631ead7e9d874089d394d67e1505338891e5))

## [0.2.6](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.5...schlock-v0.2.6) (2025-12-06)


### Bug Fixes

* allow safe command/process substitution patterns ([#38](https://github.com/27Bslash6/schlock/issues/38)) ([0f95ed4](https://github.com/27Bslash6/schlock/commit/0f95ed4fb36426e6900b01cb002e8a0da1c8889d))

## [0.2.5](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.4...schlock-v0.2.5) (2025-12-04)


### Bug Fixes

* **setup:** resolve module import failures on customer systems ([#34](https://github.com/27Bslash6/schlock/issues/34)) ([87de78f](https://github.com/27Bslash6/schlock/commit/87de78f1ac992e5a81f45945192186a077d6a4a8))

## [0.2.4](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.3...schlock-v0.2.4) (2025-12-03)


### Bug Fixes

* **security:** close P0 bypass vectors from security review ([#30](https://github.com/27Bslash6/schlock/issues/30)) ([e58f754](https://github.com/27Bslash6/schlock/commit/e58f7545ac0e65b3550af516bfe37030f7205c85))

## [0.2.3](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.2...schlock-v0.2.3) (2025-12-03)


### Bug Fixes

* add issues:write permission to labels workflow ([#27](https://github.com/27Bslash6/schlock/issues/27)) ([767e072](https://github.com/27Bslash6/schlock/commit/767e072d2b77fa4fc283a6062b5b84a65faa7f38))


### Performance Improvements

* cache RuleEngine and BashCommandParser to reduce latency 7x ([#29](https://github.com/27Bslash6/schlock/issues/29)) ([b7bb09c](https://github.com/27Bslash6/schlock/commit/b7bb09cd5adb028dcadca957beab659ffbc73b10))

## [0.2.2](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.1...schlock-v0.2.2) (2025-12-02)


### Bug Fixes

* prevent false positives in commit filter when message has whitespace ([#20](https://github.com/27Bslash6/schlock/issues/20)) ([d02f826](https://github.com/27Bslash6/schlock/commit/d02f826f7a841e2774444808a384499b57d88b18))

## [0.2.1](https://github.com/27Bslash6/schlock/compare/schlock-v0.2.0...schlock-v0.2.1) (2025-12-01)


### Bug Fixes

* **commit-filter:** add bashlex AST parsing with regex fallback ([#8](https://github.com/27Bslash6/schlock/issues/8)) ([e9d37c8](https://github.com/27Bslash6/schlock/commit/e9d37c89545d2cce6825638ec11a3725da95424a))


### Documentation

* enhance README and add ShellCheck integration details ([#15](https://github.com/27Bslash6/schlock/issues/15)) ([833c0a9](https://github.com/27Bslash6/schlock/commit/833c0a96059a00d937f66e95ae51bb253d4090e3))
* update documentation and restructure project layout ([#6](https://github.com/27Bslash6/schlock/issues/6)) ([0c83377](https://github.com/27Bslash6/schlock/commit/0c833771aa4ade5417ca1605e433781ad6f07823))
* update README badges for tests and coverage ([#16](https://github.com/27Bslash6/schlock/issues/16)) ([c9d7fc1](https://github.com/27Bslash6/schlock/commit/c9d7fc13af0ef6ee0e7e32048622954d3032ccb5))

## [0.2.0](https://github.com/27Bslash6/schlock/compare/schlock-v0.1.0...schlock-v0.2.0) (2025-11-28)


### Features

* initial release ([c5aa335](https://github.com/27Bslash6/schlock/commit/c5aa335d89dfaae0a93066b86f2543b4878b72cf))

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
