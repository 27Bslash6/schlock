# schlock Product Roadmap

*Last Updated: 2025-11-07*

This roadmap outlines the evolution of schlock from initial release (v0.1.0) through future enhancements. Priorities are driven by user feedback and real-world usage patterns.

---

## Current Status: v0.1.0 (Release Candidate)

**Status**: Feature-complete. Specs 1-7 implemented (53 tasks). Spec 8 (Testing & Documentation) in progress.

**Core Capabilities**:
- ✅ Safety validation (40 rules, bashlex AST parsing)
- ✅ Audit logging (JSONL format, always-on)
- ✅ Claude advertising blocker (optional, recommended)
- ✅ Hook integration (pre_tool_use)
- ✅ Setup wizard (`/schlock:setup` - configures ad blocker only)
- ✅ Manual validation (`/schlock:validate`, `safety-validator` skill)
- ✅ Layered configuration (plugin → user → project)

**Known Limitations**:
- **Code formatter integration**: Non-functional in v0.1.0. Claude Code does not support PostToolUse hooks for plugins. Use [pre-commit hooks](https://pre-commit.com/) for code formatting (industry standard). Formatter code remains in codebase for potential future compatibility.

---

## Release Strategy

### Phase 1: Initial Release (v0.1.x) - **CURRENT**

**Goal**: Get schlock into users' hands. Validate core value proposition.

#### v0.1.0 - Initial Release (Q4 2024)
- [x] Core safety validation with 40 security rules
- [x] Claude advertising blocker (optional)
- [x] Code formatter system (optional)
- [x] Interactive setup wizard
- [ ] 90%+ test coverage
- [ ] Complete documentation
- [ ] CI/CD pipeline

**Success Criteria**: 100+ installations, <5% false positive rate, >95% installation success

#### v0.1.1-0.1.5 - Stabilization (Q1 2025)
**Focus**: Bug fixes, performance tuning, documentation improvements

**Candidates for 0.1.x**:
- Additional safety rules based on user reports
- Performance optimizations (cache tuning, parsing efficiency)
- Documentation clarifications
- Windows/PowerShell edge cases
- Installation reliability improvements

**Trigger**: User feedback reveals bugs or usability issues

---

### Phase 2: Quality & Community (v0.2.x) - **NEXT**

**Goal**: Improve accuracy, build community feedback loops, enable team adoption.

#### v0.2.0 - False Positive Management (Q1 2025)
**Priority**: HIGH (false positives kill trust)

**Features**:
- False positive feedback system
  - GitHub issue template for structured reports
  - `/schlock-report-fp` command for quick feedback
  - Automatic command/rule context capture
  - Link to GitHub issue creation with pre-filled data
- Rule refinement based on feedback
  - Quarterly review of false positive reports
  - Rule accuracy improvements
  - Documentation of edge cases
- Enhanced rule documentation
  - Rationale for each rule
  - Known false positive scenarios
  - Suggested workarounds

**Success Criteria**: <3% false positive rate, 50+ feedback submissions, 80% of reports actionable

**Development Time**: 2-3 weeks

#### v0.2.1 - Ruleset Versioning Foundation (Q1 2025)
**Priority**: MEDIUM (enables future auto-updates)

**Features**:
- Versioned ruleset format (`data/safety_rules.yaml` schema v2)
- Version tracking in config
- Migration path documentation
- Breaking change policy
- Ruleset compatibility checks

**Success Criteria**: Clean upgrades with no config breakage

**Development Time**: 1-2 weeks

#### v0.2.2 - Team Adoption Enhancements (Q2 2025)
**Priority**: MEDIUM (organizational value)

**Features**:
- Team policy templates (conservative, moderate, permissive)
- Organization-level config examples
- Shared rule library documentation
- Best practices guide for team deployment
- Validation audit logs for compliance

**Success Criteria**: 20+ organizations enable auto-install

**Development Time**: 2-3 weeks

---

### Phase 3: Intelligence & Automation (v0.3.x - v0.5.x)

**Goal**: Learn from usage patterns, improve accuracy dynamically, enable advanced workflows.

#### v0.3.0 - Anonymous Telemetry (Q2 2025) ⚠️ Privacy-First
**Priority**: MEDIUM (data-driven improvements)

**Features**:
- Opt-in telemetry system
  - Rule trigger frequency (no command content)
  - Performance metrics (validation timing, cache hit rates)
  - Override patterns (which rules users bypass most)
  - Tool/shell distribution (bash, zsh, fish, etc.)
- Privacy guarantees
  - Zero command content collection
  - Hashed/anonymized identifiers
  - Local-first processing
  - Clear opt-in consent flow
- Analytics dashboard (public aggregate stats)
  - Most triggered rules
  - Common false positive patterns
  - Performance benchmarks by platform

**Success Criteria**: >30% opt-in rate, clear privacy policy, zero sensitive data leaks

**Development Time**: 3-4 weeks

**Blockers**: Legal review, privacy policy, data retention policy

#### v0.4.0 - Automatic Ruleset Updates (Q3 2025)
**Priority**: MEDIUM (stay current with threats)

**Features**:
- Ruleset update mechanism
  - `/schlock-update-rules` command
  - Check for new rule versions
  - Preview changes before applying
  - Explicit opt-in (never auto-apply)
- Versioned rule distribution
  - Semantic versioning for rulesets
  - Breaking change notifications
  - Rollback capability
- Update notifications
  - Alert when new rulesets available
  - Changelog display in CLI
  - Critical security update flagging

**Success Criteria**: >50% of users update within 30 days of release, zero breaking changes

**Development Time**: 2-3 weeks

**Dependencies**: v0.2.1 (versioning foundation)

#### v0.5.0 - Adaptive Rules (Q3-Q4 2025)
**Priority**: LOW (experimental)

**Features**:
- Machine learning for context-aware validation
  - Learn from user override patterns
  - Project-specific risk profiles
  - Adaptive thresholds based on user behavior
- Smart suggestions
  - Safer alternative commands
  - Context-aware warnings
  - Personalized risk explanations

**Success Criteria**: 20% reduction in false positives through adaptation

**Development Time**: 6-8 weeks

**Blockers**: Requires telemetry data (v0.3.0), complex ML pipeline

---

### Phase 4: Ecosystem & Scale (v1.x+) - **FUTURE**

**Goal**: Platform maturity, ecosystem integration, enterprise features.

#### v1.0.0 - Production Hardening (2026)

**Maturity Goals**:
- 500+ active installations
- <2% false positive rate
- 100ms p99 validation latency
- 100% backwards compatibility guarantee
- Enterprise support tier available

**Features**:
- Advanced rule engine (multi-command analysis)
- Cross-shell support (zsh, fish, PowerShell)
- Integration API for other AI coding tools
- Performance optimizations for large codebases
- Comprehensive audit logging

**Success Criteria**: 1000+ GitHub stars, stable API, production adoption by 50+ organizations

#### v1.1.0 - Community Rules Marketplace (2026+)
**Priority**: TBD (validate demand first)

**Features**:
- Domain-specific rule libraries
  - Docker/container security rules
  - Kubernetes/cloud rules
  - Database operation rules
  - Web development rules
- Community contribution system
  - Rule submission workflow
  - Peer review process
  - Trust scoring system
  - Version management
- Marketplace infrastructure
  - Rule discovery/search
  - Installation from marketplace
  - Automatic updates for subscribed rulesets
  - Rating/feedback system

**Success Criteria**: 50+ community-contributed rules, 200+ marketplace users

**Development Time**: 8-12 weeks

**Blockers**: Requires governance model, moderation resources, liability framework

#### v1.2.0 - Standalone PyPI Package (2026+)
**Trigger**: 10+ GitHub issues requesting standalone usage with proven use cases

**Features**:
- Extract core validation engine to `pip install schlock`
- Standalone CLI: `schlock validate "command"`
- Python API for programmatic usage
- Plugin depends on PyPI package
- CI/CD integration guides

**Success Criteria**: 1000+ PyPI downloads/month, 5+ third-party integrations

**Development Time**: 4-6 weeks

---

## Future Vision (2027+)

### LLM Safety Platform

Transform schlock into comprehensive AI coding assistant safety:

**Expanded Validation**:
- Code suggestions (beyond commands)
- File operations (read/write/delete)
- API calls and network requests
- Environment variable access
- Multi-AI-tool support (Copilot, Cursor, Windsurf, etc.)

**Enterprise Features**:
- Centralized policy management
- Team dashboards and analytics
- Real-time monitoring across organizations
- Compliance reporting (SOC2, ISO27001)
- SSO/SAML integration

**Intelligence Layer**:
- Anomaly detection (unusual command patterns)
- Risk profiling by AI model
- Historical trend analysis
- Predictive threat modeling

**Ecosystem Integration**:
- Security scanning tools (Semgrep, Snyk)
- SIEM integration
- Incident response workflows
- Threat intelligence feeds

---

## Deferred / Not Planned

**Why Not Now**:
- **Freemium Model**: Wait for enterprise demand signals
- **Web Dashboard**: CLI-first approach sufficient for v1.x
- **Mobile App**: No use case identified
- **Browser Extension**: Scope creep, maintenance burden
- **Real-time Collaboration**: Complex, unclear value

**Revisit When**: User requests + proven demand + clear ROI

---

## Decision Framework

### Feature Prioritization

**High Priority** (ship next minor version):
- Blocks v1.0 release
- Addresses false positives
- Improves user trust
- Clear user demand (10+ requests)

**Medium Priority** (ship within 6 months):
- Enhances existing workflows
- Enables team adoption
- Proven value from competitors
- Moderate user demand (5-10 requests)

**Low Priority** (research/experiment):
- Speculative value
- Complex implementation
- Unclear ROI
- Low user demand (<5 requests)

**Not Planned**:
- No clear use case
- Scope creep risk
- Maintenance burden > value
- Better solved by third parties

### Trigger Conditions

**Version Bump Triggers**:
- **Patch (0.1.x)**: Bug fixes, documentation, performance
- **Minor (0.x.0)**: New features, backwards compatible
- **Major (x.0.0)**: Breaking changes, API redesign

**Implementation Triggers**:
- **User Demand**: 10+ GitHub issues/requests
- **Competition**: Competitor ships similar feature
- **Security**: Critical threat emerges
- **Compliance**: Regulatory requirement
- **Performance**: Latency/scale issues

---

## Feedback & Contributions

**How to Influence Roadmap**:
1. **GitHub Issues**: Feature requests, use case descriptions
2. **False Positive Reports**: Help improve rule accuracy
3. **Community Discussion**: Join GitHub Discussions
4. **Pull Requests**: Code contributions welcome

**Roadmap Updates**: Quarterly review based on user feedback, telemetry data (if opted in), and ecosystem changes.

---

## Appendix: Related Documents

## Appendix: Related Documents

- **Development Guide**: [docs/DEVELOPMENT.md](DEVELOPMENT.md)
- **Configuration Guide**: [docs/CONFIGURATION.md](CONFIGURATION.md)
- **Contributing Guide**: [docs/CONTRIBUTING.md](CONTRIBUTING.md)
- **Installation Guide**: [docs/INSTALLING.md](INSTALLING.md)
