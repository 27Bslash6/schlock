# Contributing to schlock

## Development Setup

```bash
# Clone repository
git clone https://github.com/27Bslash6/schlock.git
cd schlock

# Install development dependencies (uv recommended)
uv pip install -e ".[dev]"

# Install pre-commit hooks (required)
uv pip install pre-commit
pre-commit install

# Run tests
uv run pytest
```

## Project Structure

```
schlock/
├── src/schlock/
│   ├── core/                # Validation engine
│   │   ├── parser.py        # Bashlex AST parsing
│   │   ├── rules.py         # Security rule engine
│   │   ├── validator.py     # Main validation pipeline
│   │   └── cache.py         # Thread-safe LRU cache
│   ├── integrations/        # Optional features
│   │   ├── audit.py         # Audit logging
│   │   ├── commit_filter.py # Advertising blocker
│   │   └── shellcheck.py    # ShellCheck integration
│   ├── setup/               # Configuration utilities
│   │   ├── wizard.py        # Setup wizard
│   │   ├── config_writer.py # Config generation
│   │   └── env_detector.py  # Environment detection
│   └── exceptions.py        # Custom exceptions
├── hooks/                   # Claude Code hooks
│   └── pre_tool_use.py      # Safety validation entry point
├── data/
│   ├── rules/               # Security rules (multi-file)
│   ├── commit_filter_rules.yaml
│   └── safety_rules.yaml
├── tests/                   # 821 tests
└── .claude-plugin/          # Plugin manifest
```

## Development Workflow

1. **Create feature branch**: `git checkout -b feature/your-feature`
2. **Make changes**: Follow coding standards below
3. **Run tests**: `uv run pytest` (must pass)
4. **Update docs**: If adding features
5. **Submit PR**: Target `main` branch

## Coding Standards

### Code Formatting

**Use pre-commit hooks** (industry standard for automatic formatting):

```bash
# Install hooks (already done if you ran setup)
pre-commit install

# Format manually
uv run ruff format .
```

**Note**: schlock's built-in formatter feature is **non-functional** in v0.1.0 because Claude Code does not support PostToolUse hooks for plugins. The `/schlock:setup` wizard only configures the advertising blocker. Use standard pre-commit hooks for code formatting.

### Python Style

- **Formatter**: `ruff format` (enforced via pre-commit)
- **Linter**: `ruff check` (0 warnings required)
- **Type hints**: Required for all public APIs
- **Docstrings**: Required for all modules, classes, public functions

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Python modules | `snake_case.py` | `commit_filter.py` |
| Hook handlers | `pre_tool_use.py` | |
| Slash commands | `schlock-[command].md` | `schlock-setup.md` |
| Test files | `test_[module].py` | `test_validator.py` |
| Classes/Types | `PascalCase` | `ValidationResult` |
| Functions/Methods | `snake_case` | `validate_command` |
| Constants | `UPPER_SNAKE_CASE` | `RISK_LEVEL` |
| Private members | `_leading_underscore` | `_cache` |

### Code Size Guidelines

- **File size**: Max 500 lines, target 200-300
- **Function size**: Max 50 lines, target 10-20
- **Class methods**: Max 10 public methods, target 3-5
- **Nesting depth**: Max 3 levels, target 1-2 (guard clauses preferred)

### Testing Philosophy

**Test what matters**: Focus on runtime security components.

- **Core security modules**: 90%+ coverage (parser, rules, validator, cache, commit_filter)
- **Wizard modules**: Unit tests for core logic, manual QA for interactive flows
- **Target**: ~88% overall coverage (honest, maintainable)

**No test theater**: Tests verify real behavior, not code coverage for its own sake.

### Test Organization

```python
# Unit tests: tests/test_<module>.py
# Integration tests: tests/test_hook_integration.py
# Benchmarks: tests/test_benchmarks.py
```

### Running Tests

```bash
# Full suite
uv run pytest

# Specific module
uv run pytest tests/test_validator.py -v

# Coverage report
uv run pytest --cov=src/schlock --cov-report=html
open htmlcov/index.html

# Benchmarks
uv run pytest tests/test_benchmarks.py -v -s
```

## Adding Security Rules

Rules are organized by category in `data/rules/`:

```
00_whitelist.yaml       # Safe commands
01_privilege_escalation.yaml
02_file_destruction.yaml
03_credential_theft.yaml
...
```

Add rules to the appropriate category file:

```yaml
rules:
  - name: rule-name
    description: What this rule detects
    risk_level: BLOCKED  # BLOCKED, HIGH, MEDIUM, LOW, SAFE
    patterns:
      - 'regex pattern'
    alternatives:
      - 'Suggested safe alternative'
```

**Risk levels**:
- **BLOCKED**: Always deny (rm -rf /, chmod 000)
- **HIGH**: Prompt user (git push --force, chmod 777)
- **MEDIUM**: Log only (curl | sh, eval)
- **LOW**: Informational (dd, find /)
- **SAFE**: Explicitly safe

**Testing new rules**:

```python
# Add test to tests/test_dangerous_commands.py
def test_new_rule():
    result = validate_command("dangerous command")
    assert not result.allowed
    assert result.risk_level == RiskLevel.BLOCKED
```

## Module Boundaries

**`core/`** — Validation engine (runtime-critical):
- `parser.py`: Bashlex AST parsing
- `rules.py`: Security rule engine
- `validator.py`: Main validation pipeline
- `cache.py`: Thread-safe LRU cache

**`integrations/`** — Optional features:
- `audit.py`: JSONL audit logging
- `commit_filter.py`: Advertising blocker
- `shellcheck.py`: ShellCheck integration

**`setup/`** — Configuration utilities:
- `wizard.py`: Interactive setup
- `config_writer.py`: YAML generation
- `env_detector.py`: Environment detection

**Dependency rule**: Lower layers never import from higher layers.

```
hooks/ → integrations/ → core/ → external (bashlex, pyyaml)
              ↓
           setup/
```

## Performance Guidelines

**Targets** (enforced via benchmarks):
- Cache hits: < 0.1ms
- Simple command parsing: < 1ms
- Complex command parsing: < 5ms
- Rule matching (40 rules): < 2ms
- Full validation (cold): < 15ms
- Cached validation: < 0.5ms
- Bulk throughput: ~100 validations/sec

**Cache design**:
- Thread-safe LRU with OrderedDict
- Default max_size: 1000
- No TTL (commands don't change)

## Release Process

1. **Update version**: `pyproject.toml` (semver: 0.x.y)
2. **Update CHANGELOG**: Document changes
3. **Run full test suite**: `make test`
4. **Tag release**: `git tag v0.x.y`
5. **Push to marketplace**: Claude Code auto-installs

## Questions?

- **GitHub Issues**: Bug reports, feature requests
- **Discussions**: Design questions, usage help
- **Security**: security@27b.io (for vulnerabilities)

## License

WTFPL - See LICENSE file.
