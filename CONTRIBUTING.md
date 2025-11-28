# Contributing to schlock

## Development Setup

```bash
# Clone repository
git clone https://github.com/27Bslash6/schlock.git
cd schlock

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (required)
pip install pre-commit
pre-commit install

# Run tests
make test
```

## Project Structure

```
schlock/
├── src/schlock/              # Core validation engine
│   ├── parser.py            # Bashlex AST parsing
│   ├── rules.py             # Security rule engine
│   ├── validator.py         # Main validation pipeline
│   ├── cache.py             # Thread-safe LRU cache
│   ├── audit.py             # Audit logging
│   ├── commit_filter.py     # Claude advertising blocker
│   ├── wizard.py            # Setup wizard
│   ├── config_writer.py     # Config generation
│   ├── exceptions.py        # Custom exceptions
│   └── env_detector.py      # Environment detection (unused in v0.1.0)
├── hooks/                   # Claude Code hooks
│   └── pre_tool_use.py      # Safety validation + audit logging
├── data/                    # Default configurations
│   ├── safety_rules.yaml    # Security rules
│   ├── commit_filter_rules.yaml # Advertising blocker patterns
│   └── formatting_tools.yaml# Formatter tool definitions (unused)
├── tests/                   # Test suite
└── .claude-plugin/          # Plugin manifest
```

## Development Workflow

1. **Create feature branch**: `git checkout -b feature/your-feature`
2. **Make changes**: Follow coding standards below
3. **Run tests**: `make test` (must pass)
4. **Update docs**: If adding features
5. **Submit PR**: Target `main` branch

## Coding Standards

### Code Formatting

**Use pre-commit hooks** (industry standard for automatic formatting):

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Format manually
ruff format .
```

**Note**: schlock's built-in formatter feature is **non-functional** in v0.1.0 because Claude Code does not support PostToolUse hooks for plugins. The `/schlock:setup` wizard only configures the advertising blocker. Use standard pre-commit hooks for code formatting.

### Python Style

- **Formatter**: `ruff format` (enforced via pre-commit)
- **Linter**: `ruff check` (0 warnings required)
- **Type hints**: Required for all public APIs
- **Docstrings**: Required for all modules, classes, public functions

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
make test

# Specific module
pytest tests/test_validator.py -v

# Coverage report
pytest --cov=src/schlock --cov-report=html
open htmlcov/index.html

# Benchmarks
pytest tests/test_benchmarks.py -v -s
```

## Adding Security Rules

Edit `data/safety_rules.yaml`:

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

**Risk level policy**:
- **BLOCKED**: Prevent execution (rm -rf /, sudo rm, chmod 000)
- **HIGH**: Warn but allow (git push --force, chmod 777)
- **MEDIUM**: Log but allow (curl | sh, wildcard expansions)
- **LOW**: Informational (dd, large finds)
- **SAFE**: Explicitly safe commands

**Testing new rules**:

```python
# Add test to tests/test_dangerous_commands.py
def test_new_rule():
    result = validate_command("dangerous command")
    assert not result.allowed
    assert result.risk_level == RiskLevel.BLOCKED
```

## Module Boundaries

**Core security modules** (runtime-critical):
- `parser.py`: Bashlex AST parsing, command extraction
- `rules.py`: Security rule engine, risk assessment
- `validator.py`: Main validation pipeline, caching
- `cache.py`: Thread-safe LRU cache
- `commit_filter.py`: Claude advertising blocker

**Wizard modules** (interactive, non-runtime):
- `wizard.py`: Setup wizard flow
- `config_writer.py`: YAML config generation
- `env_detector.py`: Environment detection (unused in v0.1.0)
- `exceptions.py`: Custom exceptions

**Design principle**: Core modules have zero wizard dependencies. Wizard modules may depend on core modules.

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
