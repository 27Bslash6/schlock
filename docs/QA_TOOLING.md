# QA Tooling Guide

This document describes the quality assurance tooling for the schlock project.

## Overview

schlock uses modern Python QA tools to ensure code quality, security, and correctness:

- **Ruff** - Fast linter, formatter, and security scanner (replaces flake8, black, isort, bandit)
- **pytest** - Testing framework with coverage
- **basedpyright** - Fast type checker (faster than mypy)
- **pre-commit** - Git hook automation

## Quick Start

```bash
# Install development dependencies
make dev

# Install pre-commit hooks
make pre-commit-install

# Run quick checks
make quick
```

## Makefile Commands

### Development Setup
- `make dev` - Install in development mode with all dependencies
- `make install` - Install in production mode
- `make pre-commit-install` - Install git hooks

### Testing
- `make test` - Run all tests
- `make test-coverage` - Run tests with coverage report
- `make test-dangerous` - Run dangerous command tests only
- `make test-fast` - Run quick tests (no slow markers)

### Code Quality
- `make lint` - Check code with ruff
- `make lint-fix` - Auto-fix linting issues
- `make format` - Format code with ruff
- `make check` - Run all checks (lint + format + type)

### Shortcuts
- `make quick` - Quick dev check (fix, format, fast tests)
- `make all` - Run all checks and tests
- `make verify` - Clean and verify everything

### Pre-commit
- `make pre-commit-run` - Run hooks on all files
- `make pre-commit-update` - Update hook versions

## Pre-commit Hooks

Hooks run automatically on `git commit`:

1. **Ruff** - Lint, format, and security scan Python code (includes S rules from bandit)
2. **Standard checks** - YAML, JSON, merge conflicts, secrets
3. **basedpyright** - Fast type checking
4. **Conventional commits** - Enforce commit message format

### Bypassing Hooks

```bash
# Skip all hooks (use sparingly!)
git commit --no-verify

# Skip specific hooks
SKIP=basedpyright git commit
SKIP=ruff git commit
```

## Configuration

### Ruff (`pyproject.toml`)
- Line length: 129
- Target: Python 3.8+
- Includes security rules (S prefix - bandit equivalent)
- Ignores intentional design patterns (B904, PERF203, etc.)

### pytest (`pyproject.toml`)
- Test directory: `tests/`
- Coverage source: `src/schlock`
- Strict markers and config

### basedpyright (`pyproject.toml`)
- Type checking mode: standard
- Python version: 3.8
- Includes src, tests, hooks, commands, skills

## CI/CD Targets

For continuous integration:

```bash
make ci           # Run all CI checks
make ci-test      # Tests with maxfail=5
make ci-lint      # Lint with GitHub output format
make ci-coverage  # Generate XML coverage report
```

## Test Coverage

Current core module coverage:

- **parser.py** - AST parsing and string literal extraction
- **rules.py** - Rule engine and pattern matching
- **validator.py** - Command validation with AST context
- **test_dangerous_commands.py** - 116/116 tests passing (100%)

Generate coverage report:

```bash
make test-coverage
open htmlcov/index.html
```

## Workflow Examples

### Before Committing

```bash
# Quick check and auto-fix
make quick

# Full verification
make all
```

### Adding New Code

```bash
# 1. Write code
vim src/schlock/new_feature.py

# 2. Write tests
vim tests/test_new_feature.py

# 3. Format and lint
make format
make lint-fix

# 4. Run tests
make test

# 5. Commit (hooks run automatically)
git add .
git commit -m "feat: add new feature"
```

### Debugging Test Failures

```bash
# Verbose output
make test-verbose

# Single test file
pytest tests/test_specific.py -v

# Single test function
pytest tests/test_file.py::test_function -v

# With debugger
pytest tests/test_file.py::test_function --pdb
```

## Known Issues

- **Wizard/config files** - Some lint warnings in setup wizard code (non-critical, not part of core validation)
- **Hook integration tests** - Expected failures (testing old API that was intentionally replaced)
- **Pattern coverage tests** - Some skipped tests for future features

Core validation system (parser, rules, validator) has **zero lint errors** and **100% test pass rate**.

## Best Practices

1. **Run `make quick` before committing** - Catches most issues fast
2. **Let pre-commit fix things** - Hooks auto-format and fix many issues
3. **Don't skip type checking** - mypy catches subtle bugs
4. **Write tests for new features** - Maintain 100% pass rate
5. **Use conventional commits** - Enables automatic changelog generation

## Troubleshooting

### Pre-commit hooks fail

```bash
# Update hooks
make pre-commit-update

# Run manually to see errors
make pre-commit-run
```

### Lint errors

```bash
# Auto-fix what's possible
make lint-fix

# Check what remains
make lint
```

### Test failures

```bash
# Run with more detail
make test-verbose

# Check specific test
pytest tests/test_file.py -vv --tb=short
```

## Resources

- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [pytest Documentation](https://docs.pytest.org/)
- [pre-commit Documentation](https://pre-commit.com/)
- [Conventional Commits](https://www.conventionalcommits.org/)
