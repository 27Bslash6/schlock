# Development Guide

## Testing

```bash
# Run all tests
uv run pytest

# With coverage
uv run pytest --cov=src/schlock --cov-report=html

# Specific test file
uv run pytest tests/test_commit_filter.py -v

# Test plugin locally
/plugin marketplace add /path/to/schlock
/plugin install schlock@local
```

## Development Commands

```bash
# Install development dependencies
uv pip install -e ".[dev]"

# Run linter
uv run ruff check src/ tests/

# Format code
uv run ruff format src/ tests/

# Type check
uv run mypy src/
```

## Naming Conventions

### Files
- **Python modules**: `snake_case.py`
- **Hook handlers**: `pre_tool_use.py`
- **Slash commands**: `schlock-[command].md`
- **Test files**: `test_[module].py`

### Code
- **Classes/Types**: `PascalCase`
- **Functions/Methods**: `snake_case`
- **Constants**: `UPPER_SNAKE_CASE`
- **Variables**: `snake_case`
- **Private members**: `_leading_underscore`

## Code Size Guidelines

- **File size**: Max 500 lines, target 200-300
- **Function size**: Max 50 lines, target 10-20
- **Class methods**: Max 10 public methods, target 3-5
- **Nesting depth**: Max 3 levels, target 1-2 (guard clauses preferred)

## Module Boundaries

**Package Structure (src/schlock/)**:
- `core/` - Validation engine (parser, rules, validator, cache)
- `integrations/` - Optional features (audit, commit_filter, shellcheck)
- `setup/` - Configuration utilities (config_writer, wizard, env_detector)

**Core**: Plugin-agnostic validation engine
- Can be imported independently
- No Claude Code dependencies
- Reusable in future PyPI package (if demand emerges)

**Plugin Infrastructure (hooks/, skills/, commands/)**: Claude Code integration
- Depends on core
- Claude Code specific
- Cannot be used outside plugin context

### Dependencies Direction

```
Layer 4: Plugin Integration (hooks, skills, commands)
  ↓
Layer 3: Orchestration (schlock.core.validator, schlock.integrations.*)
  ↓
Layer 2: Core Components (schlock.core.parser, schlock.core.rules, schlock.core.cache)
  ↓
Layer 1: External Dependencies (bashlex, pyyaml)
```

**Rule**: Lower layers never import from higher layers. No circular dependencies.
