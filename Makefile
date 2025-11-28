# Makefile for schlock
# Python-based safety validation plugin for Claude Code

.PHONY: help install dev test test-verbose test-coverage lint format check clean build docs pre-commit-install pre-commit-run all

# Configuration
PYTHON := python3
PYTEST := pytest
RUFF := ruff
PYRIGHT := basedpyright
PRE_COMMIT := pre-commit

# Directories
SRC_DIR := src/schlock
TEST_DIR := tests
HOOKS_DIR := hooks
COMMANDS_DIR := commands
SKILLS_DIR := skills

# Color output
BOLD := \033[1m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

##@ General

help: ## Display this help
	@echo "$(BOLD)schlock - Claude Code Safety Validation Plugin$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(GREEN)<target>$(RESET)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BOLD)%s$(RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development Setup

install: ## Install package in production mode
	$(PYTHON) -m pip install .

dev: ## Install package in development mode with all dependencies
	$(PYTHON) -m pip install -e ".[dev,test]"
	@echo "$(GREEN)✓ Development environment ready$(RESET)"

pre-commit-install: ## Install pre-commit hooks
	$(PRE_COMMIT) install
	$(PRE_COMMIT) install --hook-type commit-msg
	@echo "$(GREEN)✓ Pre-commit hooks installed$(RESET)"

##@ Testing

test: ## Run all tests
	$(PYTEST) $(TEST_DIR) -v

test-verbose: ## Run tests with verbose output
	$(PYTEST) $(TEST_DIR) -vv --tb=short

test-fast: ## Run tests without slow markers
	$(PYTEST) $(TEST_DIR) -v -m "not slow"

test-dangerous: ## Run dangerous command tests only
	$(PYTEST) $(TEST_DIR)/test_dangerous_commands.py -v

test-coverage: ## Run tests with coverage report
	$(PYTEST) $(TEST_DIR) --cov=$(SRC_DIR) --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/index.html$(RESET)"

test-cov: test-coverage ## Alias for test-coverage

test-watch: ## Run tests in watch mode (requires pytest-watch)
	ptw $(TEST_DIR) -- -v

##@ Code Quality

lint: ## Run ruff linter
	$(RUFF) check $(SRC_DIR) $(TEST_DIR) $(HOOKS_DIR) $(COMMANDS_DIR) $(SKILLS_DIR)

lint-fix: ## Run ruff linter with auto-fix
	$(RUFF) check --fix $(SRC_DIR) $(TEST_DIR) $(HOOKS_DIR) $(COMMANDS_DIR) $(SKILLS_DIR)

format: ## Format code with ruff
	$(RUFF) format $(SRC_DIR) $(TEST_DIR) $(HOOKS_DIR) $(COMMANDS_DIR) $(SKILLS_DIR)
	$(RUFF) check --fix $(SRC_DIR) $(TEST_DIR) $(HOOKS_DIR) $(COMMANDS_DIR) $(SKILLS_DIR)

format-check: ## Check if code is formatted
	$(RUFF) format --check $(SRC_DIR) $(TEST_DIR) $(HOOKS_DIR) $(COMMANDS_DIR) $(SKILLS_DIR)

type-check: ## Run basedpyright type checker
	$(PYRIGHT) $(SRC_DIR)

security: ## Run ruff security checks (S rules)
	$(RUFF) check $(SRC_DIR) --select S

check: lint format-check type-check ## Run all checks (lint, format, type)
	@echo "$(GREEN)✓ All checks passed$(RESET)"

##@ Pre-commit

pre-commit-run: ## Run pre-commit hooks on all files
	$(PRE_COMMIT) run --all-files

pre-commit-update: ## Update pre-commit hooks
	$(PRE_COMMIT) autoupdate

##@ Build & Release

clean: ## Clean build artifacts and caches
	rm -rf build/ dist/ *.egg-info htmlcov/ .coverage .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "$(GREEN)✓ Cleaned build artifacts$(RESET)"

build: clean ## Build distribution packages
	$(PYTHON) -m build
	@echo "$(GREEN)✓ Distribution packages built in dist/$(RESET)"

##@ CI/CD Targets

ci-test: ## Run tests in CI mode
	$(PYTEST) $(TEST_DIR) -v --tb=short --maxfail=5

ci-lint: ## Run linting in CI mode
	$(RUFF) check $(SRC_DIR) $(TEST_DIR) --output-format=github

ci-format-check: ## Check formatting in CI mode
	$(RUFF) format --check $(SRC_DIR) $(TEST_DIR)

ci-coverage: ## Generate coverage report for CI
	$(PYTEST) $(TEST_DIR) --cov=$(SRC_DIR) --cov-report=xml --cov-report=term

ci: ci-lint ci-format-check type-check ci-coverage ## Run all CI checks
	@echo "$(GREEN)✓ All CI checks passed$(RESET)"

##@ Documentation

docs: ## Build documentation (placeholder)
	@echo "$(YELLOW)Documentation build not yet implemented$(RESET)"

docs-serve: ## Serve documentation locally (placeholder)
	@echo "$(YELLOW)Documentation serve not yet implemented$(RESET)"

##@ Shortcuts

all: check test ## Run all checks and tests
	@echo "$(GREEN)✓ All checks and tests passed$(RESET)"

quick: lint-fix format test-fast ## Quick development check (fix, format, fast tests)
	@echo "$(GREEN)✓ Quick checks passed$(RESET)"

verify: clean all ## Clean and verify everything
	@echo "$(GREEN)✓ Full verification complete$(RESET)"
