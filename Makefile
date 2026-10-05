# CodeKavach task runner. CI calls the same targets, so local results match CI results.
#
# Why a Makefile and not a justfile: make is already present on macOS (GNU make 3.81) and on
# every Linux CI runner, whereas just would be one more tool to install before the first command
# works. Windows contributors use the devcontainer (E01-29) or WSL2. This is a developer-
# convenience choice, not an architectural one, so it has no ADR; do not re-open it without one.
#
# Rules: stay compatible with GNU make 3.81 (no .ONESHELL, no grouped targets, no $(file ...));
# every recipe goes through uv run; logic belongs in tools/dev/ where it can be tested; check never
# rewrites files; clean deletes only named build and cache artefacts and never touches .venv/,
# .codekavach/, vaults or ledgers. Later issues add: changelog-draft (E01-22),
# docs-check (E01-23), licences (E01-30), telemetry-check (E01-31).

.DEFAULT_GOAL := help
PYTEST_ARGS ?=

.PHONY: help setup fmt fmt-check lint type contracts test test-unit test-integration test-e2e \
	test-privacy cov check lock-check build adr clean hooks hooks-update schemas schemas-check \
	changelog-draft changelog-check

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "} {printf "  %-18s %s\n", $$1, $$2}'

setup: ## Create the development environment and install git hooks
	uv sync --all-extras
	uv run pre-commit install

fmt: ## Format code and apply safe lint fixes
	uv run ruff format .
	uv run ruff check --fix .

fmt-check: ## Check formatting without changing files
	uv run ruff format --check .

lint: ## Run the linter
	uv run ruff check .

type: ## Run mypy in strict mode
	uv run mypy

contracts: ## Check the import contracts
	uv run lint-imports

test: ## Run the test suite (narrow it with PYTEST_ARGS="...")
	uv run pytest $(PYTEST_ARGS)

test-unit: ## Run the unit tier
	uv run pytest -m unit $(PYTEST_ARGS)

test-integration: ## Run the integration tier
	uv run pytest -m integration $(PYTEST_ARGS)

test-e2e: ## Run the end-to-end tier
	uv run pytest -m e2e $(PYTEST_ARGS)

test-privacy: ## Run the privacy invariant tier
	uv run pytest -m privacy $(PYTEST_ARGS)

cov: ## Run the tests with branch coverage (terminal, XML and HTML reports)
	uv run pytest --cov --cov-report=term-missing --cov-report=xml --cov-report=html $(PYTEST_ARGS)

check: fmt-check lint type contracts test ## Run every gate CI runs, stopping at the first failure

hooks: ## Run every pre-commit hook on all files
	uv run pre-commit run --all-files --show-diff-on-failure

hooks-update: ## Update pre-commit hook revisions to their latest tags
	uv run pre-commit autoupdate

schemas: ## Re-export the JSON Schemas of the core models into docs/schemas
	uv run python -m codekavach.core.models.export

schemas-check: ## Check docs/schemas for drift and the models for missing migration steps
	uv run python -m codekavach.core.models.export --check --check-migrations

lock-check: ## Check that uv.lock matches pyproject.toml
	uv lock --check

changelog-draft: ## Print the upcoming changelog section; changes no file
	uv run towncrier build --draft --version Unreleased

changelog-check: ## Check the names of the changelog fragments
	uv run python tools/dev/check_changelog_fragments.py

build: ## Build the wheel and the sdist
	uv build

adr: ## Create the next ADR: make adr title="Title of decision"
	@if [ -z "$(title)" ]; then echo "usage: make adr title=\"Title of decision\"" >&2; exit 2; fi
	uv run python tools/dev/new_adr.py "$(title)"

clean: ## Remove build artefacts and tool caches
	rm -rf dist build htmlcov coverage.xml .coverage .coverage.* .pytest_cache .mypy_cache .ruff_cache .hypothesis .import_linter_cache
