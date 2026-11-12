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
# docs-check (E01-23), licences (E01-30), telemetry-check (E01-31), prepush (E01-34).

.DEFAULT_GOAL := help
PYTEST_ARGS ?=

.PHONY: help setup fmt fmt-check lint type contracts test test-unit test-integration test-e2e \
	test-privacy cov perf check lock-check build adr clean hooks hooks-update schemas schemas-check licences telemetry-check \
	changelog-draft changelog-check docs-check claims prepush

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

# Coverage tracing slows the code the performance budgets time (E01-34: two budgets failed under
# make cov on a clean Linux machine), so cov uses the factor CI uses unless one is already set.
cov: ## Run the tests with branch coverage (terminal, XML and HTML reports)
	CODEKAVACH_PERF_FACTOR=$${CODEKAVACH_PERF_FACTOR:-3.0} uv run pytest --cov --cov-report=term-missing --cov-report=xml --cov-report=html $(PYTEST_ARGS)

# The budgets are timed without coverage: tracing made CPU-bound code 6 to 7 times slower on the
# Linux runners (detect 31 ms to 215 ms, classification 15 ms to 84 ms, 2026-11-05 and 2026-11-07),
# well past the factor of 3. CI runs this after the coverage step, which deselects perf.
perf: ## Run the performance budget tests without coverage (factor 3.0 unless one is set)
	CODEKAVACH_PERF_FACTOR=$${CODEKAVACH_PERF_FACTOR:-3.0} uv run pytest -m "perf and not network" $(PYTEST_ARGS)

check: fmt-check lint type contracts test ## Run every gate CI runs, stopping at the first failure

hooks: ## Run every pre-commit hook on all files
	uv run pre-commit run --all-files --show-diff-on-failure

hooks-update: ## Update pre-commit hook revisions to their latest tags
	uv run pre-commit autoupdate

schemas: ## Re-export the JSON Schemas of the core models into docs/schemas
	uv run python -m codekavach.core.models.export

schemas-check: ## Check docs/schemas for drift and the models for missing migration steps
	uv run python -m codekavach.core.models.export --check --check-migrations

telemetry-check: ## Check uv.lock for telemetry packages against the deny list in pyproject.toml
	uv run python tools/dev/check_no_telemetry.py

licences: ## Check dependency licences against the policy in pyproject.toml (E01-30)
	uv run python tools/dev/check_licences.py

lock-check: ## Check that uv.lock matches pyproject.toml
	uv lock --check

docs-check: ## Check Markdown links, anchors and style offline, and the ADR index
	uv run python tools/dev/check_docs.py
	uv run python tools/dev/new_adr.py --check

claims: ## List lines with claim words for review: make claims files="README.md docs/PLAN.md"
	@if [ -z "$(files)" ]; then echo "usage: make claims files=\"README.md docs/PLAN.md\"" >&2; exit 2; fi
	uv run python tools/dev/check_docs.py --claims $(files)

changelog-draft: ## Print the upcoming changelog section; changes no file
	uv run towncrier build --draft --version Unreleased

changelog-check: ## Check the names of the changelog fragments
	uv run python tools/dev/check_changelog_fragments.py

# The six parts run one after another in the documented order, even under make -j: the hooks can
# rewrite files that check reads, and a failure should name the first broken gate.
.NOTPARALLEL: prepush
prepush: check hooks docs-check changelog-check licences telemetry-check ## Run check, hooks, docs-check, changelog-check, licences and telemetry-check in that order

build: ## Build the wheel and the sdist
	uv build

adr: ## Create the next ADR: make adr title="Title of decision"
	@if [ -z "$(title)" ]; then echo "usage: make adr title=\"Title of decision\"" >&2; exit 2; fi
	uv run python tools/dev/new_adr.py "$(title)"

clean: ## Remove build artefacts and tool caches
	rm -rf dist build htmlcov coverage.xml .coverage .coverage.* .pytest_cache .mypy_cache .ruff_cache .hypothesis .import_linter_cache

# --- E39-02: container image, compose stack, Helm chart and air-gapped bundle ----------------
# These recipes drive docker and helm, which are not Python tools, so they do not go through uv.
.PHONY: images up down logs bundle helm-lint
IMAGE ?= codekavach:local

images: ## Build the server image (dashboard, API, CLI): make images IMAGE=codekavach:local
	docker build -f deploy/docker/Dockerfile -t $(IMAGE) \
		--build-arg REVISION=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown) .

up: ## Start the local stack with docker compose and print the dashboard URL
	docker compose up -d --build codekavach
	@echo "dashboard: http://127.0.0.1:$${CODEKAVACH_PORT:-8080}  (user admin)"

down: ## Stop the local stack; the data volume is kept
	docker compose down

logs: ## Follow the server log of the local stack
	docker compose logs -f codekavach

bundle: ## Build the air-gapped bundle in deploy/bundle/out
	deploy/bundle/build-bundle.sh --image $(IMAGE)

helm-lint: ## Lint and render the Helm chart
	helm lint deploy/helm/codekavach
	helm template codekavach deploy/helm/codekavach > /dev/null
