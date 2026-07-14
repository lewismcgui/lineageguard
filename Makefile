.PHONY: install check test test-unit test-integration test-datahub lint format type demo datahub-preflight datahub-up seed-datahub serve

install:
	uv sync --all-extras

check: lint type test-unit

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check --fix .
	uv run ruff format .

type:
	uv run mypy src

test:
	uv run pytest --cov --cov-report=term-missing

test-unit:
	uv run pytest -m "not integration and not datahub" --cov --cov-report=term-missing

test-integration:
	uv run pytest -m integration

test-datahub:
	uv run pytest -m datahub

datahub-preflight:
	./scripts/datahub-preflight.sh

datahub-up:
	./scripts/datahub-up.sh

seed-datahub:
	uv run python scripts/seed-datahub-demo.py

demo:
	./scripts/demo.sh

serve:
	uv run lineageguard serve
