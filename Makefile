.PHONY: install install-all dev test lint format type-check build docs-build docs-serve clean run evaluate serve

install:
	pip install -e .

install-all:
	pip install -e ".[all]"

dev:
	pip install -e ".[maintainer]"

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=agent_security_sandbox --cov-report=term-missing

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

type-check:
	mypy src/agent_security_sandbox/

build:
	python -m build

docs-build:
	mkdocs build --strict

docs-serve:
	mkdocs serve

clean:
	rm -rf dist/ build/ site/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

run:
	asb run "Read email_001 and summarize it" --provider mock

evaluate:
	asb evaluate --benchmark data/mini_benchmark --defense D0 --provider mock

serve:
	asb serve
