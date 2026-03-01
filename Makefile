.PHONY: install dev test lint format build clean run evaluate serve

install:
	pip install -e .

dev:
	pip install -e ".[all]"

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

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

run:
	asb run "Read email_001 and summarize it" --provider mock

evaluate:
	asb evaluate --benchmark data/mini_benchmark --defense D0 --provider mock

serve:
	asb serve
