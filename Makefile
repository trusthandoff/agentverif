.PHONY: test lint

test:
	.venv/bin/python -m pytest tests/ -v --tb=short

lint:
	.venv/bin/python -m ruff check src/ api/ mcp/
