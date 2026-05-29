.PHONY: test lint install run clean help

help:
	@echo "Available targets:"
	@echo "  install  — create venv and install dependencies"
	@echo "  test     — run pytest"
	@echo "  lint     — run ruff linter"
	@echo "  run      — analyze sample logs and write reports/"
	@echo "  clean    — remove __pycache__ and .pytest_cache"

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

test:
	python3 -m pytest tests/ -q

lint:
	python3 -m ruff check analyzer/ tests/ || true

run:
	python3 main.py --all-samples --output reports/incident_report.md
	python3 main.py --all-samples --format json --output reports/incident_report.json

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
