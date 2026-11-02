.PHONY: setup test smoke

setup:
	python -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -e ".[dev]"
	.venv/bin/pip freeze > requirements.lock

test:
	.venv/bin/pytest

smoke:
	.venv/bin/pytest tests/test_smoke.py -v
