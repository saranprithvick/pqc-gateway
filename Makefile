.PHONY: setup test smoke

# Point liboqs-python at the project-local liboqs build for every target.
# This is picked up at Python import time by oqs/oqs.py (OQS_INSTALL_PATH search).
OQS_INSTALL_PATH := $(abspath .oqs)
export OQS_INSTALL_PATH

setup:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	OQS_INSTALL_PATH=$(OQS_INSTALL_PATH) .venv/bin/pip install -e ".[dev]"
	.venv/bin/pip freeze > requirements.lock

test:
	.venv/bin/pytest

smoke:
	.venv/bin/pytest tests/test_smoke.py -v -s
