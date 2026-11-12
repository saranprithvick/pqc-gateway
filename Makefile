.PHONY: setup test smoke bench

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

bench:
	@mkdir -p results/raw results/tables results/figures
	@echo "--- Micro-benchmarks ---"
	.venv/bin/python -m pqcgw.bench.micro
	@echo "--- End-to-end benchmarks ---"
	.venv/bin/python -m pqcgw.bench.e2e
	@echo "--- Analytical: bus_time ---"
	.venv/bin/python -m pqcgw.bench.analytical.bus_time
	@echo "--- Analytical: contact_window ---"
	.venv/bin/python -m pqcgw.bench.analytical.contact_window
	@echo "--- Analytical: beacon_cost ---"
	.venv/bin/python -m pqcgw.bench.analytical.beacon_cost
	@echo "--- Plots ---"
	.venv/bin/python scripts/make_plots.py
