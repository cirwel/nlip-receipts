PYTHON ?= .venv/bin/python
PIP ?= .venv/bin/pip
PYTEST ?= .venv/bin/pytest
SYS_PYTHON ?= python3

.PHONY: all setup test eval demo demo-http paper clean

all: test eval demo

setup:
	$(SYS_PYTHON) -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install pydantic fastapi uvicorn httpx pytest python-multipart \
		"nlip_sdk @ git+https://github.com/nlip-project/nlip_sdk.git" \
		"nlip-server @ git+https://github.com/nlip-project/nlip_server.git"
	$(PIP) install -e .

test:
	PYTHONPATH=. $(PYTEST) -v

eval:
	PYTHONPATH=. $(PYTHON) eval/benchmark.py
	PYTHONPATH=. $(PYTHON) eval/e2e_attacks.py

demo:
	PYTHONPATH=. $(PYTHON) demo.py

demo-http:
	PYTHONPATH=. $(PYTHON) demo.py --http

paper:
	cd paper && tectonic safeose27_report.tex

clean:
	rm -rf .pytest_cache build dist *.egg-info
