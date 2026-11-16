PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest

.PHONY: all test eval demo paper clean

all: test eval demo paper

test:
	PYTHONPATH=. $(PYTEST) -v

eval:
	PYTHONPATH=. $(PYTHON) eval/benchmark.py

demo:
	PYTHONPATH=. $(PYTHON) demo.py

paper:
	cd paper && tectonic safeose27_report.tex

clean:
	rm -rf .pytest_cache build dist *.egg-info
