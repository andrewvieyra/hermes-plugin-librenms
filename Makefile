.PHONY: test test-hermes coverage lint fmt doctor validate

PY ?= python3

test:
	$(PY) -m unittest discover -s tests -t . -v

# needs `pip install 'coverage[toml]'`; settings live in pyproject.toml
coverage:
	$(PY) -m coverage erase
	$(PY) -m coverage run -m unittest discover -s tests -t .
	$(PY) -m coverage report

test-hermes:
	@test -n "$(HERMES_AGENT_ROOT)" || (echo "set HERMES_AGENT_ROOT to a hermes-agent checkout" && exit 1)
	HERMES_AGENT_ROOT=$(HERMES_AGENT_ROOT) $(HERMES_AGENT_ROOT)/venv/bin/python -m unittest tests.test_plugin_load -v

lint:
	ruff check .
	ruff format --check .

fmt:
	ruff format .
	ruff check --fix .

doctor:
	hermes plugins doctor . --ci

# the catalog's admission checks: manifest, settings schema, dependencies, registration probe, security scan
validate:
	hermes plugins validate .
