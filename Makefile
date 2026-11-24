# chutes-tdx-measure. See BUILD.md.
PYTHON ?= python3

.PHONY: test vectors mutants lock

test:
	PYTHONPATH=. $(PYTHON) -m pytest -q -p no:cacheprovider tests

vectors:
	cd spec/vectors && sha256sum -c SHA256SUMS

mutants:
	$(PYTHON) mutants/run.py --python $(PYTHON) --out mutants-result.json

# requirements.lock and requirements-test.lock: the dependencies and pytest with hashes (uv pip
# compile from standard input; Python 3.12; no annotations). Each starts with its comment line.
lock:
	{ echo "# chutes-tdx-measure's dependencies, pinned with hashes (pip install --require-hashes -r requirements.lock)."; \
	  printf 'cryptography>=46.0.5\ndcap-qvl==0.5.3\nhttpx>=0.28.1,<1\n' | uv pip compile --generate-hashes --no-annotate --no-header --python-version 3.12 -; } > requirements.lock
	{ echo "# The tests' runner for CI (ubuntu-24.04, Python 3.12), pinned with hashes (pip install --require-hashes -r requirements-test.lock)."; \
	  echo 'pytest==8.4.2' | uv pip compile --generate-hashes --no-annotate --no-header --python-version 3.12 -; } > requirements-test.lock
