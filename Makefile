.PHONY: install lock lint test demo fixtures api dashboard

install:
	python -m pip install --require-hashes --no-deps -r requirements/requirements-dev.txt
	python -m pip install --no-deps --no-build-isolation -e .

lock:  ## regenerate hash-pinned lockfiles (requires uv)
	uv pip compile pyproject.toml --extra dashboard --generate-hashes --python-version 3.12 --universal --custom-compile-command "make lock" -o requirements/requirements.txt
	uv pip compile pyproject.toml --extra dashboard --extra dev --generate-hashes --python-version 3.12 --universal --custom-compile-command "make lock" -o requirements/requirements-dev.txt

lint:
	ruff format --check .
	ruff check .

test:
	pytest --cov

demo:
	sentinel demo --check

fixtures:  ## rotate the demo key, re-sign fixtures and re-record OSV evidence (needs network)
	python scripts/build_demo_fixtures.py --record-osv

api:
	python -m sentinel.api

dashboard:
	streamlit run sentinel/dashboard/app.py
