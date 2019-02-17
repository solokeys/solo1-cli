.PHONY: black build clean publish reinstall

# setup development environment
init: update-venv

# ensure this passes before commiting
check: lint
	black --check solo/

# automatic code fixes
fix: black

black:
	black solo/

lint:
	flake8 solo/

semi-clean:
	rm -rf **/__pycache__

clean: semi-clean
	rm -rf venv
	rm -rf dist


# Package management

build: check
	flit build

publish: check
	flit publish

venv:
	python3 -m venv venv
	venv/bin/pip install -U pip

# re-run if dev or runtime dependencies change,
# or when adding new scripts
update-venv: venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r dev-requirements.txt
	venv/bin/flit install --symlink
