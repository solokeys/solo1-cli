.PHONY: black build clean publish reinstall

init: update-venv

code-checks: black lint

black:
	black solo/

lint:
	flake8 solo/

clean:
	rm -rf venv
	rm -rf dist


# Package management

build: black
	flit build

publish:
	black --check solo/
	flit publish

venv:
	python3 -m venv venv
	venv/bin/pip install -U pip

update-venv: venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r dev-requirements.txt
	venv/bin/flit install --symlink
