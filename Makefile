.PHONY: black build clean publish reinstall

PACKAGE_NAME=solo

# setup development environment
init: update-venv

# ensure this passes before commiting
check: lint
	venv/bin/black --check $(PACKAGE_NAME)/
	venv/bin/isort --check-only --recursive $(PACKAGE_NAME)/

# automatic code fixes
fix: black isort

black:
	venv/bin/black $(PACKAGE_NAME)/

isort:
	venv/bin/isort -y --recursive $(PACKAGE_NAME)/

lint:
	venv/bin/flake8 $(PACKAGE_NAME)/

semi-clean:
	rm -rf **/__pycache__

clean: semi-clean
	rm -rf venv
	rm -rf dist


# Package management

VERSION_FILE := "$(PACKAGE_NAME)/VERSION"
VERSION := $(shell cat $(VERSION_FILE))
tag:
	git tag -a $(VERSION) -m"v$(VERSION)"
	git push origin $(VERSION)

build: check
	flit build

publish: check
	flit --repository pypi publish

venv:
	python3 -m venv venv
	venv/bin/python3 -m pip install -U pip

# re-run if dev or runtime dependencies change,
# or when adding new scripts
update-venv: venv
	venv/bin/python3 -m pip install -U pip
	venv/bin/python3 -m pip install -U -r dev-requirements.txt
	venv/bin/flit install --symlink

.PHONY: CI
CI:
	env FLIT_ROOT_INSTALL=1 $(MAKE) init
	env FLIT_ROOT_INSTALL=1 $(MAKE) build
