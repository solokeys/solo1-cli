.PHONY: black build clean publish reinstall

PACKAGE_NAME=solo
VENV=venv


# setup development environment
init: update-venv

# ensure this passes before commiting
check: lint
	$(VENV)/bin/black --check $(PACKAGE_NAME)/
	$(VENV)/bin/isort --check-only --recursive $(PACKAGE_NAME)/

# automatic code fixes
fix: black isort

black:
	$(VENV)/bin/black $(PACKAGE_NAME)/

isort:
	$(VENV)/bin/isort -y --recursive $(PACKAGE_NAME)/

lint:
	$(VENV)/bin/flake8 $(PACKAGE_NAME)/

semi-clean:
	rm -rf **/__pycache__

clean: semi-clean
	rm -rf $(VENV)
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

$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/python3 -m pip install -U pip

# re-run if dev or runtime dependencies change,
# or when adding new scripts
update-venv: $(VENV)
	$(VENV)/bin/python3 -m pip install -U pip
	$(VENV)/bin/python3 -m pip install -U -r dev-requirements.txt
	$(VENV)/bin/flit install --symlink

.PHONY: CI
CI:
	env FLIT_ROOT_INSTALL=1 $(MAKE) init VENV=$(VENV)
	env FLIT_ROOT_INSTALL=1 $(MAKE) build VENV=$(VENV)


.PHONY: build-CI-test
build-CI-test:
	sudo docker build . -t nitro-python-ci

.PHONY: CI-test
CI-test:
	sudo docker run -it --rm -v $(PWD):/app nitro-python-ci make CI VENV=venv-ci
