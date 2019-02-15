.PHONY: update-venv black build clean publish

black:
	black solo/

clean:
	rm -rf venv
	rm -rf dist


# Package management

build: black
	flit build

reinstall:
	pip uninstall -y solo-python
	flit install

publish: build
	flit publish

venv:
	python3 -m venv venv
	venv/bin/pip install -U pip

update-venv: venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r dev-requirements.txt
