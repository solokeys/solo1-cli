.PHONY: update-venv black clean

update-venv: venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r dev-requirements.txt

venv:
	python3 -m venv venv
	venv/bin/pip install -U pip

black:
	black solo/

clean:
	rm -rf venv
