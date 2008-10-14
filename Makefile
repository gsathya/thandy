
all:
	python setup.py build

test:
	export PYTHONPATH=./lib/ && python -m thandy/tests

install:
	python setup.py install
