
all:
	python setup.py build

test:
	export PYTHONPATH=./lib/ && python -c "from thandy.tests import \
	run_tests;\
	    run_tests()"

install:
	python setup.py install
