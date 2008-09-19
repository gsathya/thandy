
export PYTHONPATH=./lib

test:
	python -m sexp.tests
	python -m glider.tests
