.PHONY: test lint build smoke

test:
	PYTHONPATH=src python3 -m unittest discover -s tests

lint:
	python3 -m py_compile src/agent_release_note_check/*.py tests/*.py

build:
	python3 -m compileall -q src tests

smoke:
	PYTHONPATH=src python3 -m agent_release_note_check examples/release-notes.md --diff examples/sample.diff --min-score 80

