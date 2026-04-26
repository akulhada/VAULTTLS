PYTHON ?= python

.PHONY: test bench fake-user-study fuzz-codec clean-results

test:
	pytest -q

bench:
	$(PYTHON) tools/benchmark_artifact.py --iterations 8 --app-rounds 32 --message-size 1024

fake-user-study:
	$(PYTHON) tools/measure_fake_user_timing.py --trials 10

fuzz-codec:
	$(PYTHON) tools/fuzz_codec.py --iterations 5000

clean-results:
	rm -f results/*.json results/*.md
