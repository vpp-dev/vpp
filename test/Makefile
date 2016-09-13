TEST_MODULES = \
	test_ip \
	test_vxlan

TEST_OPTIONS =

all_custom:
	@python run_tests.py $(TEST_OPTIONS) $(TEST_MODULES)
all:
	@python -m unittest $(TEST_OPTIONS) $(TEST_MODULES)
