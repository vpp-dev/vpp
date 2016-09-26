TEST_MODULES = \
	test_ip \
	test_ip6 \
	test_vxlan \
	test_l2bd

TEST_OPTIONS =

all_custom:
	@python run_tests.py $(TEST_OPTIONS) $(TEST_MODULES)
all:
	@python -m unittest $(TEST_OPTIONS) $(TEST_MODULES)
