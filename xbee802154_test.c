#include "modtest.h"

#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST_SETUP xbee_test_setup
static int xbee_test_setup(void* arg, int testno) {
	return 0;
}

#define TEST0 modtest_fail_check
void modtest_fail_check(void* arg, struct modtest_result* result) {
	TEST_FAIL();
}


#include "gen_modtest.h"

DECL_TESTS_ARRAY();

#endif //MODTEST_ENABLE
