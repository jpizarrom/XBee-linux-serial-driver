#ifndef MODTEST_H
#define MODTEST_H

struct modtest_result {
	uint32_t testno;
	int error;
	unsigned int line;
	char msg[128];
	uint32_t next_testno;
};

typedef void (*fp_modtest)(void* data, struct modtest_result* result);
typedef int (*fp_setup_teardown)(void* arg, int testnum);

extern const size_t modtest_tests_num;
extern const fp_setup_teardown modtest_setup;
extern const fp_modtest modtest_tests[];
extern const fp_setup_teardown modtest_teardown;

#define DECL_TESTS_ARRAY() \
	const fp_setup_teardown modtest_setup    = MODTEST_SETUP; \
	const fp_setup_teardown modtest_teardown = MODTEST_TEARDOWN; \
	const fp_modtest modtest_tests[] = MODTEST_TESTS; \
	const size_t modtest_tests_num = sizeof(modtest_tests)/sizeof(fp_modtest);

//#define SET_RESULT(err, line, msg) { struct modtest_result _rslt_ = {0, err,line,msg}; return _rslt_; }
#define SET_RESULT_(rslt, errcode, lineno, message) { rslt->error = errcode; rslt->line = lineno, strncpy(result->msg, message, 127); }
#define SET_RESULT(errcode, lineno, message) SET_RESULT_(result, errcode, lineno, message)

#define PR_EXPECTED_(rslt, expected, val) \
	{    if(sizeof(val) < 2) { pr_debug("expected:%02x(%d), result: %02x(%d)\n", (uint8_t)expected,(int8_t)expected,  (uint8_t)val, (int8_t)val); \
				   snprintf(rslt->msg, 127, \
				            "expected:%02x(%d), result: %02x(%d)\n", (uint8_t)expected,(int8_t)expected,  (uint8_t)val, (int8_t)val);} \
	else if(sizeof(val) < 4) { pr_debug("expected:%04x(%d), result: %04x(%d)\n", (uint16_t)expected,(int16_t)expected,  (uint16_t)val, (int16_t)val); \
				   snprintf(rslt->msg, 127, \
					    "expected:%04x(%d), result: %04x(%d)\n", (uint16_t)expected,(int16_t)expected,  (uint16_t)val, (int16_t)val); } \
	else if(sizeof(val) < 8) { pr_debug("expected:%08x(%d), result: %08x(%d)\n", (uint32_t)expected,(int32_t)expected,  (uint32_t)val, (int32_t)val); \
				   snprintf(rslt->msg, 127, \
					    "expected:%08x(%d), result: %08x(%d)\n", (uint32_t)expected,(int32_t)expected,  (uint32_t)val, (int32_t)val); } \
	else /* size == 8 */ { pr_debug("expected:%016llx(%lld), result: %016llx(%lld)\n", (uint64_t)expected,(int64_t)expected,  (uint64_t)val, (int64_t)val); \
		                   snprintf(rslt->msg, 127, \
					    "expected:%016llx(%lld), result: %016llx(%lld)\n", (uint64_t)expected,(int64_t)expected,  (uint64_t)val, (int64_t)val); } }
#define PR_EXPECTED(expected, val) PR_EXPECTED_(result, expected, val)

#define PR_ERROR_(rslt, err) { snprintf(rslt->msg, 127, "Expect 0, %d", err); }
#define PR_ERROR(err) PR_ERROR_(result, err)
#define PR_NULL_(rslt, obj) { snprintf(rslt->msg, 127, "Expect NULL, %p", obj); }
#define PR_NULL(obj) PR_NULL_(result, obj)
#define PR_NOT_ERROR_(rslt, err) { snprintf(rslt->msg, 127, "Expect error, %d", err); }
#define PR_NOT_ERROR(err) PR_NOT_ERROR_(result, err)
#define PR_NOT_NULL_(rslt, obj) { snprintf(rslt->msg, 127, "Expect not NULL, %p", obj); }
#define PR_NOT_NULL(obj) PR_NOT_NULL_(result, obj)

#define TEST_SUCCESS() SET_RESULT(0, __LINE__, "success")
#define TEST_FAIL() SET_RESULT(-1, __LINE__, "fail")
#define TEST_IS_NULL(obj) SET_RESULT(-1, __LINE__, PR_NULL(obj) )
#define TEST_ERROR(err) { SET_RESULT(err, __LINE__, ""); PR_ERROR(err); }
#define TEST_NOT_ERROR(err) { SET_RESULT(err, __LINE__, ""); PR_NOT_ERROR(err); }
#define FAIL_IF_NOT_EQ(expected, val) if(expected != val) { SET_RESULT(-1, __LINE__, ""); PR_EXPECTED(expected,val); }
#define FAIL_IF_ERROR(err) if((err) < 0) TEST_ERROR(err)
#define FAIL_IF_NOT_ERROR(err) if(!((err) < 0)) TEST_NOT_ERROR(err)
#define FAIL_IF_NULL(obj) if((!obj)) { SET_RESULT(-1, __LINE__, ""); PR_NULL(obj) }
#define FAIL_IF_NOT_NULL(obj) if((!obj)) { SET_RESULT(-1, __LINE__, ""); PR_NOT_NULL(obj) }
#define FAIL_IF(cond) if((cond)) SET_RESULT(-1, __LINE__, "")



#if defined(MODTEST_ENABLE) && MODTEST_ENABLE
static int setup_teardown_default(void* arg, int testnum) { return 0; }

static void modtest_test(uint32_t testno, void* data, struct modtest_result* result)
{
	int i=0;
	modtest_setup(data, testno);
	pr_debug("test#%u: Start\n", testno);
	modtest_tests[testno](data, result);
	pr_debug("test#%u: Finish\n", testno);
	result->testno = testno;
	modtest_teardown(data, testno);
	result->next_testno = -1;
	for(i=testno+1; i<modtest_tests_num; i++) {
		if(modtest_tests[i] != NULL) {
			result->next_testno = i;
			break;
		}
	}
}

static int modtest_ioctl(struct file *file, unsigned int cmd, unsigned long arg, void* data)
{
	struct modtest_result* result = NULL;

	result = kmalloc(sizeof(struct modtest_result), GFP_ATOMIC);

	if( copy_from_user(result, (void __user *)arg,
				sizeof(struct modtest_result) ) ) {
		kfree(result);
		return -EFAULT;
	}

	modtest_test(result->testno, data, result);

	if ( copy_to_user((void __user *)arg, result,
				sizeof(struct modtest_result) ) ) {
		kfree(result);
		return -EFAULT;
	}

	kfree(result);
	return 0;
}
#endif



#endif


