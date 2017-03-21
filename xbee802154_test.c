#include "modtest.h"

#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST_SETUP xbee_test_setup
static int xbee_test_setup(void* arg, int testno) {
	struct xb_device* xbdev = NULL;
	xbdev = (struct xb_device*)arg;
	skb_trim(xbdev->recv_buf, 0);
	skb_queue_purge(&xbdev->recv_queue);
	skb_queue_purge(&xbdev->send_queue);
	return 0;
}

#define TEST0 modtest_fail_check
void modtest_fail_check(void* arg, struct modtest_result* result) {
	TEST_FAIL();
}

#define TEST1 modtest_success_check
void modtest_success_check(void* arg, struct modtest_result* result) {
	TEST_SUCCESS();
}

#define TEST2 buffer_calc_checksum_zero
void buffer_calc_checksum_zero(void* arg, struct modtest_result* result) {
	const char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);

	FAIL_IF_NOT_EQ(0xFF, ret);

	TEST_SUCCESS();
}

#define TEST3 buffer_calc_checksum_example
void buffer_calc_checksum_example(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x11};
	const int count = 2;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);
	
	FAIL_IF_NOT_EQ(0xCB, ret);
	TEST_SUCCESS();
}

#define TEST4 buffer_escaped_len_exampe
void buffer_escaped_len_exampe(void* arg, struct modtest_result* result) {
	const char buf[] =    { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const char escbuf[] = { 0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB };

	size_t esclen = buffer_escaped_len(buf, sizeof(buf) );

	FAIL_IF_NOT_EQ(sizeof(escbuf), esclen);

	TEST_SUCCESS();
}

#define TEST5 buffer_escape_exampe
void buffer_escape_exampe(void* arg, struct modtest_result* result) {
	char buf[] =		{ 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x00 };
	const char escbuf[] =	{ 0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB };
	size_t esclen = 0;
	int err;

	//pr_debug("bufsize %lu", sizeof(buf) );

	esclen = buffer_escaped_len(buf, 5);
	err = buffer_escape(buf, 5, esclen);

	print_hex_dump_bytes("buf: ", DUMP_PREFIX_NONE, buf, 6);
	print_hex_dump_bytes("esc: ", DUMP_PREFIX_NONE, escbuf, 6);

	FAIL_IF_ERROR(err);
	FAIL_IF_NOT_EQ(0, memcmp(escbuf, buf, esclen) );

	TEST_SUCCESS();
}

#define TEST205 frame_escape_exampe
void frame_escape_exampe(void* arg, struct modtest_result* result) {
	char buf[] =		{ 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const char escbuf[] =	{ 0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB };
	struct sk_buff* skb = NULL;

	//pr_debug("bufsize %lu", sizeof(buf) );
	
	skb = dev_alloc_skb(sizeof(buf) );
	skb_put(skb, sizeof(buf) );
	memcpy(skb->data, buf, sizeof(buf) );

	print_hex_dump_bytes("skb: ", DUMP_PREFIX_NONE, skb->data, skb->len);
	frame_escape(skb);
	print_hex_dump_bytes("skb: ", DUMP_PREFIX_NONE, skb->data, skb->len);
	print_hex_dump_bytes("esc: ", DUMP_PREFIX_NONE, escbuf, sizeof(escbuf));

	//FAIL_IF_ERROR(err);
	FAIL_IF_NOT_EQ(sizeof(escbuf), skb->len);
	FAIL_IF_NOT_EQ(0, memcmp(escbuf, skb->data, sizeof(escbuf)) );

	TEST_SUCCESS();
}


#if 0
#define TEST6 buffer_find_delimiter_exists
void buffer_find_delimiter_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	FAIL_IF_NOT_EQ(1, ret);
	TEST_SUCCESS();
}


#define TEST7 buffer_find_delimiter_non_exists
void buffer_find_delimiter_non_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	FAIL_IF_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}
#endif

#define TEST8 buffer_find_delimiter_escaped_exists
void buffer_find_delimiter_escaped_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(1, ret);
	TEST_SUCCESS();
}


#define TEST9 buffer_find_delimiter_escaped_non_exists
void buffer_find_delimiter_escaped_non_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}


#define TEST10 buffer_find_delimiter_escaped_exists_escape
void buffer_find_delimiter_escaped_exists_escape(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7D, 0x5E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(1, ret);
	TEST_SUCCESS();
}

#define TEST11 buffer_find_delimiter_escaped_non_exists_escape
void buffer_find_delimiter_escaped_non_exists_escape(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7D, 0x31, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}


#define TEST12 buffer_unescape_zero
void buffer_unescape_zero(void* arg, struct modtest_result* result) {
	char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_IF_NOT_EQ(0, ret);
	TEST_SUCCESS();
}

#define TEST13 buffer_unescape_example
void buffer_unescape_example(void* arg, struct modtest_result* result) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_IF_NOT_EQ(6, ret);
	FAIL_IF_NOT_EQ(0,  memcmp(buf, ans, 6));
	TEST_SUCCESS();
}

#define TEST14 buffer_unescape_end_escape
void buffer_unescape_end_escape(void* arg, struct modtest_result* result) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0x7D};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0x7D};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_IF_NOT_EQ(6, ret);
	FAIL_IF_NOT_EQ(0,  memcmp(buf, ans, 6));
	TEST_SUCCESS();
}

#define TEST15 frame_alloc_test
void frame_alloc_test(void* arg, struct modtest_result* result) {
	struct sk_buff* skb = frame_alloc(9, 0x0F, true);
	struct xb_frameheader* frm = NULL;

	frm = (struct xb_frameheader*)skb->data;

	FAIL_IF_NOT_EQ(0x7E, skb->data[0]);
	FAIL_IF_NOT_EQ(0x00, skb->data[1]);
	FAIL_IF_NOT_EQ(0x0a, skb->data[2]);
	FAIL_IF_NOT_EQ(0x0F, skb->data[3]);
	TEST_SUCCESS();
}

#define TEST16 frame_calc_checksum_zero
void frame_calc_checksum_zero(void* arg, struct modtest_result* result) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x00 };
	const int count = 3;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(0xFF, ret);
	TEST_SUCCESS();
}

#define TEST17 frame_calc_checksum_example
void frame_calc_checksum_example(void* arg, struct modtest_result* result) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 6;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(0xCB, ret);
	TEST_SUCCESS();
}

#define TEST18 frame_verify_zerobyte
void frame_verify_zerobyte(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST19 frame_verify_non_startmark
void frame_verify_non_startmark(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EINVAL, ret);
	TEST_SUCCESS();
}

#define TEST20 frame_verify_startmark
void frame_verify_startmark(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST21 frame_verify_length_zero
void frame_verify_length_zero(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00 };
	const int count = 3;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST22 frame_verify_length_zero_invalid
void frame_verify_length_zero_invalid(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFE };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EINVAL, ret);
	TEST_SUCCESS();
}


#define TEST23 frame_verify_length_zero_valid
void frame_verify_length_zero_valid(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(4, ret);
	TEST_SUCCESS();
}

#define TEST24 frame_verify_length_zero_valid_large
void frame_verify_length_zero_valid_large(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF, 0x01};
	const int count = 5;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(4, ret);
	TEST_SUCCESS();
}


#define TEST25 frame_verify_valid_example
void frame_verify_valid_example(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(6, ret);

	TEST_SUCCESS();
}

#define TEST125 frame_verify_modem_status
void frame_verify_modem_status(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x8A, 0x01, 0x74 };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(6, ret);

	TEST_SUCCESS();
}

//TODO frame_put_received_data

#define TEST26 frameq_enqueue_received_zerobyte
void frameq_enqueue_received_zerobyte(void* arg, struct modtest_result* result) {
	int ret = 0;
	//const char buf[] = {};
	//const int count = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	//unsigned char* tail = skb_put(xbdev->recv_buf, count);
	//memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(0, ret);
	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST27 frameq_enqueue_received_non_startmark
void frameq_enqueue_received_non_startmark(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(0, ret);
	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST28 frameq_enqueue_received_startmark
void frameq_enqueue_received_startmark(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(0, ret);
	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(1, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST29 frameq_enqueue_received_startmark_len
void frameq_enqueue_received_startmark_len(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e , 0x00, 0x3 };
	const int count = 3;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(0, ret);
	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(3, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST30 frameq_enqueue_received_valid_example
void frameq_enqueue_received_valid_example(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(1, ret);
	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}


#define TEST31 frameq_enqueue_received_valid_example_two
void frameq_enqueue_received_valid_example_two(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB,  0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 12;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(2, ret);
	FAIL_IF_NOT_EQ(2, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}


#define TEST32 frameq_enqueue_received_valid_partial
void frameq_enqueue_received_valid_partial(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x7E };
	const int count = 7;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(1, ret);
	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(1, xbdev->recv_buf->len);

	TEST_SUCCESS();
}


#define TEST33 frameq_enqueue_received_valid_invalid
void frameq_enqueue_received_valid_invalid(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x11 };
	const int count = 7;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);

	FAIL_IF_NOT_EQ(1, ret);
	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}



#define TEST34 frameq_dequeue_list_found
void frameq_dequeue_list_found(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04 ,0x08 ,0x01 ,0x49 ,0x44 ,0x69 };
	const int count = 8;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);
	FAIL_IF_NOT_EQ(1, ret);

	dequeued = frameq_dequeue_by_id(&xbdev->recv_queue, 1);

	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF(dequeued == NULL);

	TEST_SUCCESS();
}

#define TEST35 frameq_dequeue_list_notfound
void frameq_dequeue_list_notfound(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04 ,0x08 ,0x01 ,0x49 ,0x44 ,0x69 };
	const int count = 8;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);
	FAIL_IF_NOT_EQ(1, ret);

	dequeued = frameq_dequeue_by_id(&xbdev->recv_queue, 2);

	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF(dequeued != NULL);

	TEST_SUCCESS();
}


#define TEST36 frameq_dequeue_list_no_id_frame
void frameq_dequeue_list_no_id_frame(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00 ,0x05 ,0x81 ,0xFF ,0xFE ,0x00 ,0x01 ,0x80 };
	const int count = 9;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);
	FAIL_IF_NOT_EQ(1, ret);

	dequeued = frameq_dequeue_by_id(&xbdev->recv_queue, 0xFF);

	FAIL_IF(dequeued != NULL);
	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));

	TEST_SUCCESS();
}


#define TEST37 frameq_dequeue_empty_queue
void frameq_dequeue_empty_queue(void* arg, struct modtest_result* result) {
	//int ret = 0;
	//const char buf[] = { 0x7E, 0x00 ,0x05 ,0x81 ,0xFF ,0xFE ,0x00 ,0x01 ,0x80 };
	//const int count = 9;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	//unsigned char* tail = skb_put(xbdev->recv_buf, count);
	//memcpy(tail, buf, count);
	//ret = frameq_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf, 1);
	//FAIL_IF_NOT_EQ(1, ret);

	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));

	dequeued = frameq_dequeue_by_id(&xbdev->recv_queue, 0xFF);

	FAIL_IF(dequeued != NULL);
	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));

	TEST_SUCCESS();
}

#define TEST38 frameq_enqueue_send_and_recv_vr
void frameq_enqueue_send_and_recv_vr(void* arg, struct modtest_result* result) {
	//int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x56, 0x52, 0x4E };
	const int count = 8;

	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* send_buf = alloc_skb(128, GFP_KERNEL);
	struct sk_buff* skb;

	unsigned char* tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frameq_enqueue_send(&xbdev->send_queue, send_buf);

	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);

	xb_send(xbdev);
	skb = xb_recv(xbdev, 1, 1000);

	FAIL_IF_NULL(skb);

	FAIL_IF_NOT_EQ(0, skb_queue_len(&xbdev->send_queue));

	TEST_SUCCESS();
}

#define TEST39 frameq_enqueue_send_at_vr
void frameq_enqueue_send_at_vr(void* arg, struct modtest_result* result) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* skb = NULL;
	struct xb_frame_atcmd* atfrm = NULL;

	frameq_enqueue_send_at(&xbdev->send_queue, XBEE_AT_VR, 123, "", 0);

	FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));
	skb = skb_peek(&xbdev->send_queue);

	FAIL_IF_NULL(skb);

	atfrm = (struct xb_frame_atcmd*)skb->data;

	FAIL_IF_NOT_EQ(123, atfrm->id);
	FAIL_IF_NOT_EQ(XBEE_AT_VR, htons(atfrm->command) );

	FAIL_IF_NOT_EQ(4, htons(atfrm->hd.length) );
	FAIL_IF_NOT_EQ(XBEE_FRM_ATCMD, atfrm->hd.type);

	TEST_SUCCESS();
}

#define TEST40 xb_process_sendrecv_vr
void xb_process_sendrecv_vr(void* arg, struct modtest_result* result) {
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x56, 0x52, 0x4E };
	const int count = 8;
	unsigned char* tail = NULL;

	struct sk_buff* recv = NULL;
	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* send_buf = alloc_skb(128, GFP_KERNEL);

	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);

	frameq_enqueue_send(&xbdev->send_queue, send_buf);
	recv = xb_sendrecv(xbdev, 1);

	FAIL_IF_NULL(recv);
	FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}

#define TEST41 xb_get_channel_test
void xb_get_channel_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	u8 page = 0;
	u8 channel = 0;

	ret = xb_get_channel(xbdev, &page, &channel);

	FAIL_IF_ERROR(ret);

	FAIL_IF_NOT_EQ(0, page);
	FAIL_IF_NOT_EQ(12, channel);

	TEST_SUCCESS();
}


#define TEST42 xb_get_cca_ed_level_test
void xb_get_cca_ed_level_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	s32 ed_level= 0;

	ret = xb_get_cca_ed_level(xbdev, &ed_level);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(-4400, ed_level);

	TEST_SUCCESS();
}


#define TEST43 xb_get_tx_power_test
void xb_get_tx_power_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	s32 power = 0;

	ret = xb_get_tx_power(xbdev, &power);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(0, power);

	TEST_SUCCESS();
}

#define TEST44 xb_get_pan_id_test
void xb_get_pan_id_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	__le16 panid = 0;

	ret = xb_get_pan_id(xbdev, &panid);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(0x3332, panid);

	TEST_SUCCESS();
}


#define TEST45 xb_get_short_addr_test
void xb_get_short_addr_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	__le16 short_addr = 0;

	ret = xb_get_short_addr(xbdev, &short_addr);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(0x0, short_addr);

	TEST_SUCCESS();
}

#ifndef XBEE_SERIAL_NUMBER_HIGH
#define XBEE_SERIAL_NUMBER_HIGH 0x0013A200
#endif
#ifndef XBEE_SERIAL_NUMBER_LOW
#define XBEE_SERIAL_NUMBER_LOW  0x40A75ECC
#endif
static const uint64_t xbee_serialno = ((uint64_t)XBEE_SERIAL_NUMBER_HIGH<<32)|XBEE_SERIAL_NUMBER_LOW;
#define TEST46 xb_get_extended_addr_test
void xb_get_extended_addr_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	__le64 extended_adder = 0;

	ret = xb_get_extended_addr(xbdev, &extended_adder);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(xbee_serialno, extended_adder);

	TEST_SUCCESS();
}



#define TEST47 xb_set_channel_test
void xb_set_channel_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	u8 page = 0;
	u8 channel = 0;

	ret = xb_set_channel(xbdev, 0, 20);

	FAIL_IF_ERROR(ret);

	ret = xb_get_channel(xbdev, &page, &channel);

	FAIL_IF_ERROR(ret);

	FAIL_IF_NOT_EQ(0, page);
	FAIL_IF_NOT_EQ(20, channel);

	TEST_SUCCESS();
}



#define TEST48 xb_set_cca_ed_level_test
void xb_set_cca_ed_level_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;
	s32 ed_level = 0;

	ret = xb_set_cca_ed_level(xbdev, -5000);

	FAIL_IF_ERROR(ret);

	ret = xb_get_cca_ed_level(xbdev, &ed_level);

	FAIL_IF_ERROR(ret);

	FAIL_IF_NOT_EQ(-5000, ed_level);

	TEST_SUCCESS();
}


#define TEST49 xb_set_tx_power_test
void xb_set_tx_power_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	s32 power = 0;

	ret = xb_set_tx_power(xbdev, -1000);
	FAIL_IF_ERROR(ret);

	ret = xb_get_tx_power(xbdev, &power);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(-1000, power);

	TEST_SUCCESS();
}

#define TEST50 xb_set_pan_id_test
void xb_set_pan_id_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	__le16 panid = 0;

	ret = xb_set_pan_id(xbdev, 0xDBCA);
	FAIL_IF_ERROR(ret);

	ret = xb_get_pan_id(xbdev, &panid);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(0xDBCA, panid);

	TEST_SUCCESS();
}

#define TEST51 xb_set_short_addr_test
void xb_set_short_addr_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	__le16 short_addr = 0;

	ret = xb_set_short_addr(xbdev, 0xAAAA);

	FAIL_IF_ERROR(ret);

	ret = xb_get_short_addr(xbdev, &short_addr);

	FAIL_IF_ERROR(ret);
	FAIL_IF_NOT_EQ(0xAAAA, short_addr);

	TEST_SUCCESS();
}

#define TEST52 xb_set_backoff_exponent_test
void xb_set_backoff_exponent_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	u8 min_be = 0;
	u8 max_be = 0;

	ret = xb_set_backoff_exponent(xbdev, 0, 20);

	FAIL_IF_ERROR(ret);

	ret = xb_get_channel(xbdev, &min_be, &max_be);

	FAIL_IF_ERROR(ret);

	FAIL_IF_NOT_EQ(0, min_be);
	FAIL_IF_NOT_EQ(20, max_be);

	TEST_SUCCESS();
}


#define TEST53 xb_set_backoffs_exponent_test
void xb_set_backoffs_exponent_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	ret = xb_set_max_csma_backoffs(xbdev, 2);

	FAIL_IF_NOT_ERROR(ret);

	TEST_SUCCESS();
}

#define TEST54 xb_set_ackreq_default_test
void xb_set_ackreq_default_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	bool ackreq = 0;

	ret = xb_set_ackreq_default(xbdev, true);

	FAIL_IF_ERROR(ret);

	ret = xb_get_ackreq_default(xbdev, &ackreq);

	FAIL_IF_ERROR(ret);

	FAIL_IF_NOT_EQ(true, ackreq);

	TEST_SUCCESS();
}




#if 0
#define TEST55 xbee_ieee802154_set_csma_params_test
void xbee_ieee802154_set_csma_params_test(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] =  { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x52, 0x4E, 0x56 };
	const int count = 8;
	const char buf2[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x52, 0x52, 0x52 };
	const int count2 = 8;
	struct sk_buff* send_buf = NULL;
	unsigned char* tail = NULL;
	struct xb_device* xbdev = NULL;
	struct xbee_sub_if_data *sdata = netdev_priv(xbdev->dev);
	xbdev = (struct xb_device*)arg;
	xbee_cfg802154_set_backoff_exponent(xbdev->phy, &sdata->wpan_dev, 2, 5);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frameq_enqueue_send(&xbdev->send_queue, send_buf);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf2, count2);
	frameq_enqueue_send(&xbdev->send_queue, send_buf);

	ret = xb_sendrecv(xbdev, xbdev->frameid);

	FAIL_IF_ERROR(ret);

	//FAIL_IF_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));

	//FAIL_IF_NOT_EQ(0, xbdev->recv_buf->len);

	// TODO inspect received data

	TEST_SUCCESS();
}
#endif

#define TEST56 ieee802154_addr_size
void ieee802154_addr_size(void* arg, struct modtest_result* result) {
	struct ieee802154_hdr hdr;
	FAIL_IF_NOT_EQ(8, sizeof(hdr.source.extended_addr) );
	FAIL_IF_NOT_EQ(2, sizeof(hdr.source.short_addr) );
}


#include "gen_modtest.h"

DECL_TESTS_ARRAY();

#endif //MODTEST_ENABLE
