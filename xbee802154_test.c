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




#include "gen_modtest.h"

DECL_TESTS_ARRAY();

#endif //MODTEST_ENABLE
