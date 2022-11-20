#include "otrcp_common.h"

#include <linux/tty.h>
#include <net/mac802154.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

#define N_IEEE802154_OTRCP 29

enum {
	kFlagXOn = 0x11,
	kFlagXOff = 0x13,
	kFlagSequence = 0x7e,
	kEscapeSequence = 0x7d,
	kFlagSpecial = 0xf8,
};

/**
 * FCS lookup table
 *
 */
enum {
	kInitFcs = 0xffff,
	kGoodFcs = 0xf0b8,
	kFcsSize = 2,
};

enum hdlc_frame_decode_state {
	kStateNoSync,
	kStateSync,
	kStateEscaped,
};

struct hdlc_frame_decoder {
	enum hdlc_frame_decode_state state;
	uint16_t length;
};

struct hdlc_frame {
	uint8_t *ptr;
	uint16_t remaining;
	uint16_t fcs;
};

struct ttyrcp {
	struct otrcp otrcp;

	struct tty_struct *tty;

	struct completion wait_response;
	struct completion wait_notify;

	struct sk_buff_head response_queue;
	struct sk_buff_head notify_queue;

	uint8_t hdlc_lite_buf[SPINEL_FRAME_MAX_SIZE * 2 + 4];
};

static void hdlc_frame_update_fcs(struct hdlc_frame *frame, uint8_t byte)
{
	static const uint16_t fcs_table[256] = {
		0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
		0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393, 0x221a,
		0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
		0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
		0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
		0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
		0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9,
		0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
		0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
		0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
		0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
		0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
		0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
		0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb,
		0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
		0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
		0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
		0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
		0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e,
		0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
		0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
		0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
		0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
		0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
		0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
		0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78};
	frame->fcs = (frame->fcs >> 8) ^ fcs_table[(frame->fcs ^ byte) & 0xff];
}

static bool hdlc_frame_byte_needs_escape(uint8_t byte)
{
	bool rval;

	switch (byte) {
	case kFlagXOn:
	case kFlagXOff:
	case kEscapeSequence:
	case kFlagSequence:
	case kFlagSpecial:
		rval = true;
		break;

	default:
		rval = false;
		break;
	}

	return rval;
}

static bool hdlc_frame_can_write(struct hdlc_frame *frame, uint16_t write_len)
{
	return (frame->remaining >= write_len);
}

static int hdlc_frame_write_byte(struct hdlc_frame *frame, uint8_t byte)
{
	if (!hdlc_frame_can_write(frame, sizeof(uint8_t))) {
		return -ENOBUFS;
	}

	*frame->ptr++ = byte;
	frame->remaining--;
	return 1;
}

static void hdlc_frame_undo_last_writes(struct hdlc_frame *frame, uint16_t undo_len)
{
	frame->ptr -= undo_len;
	frame->remaining += undo_len;
}

static int hdlc_frame_begin(struct hdlc_frame *frame)
{
	frame->fcs = kInitFcs;

	return hdlc_frame_write_byte(frame, kFlagSequence);
}

static int hdlc_frame_encode_byte(struct hdlc_frame *frame, uint8_t byte)
{
	int rc = 0;

	if (hdlc_frame_byte_needs_escape(byte)) {
		if (!(hdlc_frame_can_write(frame, 2))) {
			rc = -ENOBUFS;
			goto exit;
		}

		rc = hdlc_frame_write_byte(frame, kEscapeSequence);
		if (rc < 0)
			goto exit;

		rc = hdlc_frame_write_byte(frame, (byte ^ 0x20));
		if (rc < 0)
			goto exit;
	} else {
		rc = hdlc_frame_write_byte(frame, byte);
		if (rc < 0)
			goto exit;
	}

	hdlc_frame_update_fcs(frame, byte);

exit:
	return rc;
}

static int hdlc_frame_encode_buffer(struct hdlc_frame *frame, const uint8_t *data, uint16_t len)
{
	struct hdlc_frame old = *frame;
	int rc = 0;

	while (len--) {
		rc = hdlc_frame_encode_byte(frame, *data++);
		if (rc < 0)
			goto exit;
	}

exit:
	if (rc < 0)
		*frame = old;

	return rc;
}

static int hdlc_frame_end(struct hdlc_frame *frame)
{
	struct hdlc_frame old = *frame;
	uint16_t fcs = frame->fcs;
	int rc = 0;

	fcs ^= 0xffff;

	rc = hdlc_frame_encode_byte(frame, fcs & 0xff);
	if (rc < 0)
		goto exit;
	rc = hdlc_frame_encode_byte(frame, fcs >> 8);
	if (rc < 0)
		goto exit;
	rc = hdlc_frame_write_byte(frame, kFlagSequence);
	if (rc < 0)
		goto exit;

exit:
	if (rc < 0)
		*frame = old;

	return rc;
}

static int hdlc_frame_decode_byte(struct hdlc_frame *frame, uint8_t byte,
				  struct hdlc_frame_decoder *decode)
{
	int error = 0;

	switch (decode->state) {
	case kStateNoSync:
		if (byte == kFlagSequence) {
			decode->state = kStateSync;
			decode->length = 0;
			frame->fcs = kInitFcs;
		}

		break;

	case kStateSync:
		switch (byte) {
		case kEscapeSequence:
			decode->state = kStateEscaped;
			break;

		case kFlagSequence:

			if (decode->length > 0) {
				error = -EINVAL;

				if ((decode->length >= kFcsSize)
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
				    && (frame->fcs == kGoodFcs)
#endif
				) {
					// Remove the FCS from the frame.
					hdlc_frame_undo_last_writes(frame, kFcsSize);
					error = 0;
				}
			}

			decode->length = 0;
			frame->fcs = kInitFcs;
			break;

		default:
			if (hdlc_frame_can_write(frame, (sizeof(uint8_t)))) {
				hdlc_frame_update_fcs(frame, byte);
				hdlc_frame_write_byte(frame, byte);
				decode->length++;
			} else {
				decode->state = kStateNoSync;
				error = -ENOBUFS;
			}

			break;
		}

		break;

	case kStateEscaped:
		if (hdlc_frame_can_write(frame, (sizeof(uint8_t)))) {
			byte ^= 0x20;
			hdlc_frame_update_fcs(frame, byte);
			hdlc_frame_write_byte(frame, byte);
			decode->length++;
			decode->state = kStateSync;
		} else {
			decode->state = kStateNoSync;
			error = -ENOBUFS;
		}

		break;
	}

	return error;
}

static int hdlc_frame_decode(struct hdlc_frame *frame, const uint8_t *data, uint16_t len)
{
	struct hdlc_frame_decoder decoder = {0};
	int err;

	while (len--) {
		err = hdlc_frame_decode_byte(frame, *data++, &decoder);
		if (err) {
			return err;
		}
	}
	return decoder.length;
}

static int ttyrcp_spinel_send(void *ctx, uint8_t *buf, size_t len, size_t *sent, uint32_t cmd,
			      spinel_prop_key_t key, spinel_tid_t tid)
{
	struct ttyrcp *rcp = ctx;
	struct hdlc_frame frm = {rcp->hdlc_lite_buf, sizeof(rcp->hdlc_lite_buf), 0};
	int rc;

	*sent = 0;
	// dev_dbg(rcp->parent, "%s buf=%p, len=%lu, cmd=%u, key=%u, tid=%u\n", __func__, buf, len,
	//	cmd, key, tid);

	rc = hdlc_frame_begin(&frm);
	if (rc < 0)
		goto end;

	rc = hdlc_frame_encode_buffer(&frm, buf, len);
	if (rc < 0)
		goto end;

	rc = hdlc_frame_end(&frm);
	if (rc < 0)
		goto end;

	rc = rcp->tty->ops->write(rcp->tty, rcp->hdlc_lite_buf, frm.ptr - rcp->hdlc_lite_buf);
	if (rc < 0)
		goto end;

	*sent = rc;
end:
	// dev_dbg(rcp->otrcp.parent, "end %s: %d\n", __func__, __LINE__);
	return rc;
}

static int ttyrcp_spinel_wait(void *ctx, uint8_t *buf, size_t len, size_t *received,
			      struct completion *completion, struct sk_buff_head *queue,
			      uint32_t sent_cmd, spinel_prop_key_t sent_key, spinel_tid_t sent_tid,
			      bool validate_cmd, bool validate_key, bool validate_tid)
{
	struct ttyrcp *rcp = ctx;
	spinel_prop_key_t key;
	uint8_t header;
	uint32_t cmd;
	uint8_t *data;
	spinel_size_t data_len;
	int rc;
	struct sk_buff *skb;

	*received = 0;

	// dev_dbg(rcp->otrcp.parent,
	//	"%s(ctx=%p, buf=%p, len=%lu, sent_cmd=%u, sent_key=%u, sent_tid=%u)\n", __func__,
	//	ctx, buf, len, sent_cmd, sent_key, sent_tid);
	reinit_completion(completion);
	rc = wait_for_completion_interruptible_timeout(completion, msecs_to_jiffies(3000));
	if (rc <= 0) {
		dev_dbg(rcp->otrcp.parent,
			"%d = %s(ctx=%p, buf=%p, len=%lu, sent_cmd=%u, sent_key=%u, sent_tid=%u)\n",
			rc, __func__, ctx, buf, len, sent_cmd, sent_key, sent_tid);
		if (rc == 0) {
			pr_debug("******************* TIMEOUT *******************\n");
			rc = -ETIMEDOUT;
		}
		goto end;
	}

	while ((skb = skb_dequeue(queue)) != NULL) {
		rc = otrcp_validate_received_data(&rcp->otrcp, skb->data, skb->len, &header, &cmd, &key, &data, &data_len,
				sent_cmd, sent_key, sent_tid,
			      validate_cmd, validate_key, validate_tid);
		if (rc >= 0) {
			memcpy(buf, data, data_len);
			*received = data_len;
			kfree_skb(skb);
			break;
		} else {
			dev_dbg(rcp->otrcp.parent,
				"unpack cmd=%u(expected=%u), key=%u(expected=%u), "
				"tid=%u(expected=%u), data=%p, data_len=%u\n",
				cmd, spinel_expected_command(sent_cmd), key, sent_key,
				SPINEL_HEADER_GET_TID(header), sent_tid, data, data_len);
		}
		kfree_skb(skb);
	}

	while ((skb = skb_dequeue(queue)) != NULL) {
		dev_warn(rcp->otrcp.parent, "unexpected response received\n");
		print_hex_dump_debug("resp<<: ", DUMP_PREFIX_NONE, 16, 1, skb->data, skb->len,
				     true);
		kfree_skb(skb);
	}

end:
	// dev_dbg(rcp->otrcp.parent, "%s: end %d\n", __func__, rc);
	return rc;
}

static int ttyrcp_spinel_wait_response(void *ctx, uint8_t *buf, size_t len, size_t *received,
			      uint32_t sent_cmd, spinel_prop_key_t sent_key, spinel_tid_t sent_tid,
			      bool validate_cmd, bool validate_key, bool validate_tid)
{
	struct ttyrcp *rcp = ctx;
	return ttyrcp_spinel_wait(ctx, buf, len, received, &rcp->wait_response, &rcp->response_queue,
			      sent_cmd, sent_key, sent_tid, validate_cmd, validate_key, validate_tid);
}

static int ttyrcp_spinel_wait_notify(void *ctx, uint8_t *buf, size_t len, size_t *received,
			      uint32_t sent_cmd, spinel_prop_key_t sent_key, spinel_tid_t sent_tid,
			      bool validate_cmd, bool validate_key, bool validate_tid)
{
	struct ttyrcp *rcp = ctx;
	return ttyrcp_spinel_wait(ctx, buf, len, received, &rcp->wait_notify, &rcp->notify_queue,
			      sent_cmd, sent_key, sent_tid, validate_cmd, validate_key, validate_tid);
}

static int ttyrcp_skb_append(struct sk_buff_head *queue, const uint8_t *buf, size_t len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}

	memcpy(skb_put(skb, len), buf, len);

	skb_queue_tail(queue, skb);

	return 0;
}

static const struct ieee802154_ops ttyrcp_ops = {
	.owner = THIS_MODULE,
	.start = otrcp_start,
	.stop = otrcp_stop,
	.xmit_async = otrcp_xmit_async,
	.ed = otrcp_ed,
	.set_channel = otrcp_set_channel,
	.set_hw_addr_filt = otrcp_set_hw_addr_filt,
	.set_txpower = otrcp_set_tx_power,
	.set_cca_mode = otrcp_set_cca_mode,
	.set_cca_ed_level = otrcp_set_cca_ed_level,
	.set_csma_params = otrcp_set_csma_params,
	.set_frame_retries = otrcp_set_frame_retries,
	.set_promiscuous_mode = otrcp_set_promiscuous_mode,
};

/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

static int ttyrcp_ldisc_open(struct tty_struct *tty)
{
	struct ieee802154_hw *hw;
	struct ttyrcp *rcp;
	int rc;

	dev_dbg(tty->dev, "%s(%p)\n", __func__, tty);

	if (!capable(CAP_NET_ADMIN)) {
		dev_dbg(tty->dev, "end %s: %d\n", __func__, __LINE__);
		return -EPERM;
	}

	if (tty->ops->write == NULL) {
		dev_dbg(tty->dev, "end %s: %d\n", __func__, __LINE__);
		return -EOPNOTSUPP;
	}

	hw = ieee802154_alloc_hw(sizeof(struct ttyrcp), &ttyrcp_ops);
	if (!hw) {
		dev_dbg(tty->dev, "end %s: %d\n", __func__, __LINE__);
		return -ENOMEM;
	}

	rcp = hw->priv;
	rcp->otrcp.hw = hw;
	rcp->otrcp.parent = tty->dev;
	rcp->otrcp.rcp_api_version = 1;
	rcp->otrcp.scan_period = 300;
	rcp->otrcp.spinel_max_frame_size = 8192;
	rcp->otrcp.phy_chan_supported_size = sizeof(rcp->otrcp.phy_chan_supported);
	rcp->otrcp.caps_size = sizeof(rcp->otrcp.caps);
	rcp->otrcp.tid = 0xFF;
	rcp->otrcp.send = ttyrcp_spinel_send;
	rcp->otrcp.wait_response = ttyrcp_spinel_wait_response;
	rcp->otrcp.wait_notify = ttyrcp_spinel_wait_notify;

	tty->receive_room = 65536;

	rcp->tty = tty_kref_get(tty);
	tty_driver_flush_buffer(tty);

	skb_queue_head_init(&rcp->notify_queue);
	skb_queue_head_init(&rcp->response_queue);
	init_completion(&rcp->wait_response);
	init_completion(&rcp->wait_notify);

	tty->disc_data = rcp;
	rc = ieee802154_register_hw(hw);

	if (rc < 0)
		goto end;

end:
	dev_dbg(tty->dev, "end %s: %d\n", __func__, __LINE__);
	return rc;
}

static void ttyrcp_ldisc_close(struct tty_struct *tty)
{
	struct ttyrcp *rcp = tty->disc_data;

	dev_dbg(tty->dev, "%s(%p)\n", __func__, tty);

	tty->disc_data = NULL;
	tty_kref_put(tty);

	if (!rcp) {
		printk(KERN_WARNING "%s: rcp is not found\n", __func__);
		return;
	}

	ieee802154_unregister_hw(rcp->otrcp.hw);
	ieee802154_free_hw(rcp->otrcp.hw);

	rcp->tty = NULL;
	dev_dbg(tty->dev, "end %s: %d\n", __func__, __LINE__);
}

static int ttyrcp_ldisc_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	dev_dbg(tty->dev, "%s(%p, %p, %u, %lu)\n", __func__, tty, file, cmd, arg);
#if 0
        struct ttyrcp *rcp = tty->disc_data;
        unsigned int tmp;

        /* First make sure we're connected. */
        if (!xb || rcp->magic != XBEE802154_MAGIC)
                return -EINVAL;

        switch (cmd) {
        case SIOCGIFNAME:
                tmp = strlen(rcp->dev->name) + 1;
                if (copy_to_user((void __user *)arg, rcp->dev->name, tmp))
                        return -EFAULT;
                return 0;
        case SIOCSIFHWADDR:
                return -EINVAL;
#ifdef MODTEST_ENABLE
        case 0x9999:
                return modtest_ioctl(file, cmd, arg, xb);
#endif
        default:
                return tty_mode_ioctl(tty, file, cmd, arg);
        }
#endif
	return 0;
}

static int ttyrcp_ldisc_hangup(struct tty_struct *tty)
{
	dev_dbg(tty->dev, "%s(%p)\n", __func__, tty);
	ttyrcp_ldisc_close(tty);
	dev_dbg(tty->dev, "end %s: %d\n", __func__, __LINE__);
	return 0;
}

/**
 * ttyrcp_ldisc_recv_buf - Receive serial bytes.
 *
 * @tty: TTY info for line.
 * @buf: ...
 * @cflags: ...
 * @count: ...
 *
 * Directly called from flush_to_ldisc() which is called from
 * tty_flip_buffer_push(), either in IRQ context if low latency tty or from
 * a normal worker thread otherwise.
 */
static int ttyrcp_ldisc_receive_buf2(struct tty_struct *tty, const unsigned char *buf,
				     const char *cflags, int count)
{
	struct hdlc_frame frm = {(uint8_t *)buf, count, 0};
	struct ttyrcp *rcp = tty->disc_data;
	struct sk_buff *skb;
	int rc = 0;

	// dev_dbg(tty->dev, "%s(tty=%p, buf=%p, clfags=%p count=%u)\n", __func__, tty, buf, cflags,
	//	count);
	// print_hex_dump_debug("receive_buf2<<: ", DUMP_PREFIX_NONE, 16, 1, buf, count, true);

	if (!tty->disc_data) {
		dev_err(tty->dev, "%s(): record for tty is not found\n", __func__);
		return 0;
	}

	rc = hdlc_frame_decode(&frm, buf, count);
	if (rc < 0) {
		dev_dbg(tty->dev, "%s(tty=%p, buf=%p, clfags=%p count=%u)\n", __func__, tty, buf,
			cflags, count);
		print_hex_dump(KERN_ERR, "receive_buf2<< ", DUMP_PREFIX_NONE, 16, 1, buf, count,
			       true);
		dev_err(tty->dev, "%s(): hdlc_frame_decode() failed: %d\n", __func__, rc);
		return 0;
	}

	switch (otrcp_spinel_receive_type(&rcp->otrcp, buf, count)) {
		case kSpinelReceiveNotification:
			otrcp_handle_notification(&rcp->otrcp, buf, count);

			if (completion_done(&rcp->wait_notify)) {
				return 0;
			}

			rc = ttyrcp_skb_append(&rcp->notify_queue,  buf, frm.ptr - buf);
			if (rc < 0) {
				return 0;
			}

			complete_all(&rcp->wait_notify);
			break;
		case kSpinelReceiveResponse:
			if (completion_done(&rcp->wait_response)) {
				dev_warn(rcp->otrcp.parent, "not wait\n");
			}

			rc = ttyrcp_skb_append(&rcp->response_queue,  buf, frm.ptr - buf);
			if (rc < 0) {
				return rc;
			}

			complete_all(&rcp->wait_response);
			break;
		default:
			kfree_skb(skb);
			dev_dbg(rcp->otrcp.parent,
				"%s: ***************** not handled tid = %x, expected %x\n", __func__,
				SPINEL_HEADER_GET_TID(skb->data[0]), rcp->otrcp.tid);
			return 0;
	}

	// dev_dbg(tty->dev, "end %s:@%d %d\n", __func__, __LINE__, count);
	return count;
}

static struct tty_ldisc_ops ttyrcp_ldisc_ops = {
	.owner = THIS_MODULE,
	.num = N_IEEE802154_OTRCP,
	.name = "n_ieee802154_otrcp",
	.open = ttyrcp_ldisc_open,
	.close = ttyrcp_ldisc_close,
	.ioctl = ttyrcp_ldisc_ioctl,
	.hangup = ttyrcp_ldisc_hangup,
	.receive_buf2 = ttyrcp_ldisc_receive_buf2,
};

/*********************************************************************/

static int __init ttyrcp_init(void)
{
	pr_debug("%s\n", __func__);
	if (tty_register_ldisc(&ttyrcp_ldisc_ops) != 0) {
		printk(KERN_ERR "%s: line discipline register failed\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static void __exit ttyrcp_exit(void)
{
	pr_debug("%s\n", __func__);
	tty_unregister_ldisc(&ttyrcp_ldisc_ops);
}

module_init(ttyrcp_init);
module_exit(ttyrcp_exit);

MODULE_DESCRIPTION("OpenThread TTY Radio Co-Processor driver");
MODULE_ALIAS_LDISC(N_IEEE802154_OTRCP);
MODULE_LICENSE("GPL");
