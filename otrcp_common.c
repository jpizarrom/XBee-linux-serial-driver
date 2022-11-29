#include "otrcp_common.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/mac802154.h>

static void ieee802154_xmit_error(struct ieee802154_hw *hw, struct sk_buff *skb, int reason)
{
	ieee802154_wake_queue(hw);
	dev_kfree_skb_any(skb);
}

static void ieee802154_xmit_hw_error(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	ieee802154_xmit_error(hw, skb, 0xff);
}

#define SPINEL_PROP_IMPL_V(prop, rcp, cmd, expected, postproc, ctx, ...)                           \
	return otrcp_spinel_command(((struct otrcp *)rcp), cmd, CONCATENATE(SPINEL_PROP_, prop),   \
				    expected, postproc, ctx,                                       \
				    CONCATENATE(spinel_data_format_str_, prop), __VA_ARGS__);

#define SPINEL_GET_PROP_IMPL(prop, rcp, ...)                                                       \
	struct otrcp_received_data_verify expected = {                                             \
		true, true, true, 0, 0, 0, 0, 0,                                                   \
	};                                                                                         \
	SPINEL_PROP_IMPL_V(prop, rcp, SPINEL_CMD_PROP_VALUE_GET, &expected, postproc_unpack, NULL, \
			   __VA_ARGS__)

#define SPINEL_SET_PROP_IMPL(prop, rcp, ...)                                                       \
	struct otrcp_received_data_verify expected = {                                             \
		true, true, true, 0, 0, 0, 0, 0,                                                   \
	};                                                                                         \
	SPINEL_PROP_IMPL_V(prop, rcp, SPINEL_CMD_PROP_VALUE_SET, &expected, postproc_return, NULL, \
			   __VA_ARGS__)

#define FORMAT_STRING(prop, format)                                                                \
	static const char CONCATENATE(*spinel_data_format_str_, prop) = format;

FORMAT_STRING(RESET, (SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT_PACKED_S));

FORMAT_STRING(CAPS, (SPINEL_DATATYPE_DATA_S));
FORMAT_STRING(HWADDR, (SPINEL_DATATYPE_EUI64_S));
FORMAT_STRING(NCP_VERSION, (SPINEL_DATATYPE_UTF8_S));
FORMAT_STRING(PHY_CCA_THRESHOLD, (SPINEL_DATATYPE_INT8_S));
FORMAT_STRING(PHY_CHAN, (SPINEL_DATATYPE_UINT8_S));
FORMAT_STRING(PHY_CHAN_SUPPORTED, (SPINEL_DATATYPE_DATA_S));
FORMAT_STRING(PHY_RSSI, (SPINEL_DATATYPE_INT8_S));
FORMAT_STRING(PHY_TX_POWER, (SPINEL_DATATYPE_INT8_S));
FORMAT_STRING(PROTOCOL_VERSION, (SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT_PACKED_S));
FORMAT_STRING(RADIO_CAPS, (SPINEL_DATATYPE_UINT_PACKED_S));
FORMAT_STRING(RCP_API_VERSION, (SPINEL_DATATYPE_UINT_PACKED_S));
FORMAT_STRING(MAC_15_4_LADDR, (SPINEL_DATATYPE_EUI64_S));
FORMAT_STRING(MAC_15_4_PANID, (SPINEL_DATATYPE_UINT16_S));
FORMAT_STRING(MAC_15_4_SADDR, (SPINEL_DATATYPE_UINT16_S));
FORMAT_STRING(MAC_PROMISCUOUS_MODE, (SPINEL_DATATYPE_UINT8_S));
FORMAT_STRING(PHY_ENABLED, (SPINEL_DATATYPE_BOOL_S));

FORMAT_STRING(STREAM_RAW, (SPINEL_DATATYPE_DATA_WLEN_S  // Frame data
			   SPINEL_DATATYPE_UINT8_S      // Channel
			   SPINEL_DATATYPE_UINT8_S      // MaxCsmaBackoffs
			   SPINEL_DATATYPE_UINT8_S      // MaxFrameRetries
			   SPINEL_DATATYPE_BOOL_S       // CsmaCaEnabled
			   SPINEL_DATATYPE_BOOL_S       // IsHeaderUpdated
			   SPINEL_DATATYPE_BOOL_S       // IsARetx
			   SPINEL_DATATYPE_BOOL_S       // SkipAes
			   SPINEL_DATATYPE_UINT32_S     // TxDelay
			   SPINEL_DATATYPE_UINT32_S))   // TxDelayBaseTime


typedef int (*postproc_func)(void *ctx, const uint8_t *buf, size_t len, size_t capacity,
			     spinel_tid_t tid, const char *fmt, va_list args);
typedef int (*s32_table_set_func)(struct otrcp *rcp, int8_t val);
typedef int (*s32_table_get_func)(struct otrcp *rcp, int8_t *val);

struct data_len {
	void *data;
	size_t len;
};

static uint spinel_max_frame_size = 8192;

module_param(spinel_max_frame_size, uint, S_IRUGO);

static int postproc_return(void *ctx, const uint8_t *buf, size_t len, size_t capacity,
			   spinel_tid_t tid, const char *fmt, va_list args)
{
	return len;
}

static int postproc_unpack(void *ctx, const uint8_t *buf, size_t len, size_t capacity,
			   spinel_tid_t tid, const char *fmt, va_list args)
{
	return spinel_datatype_vunpack_in_place(buf, len, fmt, args);
}

static int postproc_stream_raw_tid(void *ctx, const uint8_t *buf, size_t len, size_t capacity,
				   spinel_tid_t tid, const char *fmt, va_list args)
{
	spinel_tid_t *ptid = ctx;
	*ptid = tid;
	return len;
}

static int postproc_data_array_unpack(void *out, size_t out_len, const uint8_t *data, size_t len,
				      const char *fmt, size_t datasize)
{
	int remains = out_len;
	void *start = out;
	int rc;

	while (len > 0) {
		if (remains <= 0) {
			pr_debug("%s: %d shortage \n", __func__, __LINE__);
			return -ENOBUFS;
		}

		if ((rc = spinel_datatype_unpack(data, len, fmt, out)) < 0) {
			pr_debug("%s: %d rc=%d\n", __func__, __LINE__, rc);
			return rc;
		}

		data += rc;
		out += datasize;
		len -= rc;
		remains -= datasize;
	}

	return (out - start) / datasize;
}

static int postproc_array_unpack_packed_int(void *ctx, const uint8_t *buf, size_t len,
					    size_t capacity, spinel_tid_t tid, const char *fmt,
					    va_list args)
{
	struct data_len *out = ctx;
	return postproc_data_array_unpack(out->data, out->len, buf, len,
					  SPINEL_DATATYPE_UINT_PACKED_S, sizeof(uint32_t));
}

static int postproc_array_unpack_uint8(void *ctx, const uint8_t *buf, size_t len, size_t capacity,
				       spinel_tid_t tid, const char *fmt, va_list args)
{
	struct data_len *out = ctx;
	return postproc_data_array_unpack(out->data, out->len, buf, len, SPINEL_DATATYPE_UINT8_S,
					  sizeof(uint8_t));
}

static int spinel_prop_command(uint8_t *buffer, size_t length, uint32_t command,
			       spinel_prop_key_t key, spinel_tid_t tid, const char *format,
			       va_list args)
{
	int packed;
	uint16_t offset;

	// pr_debug("start %s:%d\n", __func__, __LINE__);
	//  Pack the header, command and key
	packed = spinel_datatype_pack(buffer, length, "Cii",
				      SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0 | tid, command, key);

	if (packed < 0) {
		pr_debug("%s: %d\n", __func__, __LINE__);
		return packed;
	}

	if (!(packed > 0 && packed <= sizeof(buffer))) {
		pr_debug("%s: %d\n", __func__, __LINE__);
		return -ENOBUFS;
	}

	offset = packed;

	// Pack the data (if any)
	if (format) {
		packed = spinel_datatype_vpack(buffer + offset, length - offset, format, args);

		if (packed < 0) {
			pr_debug("%s: %d\n", __func__, __LINE__);
			return packed;
		}

		if (!(packed > 0 && (packed + offset) <= length)) {
			pr_debug("%s: %d\n", __func__, __LINE__);
			return -ENOBUFS;
		}

		offset += packed;
	}

	pr_debug("end %s:%d\n", __func__, __LINE__);
	return offset;
}

static int otrcp_put_expected_info(struct sk_buff *skb, uint32_t cmd, spinel_prop_key_t key,
				   spinel_tid_t tid, size_t offset, size_t len,
				   struct otrcp_received_data_verify *pexpected)

{
	struct otrcp_received_data_verify expected = {0};
	int rc = 0;

	pr_debug("otrcp_put_excepted_info offset=%d\n", offset);

	if (pexpected) {
		pexpected->enabled = true;
	} else {
		pexpected = &expected;
		pexpected->enabled = false;
	}
	pexpected->key = key;
	pexpected->tid = tid;
	pexpected->cmd = cmd;
	pexpected->offset = offset;

	{
		memcpy(skb_put(skb, sizeof(struct otrcp_received_data_verify)), pexpected,
		       sizeof(struct otrcp_received_data_verify));
	}

	return 0;
}

static int otrcp_format_command_skb_v(struct otrcp *rcp, uint32_t cmd, spinel_prop_key_t key,
				      struct sk_buff *skb, postproc_func postproc, void *ctx,
				      struct otrcp_received_data_verify *pexpected, const char *fmt,
				      va_list args)
{
	int rc;
	uint8_t *send_buffer;
	size_t send_buflen = spinel_max_frame_size;
	spinel_tid_t tid = SPINEL_GET_NEXT_TID(rcp->tid);
	size_t offset;

	send_buffer = kmalloc(spinel_max_frame_size, GFP_KERNEL);
	if (!send_buffer) {
		return -ENOMEM;
	}

	if (cmd == SPINEL_CMD_RESET) {
		//rc = spinel_reset_command(send_buffer, send_buflen, 0, 0, 0, fmt, args);
		rc = spinel_prop_command(send_buffer, send_buflen, cmd, 0, 0, NULL, 0);
	} else if (cmd == SPINEL_CMD_PROP_VALUE_SET) {
		rcp->tid = tid;
		rc = spinel_prop_command(send_buffer, send_buflen, cmd, key, tid, fmt, args);
	} else if (cmd == SPINEL_CMD_PROP_VALUE_GET) {
		rcp->tid = tid;
		rc = spinel_prop_command(send_buffer, send_buflen, cmd, key, tid, NULL, args);
	} else {
		rc = -EINVAL;
	}

	if (rc < 0) {
		goto exit;
	}

	offset = skb->len;

	pr_debug("offset =%lu len=%d\n", offset, rc);

	memcpy(skb_put(skb, rc), send_buffer, rc);

	otrcp_put_expected_info(skb, cmd, key, tid, offset, rc, pexpected);
exit:
	kfree(send_buffer);
	return tid;
}

static int otrcp_spinel_send_command_v(struct otrcp *rcp, struct sk_buff *skb,
				       postproc_func postproc, void *ctx, const char *fmt,
				       va_list args)
{
	int rc;
	uint8_t *recv_buffer;
	size_t recv_buflen = spinel_max_frame_size;
	size_t sent_bytes = 0;
	size_t received_bytes = 0;
	struct otrcp_received_data_verify expected;
	size_t verify_size = sizeof(struct otrcp_received_data_verify);

	// pr_debug("%s %d\n", __func__, __LINE__);
	recv_buffer = kmalloc(spinel_max_frame_size, GFP_KERNEL);
	if (!recv_buffer) {
		return -ENOMEM;
	}

	expected = *(
		(struct otrcp_received_data_verify *)(skb->data +
						      (skb->len -
						       sizeof(struct otrcp_received_data_verify))));

	pr_debug("offset=%ld cmd=%u, key=%d tid=%u verify_cmd=%d verify_key=%d verify_tid=%d "
		 "enabled=%d\n",
		 expected.offset, expected.cmd, expected.key, expected.tid, expected.verify_cmd,
		 expected.verify_key, expected.verify_tid, expected.enabled);

	if ((rc = rcp->send(rcp, skb->data + expected.offset,
			    skb->len - (verify_size + expected.offset), &sent_bytes)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		goto exit;
	}

	//if (expected.key == SPINEL_PROP_STREAM_RAW) {
	if (expected.cmd == SPINEL_CMD_PROP_VALUE_GET
	    || expected.cmd == SPINEL_CMD_PROP_VALUE_SET) {
		skb_queue_tail(&rcp->xmit_queue, skb);
	}

	if (expected.enabled) {
		uint32_t cmd = expected.cmd;
		expected.cmd = otrcp_spinel_expected_command(expected.cmd);
		rc = rcp->wait_response(rcp, recv_buffer, recv_buflen, &received_bytes,
						&expected);
	}

	if (rc < 0) {
		dev_dbg(rcp->parent, "%s rc=%d\n", __func__, rc);
		print_hex_dump(KERN_INFO, "recv>>: ", DUMP_PREFIX_NONE, 16, 1, recv_buffer,
			       received_bytes, true);
	} else if (postproc) {
		rc = postproc(ctx, recv_buffer, rc, recv_buflen, expected.tid, fmt, args);
	}

exit:
	kfree(recv_buffer);
	return rc;
}

static int otrcp_spinel_command(struct otrcp *rcp, uint32_t cmd, spinel_prop_key_t key,
				struct otrcp_received_data_verify *expected, postproc_func postproc,
				void *ctx, const char *fmt, ...)
{
	va_list args;
	int rc;

	struct sk_buff *skb;

	skb = alloc_skb(spinel_max_frame_size, GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}

	skb_reserve(skb, sizeof(struct otrcp_received_data_verify));

	va_start(args, fmt);

	rc = otrcp_format_command_skb_v(rcp, cmd, key, skb, postproc, ctx, expected, fmt, args);
	if (rc < 0) {
		goto exit;
	}

	rc = otrcp_spinel_send_command_v(rcp, skb, postproc, ctx, fmt, args);

exit:
	va_end(args);

	if (rc < 0) {
		kfree_skb(skb);
	}
	return rc;
}

static int otrcp_format_command_skb(struct otrcp *rcp, uint32_t cmd, spinel_prop_key_t key,
				    struct sk_buff *skb, postproc_func postproc, void *ctx,
				    struct otrcp_received_data_verify *pexpected, const char *fmt,
				    ...)
{
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = otrcp_format_command_skb_v(rcp, cmd, key, skb, postproc, ctx, pexpected, fmt, args);
	va_end(args);

	return rc;
}

static int otrcp_spinel_send_command(struct otrcp *rcp, struct sk_buff *skb, postproc_func postproc,
				     void *ctx, const char *fmt, ...)
{
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = otrcp_spinel_send_command_v(rcp, skb, postproc, ctx, fmt, args);
	va_end(args);

	return rc;
}

/*
 * SPINEL commands
 */

static int otrcp_reset(struct otrcp *rcp, uint32_t reset)
{
	const uint8_t *buffer;
	size_t buflen;
	int rc;
	struct otrcp_received_data_verify expected = {
		false, false, true, otrcp_spinel_expected_command(SPINEL_CMD_RESET), 0, 0, 0, 0,
	};
	dev_dbg(rcp->parent, "start %s:%dn", __func__, __LINE__);
	buffer = kmalloc(spinel_max_frame_size, GFP_KERNEL);
	buflen = spinel_max_frame_size;
	pr_debug("spinel_max_frame_size =%u\n", spinel_max_frame_size);
	rc = otrcp_spinel_command(((struct otrcp *)rcp), SPINEL_CMD_RESET, 0, &expected,
				  postproc_return, NULL, spinel_data_format_str_RESET,
				  SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0, SPINEL_CMD_RESET,
				  reset);

	kfree(buffer);
	/*dev_dbg(rcp->parent, "end %s:%dn", __func__, __LINE__);*/
	return rc;
}

static int otrcp_set_stream_raw(struct otrcp *rcp, spinel_tid_t *ptid, struct sk_buff *skb_orig,
				uint8_t channel, uint8_t backoffs, uint8_t retries, bool csmaca,
				bool headerupdate, bool aretx, bool skipaes, uint32_t txdelay,
				uint32_t txdelay_base)
{
	int rc;

	struct sk_buff *skb;

	skb = alloc_skb(spinel_max_frame_size, GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}

	memcpy(skb_put(skb, skb_orig->len), skb_orig->data, skb_orig->len);

	rc = otrcp_format_command_skb(rcp, SPINEL_CMD_PROP_VALUE_SET, SPINEL_PROP_STREAM_RAW, skb,
				      postproc_stream_raw_tid, ptid, NULL,
				      spinel_data_format_str_STREAM_RAW, skb->data, skb->len,
				      channel, backoffs, retries, csmaca, headerupdate, aretx,
				      skipaes, txdelay, txdelay_base);
	if (rc < 0) {
		goto exit;
	}

	rc = otrcp_spinel_send_command(rcp, skb, postproc_stream_raw_tid, ptid,
				       spinel_data_format_str_STREAM_RAW, skb->data, skb->len,
				       channel, backoffs, retries, csmaca, headerupdate, aretx,
				       skipaes, txdelay, txdelay_base);

exit:
	if (rc < 0) {
		kfree_skb(skb);
	}
	return rc;
}

static int otrcp_get_caps(struct otrcp *rcp, uint32_t *caps, size_t caps_len)
{
	struct otrcp_received_data_verify expected = {
		true, true, true, 0, 0, 0, 0,
	};
	struct data_len datalen = {caps, sizeof(uint32_t) * caps_len};
	SPINEL_PROP_IMPL_V(CAPS, rcp, SPINEL_CMD_PROP_VALUE_GET, &expected,
			   postproc_array_unpack_packed_int, &datalen, caps, caps_len);
}

static int otrcp_get_phy_chan_supported(struct otrcp *rcp, uint8_t *phy_chan_supported,
					size_t chan_len)
{
	struct otrcp_received_data_verify expected = {
		true, true, true, 0, 0, 0, 0,
	};
	struct data_len datalen = {phy_chan_supported, chan_len};
	SPINEL_PROP_IMPL_V(PHY_CHAN_SUPPORTED, rcp, SPINEL_CMD_PROP_VALUE_GET, &expected,
			   postproc_array_unpack_uint8, &datalen, phy_chan_supported, chan_len);
}

static int otrcp_get_phy_rssi(struct otrcp *rcp, const uint8_t *rssi)
{
	SPINEL_GET_PROP_IMPL(PHY_RSSI, rcp, rssi);
}
static int otrcp_get_protocol_version(struct otrcp *rcp, const uint8_t *major, const uint8_t *minor)
{
	SPINEL_GET_PROP_IMPL(PROTOCOL_VERSION, rcp, major, minor);
}

static int otrcp_get_rcp_api_version(struct otrcp *rcp, uint32_t *rcp_api_version)
{
	SPINEL_GET_PROP_IMPL(RCP_API_VERSION, rcp, rcp_api_version);
}

static int otrcp_get_ncp_version(struct otrcp *rcp, const uint8_t *ncp_version, size_t len)
{
	SPINEL_GET_PROP_IMPL(NCP_VERSION, rcp, ncp_version, len);
}

static int otrcp_get_radio_caps(struct otrcp *rcp, uint32_t *radio_caps)
{
	SPINEL_GET_PROP_IMPL(RADIO_CAPS, rcp, radio_caps);
}

static int otrcp_get_hwaddr(struct otrcp *rcp, const uint8_t *hwaddr)
{
	SPINEL_GET_PROP_IMPL(HWADDR, rcp, hwaddr);
}

static int otrcp_get_phy_cca_threshold(struct otrcp *rcp, s8 *level)
{
	SPINEL_GET_PROP_IMPL(PHY_CCA_THRESHOLD, rcp, level);
}

static int otrcp_get_phy_chan(struct otrcp *rcp, const uint8_t *chan)
{
	SPINEL_GET_PROP_IMPL(PHY_CHAN, rcp, chan);
}

static int otrcp_get_phy_tx_power(struct otrcp *rcp, s8 *power)
{
	SPINEL_GET_PROP_IMPL(PHY_TX_POWER, rcp, power);
}

static int otrcp_set_enable(struct otrcp *rcp, bool enabled)
{
	SPINEL_SET_PROP_IMPL(PHY_ENABLED, rcp, enabled);
}

static int otrcp_set_panid(struct otrcp *rcp, u16 panid)
{
	SPINEL_SET_PROP_IMPL(MAC_15_4_PANID, rcp, panid);
}

static int otrcp_set_saddr(struct otrcp *rcp, u16 saddr)
{
	SPINEL_SET_PROP_IMPL(MAC_15_4_SADDR, rcp, saddr);
}

static int otrcp_set_laddr(struct otrcp *rcp, u64 laddr)
{
	SPINEL_SET_PROP_IMPL(MAC_15_4_LADDR, rcp, &laddr);
}

static int otrcp_set_mac_promiscuous_mode(struct otrcp *rcp, uint8_t on)
{
	SPINEL_SET_PROP_IMPL(MAC_PROMISCUOUS_MODE, rcp, on);
}

static int otrcp_set_phy_cca_threshold(struct otrcp *rcp, s8 ed_level)
{
	SPINEL_SET_PROP_IMPL(PHY_CCA_THRESHOLD, rcp, ed_level);
}

static int otrcp_set_phy_tx_power(struct otrcp *rcp, s8 power)
{
	SPINEL_SET_PROP_IMPL(PHY_TX_POWER, rcp, power);
}

static int otrcp_set_phy_chan(struct otrcp *rcp, u8 chan)
{
	SPINEL_SET_PROP_IMPL(PHY_CHAN, rcp, chan);
}

static int otrcp_get_s32_table(struct otrcp *rcp, s32 *table, size_t *sz,
			       s32_table_set_func set_table, s32_table_get_func get_table)
{
	int i, rc;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	*sz = 0;
	for (i = S8_MIN; i < S8_MAX; i++) {
		int8_t value;

		if ((rc = set_table(rcp, i)) < 0)
			continue;

		if ((rc = get_table(rcp, &value)) < 0)
			continue;

		if (*sz == 0 || table[(*sz - 1)] != (value * 100)) {
			table[*sz] = value * 100;
			*sz += 1;
		}
	}

	if ((rc = set_table(rcp, 0)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

static int otrcp_get_tx_power_table(struct otrcp *rcp, s32 *powers, size_t *sz)
{
	return otrcp_get_s32_table(rcp, powers, sz, otrcp_set_phy_tx_power, otrcp_get_phy_tx_power);
}

static int otrcp_get_cca_ed_level_table(struct otrcp *rcp, s32 *ed_levels, size_t *sz)
{
	return otrcp_get_s32_table(rcp, ed_levels, sz, otrcp_set_phy_cca_threshold,
				   otrcp_get_phy_cca_threshold);
}

static bool otrcp_has_caps(struct otrcp *rcp, uint32_t cap)
{
	int i;
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	for (i = 0; i < rcp->caps_size; i++) {
		if (rcp->caps[i] == cap) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return true;
		}
	}
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return false;
}

static int otrcp_check_rcp_supported(struct otrcp *rcp)
{
	uint32_t kRequiredRadioCaps = OT_RADIO_CAPS_ACK_TIMEOUT | OT_RADIO_CAPS_TRANSMIT_RETRIES |
				      OT_RADIO_CAPS_CSMA_BACKOFF;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	if (!otrcp_has_caps(rcp, SPINEL_CAP_MAC_RAW) &&
	    !otrcp_has_caps(rcp, SPINEL_CAP_CONFIG_RADIO)) {
		dev_err(rcp->parent, "%s: Radic co-processor function not supported\n", __func__);
		return -ENOTSUPP;
	}

	if (rcp->protocol_version_major != SPINEL_PROTOCOL_VERSION_THREAD_MAJOR ||
	    rcp->protocol_version_minor != SPINEL_PROTOCOL_VERSION_THREAD_MINOR) {
		dev_err(rcp->parent, "%s: Not supported spinel version %u.%u\n", __func__,
			rcp->protocol_version_major, rcp->protocol_version_minor);
		return -ENOTSUPP;
	}

	if ((rcp->rcp_api_version < SPINEL_MIN_HOST_SUPPORTED_RCP_API_VERSION) ||
	    (rcp->rcp_api_version > SPINEL_RCP_API_VERSION)) {
		dev_err(rcp->parent, "%s: Not supported RCP API version %u\n", __func__,
			rcp->rcp_api_version);
		return -ENOTSUPP;
	}

	if ((rcp->radio_caps & kRequiredRadioCaps) != kRequiredRadioCaps) {
		uint32_t missingCaps = (rcp->radio_caps & kRequiredRadioCaps) ^ kRequiredRadioCaps;

		dev_dbg(rcp->parent, "RCP is missing required capabilities: %s%s%s%s%s",
			(missingCaps & OT_RADIO_CAPS_ACK_TIMEOUT) ? "ack-timeout " : "",
			(missingCaps & OT_RADIO_CAPS_TRANSMIT_RETRIES) ? "tx-retries " : "",
			(missingCaps & OT_RADIO_CAPS_CSMA_BACKOFF) ? "CSMA-backoff " : "",
			(missingCaps & OT_RADIO_CAPS_TRANSMIT_SEC) ? "tx-security " : "",
			(missingCaps & OT_RADIO_CAPS_TRANSMIT_TIMING) ? "tx-timing " : "");

		return -ENOTSUPP;
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

static int ParseRadioFrame(struct otrcp *rcp, const uint8_t *buf, size_t len, struct sk_buff *skb,
			   uint8_t *channel, int8_t *lqi)
{
	int rc = 0;
	uint16_t flags = 0;
	int8_t noiseFloor = -128;
	spinel_size_t size = spinel_max_frame_size; // OT_RADIO_FRAME_MAX_SIZE;
	unsigned int receiveError = 0;
	spinel_ssize_t unpacked;
	int8_t rssi = 0;
	uint64_t timestamp = 0;
	uint32_t ackFrameCounter;
	uint8_t ackKeyId;

	uint8_t *work = kmalloc(spinel_max_frame_size, GFP_KERNEL);

	unpacked = spinel_datatype_unpack_in_place(buf, len,
		SPINEL_DATATYPE_DATA_WLEN_S		// Frame
		SPINEL_DATATYPE_INT8_S			// RSSI
		SPINEL_DATATYPE_INT8_S			// Noise Floor
		SPINEL_DATATYPE_UINT16_S		// Flags
		SPINEL_DATATYPE_STRUCT_S(		// PHY-data
			SPINEL_DATATYPE_UINT8_S		// 802.15.4 channel
			SPINEL_DATATYPE_UINT8_S		// 802.15.4 LQI
			SPINEL_DATATYPE_UINT64_S	// Timestamp (us).
		) SPINEL_DATATYPE_STRUCT_S(		// Vendor-data
			SPINEL_DATATYPE_UINT_PACKED_S	// Receive error
		),
		work, &size, &rssi, &noiseFloor, &flags,
		channel, lqi, &timestamp, &receiveError);

	memcpy(skb_put(skb, size), work, size);

	rc = unpacked;
	if (unpacked < 0) {
		goto exit;
	}

	buf += unpacked;
	len -= unpacked;

	if (receiveError == 0 && (rcp->radio_caps & OT_RADIO_CAPS_TRANSMIT_SEC)) {
		pr_debug("TRANSMIT_SEC\n");
		unpacked = spinel_datatype_unpack_in_place( buf, len,
			SPINEL_DATATYPE_STRUCT_S(	 // MAC-data
				SPINEL_DATATYPE_UINT8_S	 // Security key index
				SPINEL_DATATYPE_UINT32_S // Security frame counter
			),
			&ackKeyId, &ackFrameCounter);

		if (unpacked < 0) {
			rc = unpacked;
			goto exit;
		}

		rc += unpacked;
	}

	pr_debug("Channel %u", *channel);
	pr_debug("LQI %u", *lqi);
	pr_debug("data size %d", size);
	pr_debug("RSSI %d", rssi);
	pr_debug("noiseFloor %d", noiseFloor);
	pr_debug("flags %x", flags);
	pr_debug("Timestamp %llu", timestamp);
	pr_debug("AckKeyId %u", ackKeyId);
	pr_debug("AckFrameCounter %u", ackFrameCounter);

exit:
	return rc;
}

static int extract_stream_raw_response(struct otrcp *rcp, const uint8_t *buf, size_t len)
{
	int unpacked;
	spinel_status_t status;
	bool framePending = false;
	bool headerUpdated = false;
	int8_t lqi;
	uint8_t channel;
	struct sk_buff *skb;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	unpacked = spinel_datatype_unpack(buf, len, SPINEL_DATATYPE_UINT_PACKED_S, &status);

	dev_dbg(rcp->parent, "status=%d %d\n", status, unpacked);

	if (unpacked < 0)
		return -1;

	buf += unpacked;
	len -= unpacked;

	unpacked = spinel_datatype_unpack(buf, len, SPINEL_DATATYPE_BOOL_S, &framePending);
	if (unpacked < 0)
		return -1;

	dev_dbg(rcp->parent, "framePending=%d %d\n", framePending, unpacked);

	buf += unpacked;
	len -= unpacked;

	unpacked = spinel_datatype_unpack(buf, len, SPINEL_DATATYPE_BOOL_S, &headerUpdated);
	if (unpacked < 0)
		return -1;

	dev_dbg(rcp->parent, "headerUpdated=%d\n", headerUpdated);

	buf += unpacked;
	len -= unpacked;

	skb = alloc_skb(spinel_max_frame_size, GFP_KERNEL);

	unpacked = ParseRadioFrame(rcp, buf, len, skb, &channel, &lqi);

	kfree_skb(skb);

	buf += unpacked;
	len -= unpacked;

	print_hex_dump(KERN_INFO, "raw_resp>>: ", DUMP_PREFIX_NONE, 16, 1, buf, len, true);
	return len;
}

int otrcp_verify_received_data(struct otrcp *rcp, const uint8_t *buf, size_t len, uint8_t **data,
			       spinel_size_t *data_len, struct otrcp_received_data_verify *expected)
{
	uint8_t hdr;
	uint32_t cmd;
	spinel_prop_key_t key;
	spinel_tid_t tid;

	int rc;

	if ((rc = spinel_datatype_unpack(buf, len, "CiiD", &hdr, &cmd, &key, data, data_len)) < 0) {
		return rc;
	}

	if (len < *data_len) {
		return -ENOBUFS;
	}

	tid = SPINEL_HEADER_GET_TID(hdr);

	if (((expected->tid == tid) || !expected->verify_tid) &&
	    ((expected->cmd == cmd) || !expected->verify_cmd) &&
	    ((expected->key == key) || !expected->verify_key)) {

		rc = *data_len;
	} else {
		dev_dbg(rcp->parent,
			"unpack cmd=%u(expected=%u), key=%u(expected=%u), "
			"tid=%u(expected=%u), data=%p, data_len=%u\n",
			cmd, otrcp_spinel_expected_command(expected->cmd), key, expected->key,
			SPINEL_HEADER_GET_TID(hdr), expected->tid, data, *data_len);
		rc = -EINVAL;
	}

	return rc;
}

int otrcp_spinel_receive_type(struct otrcp *rcp, const uint8_t *buf, size_t count)
{
	int rc;
	uint8_t header;
	uint32_t cmd;
	spinel_prop_key_t key;
	spinel_tid_t tid;
	uint8_t *data = NULL;
	spinel_size_t len = 0;

	if ((rc = spinel_datatype_unpack(buf, count, "C", &header)) < 0) {
		return -1;
	}
	tid = SPINEL_HEADER_GET_TID(header);

	pr_debug("%s:%d\n", __func__, __LINE__);

	if (tid == 0) {
		rc = spinel_datatype_unpack(buf, count, "CiiD", &header, &cmd, &key, &data, &len);
		pr_debug("*************** header=%x, cmd=%d, key=%d, tid=%d data=%p, len=%u\n", header, cmd, key,
			 tid, data, len);
		if (rc > 0 && cmd == SPINEL_CMD_PROP_VALUE_IS) {
			pr_debug("%s:%d\n", __func__, __LINE__);

			if (key == SPINEL_PROP_STREAM_RAW) {
				uint8_t chan;
				int8_t lqi;
				struct sk_buff *skb = alloc_skb(spinel_max_frame_size, GFP_KERNEL);
				pr_debug("============== RECEIVE STREAM_RAW %s:%d\n", __func__,
					 __LINE__);
				print_hex_dump(KERN_INFO, "data>>: ", DUMP_PREFIX_NONE, 16, 1, data,
					       len, true);
				rc = ParseRadioFrame(rcp, data, len, skb, &chan, &lqi);
				// skb_trim(skb, skb->len - 2);
				print_hex_dump(KERN_INFO, "payl>>: ", DUMP_PREFIX_NONE, 16, 1,
					       skb->data, skb->len, true);
				ieee802154_rx_irqsafe(rcp->hw, skb, lqi);

				pr_debug("============== END RECEIVE STREAM_RAW %s:%d %d\n",
					 __func__, __LINE__, rc);
				// kfree_skb(skb);

				return kSpinelReceiveDone;
			} else {
				return kSpinelReceiveNotification;
			}
		} else {
			struct sk_buff *skb;
			while ((skb = skb_dequeue(&rcp->xmit_queue)) != NULL) {
				pr_debug("%s:%d drop\n", __func__, __LINE__);
			}

		}
		pr_debug("%s:%d\n", __func__, __LINE__);
		return -1;
	} else {
		struct sk_buff *skb;
		rc = spinel_datatype_unpack(buf, count, "CiiD", &header, &cmd, &key, &data, &len);
		pr_debug("header=%x, cmd=%d, key=%d, tid=%d data=%p, len=%u\n", header, cmd, key,
			 tid, data, len);

		if (skb_queue_len(&rcp->xmit_queue) != 1) {
			pr_debug("skb_queue_lne = %d\n", skb_queue_len(&rcp->xmit_queue));
		}

		while ((skb = skb_dequeue(&rcp->xmit_queue)) != NULL) {
			// uint32_t *offset = skb_pull(skb, sizeof(uint32_t));
			pr_debug("skb->len=%d\n", skb->len);
			struct otrcp_received_data_verify expected;
			uint32_t offset = skb->len - sizeof(struct otrcp_received_data_verify);
			expected = *((struct otrcp_received_data_verify *)(skb->data + offset));
			pr_debug("==== offset=%ld cmd=%u, key=%d tid=%u verify_cmd=%d "
				 "verify_key=%d verify_tid=%d enabled=%d\n",
				 expected.offset, expected.cmd, expected.key, expected.tid,
				 expected.verify_cmd, expected.verify_key, expected.verify_tid,
				 expected.enabled);
			pr_debug("offset =%d\n", offset);
			pr_debug("tx expected.tid=%d tid=%d\n", expected.tid, tid);
			skb_trim(skb, expected.offset);

			if (expected.key == SPINEL_PROP_STREAM_RAW) {
				if (tid == expected.tid && skb->len == rcp->tx_skb->len &&
				    memcmp(skb->data, rcp->tx_skb->data, skb->len) == 0) {
					print_hex_dump(KERN_INFO, "comp>>: ", DUMP_PREFIX_NONE, 16, 1,
						       skb->data, skb->len, true);
					extract_stream_raw_response(rcp, data, len);
					pr_debug("xmit_complete %d %p\n", tid, rcp->tx_skb);
					ieee802154_xmit_complete(rcp->hw, rcp->tx_skb, false);
					return kSpinelReceiveDone;
				} else {
					print_hex_dump(KERN_INFO, "fail>>: ", DUMP_PREFIX_NONE, 16, 1,
						       skb->data, skb->len, true);
					ieee802154_xmit_hw_error(rcp->hw, rcp->tx_skb);
					pr_debug("xmit_hw_error %d\n", tid);
					return kSpinelReceiveDone;
				}
			} else {
			       	if (tid == expected.tid) {
				       	pr_debug("%s:%d\n", __func__, __LINE__);
				       	return kSpinelReceiveResponse;
			       	} else {
					pr_debug("------------ not handled %s:%d\n", __func__, __LINE__);
				       	pr_debug("%s:%d\n", __func__, __LINE__);
					return kSpinelReceiveDone;
			       	}
			}
		}

		if (tid == rcp->tid) {
			pr_debug("%s:%d\n", __func__, __LINE__);
			return kSpinelReceiveResponse;
		} else {
			return -1;
		}
	}

	pr_debug("%s:%d\n", __func__, __LINE__);
	return -1;
}

/*
 * IEEE802.15.4 APIs
 */

int otrcp_set_channel(struct ieee802154_hw *hw, u8 page, u8 channel)
{
	int rc;
	pr_debug("%s %d\n", __func__, channel);
	rc = otrcp_set_phy_chan(hw->priv, channel);
	pr_debug("%s %d\n", __func__, rc);
	rc = otrcp_get_phy_chan(hw->priv, &channel);
	pr_debug("%s %d\n", __func__, channel);
	return 0;
}

int otrcp_set_tx_power(struct ieee802154_hw *hw, s32 power)
{
	int rc;
	char pow;
	pr_debug("%s %d\n", __func__, power);
	rc = otrcp_set_phy_tx_power(hw->priv, (s8)(power / 100));
	pr_debug("%s %d\n", __func__, rc);
	rc = otrcp_get_phy_tx_power(hw->priv, &pow);
	pr_debug("%s %d\n", __func__, pow);
	return 0;
}

int otrcp_set_cca_mode(struct ieee802154_hw *hw, const struct wpan_phy_cca *cca)
{
	pr_debug("%s %d %d\n", __func__, cca->mode, cca->opt);
	return 0;
}

int otrcp_set_cca_ed_level(struct ieee802154_hw *hw, s32 ed_level)
{
	int rc;
	char lv;
	pr_debug("%s %d\n", __func__, ed_level);
	rc = otrcp_set_phy_cca_threshold(hw->priv, (s8)(ed_level / 100));
	pr_debug("%s %d\n", __func__, rc);
	rc = otrcp_get_phy_cca_threshold(hw->priv, &lv);
	pr_debug("%s %d\n", __func__, lv);
	return 0;
}

int otrcp_set_csma_params(struct ieee802154_hw *hw, u8 min_be, u8 max_be, u8 retries)
{
	struct otrcp *rcp = hw->priv;

	dev_dbg(rcp->parent, "%s(%p, %u, %u, %u)\n", __func__, hw, min_be, max_be, retries);
	rcp->csma_min_be = min_be;
	rcp->csma_max_be = max_be;
	rcp->csma_retries = retries;

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

int otrcp_set_frame_retries(struct ieee802154_hw *hw, s8 max_frame_retries)
{
	struct otrcp *rcp = hw->priv;

	dev_dbg(rcp->parent, "%s(%p, %d)\n", __func__, hw, max_frame_retries);
	rcp->max_frame_retries = max_frame_retries;
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

int otrcp_set_promiscuous_mode(struct ieee802154_hw *hw, const bool on)
{
	int rc;

	pr_debug("%s(%p, %d)\n", __func__, hw, on);
	rc = otrcp_set_mac_promiscuous_mode(hw->priv, on);
	pr_debug("end %s:%d\n", __func__, __LINE__);
	return rc;
}

int otrcp_start(struct ieee802154_hw *hw)
{
	struct otrcp *rcp = hw->priv;
	int rc, i;

	dev_dbg(rcp->parent, "%s(%p)\n", __func__, hw);

	otrcp_reset(rcp, SPINEL_RESET_STACK);

	if ((rc = otrcp_get_ncp_version(rcp, rcp->ncp_version, sizeof(rcp->ncp_version))) < 0) {
		dev_dbg(rcp->parent, "end %s@%d %d\n", __func__, __LINE__, rc);
		return rc;
	}

	if ((rc = otrcp_get_protocol_version(rcp, &rcp->protocol_version_major,
					     &rcp->protocol_version_minor)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_get_hwaddr(rcp, rcp->hwaddr)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_get_caps(rcp, rcp->caps, rcp->caps_size)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if (otrcp_has_caps(rcp, SPINEL_CAP_RCP_API_VERSION)) {
		if ((rc = otrcp_get_rcp_api_version(rcp, &rcp->rcp_api_version)) < 0)
			return rc;
	}

	if ((rc = otrcp_get_radio_caps(rcp, &rcp->radio_caps)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_get_phy_chan(rcp, &hw->phy->current_channel)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_get_cca_ed_level_table(rcp, rcp->cca_ed_levels, &rcp->cca_ed_levels_size)) <
	    0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_get_tx_power_table(rcp, rcp->tx_powers, &rcp->tx_powers_size)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_check_rcp_supported(rcp)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if ((rc = otrcp_get_phy_chan_supported(rcp, rcp->phy_chan_supported,
					       sizeof(rcp->phy_chan_supported))) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rcp->phy_chan_supported_size = rc;

	for (i = 0; i < rcp->phy_chan_supported_size; i++) {
		hw->phy->supported.channels[0] |= BIT(rcp->phy_chan_supported[i]);
	}

	hw->phy->supported.cca_modes = BIT(NL802154_CCA_ENERGY);
	hw->phy->supported.cca_opts = 0;
	hw->phy->supported.lbt = false;
	hw->phy->supported.min_minbe = 3;
	hw->phy->supported.max_minbe = 3;
	hw->phy->supported.min_maxbe = 5;
	hw->phy->supported.max_maxbe = 5;
	hw->phy->supported.min_csma_backoffs = 0;
	hw->phy->supported.max_csma_backoffs = 16;
	hw->phy->supported.min_frame_retries = 0;
	hw->phy->supported.max_frame_retries = 16;
	hw->phy->cca.mode = NL802154_CCA_ENERGY;
	hw->flags = IEEE802154_HW_CSMA_PARAMS | IEEE802154_HW_FRAME_RETRIES | IEEE802154_HW_AFILT |
		    IEEE802154_HW_PROMISCUOUS;
	hw->phy->flags =
		WPAN_PHY_FLAG_TXPOWER | WPAN_PHY_FLAG_CCA_ED_LEVEL | WPAN_PHY_FLAG_CCA_MODE;
	hw->phy->supported.cca_ed_levels = rcp->cca_ed_levels;
	hw->phy->supported.cca_ed_levels_size = rcp->cca_ed_levels_size;
	hw->phy->supported.tx_powers = rcp->tx_powers;
	hw->phy->supported.tx_powers_size = rcp->tx_powers_size;

	if ((rc = otrcp_set_enable(rcp, true)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

void otrcp_stop(struct ieee802154_hw *hw)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;
	dev_dbg(rcp->parent, "%s %p\n", __func__, rcp);

	if ((rc = otrcp_set_enable(rcp, false)) < 0)
		dev_dbg(rcp->parent, "%s %d\n", __func__, rc);
}

int otrcp_xmit_async(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;
	spinel_tid_t tid;

	dev_dbg(rcp->parent, "%s %p\n", __func__, skb);

	rcp->tx_skb = skb;

	print_hex_dump(KERN_INFO, "xmit>>: ", DUMP_PREFIX_NONE, 16, 1, skb->data, skb->len, true);
	rc = otrcp_set_stream_raw(rcp, &tid, skb, hw->phy->current_channel, 4, 15,
				  !!(hw->flags & IEEE802154_HW_CSMA_PARAMS), false, false, false, 0,
				  0);


	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

int otrcp_ed(struct ieee802154_hw *hw, u8 *level)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;

	if ((rc = otrcp_get_phy_rssi(rcp, level)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

int otrcp_set_hw_addr_filt(struct ieee802154_hw *hw, struct ieee802154_hw_addr_filt *filt,
			   unsigned long changed)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;

	if (changed & IEEE802154_AFILT_PANC_CHANGED) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return -ENOTSUPP;
	}

	if (changed & IEEE802154_AFILT_IEEEADDR_CHANGED) {
		if ((rc = otrcp_set_laddr(rcp, filt->ieee_addr)) < 0) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return rc;
		}
	}

	if (changed & IEEE802154_AFILT_SADDR_CHANGED) {
		if ((rc = otrcp_set_saddr(rcp, filt->short_addr)) < 0) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return rc;
		}
	}

	if (changed & IEEE802154_AFILT_PANID_CHANGED) {
		if ((rc = otrcp_set_panid(rcp, le16_to_cpu(filt->pan_id))) < 0) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return rc;
		}
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}
