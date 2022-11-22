#include "otrcp_common.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/mac802154.h>

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

#define SPINEL_PROP_ARRAY_EXTRACT(prop, data, len, fmt, datasize)                                  \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
                                                                                                   \
	/*dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);*/                             \
	buffer = kmalloc((rcp)->spinel_max_frame_size, GFP_KERNEL);                                \
	buflen = (rcp)->spinel_max_frame_size;                                                     \
	rc = otrcp_spinel_prop_get(((struct otrcp *)rcp), buffer, buflen,                          \
				   CONCATENATE(SPINEL_PROP_, prop), spinel_data_format_str_##prop, \
				   buffer, &buflen);                                               \
	if (rc >= 0) {                                                                             \
		rc = spinel_data_array_unpack(data, len, buffer, rc, fmt, datasize);               \
	}                                                                                          \
	kfree(buffer);                                                                             \
	if (rc < 0) {                                                                              \
		dev_err(rcp->parent, "%s: spinel_data_unpack() failed: %d\n", __func__, rc);       \
	}                                                                                          \
	/*dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);*/                               \
	return rc;

int simple_return(struct otrcp *rcp, uint8_t *buf, size_t len)
{
	return len;
}

#define SPINEL_GET_PROP_IMPL_X(prop, rcp, postproc, ...)                                           \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
	/*dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);*/                             \
	buffer = kmalloc((rcp)->spinel_max_frame_size, GFP_KERNEL);                                \
	buflen = (rcp)->spinel_max_frame_size;                                                     \
	rc = otrcp_spinel_prop_get(((struct otrcp *)rcp), buffer, buflen,                          \
				   CONCATENATE(SPINEL_PROP_, prop), spinel_data_format_str_##prop, \
				   __VA_ARGS__);                                                   \
	if (rc >= 0) {                                                                             \
		rc = postproc(rcp, buffer, rc);                                                    \
	}                                                                                          \
	kfree(buffer);                                                                             \
	/*dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);*/                               \
	return rc;

bool isnull(void * ptr) { return !(ptr); }

#define SPINEL_GET_PROP_IMPL(prop, rcp, ...)                                                       \
	SPINEL_GET_PROP_IMPL_X(prop, rcp, simple_return, __VA_ARGS__)

#define SPINEL_SET_PROP_IMPL_X(prop, rcp, postproc, expected, ...) \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
	/*dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);*/                             \
	buffer = kmalloc((rcp)->spinel_max_frame_size, GFP_KERNEL);                                \
	buflen = rcp->spinel_max_frame_size;                                                       \
	if (!isnull(expected)) { \
	(expected)->key = CONCATENATE(SPINEL_PROP_, prop); \
	rc = otrcp_spinel_prop_set(((struct otrcp *)rcp), buffer, buflen,                          \
				   CONCATENATE(SPINEL_PROP_, prop), expected,    \
				   spinel_data_format_str_##prop, __VA_ARGS__);      \
	if (rc >= 0) {                                                                             \
		rc = postproc(rcp, buffer, rc);                                                    \
	}                                                                                          \
	kfree(buffer);                                                                             \
	} \
	/*dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);*/                               \
	return rc;

#define SPINEL_SET_PROP_IMPL(prop, rcp, ...)                                                       \
	struct otrcp_received_data_verify expected = { \
		0,	      0, \
		0,	      true, \
		true, true, \
	}; \
	\
	SPINEL_SET_PROP_IMPL_X(prop, rcp, simple_return, &expected, __VA_ARGS__)

#define SPINEL_RESET_IMPL_X(rcp, postproc, ...)                                                    \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);                                 \
	buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);                                  \
	buflen = rcp->spinel_max_frame_size;                                                       \
	rc = otrcp_spinel_reset(                                                                   \
		((struct otrcp *)rcp), buffer, buflen, spinel_data_format_str_RESET,               \
		SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0, SPINEL_CMD_RESET, __VA_ARGS__);          \
	if (rc >= 0) {                                                                             \
		rc = postproc(rcp, buffer, rc);                                                    \
	}                                                                                          \
	kfree(buffer);                                                                             \
	/*dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);*/                               \
	return rc;

#define SPINEL_RESET_IMPL(rcp, ...) SPINEL_RESET_IMPL_X(rcp, simple_return, __VA_ARGS__)

static int spinel_reset_command(uint8_t *buffer, size_t length, const char *format, va_list args)
{
	int packed;

	// pr_debug("start %s:%d\n", __func__, __LINE__);
	//  Pack the header, command and key
	packed = spinel_datatype_vpack(buffer, length, format, args);

	if (packed < 0) {
		pr_debug("end %s:%d\n", __func__, __LINE__);
		return packed;
	}

	if (!(packed > 0 && packed <= sizeof(buffer))) {
		pr_debug("end %s:%d\n", __func__, __LINE__);
		return -ENOBUFS;
	}

	// pr_debug("end %s:%d\n", __func__, __LINE__);
	return packed;
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

	// pr_debug("end %s:%d\n", __func__, __LINE__);
	return offset;
}

static int spinel_data_array_unpack(void *out, size_t out_len, uint8_t *data, size_t len,
				    const char *fmt, size_t datasize)
{
	int rc;
	int remains = out_len;
	void *start = out;

	// pr_debug("start %s:%d\n", __func__, __LINE__);
	while (len > 0) {
		if (remains <= 0) {
			pr_debug("%s: %d shotrage \n", __func__, __LINE__);
			return -1;
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

	// pr_debug("end %s:%d\n", __func__, __LINE__);
	return (out - start) / datasize;
}

static int otrcp_spinel_prop_get_v(struct otrcp *rcp, uint8_t *buffer, size_t length,
				   spinel_prop_key_t key, const char *fmt, va_list args)
{
	int err;
	uint8_t *recv_buffer;
	size_t recv_buflen;
	size_t sent_bytes = 0;
	size_t received_bytes = 0;
	spinel_tid_t tid = SPINEL_GET_NEXT_TID(rcp->tid);

	struct otrcp_received_data_verify expected = {
		tid,  otrcp_spinel_expected_command(SPINEL_CMD_PROP_VALUE_SET), key, true, true,
		true,
	};

	recv_buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);
	if (!recv_buffer) {
		return -ENOMEM;
	}
	recv_buflen = rcp->spinel_max_frame_size;
	rcp->tid = tid;

	// dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	err = spinel_prop_command(buffer, length, SPINEL_CMD_PROP_VALUE_GET, key, tid, NULL, 0);
	if (err >= 0) {
		err = rcp->send(rcp, buffer, err, &sent_bytes, SPINEL_CMD_PROP_VALUE_SET, key, tid);
	}
	if (err < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return err;
	}

	err = rcp->wait_response(rcp, buffer, length, &received_bytes, &expected);
	if (err < 0) {
		dev_dbg(rcp->parent, "%s buf=%p, len=%lu, key=%u, tid=%u\n", __func__, buffer,
			length, key, tid);
		return err;
	}
	err = spinel_datatype_vunpack_in_place(buffer, err, fmt, args);
	kfree(recv_buffer);
	// dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return err;
}

static int otrcp_spinel_prop_get(struct otrcp *rcp, uint8_t *buffer, size_t length,
				 spinel_prop_key_t key, const char *fmt, ...)
{
	va_list args;
	int rc;
	// dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	va_start(args, fmt);
	rc = otrcp_spinel_prop_get_v(rcp, buffer, length, key, fmt, args);
	va_end(args);
	// dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return rc;
}

static int otrcp_spinel_prop_set_v(struct otrcp *rcp, uint8_t *buffer, size_t length,
				   spinel_prop_key_t key, struct otrcp_received_data_verify *expected,
				   const char *fmt, va_list args)
{
	int err;
	uint8_t *recv_buffer;
	size_t recv_buflen = rcp->spinel_max_frame_size;
	size_t sent_bytes = 0;
	size_t received_bytes = 0;
	spinel_tid_t tid = SPINEL_GET_NEXT_TID(rcp->tid);

	expected->tid = tid;
	expected->cmd = otrcp_spinel_expected_command(SPINEL_CMD_PROP_VALUE_SET);

	recv_buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);
	if (!recv_buffer) {
		return -ENOMEM;
	}
	recv_buflen = rcp->spinel_max_frame_size;
	rcp->tid = tid;

	// dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	err = spinel_prop_command(buffer, length, SPINEL_CMD_PROP_VALUE_SET, key, tid, fmt, args);
	if (err >= 0) {
		err = rcp->send(rcp, buffer, err, &sent_bytes, SPINEL_CMD_PROP_VALUE_SET, key, tid);
	}

	if (err < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return err;
	}

	err = rcp->wait_response(rcp, recv_buffer, recv_buflen, &received_bytes, expected);
	if (err < 0) {
		dev_dbg(rcp->parent, "%s err=%d\n", __func__, err);
		print_hex_dump(KERN_INFO, "send>>: ", DUMP_PREFIX_NONE, 16, 1, buffer, sent_bytes,
			       true);
		print_hex_dump(KERN_INFO, "recv>>: ", DUMP_PREFIX_NONE, 16, 1, recv_buffer,
			       received_bytes, true);
	} else {
		memcpy(buffer, recv_buffer, recv_buflen);
	}
	kfree(recv_buffer);
	// dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return err;
}

static int otrcp_spinel_prop_set(struct otrcp *rcp, uint8_t *buffer, size_t length,
				 spinel_prop_key_t key, struct otrcp_received_data_verify *expected,
				 const char *fmt, ...)
{
	va_list args;
	int rc;

	// dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	va_start(args, fmt);
	rc = otrcp_spinel_prop_set_v(rcp, buffer, length, key, expected, fmt, args);
	va_end(args);
	// dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return rc;
}

static int otrcp_spinel_reset_v(struct otrcp *rcp, uint8_t *buffer, size_t length, const char *fmt,
				va_list args)
{
	int err;
	uint8_t *recv_buffer;
	size_t recv_buflen = rcp->spinel_max_frame_size;
	size_t sent_bytes = 0;
	size_t received_bytes = 0;
	struct otrcp_received_data_verify expected = {
		0, otrcp_spinel_expected_command(SPINEL_CMD_RESET), 0, false, false, true,
	};

	recv_buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);
	if (!recv_buffer) {
		return -ENOMEM;
	}
	recv_buflen = rcp->spinel_max_frame_size;
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	err = spinel_reset_command(buffer, length, fmt, args);
	if (err >= 0) {
		err = rcp->send(rcp, buffer, err, &sent_bytes, SPINEL_CMD_RESET, 0, 0);
	}
	if (err >= 0) {
		err = rcp->wait_notify(rcp, recv_buffer, recv_buflen, &received_bytes, &expected);
	}

	if (err < 0) {
		dev_dbg(rcp->parent, "%s err=%d\n", __func__, err);
		print_hex_dump(KERN_INFO, "send>>: ", DUMP_PREFIX_NONE, 16, 1, buffer, sent_bytes,
			       true);
		print_hex_dump(KERN_INFO, "recv>>: ", DUMP_PREFIX_NONE, 16, 1, recv_buffer,
			       received_bytes, true);
	}
	kfree(recv_buffer);
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return err;
}

static int otrcp_spinel_reset(struct otrcp *rcp, uint8_t *buffer, size_t length, const char *fmt,
			      ...)
{
	va_list args;
	int rc;
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	va_start(args, fmt);
	rc = otrcp_spinel_reset_v(rcp, buffer, length, fmt, args);
	va_end(args);
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return rc;
}

/*
 * SPINEL commands
 */

static int otrcp_reset(struct otrcp *rcp, uint32_t reset)
{
	SPINEL_RESET_IMPL(rcp, reset)
}

static int otrcp_get_caps(struct otrcp *rcp, uint32_t *caps, size_t caps_len)
{
	SPINEL_PROP_ARRAY_EXTRACT(CAPS, caps, caps_len, SPINEL_DATATYPE_UINT_PACKED_S,
				  sizeof(uint32_t));
}

static int otrcp_get_phy_chan_supported(struct otrcp *rcp, uint8_t *phy_chan_supported,
					size_t chan_len)
{
	SPINEL_PROP_ARRAY_EXTRACT(PHY_CHAN_SUPPORTED, phy_chan_supported, chan_len,
				  SPINEL_DATATYPE_UINT8_S, sizeof(uint8_t));
}

static int ParseRadioFrame(struct otrcp *rcp, const uint8_t *buf, size_t len, struct sk_buff *skb,
			   uint8_t *channel, int8_t *lqi)
{
	int rc = 0;
	uint16_t flags = 0;
	int8_t noiseFloor = -128;
	spinel_size_t size = 8192; // OT_RADIO_FRAME_MAX_SIZE;
	unsigned int receiveError = 0;
	spinel_ssize_t unpacked;
	int8_t rssi = 0;
	uint64_t timestamp = 0;
	uint32_t ackFrameCounter;
	uint8_t ackKeyId;

	uint8_t *work = kmalloc(8192, GFP_KERNEL);

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

int extract_stream_raw_response(struct otrcp *rcp, uint8_t *buf, size_t len)
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

	skb = alloc_skb(8192, GFP_KERNEL);

	unpacked = ParseRadioFrame(rcp, buf, len, skb, &channel, &lqi);

	kfree_skb(skb);

	buf += unpacked;
	len -= unpacked;

	print_hex_dump(KERN_INFO, "raw_resp>>: ", DUMP_PREFIX_NONE, 16, 1, buf, len, true);
	return len;
}

static int otrcp_set_stream_raw(struct otrcp *rcp, uint8_t *frame, uint16_t frame_length,
				uint8_t channel, uint8_t backoffs, uint8_t retries, bool csmaca,
				bool headerupdate, bool aretx, bool skipaes, uint32_t txdelay,
				uint32_t txdelay_base)
{
	struct otrcp_received_data_verify expected = {
		0,	      0,
		0,	      false,
		false, false,
	};
	SPINEL_SET_PROP_IMPL_X(STREAM_RAW, rcp, extract_stream_raw_response, &expected,
			       frame, frame_length, channel, backoffs, retries, csmaca,
			       headerupdate, aretx, skipaes, txdelay, txdelay_base);
}

static int otrcp_get_phy_rssi(struct otrcp *rcp, uint8_t *rssi)
{
	SPINEL_GET_PROP_IMPL(PHY_RSSI, rcp, rssi);
}
static int otrcp_get_protocol_version(struct otrcp *rcp, uint8_t *major, uint8_t *minor)
{
	SPINEL_GET_PROP_IMPL(PROTOCOL_VERSION, rcp, major, minor);
}

static int otrcp_get_rcp_api_version(struct otrcp *rcp, uint32_t *rcp_api_version)
{
	SPINEL_GET_PROP_IMPL(RCP_API_VERSION, rcp, rcp_api_version);
}

static int otrcp_get_ncp_version(struct otrcp *rcp, uint8_t *ncp_version, size_t len)
{
	SPINEL_GET_PROP_IMPL(NCP_VERSION, rcp, ncp_version, len);
}

static int otrcp_get_radio_caps(struct otrcp *rcp, uint32_t *radio_caps)
{
	SPINEL_GET_PROP_IMPL(RADIO_CAPS, rcp, radio_caps);
}

static int otrcp_get_hwaddr(struct otrcp *rcp, uint8_t *hwaddr)
{
	SPINEL_GET_PROP_IMPL(HWADDR, rcp, hwaddr);
}

static int otrcp_get_phy_cca_threshold(struct otrcp *rcp, s8 *level)
{
	SPINEL_GET_PROP_IMPL(PHY_CCA_THRESHOLD, rcp, level);
}

static int otrcp_get_phy_chan(struct otrcp *rcp, uint8_t *chan)
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

static int otrcp_get_tx_power_table(struct otrcp *rcp, s32 *powers, size_t *sz)
{
	int i, rc;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	*sz = 0;
	for (i = S8_MIN; i < S8_MAX; i++) {
		int8_t power;

		if ((rc = otrcp_set_phy_tx_power(rcp, i)) < 0)
			continue;

		if ((rc = otrcp_get_phy_tx_power(rcp, &power)) < 0)
			continue;

		if (*sz == 0 || powers[(*sz - 1)] != (power * 100)) {
			powers[*sz] = power * 100;
			*sz += 1;
		}
	}

	if ((rc = otrcp_set_phy_tx_power(rcp, 0)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

static int otrcp_get_cca_ed_level_table(struct otrcp *rcp, s32 *ed_levels, size_t *sz)
{
	int i, rc;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	*sz = 0;
	for (i = S8_MIN; i < S8_MAX; i++) {
		int8_t level;

		if ((rc = otrcp_set_phy_cca_threshold(rcp, i)) < 0)
			continue;

		if ((rc = otrcp_get_phy_cca_threshold(rcp, &level)) < 0)
			continue;

		if (*sz == 0 || ed_levels[(*sz - 1)] != (level * 100)) {
			ed_levels[*sz] = level * 100;
			*sz += 1;
		}
	}

	if ((rc = otrcp_set_phy_cca_threshold(rcp, 0)) < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
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

void otrcp_handle_notification(struct otrcp *rcp, const uint8_t *buf, size_t count)
{
}

enum spinel_received_data_type otrcp_spinel_receive_type(struct otrcp *rcp, const uint8_t *buf,
							 size_t count)
{
	int rc;
	uint8_t header;
	uint32_t cmd;
	spinel_prop_key_t key;
	spinel_tid_t tid;

	if ((rc = spinel_datatype_unpack(buf, count, "C", &header)) < 0) {
		return kSpinelReceiveUnknown;
	}
	tid = SPINEL_HEADER_GET_TID(header);

	pr_debug("tid %x\n", tid);

	if (tid == 0) {
		rc = spinel_datatype_unpack(buf, count, "Cii", &header, &cmd, &key);
		if (rc > 0 && cmd == SPINEL_CMD_PROP_VALUE_IS) {
			return kSpinelReceiveNotification;
		}
		return kSpinelReceiveUnknown;
	} else {
		if (tid == rcp->tid) {
			return kSpinelReceiveResponse;
		}
		else {
#if 0
			struct sk_buff *skb = skb_peek(&rcp->xmit_queue);
			/*
			do {
				if (!skb)
					break;

				spinel_tid_t sent_tid = *((spinel_tid_t*)(skb->data));
				if (tid == sent_tid) {
					pr_debug("ieee802154_xmit_complete\n");
					skb_pull(skb, sizeof(spinel_tid_t));
					ieee802154_xmit_complete(rcp->hw, skb, false);
				}
			} while ((skb = skb_queue_next(&rcp->xmit_queue, skb)));
			*/
#endif
			return kSpinelReceiveUnknown;
		}
	}

	return kSpinelReceiveUnknown;
}

int otrcp_validate_received_data(struct otrcp *rcp, uint8_t *buf, size_t len, uint8_t **data,
				 spinel_size_t *data_len,
				 struct otrcp_received_data_verify *expected)
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

	if (((expected->tid == tid) || !expected->validate_tid) &&
	    ((expected->cmd == cmd) || !expected->validate_cmd) &&
	    ((expected->key == key) || !expected->validate_key)) {

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
	hw->flags = IEEE802154_HW_OMIT_CKSUM | IEEE802154_HW_CSMA_PARAMS |
		    IEEE802154_HW_FRAME_RETRIES | IEEE802154_HW_AFILT | IEEE802154_HW_PROMISCUOUS;
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
	spinel_tid_t *tid_ptr;

	dev_dbg(rcp->parent, "%s %p\n", __func__, rcp);

	rc = otrcp_set_stream_raw(rcp, skb->data, skb->len, hw->phy->current_channel, 4, 15,
				  !!(hw->flags & IEEE802154_HW_CSMA_PARAMS), false, false, false, 0,
				  0);

	if (rc < 0) {
		dev_dbg(rcp->parent, "%s %d\n", __func__, rc);
		return rc;
	}

	tid_ptr = (spinel_tid_t *)skb_push(skb, sizeof(spinel_tid_t));
	*tid_ptr = 0;

	pr_debug("queue_tail xmit %p\n", skb);
	
	skb_queue_tail(&rcp->xmit_queue, skb);

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
