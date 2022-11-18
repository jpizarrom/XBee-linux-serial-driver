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
// FORMAT_STRING(PHY_CHAN_PREFERRED, (SPINEL_DATATYPE_DATA_S));
FORMAT_STRING(PHY_CHAN_SUPPORTED, (SPINEL_DATATYPE_DATA_S));
// FORMAT_STRING(PHY_FEM_LNA_GAIN, (SPINEL_DATATYPE_INT8_S));
// FORMAT_STRING(PHY_REGION_CODE, (SPINEL_DATATYPE_UINT16_S));
FORMAT_STRING(PHY_RSSI, (SPINEL_DATATYPE_INT8_S));
// FORMAT_STRING(PHY_RX_SENSITIVITY, (SPINEL_DATATYPE_INT8_S));
FORMAT_STRING(PHY_TX_POWER, (SPINEL_DATATYPE_INT8_S));
FORMAT_STRING(PROTOCOL_VERSION, (SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT_PACKED_S));
FORMAT_STRING(RADIO_CAPS, (SPINEL_DATATYPE_UINT_PACKED_S));
// FORMAT_STRING(RADIO_COEX_ENABLE, (SPINEL_DATATYPE_BOOL_S));
// FORMAT_STRING(
//	RADIO_COEX_METRICS,
//	(SPINEL_DATATYPE_STRUCT_S(
//		SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
//			SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
//				SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S)
//		 SPINEL_DATATYPE_STRUCT_S(
//			 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
//				 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
//					 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
//						 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S)
//			 SPINEL_DATATYPE_BOOL_S SPINEL_DATATYPE_UINT32_S));
FORMAT_STRING(RCP_API_VERSION, (SPINEL_DATATYPE_UINT_PACKED_S));
// FORMAT_STRING(THREAD_ACTIVE_DATASET, (SPINEL_DATATYPE_VOID_S));
// FORMAT_STRING(THREAD_PENDING_DATASET, (SPINEL_DATATYPE_VOID_S));
FORMAT_STRING(MAC_15_4_LADDR, (SPINEL_DATATYPE_EUI64_S));
FORMAT_STRING(MAC_15_4_PANID, (SPINEL_DATATYPE_UINT16_S));
FORMAT_STRING(MAC_15_4_SADDR, (SPINEL_DATATYPE_UINT16_S));
FORMAT_STRING(MAC_PROMISCUOUS_MODE, (SPINEL_DATATYPE_UINT8_S));
// FORMAT_STRING(MAC_RAW_STREAM_ENABLED, (SPINEL_DATATYPE_UTF8_S));
// FORMAT_STRING(MAC_SCAN_MASK, (SPINEL_DATATYPE_DATA_S));
// FORMAT_STRING(MAC_SCAN_PERIOD, (SPINEL_DATATYPE_UINT16_S));
// FORMAT_STRING(MAC_SCAN_STATE, (SPINEL_DATATYPE_UINT8_S));
// FORMAT_STRING(NEST_STREAM_MFG, (SPINEL_DATATYPE_UTF8_S));
// FORMAT_STRING(PHY_CHAN_MAX_POWER, (SPINEL_DATATYPE_UINT8_S SPINEL_DATATYPE_INT8_S));
FORMAT_STRING(PHY_ENABLED, (SPINEL_DATATYPE_BOOL_S));
// FORMAT_STRING(RCP_ENH_ACK_PROBING,
//		     (SPINEL_DATATYPE_UINT16_S SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_UINT8_S));
// FORMAT_STRING(RCP_MAC_FRAME_COUNTER, (SPINEL_DATATYPE_UINT32_S));
// FORMAT_STRING(RCP_MAC_KEY,
//		     (SPINEL_DATATYPE_UINT8_S SPINEL_DATATYPE_UINT8_S SPINEL_DATATYPE_DATA_WLEN_S
//			      SPINEL_DATATYPE_DATA_WLEN_S SPINEL_DATATYPE_DATA_WLEN_S));

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
/*
SPINEL_FUNC_PROP_SET(MAC_SRC_MATCH_ENABLED
//Set( MAC_SRC_MATCH_ENABLED, SPINEL_DATATYPE_BOOL_S, aEnable);
SPINEL_FUNC_PROP_SET(MAC_SRC_MATCH_EXTENDED_ADDRESSES
//Set( MAC_SRC_MATCH_EXTENDED_ADDRESSES, nullptr));
SPINEL_FUNC_PROP_SET(MAC_SRC_MATCH_SHORT_ADDRESSES
//Set( MAC_SRC_MATCH_SHORT_ADDRESSES, nullptr));
*/

#define SPINEL_PROP_ARRAY_PACK(prop, data, len, elemfmt, datasize)                                 \
	int rc, i;                                                                                 \
	char *fmt;                                                                                 \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
                                                                                                   \
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__); \
	buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);                                  \
	buflen = rcp->spinel_max_frame_size;                                                       \
	fmt = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);                                     \
	fmt[0] = '\0';                                                                             \
	strcat(fmt, (spinel_data_format_str_##prop));                                              \
	strcat(fmt, "(");                                                                          \
	for (i = 0; i < len; i++) {                                                                \
		strcat(fmt, elemfmt);                                                              \
	}                                                                                          \
	strcat(fmt, ")");                                                                          \
                                                                                                   \
	rc = otrcp_spinel_prop_set(rcp, buffer, buflen, CONCATENATE(SPINEL_PROP_, prop), fmt,      \
				   data, len);                                                     \
	kfree(buffer);                                                                             \
	kfree(fmt);                                                                                \
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__); \
	return rc;

#define SPINEL_PROP_ARRAY_EXTRACT(prop, data, len, fmt, datasize)                                  \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
                                                                                                   \
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__); \
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
		pr_err("%s: spinel_data_unpack() failed: %d\n", __func__, rc);                     \
	}                                                                                          \
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__); \
	return rc;

#define SPINEL_GET_PROP_IMPL(prop, rcp, ...)                                                       \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__); \
	buffer = kmalloc((rcp)->spinel_max_frame_size, GFP_KERNEL);                                \
	buflen = (rcp)->spinel_max_frame_size;                                                     \
	rc = otrcp_spinel_prop_get(((struct otrcp *)rcp), buffer, buflen,                          \
				   CONCATENATE(SPINEL_PROP_, prop), spinel_data_format_str_##prop, \
				   __VA_ARGS__);                                                   \
	kfree(buffer);                                                                             \
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__); \
	return rc;

#define SPINEL_SET_PROP_IMPL(prop, rcp, ...)                                                       \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__); \
	buffer = kmalloc((rcp)->spinel_max_frame_size, GFP_KERNEL);                                \
	buflen = rcp->spinel_max_frame_size;                                                       \
	rc = otrcp_spinel_prop_set(((struct otrcp *)rcp), buffer, buflen,                          \
				   CONCATENATE(SPINEL_PROP_, prop), spinel_data_format_str_##prop, \
				   __VA_ARGS__);                                                   \
	kfree(buffer);                                                                             \
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__); \
	return rc;

#define SPINEL_RESET_IMPL(rcp, ...)                                                                \
	uint8_t *buffer;                                                                           \
	size_t buflen;                                                                             \
	int rc;                                                                                    \
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__); \
	buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);                                  \
	buflen = rcp->spinel_max_frame_size;                                                       \
	rc = otrcp_spinel_reset(                                                                   \
		((struct otrcp *)rcp), buffer, buflen, spinel_data_format_str_RESET,               \
		SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0, SPINEL_CMD_RESET, __VA_ARGS__);          \
	kfree(buffer);                                                                             \
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__); \
	return rc;

static int spinel_reset_command(uint8_t *buffer, size_t length, const char *format, va_list args)
{
	int packed;

	pr_debug("start %s:%d\n", __func__, __LINE__);
	// Pack the header, command and key
	packed = spinel_datatype_vpack(buffer, length, format, args);

	if (packed < 0) {
		pr_debug("end %s:%d\n", __func__, __LINE__);
		return packed;
	}

	if (!(packed > 0 && packed <= sizeof(buffer))) {
		pr_debug("end %s:%d\n", __func__, __LINE__);
		return -ENOBUFS;
	}

	pr_debug("end %s:%d\n", __func__, __LINE__);
	return packed;
}

static int spinel_command(uint8_t *buffer, size_t length, uint32_t command, spinel_prop_key_t key,
			  spinel_tid_t tid, const char *format, va_list args)
{
	int packed;
	uint16_t offset;

	pr_debug("start %s:%d\n", __func__, __LINE__);
	// Pack the header, command and key
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

static int spinel_data_array_unpack(void *out, size_t out_len, uint8_t *data, size_t len,
				    const char *fmt, size_t datasize)
{
	int rc;
	int remains = out_len;
	void *start = out;

	pr_debug("start %s:%d\n", __func__, __LINE__);
	while (len > 0) {
		if (remains <= 0) {
			pr_debug("%s: %d shotrage \n", __func__, __LINE__);
			return -1;
		}
		rc = spinel_datatype_unpack(data, len, fmt, out);
		if (rc < 0) {
			pr_debug("%s: %d rc=%d\n", __func__, __LINE__, rc);
			return rc;
		}
		data += rc;
		out += datasize;
		len -= rc;
		remains -= datasize;
	}

	pr_debug("end %s:%d\n", __func__, __LINE__);
	return (out - start) / datasize;
}

static int otrcp_spinel_prop_get_v(struct otrcp *rcp, uint8_t *buffer, size_t length,
				   spinel_prop_key_t key, const char *fmt, va_list args)
{
	int err;

	spinel_tid_t tid = SPINEL_GET_NEXT_TID(rcp->tid);
	rcp->tid = tid;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	err = spinel_command(buffer, length, SPINEL_CMD_PROP_VALUE_GET, key, tid, NULL, 0);
	if (err >= 0) {
		err = rcp->send(rcp, buffer, err, SPINEL_CMD_PROP_VALUE_SET, key, tid);
	}
	if (err < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return err;
	}

	err = rcp->resp(rcp, buffer, length, SPINEL_CMD_PROP_VALUE_SET, key, tid);
	if (err < 0) {
		dev_dbg(rcp->parent, "%s buf=%p, len=%lu, key=%u, tid=%u\n", __func__, buffer, length,
			key, tid);
		return err;
	}
	err = spinel_datatype_vunpack_in_place(buffer, err, fmt, args);
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return err;
}

static int otrcp_spinel_prop_get(struct otrcp *rcp, uint8_t *buffer, size_t length,
				 spinel_prop_key_t key, const char *fmt, ...)
{
	va_list args;
	int rc;
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	va_start(args, fmt);
	rc = otrcp_spinel_prop_get_v(rcp, buffer, length, key, fmt, args);
	va_end(args);
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return rc;
}

static int otrcp_spinel_prop_set_v(struct otrcp *rcp, uint8_t *buffer, size_t length,
				   spinel_prop_key_t key, const char *fmt, va_list args)
{
	int err;

	spinel_tid_t tid = SPINEL_GET_NEXT_TID(rcp->tid);
	rcp->tid = tid;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	err = spinel_command(buffer, length, SPINEL_CMD_PROP_VALUE_SET, key, tid, fmt, args);
	if (err >= 0) {
		err = rcp->send(rcp, buffer, err, SPINEL_CMD_PROP_VALUE_SET, key, tid);
	}

	if (err < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return err;
	}

	if(key == SPINEL_PROP_STREAM_RAW) {
		dev_dbg(rcp->parent, "%s STREAM_RAW %d\n", __func__, err);
	}
	err = rcp->resp(rcp, buffer, length, SPINEL_CMD_PROP_VALUE_SET, key, tid);
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return err;
}

static int otrcp_spinel_prop_set(struct otrcp *rcp, uint8_t *buffer, size_t length,
				 spinel_prop_key_t key, const char *fmt, ...)
{
	va_list args;
	int rc;
	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	va_start(args, fmt);
	rc = otrcp_spinel_prop_set_v(rcp, buffer, length, key, fmt, args);
	va_end(args);
	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return rc;
}

static int otrcp_spinel_reset_v(struct otrcp *rcp, uint8_t *buffer, size_t length, const char *fmt,
				va_list args)
{
	int err;

	dev_dbg(rcp->parent, "start %s:%d\n", __func__, __LINE__);
	err = spinel_reset_command(buffer, length, fmt, args);
	if (err >= 0) {
		err = rcp->send(rcp, buffer, err, SPINEL_CMD_RESET, 0, 0);
	}
	err = rcp->resp(rcp, buffer, length, SPINEL_CMD_RESET, 0, 0);
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
/*
static int otrcp_set_mac_scan_mask(struct otrcp *rcp, uint8_t *mask, size_t len)
{
	SPINEL_PROP_ARRAY_PACK(MAC_SCAN_MASK, mask, len, SPINEL_DATATYPE_UINT8_S, sizeof(uint8_t))
}
*/

static int otrcp_set_stream_raw(struct otrcp *rcp, uint8_t *frame, uint8_t channel, uint8_t backoffs,
				uint8_t retries, bool csmaca, bool headerupdate, bool aretx,
				bool skipaes, uint32_t txdelay, uint32_t txdelay_base)
{
	SPINEL_SET_PROP_IMPL(STREAM_RAW, rcp, frame, channel, backoffs, retries,
				csmaca, headerupdate, aretx, skipaes, txdelay, txdelay_base);

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
/*
static int otrcp_set_scan_period(struct otrcp *rcp, uint16_t duration)
{
	SPINEL_SET_PROP_IMPL(MAC_SCAN_MASK, rcp, duration);
}

static int otrcp_set_scan_state(struct otrcp *rcp, uint8_t state)
{
	SPINEL_SET_PROP_IMPL(MAC_SCAN_STATE, rcp, state);
}
*/
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
		rc = otrcp_set_phy_tx_power(rcp, i);
		if (rc < 0)
			continue;

		rc = otrcp_get_phy_tx_power(rcp, &power);
		if (rc < 0)
			continue;

		if (*sz == 0 || powers[(*sz - 1)] != (power * 100)) {
			powers[*sz] = power * 100;
			*sz += 1;
		}
	}

	rc = otrcp_set_phy_tx_power(rcp, 0);
	if (rc < 0) {
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

		rc = otrcp_set_phy_cca_threshold(rcp, i);
		if (rc < 0)
			continue;

		rc = otrcp_get_phy_cca_threshold(rcp, &level);
		if (rc < 0)
			continue;

		if (*sz == 0 || ed_levels[(*sz - 1)] != (level * 100)) {
			ed_levels[*sz] = level * 100;
			*sz += 1;
		}
	}

	rc = otrcp_set_phy_cca_threshold(rcp, 0);
	if (rc < 0) {
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
		pr_err("%s: Radic co-processor function not supported\n", __func__);
		return -ENOTSUPP;
	}

	if (rcp->protocol_version_major != SPINEL_PROTOCOL_VERSION_THREAD_MAJOR ||
	    rcp->protocol_version_minor != SPINEL_PROTOCOL_VERSION_THREAD_MINOR) {
		pr_err("%s: Not supported spinel version %u.%u\n", __func__,
		       rcp->protocol_version_major, rcp->protocol_version_minor);
		return -ENOTSUPP;
	}

	if ((rcp->rcp_api_version < SPINEL_MIN_HOST_SUPPORTED_RCP_API_VERSION) ||
	    (rcp->rcp_api_version > SPINEL_RCP_API_VERSION)) {
		pr_err("%s: Not supported RCP API version %u\n", __func__, rcp->rcp_api_version);
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

	pr_debug("%s(%p)\n", __func__, hw);
	dev_dbg(rcp->parent, "ptr %s\n", dev_driver_string(&hw->phy->dev));

	otrcp_reset(rcp, SPINEL_RESET_STACK);

	rc = otrcp_get_ncp_version(rcp, rcp->ncp_version, sizeof(rcp->ncp_version));
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_protocol_version(rcp, &rcp->protocol_version_major,
					&rcp->protocol_version_minor);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_hwaddr(rcp, rcp->hwaddr);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_caps(rcp, rcp->caps, rcp->caps_size);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	if (otrcp_has_caps(rcp, SPINEL_CAP_RCP_API_VERSION)) {
		rc = otrcp_get_rcp_api_version(rcp, &rcp->rcp_api_version);
		if (rc < 0)
			return rc;
	}

	rc = otrcp_get_radio_caps(rcp, &rcp->radio_caps);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_phy_chan(rcp, &hw->phy->current_channel);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_cca_ed_level_table(rcp, rcp->cca_ed_levels, &rcp->cca_ed_levels_size);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_tx_power_table(rcp, rcp->tx_powers, &rcp->tx_powers_size);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_check_rcp_supported(rcp);
	if (rc < 0) {
		dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
		return rc;
	}

	rc = otrcp_get_phy_chan_supported(rcp, rcp->phy_chan_supported,
					  sizeof(rcp->phy_chan_supported));
	if (rc < 0) {
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

	rc = otrcp_set_enable(rcp, true);
	if (rc < 0) {
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
	rc = otrcp_set_enable(rcp, false);
	if (rc < 0)
		dev_dbg(rcp->parent, "%s %d\n", __func__, rc);
}


int otrcp_xmit_async(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;

	dev_dbg(rcp->parent, "%s %p\n", __func__, rcp);

	rc = otrcp_set_stream_raw(rcp, skb->data, hw->phy->current_channel, 4,
				  4, !!(hw->flags & IEEE802154_HW_CSMA_PARAMS), false, false,
				  false, 0, 0);

	dev_dbg(rcp->parent, "%s %d\n", __func__, rc);
	if (rc < 0) {
		print_hex_dump(KERN_INFO, "xmit>>: ", DUMP_PREFIX_NONE, 16, 1, skb->data,
			       skb->len, true);
		return 0; //TODO
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}

int otrcp_ed(struct ieee802154_hw *hw, u8 *level)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;

	rc = otrcp_get_phy_rssi(rcp, level);
	if (rc < 0) {
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
		rc = otrcp_set_laddr(rcp, filt->ieee_addr);
		if (rc < 0) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return rc;
		}
	}

	if (changed & IEEE802154_AFILT_SADDR_CHANGED) {
		rc = otrcp_set_saddr(rcp, filt->short_addr);
		if (rc < 0) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return rc;
		}
	}

	if (changed & IEEE802154_AFILT_PANID_CHANGED) {
		rc = otrcp_set_panid(rcp, le16_to_cpu(filt->pan_id));
		if (rc < 0) {
			dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
			return rc;
		}
	}

	dev_dbg(rcp->parent, "end %s:%d\n", __func__, __LINE__);
	return 0;
}
