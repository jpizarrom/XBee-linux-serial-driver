#ifndef RCP_COMMON_H__
#define RCP_COMMON_H__

#include "spinel.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tty.h>
#include <linux/types.h>
#include <net/mac802154.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

#define SPINEL_PROP_ARRAY_EXTRACT(prop, data, len, fmt, datasize)                                  \
	{                                                                                          \
		struct spinel_command cmd;                                                         \
		uint8_t *work_buffer;                                                              \
		size_t work_len;                                                                   \
		int rc;                                                                            \
                                                                                                   \
		work_buffer = kmalloc(rcp->spinel_max_frame_size, GFP_KERNEL);                     \
		work_len = rcp->spinel_max_frame_size;                                             \
		SETUP_SPINEL_COMMAND(cmd, rcp);                                                    \
		rc = spinel_prop_get(&cmd, __CONCAT(SPINEL_PROP_, prop), spinel_data_format_str_ ## prop, work_buffer, &work_len);              \
		if (rc < 0) {                                                                      \
			pr_err("%s: spinel_get_caps() failed: %d\n", __func__, rc);                \
			goto end;                                                                  \
		}                                                                                  \
		rc = spinel_data_array_unpack(data, len, work_buffer, rc, fmt, datasize);          \
		if (rc < 0) {                                                                      \
			pr_err("%s: spinel_data_unpack() failed: %d\n", __func__, rc);             \
			goto end;                                                                  \
		}                                                                                  \
	end:                                                                                       \
		kfree(work_buffer);                                                                \
		return rc;                                                                         \
	}

#define SPINEL_PROP_IMPL(setget, prop, rcp, ...)                                                   \
	{                                                                                          \
		struct spinel_command cmd;                                                         \
		int rc;                                                                            \
		SETUP_SPINEL_COMMAND(cmd, ((struct otrcp *)(rcp)));                                \
		rc = CONCATENATE(CONCATENATE(SPINEL_, setget), prop)(&cmd, __VA_ARGS__);           \
		if (rc < 0) {                                                                      \
			pr_err("%s: Failed SPINEL_" #setget #prop "(): %d\n", __func__, rc);       \
		}                                                                                  \
		return rc;                                                                         \
	}

#define SPINEL_GET_PROP_IMPL(prop, rcp, ...)                                                       \
	{                                                                                          \
		struct spinel_command cmd;                                                         \
		int rc;                                                                            \
		SETUP_SPINEL_COMMAND(cmd, ((struct otrcp *)(rcp)));                                \
		rc = spinel_prop_get(&cmd, __CONCAT(SPINEL_PROP_, prop), spinel_data_format_str_ ## prop, __VA_ARGS__);              \
		return rc;                                                                         \
	}

#define SPINEL_SET_PROP_IMPL(prop, rcp, ...)                                                       \
	{                                                                                          \
		struct spinel_command cmd;                                                         \
		int rc;                                                                            \
		SETUP_SPINEL_COMMAND(cmd, ((struct otrcp *)(rcp)));                                \
		rc = spinel_prop_set(&cmd, __CONCAT(SPINEL_PROP_, prop), spinel_data_format_str_ ## prop, __VA_ARGS__);              \
		return rc;                                                                         \
	}

#define SPINEL_GET_PROP(prop, rcp, ...) SPINEL_PROP_IMPL(GET_, prop, (rcp), __VA_ARGS__)
#define SPINEL_SET_PROP(prop, rcp, ...) SPINEL_PROP_IMPL(SET_, prop, (rcp), __VA_ARGS__)

#define SPINEL_FUNC_PROP_GET(prop, fmt)                                                            \
	static inline int __CONCAT(SPINEL_GET_, prop)(struct spinel_command * cmd, ...)            \
	{                                                                                          \
		int rc;                                                                            \
		va_list args;                                                                      \
		va_start(args, cmd);                                                               \
		rc = spinel_prop_get_v(cmd, __CONCAT(SPINEL_PROP_, prop), fmt, args);              \
		va_end(args);                                                                      \
		return rc;                                                                         \
	}

#define SPINEL_FUNC_PROP_SET(prop, fmt)                                                            \
	static inline int __CONCAT(SPINEL_SET_, prop)(struct spinel_command * cmd, ...)            \
	{                                                                                          \
		int rc;                                                                            \
		va_list args;                                                                      \
		va_start(args, cmd);                                                               \
		rc = spinel_prop_set_v(cmd, __CONCAT(SPINEL_PROP_, prop), fmt, args);              \
		va_end(args);                                                                      \
		return rc;                                                                         \
	}

#define SPINEL_FUNC_RESET(fmt)                                                                     \
	static inline int SPINEL_RESET(struct spinel_command *cmd, ...)                            \
	{                                                                                          \
		va_list args;                                                                      \
		int err;                                                                           \
                                                                                                   \
		mutex_lock(cmd->send_mutex);                                                       \
		va_start(args, cmd);                                                               \
		err = spinel_reset_command(cmd->buffer, cmd->length, fmt, args);                   \
		va_end(args);                                                                      \
		if (err >= 0) {                                                                    \
			err = cmd->send(cmd->ctx, cmd->buffer, err, SPINEL_CMD_RESET, 0, 0);       \
		}                                                                                  \
		mutex_unlock(cmd->send_mutex);                                                     \
		err = cmd->resp(cmd->ctx, cmd->buffer, cmd->length, SPINEL_CMD_RESET, 0, 0);       \
		return err;                                                                        \
	}



#define SETUP_SPINEL_COMMAND(cmd, rcp) rcp->spinel_command_setup(&cmd, rcp)

enum {
	OT_RADIO_CAPS_NONE = 0,		    ///< Radio supports no capability.
	OT_RADIO_CAPS_ACK_TIMEOUT = 1 << 0, ///< Radio supports AckTime event.
	OT_RADIO_CAPS_ENERGY_SCAN = 1 << 1, ///< Radio supports Energy Scans.
	OT_RADIO_CAPS_TRANSMIT_RETRIES =
		1 << 2, ///< Radio supports tx retry logic with collision avoidance (CSMA).
	OT_RADIO_CAPS_CSMA_BACKOFF =
		1 << 3, ///< Radio supports CSMA backoff for frame transmission (but no retry).
	OT_RADIO_CAPS_SLEEP_TO_TX =
		1 << 4, ///< Radio supports direct transition from sleep to TX with CSMA.
	OT_RADIO_CAPS_TRANSMIT_SEC = 1 << 5,	///< Radio supports tx security.
	OT_RADIO_CAPS_TRANSMIT_TIMING = 1 << 6, ///< Radio supports tx at specific time.
	OT_RADIO_CAPS_RECEIVE_TIMING = 1 << 7,	///< Radio supports rx at specific time.
};

enum {
	// kMaxSpinelFrame        = SpinelInterface::kMaxFrameSize,
	kMaxWaitTime = 2000,	  ///< Max time to wait for response in milliseconds.
	kVersionStringSize = 128, ///< Max size of version string.
	kCapsBufferSize = 100,	  ///< Max buffer size used to store `SPINEL_PROP_CAPS` value.
	kChannelMaskBufferSize =
		32, ///< Max buffer size used to store `SPINEL_PROP_PHY_CHAN_SUPPORTED` value.
};


struct spinel_command {
	uint8_t *buffer;
	size_t length;
	spinel_tid_t tid;
	int (*send)(void *ctx, uint8_t *buf, size_t len, uint32_t cmd, spinel_prop_key_t key,
		    spinel_tid_t tid);
	int (*resp)(void *ctx, uint8_t *buf, size_t len, uint32_t cmd, spinel_prop_key_t key,
		    spinel_tid_t tid);
	void *ctx;
	struct mutex *send_mutex;
	struct mutex *resp_mutex;
};

struct otrcp {
	struct ieee802154_hw *hw;
	struct device *parent;

	uint8_t csma_min_be;
	uint8_t csma_max_be;
	uint8_t csma_retries;
	int8_t max_frame_retries;

	uint8_t ncp_version[kVersionStringSize];
	uint8_t protocol_version_major;
	uint8_t protocol_version_minor;
	uint32_t rcp_api_version;

	uint32_t radio_caps;
	uint32_t caps[kCapsBufferSize];
	size_t caps_size;

	int32_t tx_powers[U8_MAX];
	size_t tx_powers_size;

	int32_t cca_ed_levels[U8_MAX];
	size_t cca_ed_levels_size;

	size_t spinel_max_frame_size;
	uint16_t scan_period;

	uint8_t phy_chan_supported[32];
	size_t phy_chan_supported_size;

	uint8_t hwaddr[8];

	void (*spinel_command_setup)(struct spinel_command *cmd, struct otrcp *rcp);
};

int otrcp_set_channel(struct ieee802154_hw *hw, u8 page, u8 channel);
int otrcp_set_tx_power(struct ieee802154_hw *hw, s32 power);
int otrcp_set_cca_mode(struct ieee802154_hw *hw, const struct wpan_phy_cca *cca);
int otrcp_set_cca_ed_level(struct ieee802154_hw *hw, s32 ed_level);
int otrcp_set_csma_params(struct ieee802154_hw *hw, u8 min_be, u8 max_be, u8 retries);
int otrcp_set_frame_retries(struct ieee802154_hw *hw, s8 max_frame_retries);
int otrcp_set_promiscuous_mode(struct ieee802154_hw *hw, const bool on);
int otrcp_start(struct ieee802154_hw *hw);
void otrcp_stop(struct ieee802154_hw *hw);
int otrcp_xmit_async(struct ieee802154_hw *hw, struct sk_buff *skb);
int otrcp_ed(struct ieee802154_hw *hw, u8 *level);
int otrcp_set_hw_addr_filt(struct ieee802154_hw *hw, struct ieee802154_hw_addr_filt *filt,
			   unsigned long changed);










uint32_t spinel_expected_command(uint32_t cmd);

int spinel_command(uint8_t *buffer, size_t length, uint32_t aCommand, spinel_prop_key_t aKey,
		   spinel_tid_t tid, const char *aFormat, va_list args);

int spinel_reset_command(uint8_t *buffer, size_t length, const char *aFormat, va_list args);

int spinel_prop_get_v(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt,
		      va_list args);
int spinel_prop_get(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt, ...);

int spinel_prop_set_v(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt,
		      va_list args);
int spinel_prop_set(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt, ...);

int spinel_data_array_unpack(void *out, size_t out_len, uint8_t *data, size_t len, const char *fmt,
			     size_t datasize);

#define SPINEL_FORMAT_STRING(prop, format) static const char CONCATENATE(*spinel_data_format_str_, prop) = format;

SPINEL_FUNC_RESET((SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT_PACKED_S));

SPINEL_FORMAT_STRING(CAPS, (SPINEL_DATATYPE_DATA_S));
SPINEL_FORMAT_STRING(HWADDR, (SPINEL_DATATYPE_EUI64_S));
SPINEL_FORMAT_STRING(NCP_VERSION, (SPINEL_DATATYPE_UTF8_S));
SPINEL_FORMAT_STRING(PHY_CCA_THRESHOLD, (SPINEL_DATATYPE_INT8_S));
SPINEL_FORMAT_STRING(PHY_CHAN, (SPINEL_DATATYPE_UINT8_S));
SPINEL_FORMAT_STRING(PHY_CHAN_PREFERRED, (SPINEL_DATATYPE_DATA_S));
SPINEL_FORMAT_STRING(PHY_CHAN_SUPPORTED, (SPINEL_DATATYPE_DATA_S));
SPINEL_FORMAT_STRING(PHY_FEM_LNA_GAIN, (SPINEL_DATATYPE_INT8_S));
SPINEL_FORMAT_STRING(PHY_REGION_CODE, (SPINEL_DATATYPE_UINT16_S));
SPINEL_FORMAT_STRING(PHY_RSSI, (SPINEL_DATATYPE_INT8_S));
SPINEL_FORMAT_STRING(PHY_RX_SENSITIVITY, (SPINEL_DATATYPE_INT8_S));
SPINEL_FORMAT_STRING(PHY_TX_POWER, (SPINEL_DATATYPE_INT8_S));
SPINEL_FORMAT_STRING(PROTOCOL_VERSION,
		     (SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT_PACKED_S));
SPINEL_FORMAT_STRING(RADIO_CAPS, (SPINEL_DATATYPE_UINT_PACKED_S));
SPINEL_FORMAT_STRING(RADIO_COEX_ENABLE, (SPINEL_DATATYPE_BOOL_S));
SPINEL_FORMAT_STRING(
	RADIO_COEX_METRICS,
	(SPINEL_DATATYPE_STRUCT_S(
		SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
			SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
				SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S)
		 SPINEL_DATATYPE_STRUCT_S(
			 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
				 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
					 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S
						 SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S)
			 SPINEL_DATATYPE_BOOL_S SPINEL_DATATYPE_UINT32_S));
SPINEL_FORMAT_STRING(RCP_API_VERSION, (SPINEL_DATATYPE_UINT_PACKED_S));
SPINEL_FORMAT_STRING(THREAD_ACTIVE_DATASET, (SPINEL_DATATYPE_VOID_S));
SPINEL_FORMAT_STRING(THREAD_PENDING_DATASET, (SPINEL_DATATYPE_VOID_S));
SPINEL_FORMAT_STRING(MAC_15_4_LADDR, (SPINEL_DATATYPE_EUI64_S));
SPINEL_FORMAT_STRING(MAC_15_4_PANID, (SPINEL_DATATYPE_UINT16_S));
SPINEL_FORMAT_STRING(MAC_15_4_SADDR, (SPINEL_DATATYPE_UINT16_S));
SPINEL_FORMAT_STRING(MAC_PROMISCUOUS_MODE, (SPINEL_DATATYPE_UINT8_S));
SPINEL_FORMAT_STRING(MAC_RAW_STREAM_ENABLED, (SPINEL_DATATYPE_UTF8_S));
SPINEL_FORMAT_STRING(MAC_SCAN_MASK, (SPINEL_DATATYPE_DATA_S));
SPINEL_FORMAT_STRING(MAC_SCAN_PERIOD, (SPINEL_DATATYPE_UINT16_S));
SPINEL_FORMAT_STRING(MAC_SCAN_STATE, (SPINEL_DATATYPE_UINT8_S));
SPINEL_FORMAT_STRING(NEST_STREAM_MFG, (SPINEL_DATATYPE_UTF8_S));
SPINEL_FORMAT_STRING(PHY_CHAN_MAX_POWER, (SPINEL_DATATYPE_UINT8_S SPINEL_DATATYPE_INT8_S));
SPINEL_FORMAT_STRING(PHY_ENABLED, (SPINEL_DATATYPE_BOOL_S));
SPINEL_FORMAT_STRING(RCP_ENH_ACK_PROBING,
		     (SPINEL_DATATYPE_UINT16_S SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_UINT8_S));
SPINEL_FORMAT_STRING(RCP_MAC_FRAME_COUNTER, (SPINEL_DATATYPE_UINT32_S));
SPINEL_FORMAT_STRING(RCP_MAC_KEY,
		     (SPINEL_DATATYPE_UINT8_S SPINEL_DATATYPE_UINT8_S SPINEL_DATATYPE_DATA_WLEN_S
			      SPINEL_DATATYPE_DATA_WLEN_S SPINEL_DATATYPE_DATA_WLEN_S));

/*
SPINEL_FUNC_PROP_SET(MAC_SRC_MATCH_ENABLED
//Set( MAC_SRC_MATCH_ENABLED, SPINEL_DATATYPE_BOOL_S, aEnable);
SPINEL_FUNC_PROP_SET(MAC_SRC_MATCH_EXTENDED_ADDRESSES
//Set( MAC_SRC_MATCH_EXTENDED_ADDRESSES, nullptr));
SPINEL_FUNC_PROP_SET(MAC_SRC_MATCH_SHORT_ADDRESSES
//Set( MAC_SRC_MATCH_SHORT_ADDRESSES, nullptr));
*/








#endif // RCP_COMMON_H__
