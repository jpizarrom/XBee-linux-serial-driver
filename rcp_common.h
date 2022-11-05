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
		rc = CONCATENATE(SPINEL_GET_, prop)(&cmd, work_buffer, &work_len);                 \
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

#define SPINEL_GET_PROP(prop, rcp, ...) SPINEL_PROP_IMPL(GET_, prop, (rcp), __VA_ARGS__)
#define SPINEL_SET_PROP(prop, rcp, ...) SPINEL_PROP_IMPL(SET_, prop, (rcp), __VA_ARGS__)

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

#endif // RCP_COMMON_H__
