#ifndef RCP_COMMON_H__
#define RCP_COMMON_H__

#include "spinel.h"

#include <linux/types.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

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

enum spinel_received_data_type {
	kSpinelReceiveUnknown = 0,
	kSpinelReceiveResponse = 1,
	kSpinelReceiveNotification = 2,
};

struct otrcp {
	struct ieee802154_hw *hw;
	struct device *parent;

	uint8_t csma_min_be;
	uint8_t csma_max_be;
	uint8_t csma_retries;
	int8_t max_frame_retries;

	uint8_t tid;

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

	int (*send)(void *ctx, uint8_t *buf, size_t len, size_t *sent_bytes,
		    uint32_t cmd, spinel_prop_key_t key, spinel_tid_t tid);
	int (*resp)(void *ctx, uint8_t *buf, size_t len, size_t *received_bytes,
		    uint32_t cmd, spinel_prop_key_t key, spinel_tid_t tid,
		    bool validate_cmd, bool validate_key, bool validate_tid);

	int (*wait_notify)(void *ctx, uint8_t *buf, size_t len, size_t *received_bytes,
		    uint32_t cmd, spinel_prop_key_t key, spinel_tid_t tid,
		    bool validate_cmd, bool validate_key, bool validate_tid);

	uint8_t prev_send[8192];
	spinel_tid_t prev_tid;
	spinel_prop_key_t prev_key;
};

struct ieee802154_hw;
struct ieee802154_hw_addr_filt;
struct sk_buff;
struct wpan_phy_cca;

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

enum spinel_received_data_type otrcp_spinel_receive_type(struct otrcp *rcp, const uint8_t *buf, size_t count);
void otrcp_handle_notification(struct otrcp *rcp, const uint8_t *buf, size_t count);

static inline uint32_t spinel_expected_command(uint32_t cmd)
{
	switch (cmd) {
	case SPINEL_CMD_PROP_VALUE_SET:
		return SPINEL_CMD_PROP_VALUE_IS;
	case SPINEL_CMD_PROP_VALUE_INSERT:
		return SPINEL_CMD_PROP_VALUE_INSERTED;
	case SPINEL_CMD_PROP_VALUE_REMOVE:
		return SPINEL_CMD_PROP_VALUE_REMOVED;
	}
	return 0;
}

#endif // RCP_COMMON_H__
