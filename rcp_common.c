#include "rcp_common.h"

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

static int otrcp_set_mac_scan_mask(struct otrcp *rcp, uint8_t *mask, size_t len)
{
	struct spinel_command cmd;
	int rc, i;
	char fmt[36] = "D(";

	for (i = 0; i < len; i++) {
		strcat(fmt, "C");
	}
	strcat(fmt, ")");

	SETUP_SPINEL_COMMAND(cmd, ((struct otrcp *)(rcp)));
	rc = spinel_prop_set(&cmd, SPINEL_PROP_MAC_SCAN_MASK, fmt, mask, len);
	if (rc < 0) {
		pr_err("%s: Failed SPINEL_ (): %d\n", __func__, rc);
	}
	return rc;
}

static bool otrcp_has_caps(struct otrcp *rcp, uint32_t cap)
{
	int i;
	for (i = 0; i < rcp->caps_size; i++) {
		if (rcp->caps[i] == cap)
			return true;
	}
	return false;
}

static int otrcp_get_protocol_version(struct otrcp *rcp, uint8_t *major, uint8_t *minor)
{
	SPINEL_GET_PROP(PROTOCOL_VERSION, rcp, major, minor);
}

static int otrcp_get_rcp_api_version(struct otrcp *rcp, uint32_t *rcp_api_version)
{
	SPINEL_GET_PROP(RCP_API_VERSION, rcp, rcp_api_version);
}

static int otrcp_get_ncp_version(struct otrcp *rcp, uint8_t *ncp_version, size_t len)
{
	SPINEL_GET_PROP(NCP_VERSION, rcp, ncp_version, len);
}

static int otrcp_get_radio_caps(struct otrcp *rcp, uint32_t *radio_caps)
{
	SPINEL_GET_PROP(RADIO_CAPS, rcp, radio_caps);
}

static int otrcp_get_hwaddr(struct otrcp *rcp, uint8_t *hwaddr)
{
	SPINEL_GET_PROP(HWADDR, rcp, hwaddr);
}

static int otrcp_get_phy_cca_threshold(struct otrcp *rcp, s8 *level)
{
	SPINEL_GET_PROP(PHY_CCA_THRESHOLD, rcp, level);
}

static int otrcp_get_phy_chan(struct otrcp *rcp, uint8_t *chan)
{
	SPINEL_GET_PROP(PHY_CHAN, rcp, chan);
}

static int otrcp_get_phy_tx_power(struct otrcp *rcp, s8 *power)
{
	SPINEL_GET_PROP(PHY_TX_POWER, rcp, power);
}

static int otrcp_set_enable(struct otrcp *rcp, bool enabled)
{
	SPINEL_SET_PROP(PHY_ENABLED, rcp, enabled);
}

static int otrcp_set_panid(struct otrcp *rcp, u16 panid)
{
	SPINEL_SET_PROP(MAC_15_4_PANID, rcp, panid);
}

static int otrcp_set_saddr(struct otrcp *rcp, u16 saddr)
{
	SPINEL_SET_PROP(MAC_15_4_SADDR, rcp, saddr);
}

static int otrcp_set_laddr(struct otrcp *rcp, u64 laddr)
{
	SPINEL_SET_PROP(MAC_15_4_LADDR, rcp, &laddr);
}

static int otrcp_set_scan_period(struct otrcp *rcp, uint16_t duration)
{
	SPINEL_SET_PROP(MAC_SCAN_MASK, rcp, duration);
}

static int otrcp_set_scan_state(struct otrcp *rcp, uint8_t state)
{
	SPINEL_SET_PROP(MAC_SCAN_STATE, rcp, state);
}

static int otrcp_set_phy_cca_threshold(struct otrcp *rcp, s8 ed_level)
{
	SPINEL_SET_PROP(PHY_CCA_THRESHOLD, rcp, ed_level);
}

static int otrcp_set_phy_tx_power(struct otrcp *rcp, s8 power)
{
	SPINEL_SET_PROP(PHY_TX_POWER, rcp, power);
}

static int otrcp_set_phy_chan(struct otrcp *rcp, u8 chan)
{
	SPINEL_SET_PROP(PHY_CHAN, rcp, chan);
}

static int otrcp_get_tx_power_table(struct otrcp *rcp, s32 *powers, size_t *sz)
{
	int i, rc;

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
	if (rc < 0)
		return rc;

	return 0;
}

static int otrcp_get_cca_ed_level_table(struct otrcp *rcp, s32 *ed_levels, size_t *sz)
{
	int i, rc;

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
	if (rc < 0)
		return rc;

	return 0;
}

static int otrcp_reset(struct otrcp *rcp, uint32_t reset)
{
	struct spinel_command cmd;
	int rc;

	pr_debug("%s(%p, %d)\n", __func__, rcp, reset);
	SETUP_SPINEL_COMMAND(cmd, ((struct otrcp *)(rcp)));
	rc = SPINEL_RESET(&cmd, SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0, SPINEL_CMD_RESET,
			  (uint8_t)reset);
	if (rc < 0) {
		pr_err("%s: Failed SPINEL_RESET(): %d\n", __func__, rc);
	}

	return rc;
}

static int otrcp_check_rcp_supported(struct otrcp *rcp)
{
	uint32_t kRequiredRadioCaps = OT_RADIO_CAPS_ACK_TIMEOUT | OT_RADIO_CAPS_TRANSMIT_RETRIES |
				      OT_RADIO_CAPS_CSMA_BACKOFF;

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

		pr_debug("RCP is missing required capabilities: %s%s%s%s%s",
			 (missingCaps & OT_RADIO_CAPS_ACK_TIMEOUT) ? "ack-timeout " : "",
			 (missingCaps & OT_RADIO_CAPS_TRANSMIT_RETRIES) ? "tx-retries " : "",
			 (missingCaps & OT_RADIO_CAPS_CSMA_BACKOFF) ? "CSMA-backoff " : "",
			 (missingCaps & OT_RADIO_CAPS_TRANSMIT_SEC) ? "tx-security " : "",
			 (missingCaps & OT_RADIO_CAPS_TRANSMIT_TIMING) ? "tx-timing " : "");

		return -ENOTSUPP;
	}

	return 0;
}

int otrcp_set_channel(struct ieee802154_hw *hw, u8 page, u8 channel)
{
	int rc;
	pr_info("%s %d\n", __func__, channel);
	rc = otrcp_set_phy_chan(hw->priv, channel);
	pr_info("%s %d\n", __func__, rc);
	rc = otrcp_get_phy_chan(hw->priv, &channel);
	pr_info("%s %d\n", __func__, channel);
	return 0;
}

int otrcp_set_tx_power(struct ieee802154_hw *hw, s32 power)
{
	int rc;
	char pow;
	pr_info("%s %d\n", __func__, power);
	rc = otrcp_set_phy_tx_power(hw->priv, (s8)(power / 100));
	pr_info("%s %d\n", __func__, rc);
	rc = otrcp_get_phy_tx_power(hw->priv, &pow);
	pr_info("%s %d\n", __func__, pow);
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
	pr_info("%s %d\n", __func__, ed_level);
	rc = otrcp_set_phy_cca_threshold(hw->priv, (s8)(ed_level / 100));
	pr_info("%s %d\n", __func__, rc);
	rc = otrcp_get_phy_cca_threshold(hw->priv, &lv);
	pr_info("%s %d\n", __func__, lv);
	return 0;
}

int otrcp_set_csma_params(struct ieee802154_hw *hw, u8 min_be, u8 max_be, u8 retries)
{
	struct otrcp *rcp = hw->priv;

	pr_debug("%s(%p, %u, %u, %u)\n", __func__, hw, min_be, max_be, retries);
	rcp->csma_min_be = min_be;
	rcp->csma_max_be = max_be;
	rcp->csma_retries = retries;

	return 0;
}

int otrcp_set_frame_retries(struct ieee802154_hw *hw, s8 max_frame_retries)
{
	struct otrcp *rcp = hw->priv;

	pr_debug("%s(%p, %d)\n", __func__, hw, max_frame_retries);
	rcp->max_frame_retries = max_frame_retries;
	return 0;
}

int otrcp_set_promiscuous_mode(struct ieee802154_hw *hw, const bool on)
{
	pr_debug("%s(%p, %d)\n", __func__, hw, on);
	SPINEL_SET_PROP(MAC_PROMISCUOUS_MODE, hw->priv, on);
}

int otrcp_start(struct ieee802154_hw *hw)
{
	struct otrcp *rcp = hw->priv;
	int rc, i;

	// pr_debug("%s(%p)\n", __func__, hw);
	// dev_dbg(rcp->parent, "ptr %s\n", dev_driver_string(&hw->phy->dev));

	otrcp_reset(rcp, SPINEL_RESET_STACK);

	rc = otrcp_get_ncp_version(rcp, rcp->ncp_version, sizeof(rcp->ncp_version));
	if (rc < 0)
		return rc;

	rc = otrcp_get_protocol_version(rcp, &rcp->protocol_version_major,
					&rcp->protocol_version_minor);
	if (rc < 0)
		return rc;

	rc = otrcp_get_hwaddr(rcp, rcp->hwaddr);
	if (rc < 0)
		return rc;

	rc = otrcp_get_caps(rcp, rcp->caps, rcp->caps_size);
	if (rc < 0)
		return rc;

	if (otrcp_has_caps(rcp, SPINEL_CAP_RCP_API_VERSION)) {
		rc = otrcp_get_rcp_api_version(rcp, &rcp->rcp_api_version);
		if (rc < 0)
			return rc;
	}

	rc = otrcp_get_radio_caps(rcp, &rcp->radio_caps);
	if (rc < 0)
		return rc;

	rc = otrcp_get_phy_chan(rcp, &hw->phy->current_channel);
	if (rc < 0)
		return rc;

	rc = otrcp_get_cca_ed_level_table(rcp, rcp->cca_ed_levels, &rcp->cca_ed_levels_size);
	if (rc < 0)
		return rc;

	rc = otrcp_get_tx_power_table(rcp, rcp->tx_powers, &rcp->tx_powers_size);
	if (rc < 0)
		return rc;

	rc = otrcp_check_rcp_supported(rcp);
	if (rc < 0)
		return rc;

	rc = otrcp_get_phy_chan_supported(rcp, rcp->phy_chan_supported,
					  sizeof(rcp->phy_chan_supported));
	if (rc < 0)
		return rc;

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
	if (rc < 0)
		return rc;

	return 0;
}

void otrcp_stop(struct ieee802154_hw *hw)
{
	struct otrcp *rcp = hw->priv;
	pr_debug("%s %p\n", __func__, rcp);
}

int otrcp_xmit_async(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	/*(
	    error = Request(SPINEL_CMD_PROP_VALUE_SET, SPINEL_PROP_STREAM_RAW,
			    SPINEL_DATATYPE_DATA_WLEN_S                                   // Frame
	   data SPINEL_DATATYPE_UINT8_S                                   // Channel
				    SPINEL_DATATYPE_UINT8_S                               //
	   MaxCsmaBackoffs SPINEL_DATATYPE_UINT8_S                           // MaxFrameRetries
					    SPINEL_DATATYPE_BOOL_S                        //
	   CsmaCaEnabled SPINEL_DATATYPE_BOOL_S                    // IsHeaderUpdated
						    SPINEL_DATATYPE_BOOL_S                // IsARetx
							SPINEL_DATATYPE_BOOL_S            // SkipAes
							    SPINEL_DATATYPE_UINT32_S      // TxDelay
								SPINEL_DATATYPE_UINT32_S, //
	   TxDelayBaseTime mTransmitFrame->mPsdu, mTransmitFrame->mLength, mTransmitFrame->mChannel,
			    mTransmitFrame->mInfo.mTxInfo.mMaxCsmaBackoffs,
	   mTransmitFrame->mInfo.mTxInfo.mMaxFrameRetries,
			    mTransmitFrame->mInfo.mTxInfo.mCsmaCaEnabled,
	   mTransmitFrame->mInfo.mTxInfo.mIsHeaderUpdated, mTransmitFrame->mInfo.mTxInfo.mIsARetx,
	   mTransmitFrame->mInfo.mTxInfo.mIsSecurityProcessed,
			    mTransmitFrame->mInfo.mTxInfo.mTxDelay,
	   mTransmitFrame->mInfo.mTxInfo.mTxDelayBaseTime);
	*/
	return 0;
}

int otrcp_ed(struct ieee802154_hw *hw, u8 *level)
{
	struct otrcp *rcp = hw->priv;

	int rc = 0;

	rc = otrcp_set_mac_scan_mask(rcp, rcp->phy_chan_supported, rcp->phy_chan_supported_size);
	if (rc < 0)
		return rc;

	rc = otrcp_set_scan_period(rcp, rcp->scan_period);
	if (rc < 0)
		return rc;

	rc = otrcp_set_scan_state(rcp, SPINEL_SCAN_STATE_ENERGY);
	if (rc < 0)
		return rc;

	return rc;
}

int otrcp_set_hw_addr_filt(struct ieee802154_hw *hw, struct ieee802154_hw_addr_filt *filt,
			   unsigned long changed)
{
	struct otrcp *rcp = hw->priv;
	int rc = 0;

	if (changed & IEEE802154_AFILT_PANC_CHANGED) {
		return -ENOTSUPP;
	}

	if (changed & IEEE802154_AFILT_IEEEADDR_CHANGED) {
		rc = otrcp_set_laddr(rcp, filt->ieee_addr);
		if (rc < 0)
			return rc;
	}

	if (changed & IEEE802154_AFILT_SADDR_CHANGED) {
		rc = otrcp_set_saddr(rcp, filt->short_addr);
		if (rc < 0)
			return rc;
	}

	if (changed & IEEE802154_AFILT_PANID_CHANGED) {
		rc = otrcp_set_panid(rcp, le16_to_cpu(filt->pan_id));
		if (rc < 0)
			return rc;
	}

	return 0;
}
