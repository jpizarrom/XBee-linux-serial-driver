/*
 * Digi XBee 802.15.4 device driver
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
/*
 * This depends on the linux-wsn mac802154 code from its kernel
 * repository dev branch.
 *
 * See <https://code.google.com/p/linux-wsn/wiki/LinuxStack>.
 */
/*
 * Use `ldattach 255 <device>` to attach the N_IEEE802154_XBEE (255)
 * line discipline to a serial device after this driver has been loaded and
 * this driver will open the device and create an ieee802154 interface
 * from it. NOTE: The `izattach` program is specific to the generic
 * serial protocol from linux-wsn, so that line discipline will not work
 * with the XBee.
 *
 * Use `iz add <phy>` to get a working ieee802154 network interface.
 *
 * TODO: Need to figure out howto add 6lowpan interface in top of the
 * ieee802154 interface. (linux-wsn + libnl + RTM_NEWLINK)
 * 
 * TODO: Use 6LoWPAN, ROLL/Trickle, and COAP?
 *
 * NOTE: In 6LoWPAN the entire mesh is within link-local scope.
 * [draft-shelby-6lowpan-nd]
 */
/*
 * The 6lowpan module will attach its packet_type to ETH_P_IEEE802154.
 * Its lowpan_rcv() will take these packets and resubmit them to that
 * IEEE 802.15.4 device's 6LoWPAN interface as a parsed IPv6 packet. So
 * make sure to set the sk_buff->protocol as ETH_P_IEEE802154.
 */
/*
 * IEEE 802.15.4 data frame (sec. 5.5.3.2, pg. 22):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Frame Control         |  Sequence ID  |               |
 *  +---------------+---------------+---------------+               ~
 *  |                                                               |
 *  ~            Addressing Fields (variable 4-20 octets)           ~
 *  |                                                               |
 *  ~                                               +-+-+-+-+-+-+-+-+
 *  |                                               |               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               ~
 *  |                                                               |
 *  ~         Axillary Security Header (variable 0-14 octets)       ~
 *  |                                                               |
 *  ~               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               | Command Type  |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *  |                                                               |
 *  ~                        Payload (variable)                     ~
 *  |                                                               |
 *  ~                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |     Frame Check Sequence      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * See also <http://www.makelinux.net/ldd3/chp-17-sect-6.shtml>.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <net/mac802154.h>
#include <net/wpan-phy.h>

#define N_IEEE802154_XBEE 255

//module_param(mode, bool, 0);
//MODULE_PARM_DESC(mode, "Use API mode");
//module_param(resp, bool, 0);
//MODULE_PARM_DESC(resp, "Enable command responses");

/*********************************************************************/

struct xbee_device {
	struct tty_struct *tty;
	struct ieee802154_dev *dev;

	struct wait_queue_head_t frame_wq;
	struct list_head frame_pend;
};

struct xbee_frame {
	struct list_head list;
	int ack;

	u16 len;
	u8 id;
	unsigned char *raw_data;
	u8 csum;

	/* parsed elements */
	u8 fid;
	u8 status;
	unsigned char cmd[2];
	u8 addr[IEEE802154_ALEN];
	u8 saddr[IEEE802154_SHORT_ALEN];
	u8 flags;
	u8 rssi;
	unsigned char *data;
};

/* API frame types */
enum {
	XBEE_FRM_STAT = 0x8A,
	XBEE_FRM_CMD = 0x08,
	XBEE_FRM_CMDQ = 0x09,
	XBEE_FRM_CMDR = 0x88,
	XBEE_FRM_RCMD = 0x17,
	XBEE_FRM_RCMDR = 0x97,
	XBEE_FRM_TX64 = 0x00,
	XBEE_FRM_TX16 = 0x01,
	XBEE_FRM_TXS = 0x89,
	XBEE_FRM_RX64 = 0x80,
	XBEE_FRM_RX16 = 0x81,
	XBEE_FRM_RX64IO = 0x82,
	XBEE_FRM_RX16IO = 0x83,
};

/*********************************************************************/

/*
 * See include/linux/nl802154.h and include/net/nl802154.h for the
 * netlink messages that implement specific features, specifically:
 *
 * ieee802154_nl_assoc_indic - Notify userland of an association request.
 * ieee802154_nl_assoc_confirm - Notify userland of association.
 * ieee802154_nl_disassoc_indic - Notify userland of disassociation.
 * ieee802154_nl_disassoc_confirm - Notify userland of disassociation completion.
 * ieee802154_nl_scan_confirm - Notify userland of completion of scan.
 * ieee802154_nl_beacon_indic - Notify userland of a received beacon.
 * ieee802154_nl_start_confirm - Notify userland of completion of start.
 */

/**
 * xbee_ieee802154_assoc_req - Make an association request to the HW.
 *
 * @dev: The network device which we are associating to a network.
 * @addr: The coordinator with which we wish to associate.
 * @channel: The channel on which to associate.
 * @cap: The capability information field to use in the association.
 *
 * Start an association with a coordinator. The coordinator's address
 * and PAN ID can be found in @addr.
 *
 * Note: This is in section 7.3.1 and 7.5.3.1 of the IEEE
 *       802.15.4-2006 document.
 *
 * Note: Should be responded to with ieee802154_nl_assoc_confirm().
 */
static int xbee_ieee802154_assoc_req(struct net_device *dev,
				     struct ieee802154_addr *addr,
				     u8 channel, u8 page, u8 cap);

/**
 * xbee_ieee802154_assoc_resp - Send an association response to a device.
 *
 * @dev: The network device on which to send the response.
 * @addr: The address of the device to respond to.
 * @short_addr: The assigned short address for the device (if any).
 * @status: The result of the association request.
 *
 * Queue the association response of the coordinator to another
 * device's attempt to associate with the network which we
 * coordinate. This is then added to the indirect-send queue to be
 * transmitted to the end device when it polls for data.
 *
 * Note: This is in section 7.3.2 and 7.5.3.1 of the IEEE
 *       802.15.4-2006 document.
 *
 * Note: Should be in response to ieee802154_nl_assoc_indic().
 */
static int xbee_ieee802154_assoc_resp(struct net_device *dev,
				      struct ieee802154_addr *addr,
				      u16 short_addr, u8 status);

/**
 * xbee_ieee802154_disassoc_req - Disassociate a device from a network.
 *
 * @dev: The network device on which we're disassociating a device.
 * @addr: The device to disassociate from the network.
 * @reason: The reason to give to the device for being disassociated.
 *
 * This sends a disassociation notification to the device being
 * disassociated from the network.
 *
 * Note: This is in section 7.5.3.2 of the IEEE 802.15.4-2006
 *       document, with the reason described in 7.3.3.2.
 *
 * Note: Should be responded to with ieee802154_nl_disassoc_confirm().
 */
static int xbee_ieee802154_disassoc_req(struct net_device *dev,
					struct ieee802154_addr *addr,
					u8 reason);

/**
 * xbee_ieee802154_start_req - Start an IEEE 802.15.4 PAN.
 *
 * @dev: The network device on which to start the PAN.
 * @addr: The coordinator address to use when starting the PAN.
 * @channel: The channel on which to start the PAN.
 * @bcn_ord: Beacon order.
 * @sf_ord: Superframe order.
 * @pan_coord: Whether or not we are the PAN coordinator or just
 *             requesting a realignment perhaps?
 * @blx: Battery Life Extension feature bitfield.
 * @coord_realign: Something to realign something else.
 *
 * If pan_coord is non-zero then this starts a network with the
 * provided parameters, otherwise it attempts a coordinator
 * realignment of the stated network instead.
 *
 * Note: This is in section 7.5.2.3 of the IEEE 802.15.4-2006
 * document, with 7.3.8 describing coordinator realignment.
 *
 * Note: Should be responded to with ieee802154_nl_start_confirm().
 */
static int xbee_ieee802154_start_req(struct net_device *dev,
				     struct ieee802154_addr *addr,
				     u8 channel, u8 page, u8 bcn_ord,
				     u8 sf_ord, u8 pan_coord, u8 blx,
				     u8 coord_realign);

/**
 * xbee_ieee802154_scan_req - Start a channel scan.
 *
 * @dev: The network device on which to perform a channel scan.
 * @type: The type of scan to perform.
 * @channels: The channel bitmask to scan.
 * @duration: How long to spend on each channel.
 *
 * This starts either a passive (energy) scan or an active (PAN) scan
 * on the channels indicated in the @channels bitmask. The duration of
 * the scan is measured in terms of superframe duration. Specifically,
 * the scan will spend aBaseSuperFrameDuration * ((2^n) + 1) on each
 * channel.
 *
 * Note: This is in section 7.5.2.1 of the IEEE 802.15.4-2006 document. 
 *
 * Note: Should be responded to with ieee802154_nl_scan_confirm().
 */
static int xbee_ieee802154_scan_req(struct net_device *dev,
				    u8 type, u32 channels,
				    u8 page, u8 duration);

/**
 * xbee_ieee802154_get_phy - Return a phy corresponding to this device.
 *
 * @dev: The network device for which to return the wan-phy object
 *
 * This function returns a wpan-phy object corresponding to the passed
 * network device. Reference counter for wpan-phy object is incremented,
 * so when the wpan-phy isn't necessary, you should drop the reference
 * via @wpan_phy_put() call.
 */
struct wpan_phy *xbee_ieee802154_get_phy(const struct net_device *dev);

/**
 * xbee_ieee802154_get_pan_id - Retrieve the PAN ID of the device.
 *
 * @dev: The network device to retrieve the PAN of.
 *
 * Return the ID of the PAN from the PIB.
 */
static u16 xbee_ieee802154_get_pan_id(const struct net_device *dev);

/**
 * xbee_ieee802154_get_short_addr - Retrieve the short address of the device.
 *
 * @dev: The network device to retrieve the short address of.
 *
 * Returns the IEEE 802.15.4 short-form address cached for this
 * device. If the device has not yet had a short address assigned
 * then this should return 0xFFFF to indicate a lack of association.
 */
static u16 xbee_ieee802154_get_short_addr(const struct net_device *dev);

/**
 * xbee_ieee802154_get_dsn - Retrieve the DSN of the device.
 *
 * @dev: The network device to retrieve the DSN for.
 *
 * Returns the IEEE 802.15.4 DSN for the network device.
 * The DSN is the sequence number which will be added to each
 * packet or MAC command frame by the MAC during transmission.
 *
 * DSN means 'Data Sequence Number'.
 *
 * Note: This is in section 7.2.1.2 of the IEEE 802.15.4-2006
 *       document.
 */
static u8 xbee_ieee802154_get_dsn(const struct net_device *dev);

/**
 * xbee_ieee802154_get_bsn - Retrieve the BSN of the device.
 *
 * @dev: The network device to retrieve the BSN for.
 *
 * Returns the IEEE 802.15.4 BSN for the network device.
 * The BSN is the sequence number which will be added to each
 * beacon frame sent by the MAC.
 *
 * BSN means 'Beacon Sequence Number'.
 *
 * Note: This is in section 7.2.1.2 of the IEEE 802.15.4-2006
 *       document.
 */
static u8 xbee_ieee802154_get_bsn(const struct net_device *dev);

/*************************************************************************/

/*
 * Callbacks from mac802154 to the driver. Must handle xmit(). 
 *
 * See net/mac802154/ieee802154_dev.c, include/net/mac802154.h,
 * and net/mac802154/mac802154.h from linux-wsn.
 */

/**
 * xbee_ieee802154_set_channel - Set radio for listening on specific channel.
 *
 * @dev: ...
 * @page: ...
 * @channel: ...
 */
static int xbee_ieee802154_set_channel(struct ieee802154_dev *dev,
				       int page, int channel);

/**
 * xbee_ieee802154_ed - Handler that 802.15.4 module calls for Energy Detection.
 *
 * @dev: ...
 * @level: ...
 */
static int xbee_ieee802154_ed(struct ieee802154_dev *dev, u8 *level);

/**
 * xbee_ieee802154_addr - ...
 *
 * @dev: ...
 * @addr: ...
 */
static int xbee_ieee802154_addr(struct ieee802154_dev *dev,
				u8 addr[IEEE802154_ALEN]);

/**
 * xbee_ieee802154_xmit - Handler that 802.15.4 module calls for each transmitted frame.
 *
 * @dev: ...
 * @skb: ...
 */
static int xbee_ieee802154_xmit(struct ieee802154_dev *dev,
				struct sk_buff *skb)
{
	struct xb_device *xbdev;

	// convert to XBee frame
	xbee_frm_conv_ieee2xbee(skb);

	// send over tty
	xbdev = dev->priv;
	xbdev->tty->write(skb->data, skb->data_len);
}

/**
 * xbee_ieee802154_start - For device initialisation before the first interface is attached.
 *
 * @dev: ...
 */
static int xbee_ieee802154_start(struct ieee802154_dev *dev)
{
	struct xb_device *xbdev = dev->priv;
	int ret;

	if (tty->ops->start)
		tty->ops->start(tty);

	ret = xbee_send_cmd(xbdev, XBEE_CMD_FR);

	return ret;
}

/**
 * xbee_ieee802154_stop - For device cleanup after last interface is removed.
 *
 * @dev: ...
 */
static void xbee_ieee802154_stop(struct ieee802154_dev *dev);

/**
 * xbee_netdev_reg - Upon net_dev registration.
 *
 * XXX: obsolete
 */
static void xbee_netdev_reg(struct net_dev *dev)
{
	dev->addr_len           = IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);
	dev->hard_header_len    = MAC802154_MAX_MHR_SIZE;
	dev->header_ops         = &mac802154_header_ops;
	dev->needed_tailroom    = 2; /* FCS */
	dev->mtu                = IEEE802154_MTU;
	dev->tx_queue_len       = 10;
	dev->type               = ARPHRD_IEEE802154;
	dev->flags              = IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo     = 0;

	dev->destructor         = free_netdev;
	dev->netdev_ops         = &mac802154_wpan_ops;
	dev->ml_priv            = &mac802154_mlme_wpan.wpan_ops;

	priv                    = netdev_priv(dev);
	priv->type              = IEEE802154_DEV_WPAN;

	priv->chan = -1; /* not initialized */
	priv->page = 0; /* for compat */

	spin_lock_init(&priv->mib_lock);

	get_random_bytes(&priv->bsn, 1);
	get_random_bytes(&priv->dsn, 1);

	priv->pan_id = IEEE802154_PANID_BROADCAST;
	priv->short_addr = IEEE802154_ADDR_BROADCAST;
}

/*************************************************************************/

/**
 * xbee_send_cmd - Send an AT command frame.
 *
 * @xbdev: ...
 * @cmd: ...
 * @param: ...
 * @len: ...
 *
 * Create an API frame, put it in the TTY frame send queue, and wait for a
 * response in the TTY frame receive queue.
 *
 * NOTE: Are we called from process context? Do we need to wait until a
 * command response is received for completion?
 */
static int xbee_frame_send_cmd(struct xb_device *xbdev,
			 const unsigned char cmd[2],
			 const unsigned char *data, size_t len);

/**
 * xbee_send_frame - ...
 *
 * @xbdev: ...
 * @frame: ...
 */
static void xbee_frm_xbee_send(struct xb_device *xbdev,
			       struct sk_buff *skb)
{
//	struct tty_struct *tty = xbdev->tty;

	/* expect XBee API frame ACK */
	xbee_state_frm_resp_enqueue(skb);

	/* write frame to TTY */
	xbdev->tty->write(skb->data, skb->data_len);

	/* block if blocking */
	if (1) {
		ret = wait_event_timeout(xbdev->frame_wq, frame->ack != -1, 100);
		if (ret == 0)
			return -ERESTARTSYS;
		else {
			list_del(frame->list);
			return 0;
		}
	}
}

static void xbee_state_frm_resp_enqueue(struct sk_buff *skb)
{
	struct *xbee_frm_resp *resp;

	// resp = ...
	// resp->timestamp = ...

	// fid = ...
	xbee_frm_xbee_add_fid(skb, fid);
	// resp->fid = fid

	list_add_tail(resp, xbdev->frame_pend);
}

/**
 *
 */
static void xbee_frm_conv_ieee2xbee(struct sk_buff *skb)
{
	
}

/*********************************************************************/

/**
 * xbee_rx - Receive an packet from RX frame.
 *
 * @skb: ...
 *
 * Convert the XBee frame into an IEEE 802.15.4 MAC frame then pass it to
 * the networking stack. (The sk_buff should already have been connected
 * to the net_device and any other details.)
 *
 * XBee packet type 0x80, RX w/ 64-bit address:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    7     E    |    len msb    |    len lsb    |    8     0    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                          src address                          +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     RSSI      |    options    |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 *  |                                                               |
 *  ~                             data                              ~
 *  |                                                               |
 *  ~                                               +-+-+-+-+-+-+-+-+
 *  |                                               |   checksum    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * IEEE 802.15.4 data frame (sec. 7.2.1, pg. 138):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |0 0 1 0 0 0 0 0 0 0 1 1 0 1 1 1|  sequence ID  |    dst pan    ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~               |                                               |
 *  +-+-+-+-+-+-+-+-+          dst address                          ~
 *  |                                                               |
 *  ~               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               |            src pan            |               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               ~
 *  |                                                               |
 *  ~                          src address          +-+-+-+-+-+-+-+-+
 *  |                                               | command type  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  ~                        payload (variable)                     ~
 *  |                                                               |
 *  ~                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |     frame check sequence      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void xbee_pkt_recv_rx64(struct sk_buff *skb)
{
	u16 len;
	u64 src;
	u8 rssi, opts;

	/* copy len */
	len = be16_to_cpup(skb->data + 1);

	/* copy src addr */
	src = be64_to_cpup(skb->data + 4);

	/* copy rssi */
	rssi = (u8)*(skb->data + 12);

	/* copy options */
	opts = (u8)*(skb->data + 13);

	/* get our MAC address (is dst addr) */
	dst = xbee_get

	/* prepend 10 bytes to skb, append 1 byte, view skb as IEEE pkt */

	/* always add 16-byte PAN, per 7.2.1.1.5 */
	span = ifpan;
	if (options & (XBEE_FRAME_OP_BCAST_PAN))
		dpan = IEEE802154_BCAST_PAN;
	else
		dpan = ifpan;

	/* write frame control */
	/* write sequence id */
	/* write dst pan */
	/* write dst addr */
	/* write src pan */
	/* write src addr */
	/* write command type */

//	skb->dev = dev;
//	skb_set_mac_header(skb->mac_header = ...;
	skb->protocol = htons(ETH_P_IEEE802154);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

//	netif_rx(skb);
//	ieee802154_rx_irqsafe(xbdev->dev, skb, rssi);
	ieee802154_rx(xbdev->dev, skb, rssi);
}

/**
 *
 */
static void xbee_state_frm_resp_dequeue(struct xb_device *xbdev,
					u8 fid)
{
	struct list_head *p;
	struct xbee_frm_resp *resp;

	/* XXX: use safe version? */
	list_for_each_safe(p, xbdev->frame_pend) {
		if (p != xbdev->frame_pend) {
			resp = list_entry(p, struct xbee_frame, list);
			if (fid == resp->fid)
				list_del_entry(p, struct xbee_frame, list);
		}
	}
}

/**
 * xbee_recv_frame - ...
 *
 * @xbdev: ...
 * @frame: ...
 *
 * Verify the XBee frame, then take appropriate action depending on the
 * frame type.
 */
static void xbee_frm_xbee_recv(struct xb_device *xbdev,
			       struct sk_buff *skb)
{
	u8 *id;

	/* verify length and checksum */
	err = xbee_frm_xbee_verify(skb);
	if (err) {
		XBEE_WARN("dropping invalid frame 0x%x", err);
		return;
	}

	id = xbee_frm_xbee_id(skb);
	switch (id) {
	case XBEE_FRM_STAT:
		xbee_frame_recv_stat(skb);
		break;
	case XBEE_FRM_CMDR:
		xbee_frame_recv_cmdr(skb);
		break;
	case XBEE_FRM_RCMDR:
		xbee_frame_recv_rcmdr(skb);
		break;
	case XBEE_FRM_TXSTAT:
		xbee_frame_recv_txstat(skb);
		break;
	case XBEE_FRM_RX64:
		xbee_frame_recv_rx64(xbdev, skb);
		break;
	case XBEE_FRM_RX16:
		xbee_frame_recv_rx16(skb);
		break;
	case XBEE_FRM_RX64IO:
	case XBEE_FRM_RX16IO:
		XBEE_WARN("received unimplemented frame type 0x%x", id);
		skb_free(skb);
		break;
	case XBEE_FRM_CMD:
	case XBEE_FRM_CMDQ:
	case XBEE_FRM_RCMD:
	case XBEE_FRM_TX64:
	case XBEE_FRM_TX16:
		XBEE_WARN("received tx-only frame type 0x%x", id);
		skb_free(skb);
		break;
	default:
		XBEE_WARN("received unknown frame type 0x%x", id);
		skb_free(skb);
		break;
	}
}

static int xbee_frm_new(struct xb_device *xbdev,
			struct sk_buff **skb)
{
	struct sk_buff *new_skb;
	int ret;

	new_skb = alloc_skb(XBEE_SKB_MAXLEN, GFP_KERNEL);
	if (new_skb == NULL) {
		XBEE_ERR("failed to allocate new skb");
		return 1;
	} else {
		skb = xbdev->frame;
		xbdev->frame = new_skb;
		*skb = old_skb;

		xbdev->frame_len = 0;
		xbdev->frame_esc = 0;
		return 0;
	}
}

/*********************************************************************/

/*
 * See Documentation/tty.txt for details.
 */

/**
 * xbee_ldisc_recv_buf - Receive serial bytes.
 *
 * @tty: TTY info for line.
 * @cp: ...
 * @fp: ...
 * @count: ...
 *
 * Directly called from flush_to_ldisc() which is called from
 * tty_flip_buffer_push(), either in IRQ context if low latency tty or from
 * a normal worker thread otherwise.
 */
static void xbee_ldisc_recv_buf(struct tty_struct *tty,
				const unsigned char *cp,
				char *fp, int count)
{
	struct ieee802154_dev *dev;
	struct xb_device *xbdev;
	char c;
	struct sk_buff *skb;

	xbdev = tty->disc_data;

	/* copy (i wish i could just lock and link them in an array) buffers */
	while (count--) {
		c = *cp++;

		/* escape this byte */
		if (xbdev->frame_esc) {
			c ^= 0x20;
			xbdev->frame_esc = 0;
		}

		switch (c) {
		case XBEE_CHAR_ESC: /* escape next byte */
			xbdev->frame_esc = 1;
			break;
		case XBEE_CHAR_NEWFRM: /* new frame */
			XBEE_INFO("new frame");
			/* switch to new frame buffer */
			ret = xbee_frm_new(xbdev, &skb);
			if (unlikely(ret))
				XBEE_ERR("derp");
			/* submit old frame buffer to stack */
			else {
				xbee_frm_xbee_recv(xbdev, skb);
				skb_free(skb);
			}
			/* reset overflow status */
			overflow = 0;
			break;
		default:
			/* check for frame buffer overflow */
			if (overflow || xbdev->frame_len == XBEE_FRAME_MAXLEN) {
				overflow = 1;
				continue;
			}
			/* append to frame buffer */
			skb_pull(xbdev->frame, 1) = c;
			/* increase current frame buffer len */
			xbdev->frame_len += 1;
			break;
		}
	}

	if (overflow)
		XBEE_WARN("was buffer overflow");

	/* peak at frame to check if completed */
	if (xbee_frame_peak_done(xbdev)) {
		ret = xbee_frm_new(xbdev, &skb);
		if (unlikely(ret))
			XBEE_ERR("derp");
		else {
			xbee_frame_recv(xbdev, skb);
			skb_free(skb);
		}
	}
}

/**
 * xbee_ldisc_ioctl - ...
 *
 * @tty: TTY info for line.
 * @file: ...
 * @cmd: ...
 * @arg: ...
 */
static int xbee_ldisc_ioctl(struct tty_struct *tty, struct file *file,
			    unsigned int cmd, unsigned long arg);

/**
 * xbee_ldisc_close - Close line discipline and unregister with ieee802154.
 *
 * @tty: TTY info for line.
 */
static void xbee_ldisc_close(struct tty_struct *tty);

/**
 * xbee_ldisc_hangup - Hang up line discipline.
 *
 * @tty: TTY info for line.
 *
 * "The line discipline should cease I/O to the tty.
 * No further calls into the ldisc code will occur."
 */
static int xbee_ldisc_hangup(struct tty_struct *tty)
{
	struct ieee802154_dev *dev;
	
	dev = tty->dev;
	return ieee802154_unregister_device(dev);
}

/**
 * xbee_ldisc_open - Initialize line discipline and register with ieee802154.
 *
 * @tty: TTY info for line.
 *
 * Called from a process context to change the TTY line discipline.
 * Called from a process context 
 *
 * 
 */
static int xbee_ldisc_open(struct tty_struct *tty)
{
	struct ieee802154_dev *dev;
	struct xb_device *xbdev;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/*
	 * TODO: The traditional method to check if another line discipline
	 * is still installed has been to check tty->disc_data for a non-NULL
	 * address, even though line disciplines are under no obligation
	 * to clear it upon uninstallation.
	 */

	if (tty->disc_data != NULL)
		return -EBUSY;

	tty->receive_room = 65536;

	if (tty->ops->stop)
		tty->ops->stop(tty);

	tty_driver_flush_buffer(tty);

	dev = ieee802154_alloc_device(sizeof(*xbdev), &xbee_ieee802154_ops);
	if (!dev)
		return -ENOMEM;

	xbdev = dev->priv;
	xbdev->tty = tty_kref_get(tty);
	xbdev->dev = dev;
	mutex_init(&xbdev->mutex);
//	init_completion(&xbdev->cmd_resp_done);
	init_waitqueue_head(&xbdev->frame_waitq);

	dev->extra_tx_headroom = 0;
	dev->phy->channels_supported[0] = 0x7fff800;

	dev->flags = IEEE802154_HW_OMIT_CKSUM;

	dev->parent = tty->dev;

	dev->ml_priv = &xbee_ieee802154_mlme_ops;

	err = ieee802154_register_device(dev);
	if (err) {
		XBEE_ERROR("%s: device register failed\n", __func__);
		goto err;
	}

	return 0;

err:
	tty->disc_data = NULL;
	tty_kref_put(tty);
	xbdev->tty = NULL;

	ieee802154_free_device(xbdev->dev);

	return err;
}

/*********************************************************************/

/**
 * xbee_ldisc - TTY line discipline ops.
 */
static struct tty_ldisc_ops xbee_ldisc_ops = {
	.owner		= THIS_MODULE,
	.magic		= TTY_LDISC_MAGIC,
 	.name		= "n_ieee802154_xbee",
//	.flags		= 0,
	.open		= xbee_ldisc_open,
	.close		= xbee_ldisc_close,
	.ioctl		= xbee_ldisc_ioctl,
 	.hangup		= xbee_ldisc_hangup,
	.receive_buf	= xbee_ldisc_recv_buf,
};

/**
 * xbee_ieee802154_ops - ieee802154 MCPS ops.
 *
 * This is part of linux-wsn. It is similar to netdev_ops.
 */
static struct ieee802154_ops xbee_ieee802154_ops = {
	.owner		= THIS_MODULE,
	.xmit		= xbee_ieee802154_xmit,
	.ed		= xbee_ieee802154_ed,
	.set_channel	= xbee_ieee802154_set_channel,
	.set_hw_addr_filt = xbee_ieee802154_filter,
	.start		= xbee_ieee802154_start,
	.stop		= xbee_ieee802154_stop,
	.ieee_addr	= xbee_ieee802154_addr,
};

/**
 * xbee_ieee802154_mlme_ops - ieee802154 MLME ops.
 *
 * Relay MLME ops to HW.
 */
static struct ieee802154_mlme_ops xbee_ieee802154_mlme_ops = {
	.assoc_req	= xbee_ieee802154_assoc_req,
	.assoc_resp	= xbee_ieee802154_assoc_resp,
	.disassoc_req	= xbee_ieee802154_disassoc_req,
	.start_req	= xbee_ieee802154_start_req,
	.scan_req	= xbee_ieee802154_scan_req,
	.wpan_ops.get_phy = xbee_ieee802154_get_phy,
	.get_pan_id	= xbee_ieee802154_get_pan_id,
	.get_short_addr	= xbee_ieee802154_get_short_addr,
	.get_dsn	= xbee_ieee802154_get_dsn,
	.get_bsn	= xbee_ieee802154_get_bsn,
};

static int __init xbee_init(void)
{
	int err;

	XBEE_INFO("XBee IEEE 802.15.4 serial driver v.%s", VERSION);

	if ((err = tty_register_ldisc(N_IEEE802154_XBEE, &xbee_ldisc_ops)) != 0) {
		XBEE_ERROR("Can't register N_IEEE802154_XBEE line discipline (err = %d)\n", err);
		return err;
	}

	return 0;
}

static void __exit xbee_exit(void)
{
	int err;

	if ((err = tty_unregister_ldisc(N_IEEE802154_XBEE)))
		XBEE_ERROR("%s(), can't unregister N_IEEE802154_XBEE line discipline (err = %d)\n",
			   __func__, err);

	XBEE_INFO("Unloaded.");
}

module_init(xbee_init);
module_exit(xbee_exit);

MODULE_DESCRIPTION("Digi XBee IEEE 802.15.4 serial driver");
MODULE_ALIAS_LDISC(N_IEEE802154_XBEE);
MODULE_LICENSE("Dual GPL/CC0");

