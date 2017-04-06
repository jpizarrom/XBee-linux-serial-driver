#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/seq_buf.h>
#include <linux/nl80211.h>
#include <net/netlink.h>
#include <linux/nl802154.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <linux/if_arp.h>
#include <linux/jiffies.h>
#include <net/mac802154.h>
#include <net/cfg802154.h>
#include <net/nl802154.h>
#include <net/regulatory.h>
#include <net/ieee802154_netdev.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

#define N_IEEE802154_XBEE 25

#define XBEE802154_MAGIC 0x9BEE

static const void *const xbee_wpan_phy_privid = &xbee_wpan_phy_privid;
struct workqueue_struct *xbee_init_workq = NULL;

struct xb_device;

struct xb_work {
        struct work_struct work;
        struct xb_device* xb;
};

struct xb_device {
        struct tty_struct *tty;
        struct device *parent;
        struct net_device* dev;
        struct wpan_phy* phy;

        struct completion cmd_resp_done;
        struct completion send_done;
        struct completion modem_status_receive;

        struct sk_buff_head recv_queue;
        struct sk_buff_head send_queue;
        struct sk_buff* recv_buf;

        struct workqueue_struct    *sendrecv_workq;

        struct xb_work send_work;
        struct xb_work recv_work;
        struct xb_work init_work;

        struct mutex queue_mutex;

        uint8_t frameid;
        uint8_t api;
        struct sk_buff* last_atresp;
        unsigned short firmware_version;
        uint16_t magic;
};

struct mac802154_llsec {
};

struct xbee_sub_if_data {
        struct list_head list; /* the ieee802154_priv->slaves list */

        struct wpan_dev wpan_dev;

        struct xb_device* local;
        struct net_device *dev;

        //unsigned long state;
        //char name[IFNAMSIZ];

        /* protects sec from concurrent access by netlink. access by
        * encrypt/decrypt/header_create safe without additional protection.
        */
        //struct mutex sec_mtx;

        struct mac802154_llsec sec;
};

struct xb_frame_header {
        uint8_t start_delimiter; // 0x7e
        uint16_t length;
        uint8_t type;
} __attribute__((aligned(1), packed));

struct xb_frame_header_id {
        uint8_t start_delimiter; // 0x7e
        uint16_t length;
        uint8_t type;
        uint8_t id;
} __attribute__((aligned(1), packed));

struct xb_frame_atcmd {
        struct xb_frame_header hd;
        uint8_t id;
        uint16_t command;
} __attribute__((aligned(1), packed));

struct xb_frame_atcmdr {
        struct xb_frame_header hd;
        uint8_t id;
        uint16_t command;
        uint8_t status;
        uint8_t response[];
} __attribute__((aligned(1), packed));

struct xb_frame_tx64 {
        struct xb_frame_header hd;
        uint8_t id;
        uint64_t destaddr;
        uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_tx16 {
        struct xb_frame_header hd;
        uint8_t id;
        uint16_t destaddr;
        uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_rx64 {
        struct xb_frame_header hd;
        uint64_t srcaddr;
        uint8_t rssi;
        uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_rx16 {
        struct xb_frame_header hd;
        uint16_t srcaddr;
        uint8_t rssi;
        uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_txstat {
        struct xb_frame_header hd;
        uint8_t id;
        uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_mstat {
        struct xb_frame_header hd;
        uint8_t status;
} __attribute__((aligned(1), packed));

struct xb_frame_rcmd {
        struct xb_frame_header hd;
        uint8_t id;
        uint64_t destaddr64;
        uint16_t destaddr16;
        uint16_t command;
} __attribute__((aligned(1), packed));

struct xb_frame_rcmdr {
        struct xb_frame_header hd;
        uint8_t id;
        uint64_t destaddr64;
        uint16_t destaddr16;
        uint16_t command;
        uint8_t status;
} __attribute__((aligned(1), packed));

/* API frame types */
enum {
        XBEE_FRM_TX64        = 0x00,
        XBEE_FRM_TX16        = 0x01,
        XBEE_FRM_ATCMD        = 0x08,
        XBEE_FRM_ATCMDQ        = 0x09,
        XBEE_FRM_RCMD        = 0x17,
        XBEE_FRM_RX64        = 0x80,
        XBEE_FRM_RX16        = 0x81,
        XBEE_FRM_RX64IO        = 0x82,
        XBEE_FRM_RX16IO        = 0x83,
        XBEE_FRM_ATCMDR        = 0x88,
        XBEE_FRM_TXSTAT        = 0x89,
        XBEE_FRM_MSTAT        = 0x8A,
        XBEE_FRM_RCMDR        = 0x97,
};

#define AT_DECL(x, y) ( x << 8 | y )

enum {
        XBEE_AT_AP = AT_DECL('A','P'),
        XBEE_AT_AS = AT_DECL('A','S'),
        XBEE_AT_CA = AT_DECL('C','A'),
        XBEE_AT_CE = AT_DECL('C','E'),
        XBEE_AT_CH = AT_DECL('C','H'),
        XBEE_AT_ED = AT_DECL('E','D'),
        XBEE_AT_FR = AT_DECL('F','R'),
        XBEE_AT_ID = AT_DECL('I','D'),
        XBEE_AT_MM = AT_DECL('M','M'),
        XBEE_AT_MY = AT_DECL('M','Y'),
        XBEE_AT_PL = AT_DECL('P','L'),
        XBEE_AT_RE = AT_DECL('R','E'),
        XBEE_AT_RN = AT_DECL('R','N'),
        XBEE_AT_RR = AT_DECL('R','R'),
        XBEE_AT_SC = AT_DECL('S','C'),
        XBEE_AT_SD = AT_DECL('S','D'),
        XBEE_AT_SH = AT_DECL('S','H'),
        XBEE_AT_SL = AT_DECL('S','L'),
        XBEE_AT_VR = AT_DECL('V','R'),
};

enum {
        XBEE_DELIMITER = 0x7E,
        XBEE_ESCAPED_DELIMITER = 0x5E ,
        XBEE_ESCAPE = 0x7D ,
        XBEE_ESCMASK = 0x20 ,
        XBEE_XON = 0x11 ,
        XBEE_XOFF = 0x13,
};

enum {
        XBEE_MM_DIGI_WITH_ACK   = 0,
        XBEE_MM_802154_NO_ACK   = 1,
        XBEE_MM_802154_WITH_ACK = 2,
        XBEE_MM_DIGI_NO_ACK   = 3
};

enum {
        XBEE_ATCMDR_OK = 0,
        XBEE_ATCMDR_ERROR = 1,
        XBEE_ATCMDR_INVALID_COMMAND = 2,
        XBEE_ATCMDR_INVALID_PARAMETER = 3,
};

enum {
        XBEE_API_V1 = 1,
        XBEE_API_V2 = 2,
};


static const size_t XBEE_FRAME_DELIMITER_SIZE = 1;
static const size_t XBEE_FRAME_LENGTH_SIZE = 2;
static const size_t XBEE_FRAME_CHECKSUM_SIZE = 1;
static const size_t XBEE_FRAME_TYPE_SIZE = 1;
static const size_t XBEE_FRAME_ID_SIZE = 1;
static const size_t XBEE_FRAME_AT_COMMAND_SIZE = 2;

static const size_t XBEE_FRAME_OFFSET_PAYLOAD = 3;
static const size_t XBEE_FRAME_COMMON_HEADER_AND_TRAILER = 4;

#define ieee802154_sub_if_data xbee_sub_if_data

/**
 * DOC: ************** Functions copied from other files. ***************** 
 */

/**
 * mac802154_set_header_security()
 * @sdata: -
 * @hdr: -
 * @cb: -
 */
static int
mac802154_set_header_security(struct ieee802154_sub_if_data *sdata,
					 struct ieee802154_hdr *hdr,
					 const struct ieee802154_mac_cb *cb)
{
	return 0;
}

/**
 * mac802154_llsec_decrypt()
 * @sec: -
 * @skb: -
 */
static int
mac802154_llsec_decrypt(struct mac802154_llsec *sec, struct sk_buff *skb)
{
	return 0;
}

/**
 * mac802154_wpan_update_llsec()
 * @dev: -
 */
static int
mac802154_wpan_update_llsec(struct net_device *dev)
{
	return 0;
}

/**
 * mac802154_llsec_destroy()
 * @sec: -
 */
static void mac802154_llsec_destroy(struct mac802154_llsec *sec)
{
	return;
}

/**
 * ieee802154_print_addr()
 * @name: -
 * @addr: -
 */
static void
ieee802154_print_addr(const char *name, const struct ieee802154_addr *addr)
{
	if (!addr) {
		pr_debug("%s address is null\n", name);
		return;
	}


	if (addr->mode == IEEE802154_ADDR_NONE)
		pr_debug("%s not present\n", name);

	pr_debug("%s PAN ID: %04x\n", name, le16_to_cpu(addr->pan_id));
	if (addr->mode == IEEE802154_ADDR_SHORT) {
		pr_debug("%s is short: %04x\n", name,
				le16_to_cpu(addr->short_addr));
	} else {
		u64 hw = swab64((__force u64)addr->extended_addr);

		pr_debug("%s is hardware: %8phC\n", name, &hw);
	}
}

/**
 * IEEE802154_DEV_TO_SUB_IF() - Copy from Linux/net/mac802154/ieee802154_i.h
 * @dev: -
 */
static inline struct ieee802154_sub_if_data *
IEEE802154_DEV_TO_SUB_IF(const struct net_device *dev)
{
	return netdev_priv(dev);
}

/**
 * ieee802154_if_setup() - Copy from Linux/net/mac802154/iface.c
 * @dev: -
 */
static void ieee802154_if_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE802154_EXTENDED_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_EXTENDED_ADDR_LEN);

	/* Let hard_header_len set to IEEE802154_MIN_HEADER_LEN. AF_PACKET
	 * will not send frames without any payload, but ack frames
	 * has no payload, so substract one that we can send a 3 bytes
	 * frame. The xmit callback assumes at least a hard header where two
	 * bytes fc and sequence field are set.
	 */
	dev->hard_header_len	= IEEE802154_MIN_HEADER_LEN - 1;
	/* The auth_tag header is for security and places in private payload
	 * room of mac frame which stucks between payload and FCS field.
	 */
	dev->needed_tailroom	= IEEE802154_MAX_AUTH_TAG_LEN +
				  IEEE802154_FCS_LEN;
	/* The mtu size is the payload without mac header in this case.
	 * We have a dynamic length header with a minimum header length
	 * which is hard_header_len. In this case we let mtu to the size
	 * of maximum payload which is IEEE802154_MTU - IEEE802154_FCS_LEN -
	 * hard_header_len. The FCS which is set by hardware or ndo_start_xmit
	 * and the minimum mac header which can be evaluated inside driver
	 * layer. The rest of mac header will be part of payload if greater
	 * than hard_header_len.
	 */
	dev->mtu		= IEEE802154_MTU - IEEE802154_FCS_LEN -
				  dev->hard_header_len;
	dev->tx_queue_len	= 300;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
}

/**
 * ieee802154_header_create() - Copy from Linux/net/mac802154/iface.c
 * @skb: -
 * @dev: -
 * @daddr: -
 * @saddr: -
 * @len: -
 */
static int ieee802154_header_create(struct sk_buff *skb,
				    struct net_device *dev,
				    const struct ieee802154_addr *daddr,
				    const struct ieee802154_addr *saddr,
				    unsigned len)
{
	struct ieee802154_hdr hdr;
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct ieee802154_mac_cb *cb = mac_cb(skb);
	int hlen;

	if (!daddr)
		return -EINVAL;

	memset(&hdr.fc, 0, sizeof(hdr.fc));
	hdr.fc.type = cb->type;
	hdr.fc.security_enabled = cb->secen;
	hdr.fc.ack_request = cb->ackreq;
	hdr.seq = atomic_inc_return(&dev->ieee802154_ptr->dsn) & 0xFF;

	if (mac802154_set_header_security(sdata, &hdr, cb) < 0)
		return -EINVAL;

	if (!saddr) {
		if (wpan_dev->short_addr == cpu_to_le16(IEEE802154_ADDR_BROADCAST) ||
		    wpan_dev->short_addr == cpu_to_le16(IEEE802154_ADDR_UNDEF) ||
		    wpan_dev->pan_id == cpu_to_le16(IEEE802154_PANID_BROADCAST)) {
			hdr.source.mode = IEEE802154_ADDR_LONG;
			hdr.source.extended_addr = wpan_dev->extended_addr;
		} else {
			hdr.source.mode = IEEE802154_ADDR_SHORT;
			hdr.source.short_addr = wpan_dev->short_addr;
		}

		hdr.source.pan_id = wpan_dev->pan_id;
	} else {
		hdr.source = *(const struct ieee802154_addr *)saddr;
	}

	hdr.dest = *(const struct ieee802154_addr *)daddr;

	hlen = ieee802154_hdr_push(skb, &hdr);
	if (hlen < 0)
		return -EINVAL;

	skb_reset_mac_header(skb);
	skb->mac_len = hlen;

	if (len > ieee802154_max_payload(&hdr))
		return -EMSGSIZE;

	return hlen;
}

/**
 * mac802154_wpan_ioctl() - Copy from Linux/net/mac802154/iface.c
 * @dev: -
 * @ifr: -
 * @cmd: -
 */
static int
mac802154_wpan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct sockaddr_ieee802154 *sa =
		(struct sockaddr_ieee802154 *)&ifr->ifr_addr;
	int err = -ENOIOCTLCMD;

	if (cmd != SIOCGIFADDR && cmd != SIOCSIFADDR)
		return err;

	rtnl_lock();

	switch (cmd) {
	case SIOCGIFADDR:
	{
		u16 pan_id, short_addr;

		pan_id = le16_to_cpu(wpan_dev->pan_id);
		short_addr = le16_to_cpu(wpan_dev->short_addr);
		if (pan_id == IEEE802154_PANID_BROADCAST ||
		    short_addr == IEEE802154_ADDR_BROADCAST) {
			err = -EADDRNOTAVAIL;
			break;
		}

		sa->family = AF_IEEE802154;
		sa->addr.addr_type = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = pan_id;
		sa->addr.short_addr = short_addr;

		err = 0;
		break;
	}
	case SIOCSIFADDR:
		if (netif_running(dev)) {
			rtnl_unlock();
			return -EBUSY;
		}

		dev_warn(&dev->dev,
			 "Using DEBUGing ioctl SIOCSIFADDR isn't recommended!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.addr_type != IEEE802154_ADDR_SHORT ||
		    sa->addr.pan_id == IEEE802154_PANID_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_UNDEF) {
			err = -EINVAL;
			break;
		}

		wpan_dev->pan_id = cpu_to_le16(sa->addr.pan_id);
		wpan_dev->short_addr = cpu_to_le16(sa->addr.short_addr);

		err = mac802154_wpan_update_llsec(dev);
		break;
	}

	rtnl_unlock();
	return err;
}

/**
 * mac802154_wpan_free() - Copy from Linux/net/mac802154/iface.c
 * @dev: -
 */
static void mac802154_wpan_free(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	mac802154_llsec_destroy(&sdata->sec);

	free_netdev(dev);
}


/**
 * ieee802154_deliver_skb() - Copy from Linux/net/mac802154/rx.c
 * @skb: -
 */
static int ieee802154_deliver_skb(struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = htons(ETH_P_IEEE802154);

	return netif_receive_skb(skb);
}

/**
 * ieee802154_subif_frame() - Copy from Linux/net/mac802154/rx.c
 * @sdata: -
 * @skb: -
 * @hdr: -
 */
static int
ieee802154_subif_frame(struct ieee802154_sub_if_data *sdata,
		       struct sk_buff *skb, const struct ieee802154_hdr *hdr)
{
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	__le16 span, sshort;
	int rc;

	pr_debug("getting packet via slave interface %s\n", sdata->dev->name);

	span = wpan_dev->pan_id;
	sshort = wpan_dev->short_addr;

	switch (mac_cb(skb)->dest.mode) {
	case IEEE802154_ADDR_NONE:
		if (mac_cb(skb)->dest.mode != IEEE802154_ADDR_NONE)
			/* FIXME: check if we are PAN coordinator */
			skb->pkt_type = PACKET_OTHERHOST;
		else
			/* ACK comes with both addresses empty */
			skb->pkt_type = PACKET_HOST;
		break;
	case IEEE802154_ADDR_LONG:
		if (mac_cb(skb)->dest.pan_id != span &&
		    mac_cb(skb)->dest.pan_id != cpu_to_le16(IEEE802154_PANID_BROADCAST))
			skb->pkt_type = PACKET_OTHERHOST;
		else if (mac_cb(skb)->dest.extended_addr == wpan_dev->extended_addr)
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	case IEEE802154_ADDR_SHORT:
		if (mac_cb(skb)->dest.pan_id != span &&
		    mac_cb(skb)->dest.pan_id != cpu_to_le16(IEEE802154_PANID_BROADCAST))
			skb->pkt_type = PACKET_OTHERHOST;
		else if (mac_cb(skb)->dest.short_addr == sshort)
			skb->pkt_type = PACKET_HOST;
		else if (mac_cb(skb)->dest.short_addr ==
			  cpu_to_le16(IEEE802154_ADDR_BROADCAST))
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	default:
		pr_debug("invalid dest mode\n");
		goto fail;
	}

	skb->dev = sdata->dev;

	/* TODO this should be moved after netif_receive_skb call, otherwise
	 * wireshark will show a mac header with security fields and the
	 * payload is already decrypted.
	 */
	rc = mac802154_llsec_decrypt(&sdata->sec, skb);
	if (rc) {
		pr_debug("decryption failed: %i\n", rc);
		goto fail;
	}

	sdata->dev->stats.rx_packets++;
	sdata->dev->stats.rx_bytes += skb->len;

	switch (mac_cb(skb)->type) {
	case IEEE802154_FC_TYPE_BEACON:
	case IEEE802154_FC_TYPE_ACK:
	case IEEE802154_FC_TYPE_MAC_CMD:
		goto fail;

	case IEEE802154_FC_TYPE_DATA:
		return ieee802154_deliver_skb(skb);
	default:
		pr_warn_ratelimited("ieee802154: bad frame received "
				    "(type = %d)\n", mac_cb(skb)->type);
		goto fail;
	}

fail:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/**
 * ieee802154_parse_frame_start() - Copy from Linux/net/mac802154/rx.c
 * @skb: -
 * @hdr: -
 */
static int
ieee802154_parse_frame_start(struct sk_buff *skb, struct ieee802154_hdr *hdr)
{
	int hlen;
	struct ieee802154_mac_cb *cb = mac_cb_init(skb);

	skb_reset_mac_header(skb);

	hlen = ieee802154_hdr_pull(skb, hdr);
	if (hlen < 0)
		return -EINVAL;

	skb->mac_len = hlen;

	pr_debug("fc: %04x dsn: %02x\n", le16_to_cpup((__le16 *)&hdr->fc),
		 hdr->seq);

	cb->type = hdr->fc.type;
	cb->ackreq = hdr->fc.ack_request;
	cb->secen = hdr->fc.security_enabled;

	ieee802154_print_addr("destination", &hdr->dest);
	ieee802154_print_addr("source", &hdr->source);

	cb->source = hdr->source;
	cb->dest = hdr->dest;

	if (hdr->fc.security_enabled) {
		u64 key;

		pr_debug("seclevel %i\n", hdr->sec.level);

		switch (hdr->sec.key_id_mode) {
		case IEEE802154_SCF_KEY_IMPLICIT:
			pr_debug("implicit key\n");
			break;

		case IEEE802154_SCF_KEY_INDEX:
			pr_debug("key %02x\n", hdr->sec.key_id);
			break;

		case IEEE802154_SCF_KEY_SHORT_INDEX:
			pr_debug("key %04x:%04x %02x\n",
				 le32_to_cpu(hdr->sec.short_src) >> 16,
				 le32_to_cpu(hdr->sec.short_src) & 0xffff,
				 hdr->sec.key_id);
			break;

		case IEEE802154_SCF_KEY_HW_INDEX:
			key = swab64((__force u64)hdr->sec.extended_src);
			pr_debug("key source %8phC %02x\n", &key,
				 hdr->sec.key_id);
			break;
		}
	}

	return 0;
}
#undef ieee802154_sub_if_data

/**
 * DOC: ************** Utility functions. ***************** 
 */

/**
 * extended_addr_hton()
 * @net:  IEEE802.15.4 extended address represented by network byte order.
 * @host: IEEE802.15.4 extended address represented by host byte order.
 */
static void
extended_addr_hton(uint64_t* net, uint64_t* host)
{
#ifndef __BIG_ENDIAN
        ieee802154_be64_to_le64(net, host);
#else
        memcpy(net, host, sizeof(uint64_t) );
#endif
}

/**
 * DOC: ************** Debug print utility functions. ***************** 
 */


/**
 * pr_ieee802154_addr()
 * @name: -
 * @addr: print this address.
 */
static void
pr_ieee802154_addr(const char *name, const struct ieee802154_addr *addr)
{
        if (!addr) {
                pr_debug("%s address is null\n", name);
                return;
        }


        if (addr->mode == IEEE802154_ADDR_NONE)
                pr_debug("%s not present\n", name);

        pr_debug("%s PAN ID: %04x\n", name, le16_to_cpu(addr->pan_id));
        if (addr->mode == IEEE802154_ADDR_SHORT) {
                pr_debug("%s is short: %04x\n", name,
                                le16_to_cpu(addr->short_addr));
        } else {
                u64 hw = swab64((__force u64)addr->extended_addr);

                pr_debug("%s is hardware: %8phC\n", name, &hw);
        }
}

/**
 * pr_ieee802154_hdr()
 * @hdr: print this header.
 */
static void
pr_ieee802154_hdr(const struct ieee802154_hdr *hdr)
{
        struct ieee802154_hdr_fc fc = hdr->fc;

        pr_debug("fc: intra_pan:%d ackreq:%x pending:%d secen:%x "
                        "type:%x saddr_mode:%x version:%x daddr_mode:%x",
                        fc.intra_pan, fc.ack_request, fc.frame_pending,
                        fc.security_enabled, fc.type, fc.source_addr_mode,
                        fc.version, fc.dest_addr_mode);

        pr_debug("seq %d", hdr->seq);
        pr_ieee802154_addr("src", &hdr->source);
        pr_ieee802154_addr("dst", &hdr->dest);
}

/**
 * pr_wpan_phy_supported()
 * @phy: print this phy.
 */
static void
pr_wpan_phy_supported(struct wpan_phy* phy)
{
        struct wpan_phy_supported *supported = &phy->supported;
        u32 *channels = supported->channels;
        pr_debug("wpan_phy=%p {\n", phy);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[0], channels[1], channels[2], channels[3]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[4], channels[5], channels[6], channels[0]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[8], channels[9], channels[10], channels[11]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[12], channels[13], channels[14], channels[15]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[16], channels[17], channels[18], channels[19]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[20], channels[21], channels[22], channels[23]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[24], channels[25], channels[26], channels[27]);
        pr_debug("             channels = %08x, %08x, %08x, %08x\n",
                        channels[28], channels[29], channels[30], channels[31]);
        pr_debug("            cca_modes = %u\n", supported->cca_modes);
        pr_debug("             cca_opts = %u\n", supported->cca_opts);
        pr_debug("              iftypes = %u\n", supported->iftypes);
        pr_debug("                  lbt = %u\n", supported->lbt);
        pr_debug("            min_minbe = %u\n", supported->min_minbe);
        pr_debug("            max_minbe = %u\n", supported->max_minbe);
        pr_debug("            min_maxbe = %u\n", supported->min_maxbe);
        pr_debug("            max_maxbe = %u\n", supported->max_maxbe);
        pr_debug("    min_csma_backoffs = %u\n", supported->min_csma_backoffs);
        pr_debug("    max_csma_backoffs = %u\n", supported->max_csma_backoffs);
        pr_debug("    min_frame_retries = %u\n", supported->min_frame_retries);
        pr_debug("    max_frame_retries = %u\n", supported->max_frame_retries);
        pr_debug("       tx_powers_size = %zu\n", supported->tx_powers_size);
        pr_debug("   cca_ed_levels_size = %zu\n", supported->cca_ed_levels_size);
        pr_debug("}\n");

//const s32 *tx_powers, *cca_ed_levels;
}

/**
 * pr_wpan_phy()
 * @phy: print this phy.
 */
static void
pr_wpan_phy(struct wpan_phy* phy)
{
        pr_debug("wpan_phy=%p {\n", phy);
        pr_debug("               privid = %p\n", phy->privid);
        pr_debug("                flags = %d\n", phy->flags);
        pr_debug("      current_channel = %d\n", phy->current_channel);
        pr_debug("         current_page = %d\n", phy->current_page);
        pr_debug("       transmit_power = %d\n", phy->transmit_power);
        pr_debug("             cca.mode = %d\n", phy->cca.mode);
        pr_debug("              cca.opt = %d\n", phy->cca.opt);
        pr_debug("   perm_extended_addr = %016llx\n", phy->perm_extended_addr);
        pr_debug("         cca_ed_level = %d\n", phy->cca_ed_level);
        pr_debug("      symbol_duration = %u\n", phy->symbol_duration);
        pr_debug("          lifs_period = %u\n", phy->lifs_period);
        pr_debug("          sifs_period = %u\n", phy->sifs_period);
        //pr_debug("                 _net = %p\n", phy->_net->net);
        pr_debug("                 priv = %p\n", phy->priv);
        pr_debug("}\n");
//struct wpan_phy_supported supported;
//struct device dev;
}

/**
 * pr_wpan_dev()
 * @dev: WPAN dev that is associated with this XBee.
 */
static void
pr_wpan_dev(struct wpan_dev* dev)
{
        pr_debug("wpan_dev=%p {\n", dev);
        pr_debug("            wpan_phy = %p\n", dev->wpan_phy);
        pr_debug("              iftype = %d\n", dev->iftype);
        pr_debug("              netdev = %p\n", dev->netdev);
        pr_debug("          lowpan_dev = %p\n", dev->lowpan_dev);
        pr_debug("          identifier = %x\n", dev->identifier);
        pr_debug("              pan_id = %04x\n", dev->pan_id);
        pr_debug("          short_addr = %04x\n", dev->short_addr);
        pr_debug("       extended_addr = %016llx\n", dev->extended_addr);
        pr_debug("                 bsn = %u\n", dev->bsn.counter);
        pr_debug("                 dsn = %u\n", dev->dsn.counter);
        pr_debug("              min_be = %u\n", dev->min_be);
        pr_debug("              max_be = %u\n", dev->max_be);
        pr_debug("        csma_retries = %u\n", dev->csma_retries);
        pr_debug("       frame_retries = %d\n", dev->frame_retries);
        pr_debug("                 lbt = %u\n", dev->lbt);
        pr_debug("    promiscuous_mode = %d\n", dev->promiscuous_mode);
        pr_debug("              ackreq = %d\n", dev->ackreq);
        pr_debug("}\n");
}

/**
 * pr_frame_atcmdr()
 * @skb: AT Command response frame to print.
 */
static void
pr_frame_atcmdr(struct sk_buff *skb)
{
        // AT command response must handle call side.
        struct xb_frame_atcmdr* atresp = (struct xb_frame_atcmdr*)skb->data;
        pr_debug("AT_R: id=0x%02x cmd=%c%c status=%d\n",
                        atresp->id, atresp->command&0xFF,
                        (atresp->command & 0xFF00)>>8 , atresp->status);
}

/**
 * pr_frame_rx64io()
 * @skb: frame to print.
 */
static void
pr_frame_rx64io(struct sk_buff *skb)
{
        struct xb_frame_rx64* rx64 = (struct xb_frame_rx64*)skb->data;
        pr_debug("UNEXPECTED RX64IO: addr=%016llx rssi=%d options=%x\n",
                        rx64->srcaddr, rx64->rssi, rx64->options);
}

/**
 * pr_frame_rx16io()
 * @skb: frame to print.
 */
static void
pr_frame_rx16io(struct sk_buff *skb)
{
        struct xb_frame_rx16* rx16 = (struct xb_frame_rx16*)skb->data;
        pr_debug("UNEXPECTED RX16IO: addr=%04x rssi=%d options=%x\n",
                        rx16->srcaddr, rx16->rssi, rx16->options);
}

/**
 * pr_frame_atcmd()
 * @skb: frame to print.
 */
static void
pr_frame_atcmd(struct sk_buff *skb)
{
        struct xb_frame_atcmd* atcmd = (struct xb_frame_atcmd*)skb->data;
        pr_debug("UNEXPECTED ATCMD: id=0x%02x cmd=%c%c\n",
                        atcmd->id, atcmd->command&0xFF,
                        (atcmd->command & 0xFF00)>>8);
}

/**
 * pr_frame_atcmdq()
 * @skb: frame to print.
 */
static void
pr_frame_atcmdq(struct sk_buff *skb)
{
        struct xb_frame_atcmd* atcmd = (struct xb_frame_atcmd*)skb->data;
        pr_debug("UNEXPECTED ATCMDQ: id=0x%02x cmd=%c%c\n",
                        atcmd->id, atcmd->command&0xFF,
                        (atcmd->command & 0xFF00)>>8);
}

/**
 * pr_frame_rcmd()
 * @skb: frame to print.
 */
static void
pr_frame_rcmd(struct sk_buff *skb)
{
        struct xb_frame_rcmd* ratcmd = (struct xb_frame_rcmd*)skb->data;
        pr_debug("UNEXPECTED RATCMD: id=0x%02x addr64=%016llx "
                        "addr16=%04x cmd=%c%c\n",
                        ratcmd->id, ratcmd->destaddr64, ratcmd->destaddr16,
                        ratcmd->command&0xFF, (ratcmd->command & 0xFF00)>>8);
}

/**
 * pr_frame_rcmdr()
 * @skb: frame to print.
 */
static void
pr_frame_rcmdr(struct sk_buff *skb)
{
        struct xb_frame_rcmdr* ratcmdr = (struct xb_frame_rcmdr*)skb->data;
        pr_debug("UNEXPECTED RATCMDR: id=0x%02x addr64=%016llx "
                        "addr16=%04x cmd=%c%c status=%d\n",
                        ratcmdr->id,
                        ratcmdr->destaddr64, ratcmdr->destaddr16,
                        ratcmdr->command&0xFF,
                        (ratcmdr->command & 0xFF00)>>8, ratcmdr->status);
}

/**
 * pr_frame_tx64()
 * @skb: frame to print.
 */
static void
pr_frame_tx64(struct sk_buff *skb)
{
        struct xb_frame_tx64* tx64 = (struct xb_frame_tx64*)skb->data;
        pr_debug("UNEXPECTED TX64: id=0x%02x addr=%llx options=%x\n",
                        tx64->id, tx64->destaddr, tx64->options);
}

/**
 * pr_frame_tx16()
 * @skb: frame to print.
 */
static void
pr_frame_tx16(struct sk_buff *skb)
{
        struct xb_frame_tx16* tx16 = (struct xb_frame_tx16*)skb->data;
        pr_debug("UNEXPECTED TX16: id=0x%02x addr=%04x options=%x\n",
                        tx16->id, tx16->destaddr, tx16->options);
}

/**
 * pr_frame_default()
 * @skb: frame to print.
 */
static void
pr_frame_default(struct sk_buff *skb)
{
        pr_debug("%s\n", __func__);
}

/**
 * DOC: ************** Buffer utility functions. ***************** 
 */

/**
 * buffer_calc_checksum()
 *
 * @buf: data which formatted by APIv1.
 * @len: buffer length.
 */
static unsigned char
buffer_calc_checksum(const unsigned char* buf, const size_t len)
{
        size_t i=0;
        unsigned char checksum = 0;
        for(i=0; i<len; i++) {
                checksum += buf[i];
        }
        return 0xFF - checksum;
}

/**
 * buffer_find_delimiter_escaped()
 *
 * @buf: data which formatted by APIv2.
 * @len: buffer length.
 */
static int
buffer_find_delimiter_escaped(const unsigned char* buf, const size_t len)
{
        size_t i=0;
        bool esc = false;
        for(i=0; i<len; i++) {
                if(buf[i] == XBEE_ESCAPE) {
                        esc = true; continue;
                }
                else if(buf[i] == XBEE_ESCAPED_DELIMITER && esc) {
                        return i-1;
                }
                else if(buf[i] == XBEE_DELIMITER && !esc) {
                        return i;
                }
                esc = false;
        }
        return -1;
}

/**
 * buffer_unescape()
 *
 * @buf: data which formatted by APIv1.
 * @len: buffer length.
 */
static size_t
buffer_unescape(unsigned char* buf, const size_t len)
{
        size_t i=0;
        int escape_count = 0;
        bool esc = false;

        for(i=0; i<len; i++) {
                if(buf[i] == XBEE_ESCAPE) {
                        esc = true;
                        escape_count++;
                        continue;
                }
                if(esc) buf[i-escape_count] = (buf[i] ^ XBEE_ESCMASK);
                else    buf[i-escape_count] =  buf[i];
                esc = false;
        }
        if(esc) {
                buf[i-escape_count] = XBEE_ESCAPE;
                escape_count--;
        }

        return len-escape_count;
}

/**
 * buffer_escaped_len()
 *
 * @buf: data which formatted by APIv1.
 * @len: buffer length.
 */
static size_t
buffer_escaped_len(const unsigned char* buf, const size_t len)
{
        size_t i=0;
        int escape_count = 0;

        for(i=1; i<len; i++) {
                if( buf[i] == XBEE_DELIMITER ||
                    buf[i] == XBEE_ESCAPE ||
                    buf[i] == XBEE_XON ||
                    buf[i] == XBEE_XOFF)
                {
                        escape_count++;
                }
        }

        return len+escape_count;
}

/**
 * buffer_escape()
 * @buf: Data which formatted by APIv1.
 * @data_len: Buffer length. TODO
 * @buf_len: Buffer length. TODO
 *
 * Buffer must enough large to contain escaped data size.
 */
static int
buffer_escape(unsigned char* buf, const size_t data_len, const size_t buf_len)
{
        size_t i=0;
        size_t tail_ptr=buf_len;

        for(i=data_len-1; i>0; i--) {
                if((buf[i] == XBEE_DELIMITER ||
                    buf[i] == XBEE_ESCAPE ||
                    buf[i] == XBEE_XON ||
                    buf[i] == XBEE_XOFF) )
                {
                        buf[--tail_ptr] = (buf[i] ^ XBEE_ESCMASK);
                        buf[--tail_ptr] = XBEE_ESCAPE;
                }
                else {
                        buf[--tail_ptr] = buf[i];
                }
                
                if(tail_ptr < i) {
                        return -1;
                }
        }

        return buf_len - tail_ptr;
}

/**
 * DOC: ************** XBee Frame utility functions. ***************** 
 */

/**
 * frame_alloc() - allocate XBee frame as sk_buff.
 * @paylen: payload length.
 * @type: XBee frame type
 * @alloc_csum: if true, allocate one more byte for checksum.
 */
static struct sk_buff*
frame_alloc(size_t paylen, uint8_t type, bool alloc_csum)
{
        struct sk_buff* new_skb = NULL;
        struct xb_frame_header* frm = NULL;
        size_t csum_size = alloc_csum;
        size_t frame_size = paylen + sizeof(struct xb_frame_header) + csum_size;

        new_skb = dev_alloc_skb(frame_size);
        if(!new_skb)
                return NULL;

        frm = (struct xb_frame_header*)skb_put(new_skb, frame_size);
        if(!frm) {
                kfree_skb(new_skb);
                return NULL;
        }

        frm->start_delimiter  = XBEE_DELIMITER;
        frm->length = htons(paylen + XBEE_FRAME_CHECKSUM_SIZE);
        frm->type = type;
        return new_skb;
}

/**
 * frame_payload_length()
 * @frame: XBee frame. (v1/v2)
 */
static uint16_t
frame_payload_length(struct sk_buff* frame)
{
        struct xb_frame_header* frm = (struct xb_frame_header*)frame->data;
        if(!frm)
                return 0;

        return htons(frm->length);
}

/**
 * frame_payload_buffer()
 * @frame: XBee frame. (v1/v2)
 */
static const unsigned char*
frame_payload_buffer(struct sk_buff* frame)
{
        return frame->data + XBEE_FRAME_OFFSET_PAYLOAD;
}

/**
 * frame_calc_checksum()
 * @frame: XBee frame. (must be v1 API)
 */
static unsigned char
frame_calc_checksum(struct sk_buff* frame)
{
        return buffer_calc_checksum(frame_payload_buffer(frame),
                                frame_payload_length(frame) );
}

/**
 * frame_put_checksum()
 * @frame: XBee frame. (must be v1 API)
 */
static void
frame_put_checksum(struct sk_buff* frame)
{
        uint8_t csum = frame_calc_checksum(frame);
        uint8_t* putbuf = skb_put(frame, XBEE_FRAME_CHECKSUM_SIZE);
        *putbuf = csum;
}

/**
 * frame_trim_checksum()
 * @frame: XBee frame. (must be v1 API)
 */
static void
frame_trim_checksum(struct sk_buff* frame)
{
        skb_trim(frame, frame->len - XBEE_FRAME_CHECKSUM_SIZE);
}

/**
 * frame_escape()
 * @frame: XBee frame. (must be v1 API)
 */
static int
frame_escape(struct sk_buff* frame)
{
        size_t esclen = 0;
        size_t datalen = 0;
        uint8_t csum = 0;

        if(frame->len < XBEE_FRAME_COMMON_HEADER_AND_TRAILER)
                return -1;
        
        datalen = frame_payload_length(frame) + XBEE_FRAME_OFFSET_PAYLOAD;
        esclen = buffer_escaped_len(frame->data, datalen);

        if(esclen > datalen) {
                csum = frame->data[datalen];
                skb_put(frame, esclen - datalen);
                buffer_escape(frame->data, datalen, esclen);
                frame->data[esclen] = csum;
        }

        return 0;
}

/**
 * frame_unescape()
 * @frame: XBee frame. (must be v2 API frame)
 */
static void
frame_unescape(struct sk_buff* frame)
{
        int unesc_len = 0;
        unesc_len = buffer_unescape(frame->data, frame->len);
        skb_trim(frame, unesc_len);
}

/**
 * frame_verify()
 * @recv_buf: sk_buff which stores received data from XBee.
 */
static int
frame_verify(struct sk_buff* recv_buf)
{
        unsigned short length = 0;
        uint8_t checksum = 0;
        struct xb_frame_header* header = NULL;

        if(recv_buf->len < XBEE_FRAME_DELIMITER_SIZE)
                return -EAGAIN;

        header = (struct xb_frame_header*)recv_buf->data;

        if(recv_buf->data[0] != XBEE_DELIMITER)
                return -EINVAL;
        if(recv_buf->len < XBEE_FRAME_OFFSET_PAYLOAD)
                return -EAGAIN;

        length = htons(header->length);

        if(recv_buf->len < length + XBEE_FRAME_COMMON_HEADER_AND_TRAILER)
                return -EAGAIN;

        checksum = frame_calc_checksum(recv_buf);

        if(checksum!=recv_buf->data[length+XBEE_FRAME_OFFSET_PAYLOAD])
                return -EINVAL;

        return length + XBEE_FRAME_COMMON_HEADER_AND_TRAILER;
}

/**
 * frame_put_received_data()
 *
 * @recv_buf: sk_buff to store received data.
 * @buf: New received data.
 * @len: Length of buf.
 */
static int
frame_put_received_data(struct sk_buff* recv_buf,
                const unsigned char* buf, const size_t len)
{
        int delimiter_pos = 0;
        unsigned char* tail = NULL;

        delimiter_pos = buffer_find_delimiter_escaped(buf, len);

        if(recv_buf->len == 0) {
                if(delimiter_pos == -1) {
                        return 0;
                }
                tail = skb_put(recv_buf, len-delimiter_pos);
                memcpy(tail, buf+delimiter_pos, len-delimiter_pos);
                return len-delimiter_pos;
        }
        else {
                tail = skb_put(recv_buf, len);
                memcpy(tail, buf, len);
                return len;
        }
}

/**
 * frame_atcmdr_result()
 * @atcmd_resp_frame: AT command response frame.
 */
static int
frame_atcmdr_result(struct sk_buff* atcmd_resp_frame)
{
        struct xb_frame_atcmdr* atcmdr =
                (struct xb_frame_atcmdr*)atcmd_resp_frame->data;
        return -atcmdr->status;
}

/**
 * frameq_enqueue_received()
 *
 * @recv_queue: Received frame queue.
 * @recv_buf: sk_buff which contains received data.
 */
static int
frameq_enqueue_received(struct sk_buff_head *recv_queue,
                        struct sk_buff* recv_buf, bool apiv2)
{
        int frame_count = 0;
        int ret = 0;

        if(apiv2)
                frame_unescape(recv_buf);

        while ( (ret = frame_verify(recv_buf)) > 0) {
                int verified_len = ret;
                int remains = recv_buf->len - verified_len;
                unsigned char* append = NULL;
                struct sk_buff* newframe = NULL;

                newframe = dev_alloc_skb(IEEE802154_MTU);

                append = skb_put(newframe, verified_len);
                memcpy(append, recv_buf->data, verified_len);

                print_hex_dump_bytes("<<<< ", DUMP_PREFIX_NONE,
                                newframe->data, newframe->len);
                skb_queue_tail(recv_queue, newframe);

                memmove(recv_buf->data, recv_buf->data+verified_len,  remains);
                skb_trim(recv_buf, remains);

                frame_count++;
        }

        if (ret == -EINVAL) {
                skb_trim(recv_buf, 0);
        }

        return frame_count;
}

/**
 * frameq_dequeue_by_id()
 *
 * @recv_queue: receive queue
 * @frameid: Dequeue frame which has this id from receive queue.
 */
static struct sk_buff*
frameq_dequeue_by_id(struct sk_buff_head *recv_queue, uint8_t frameid)
{
        struct sk_buff* skb = NULL;
        struct xb_frame_header_id* hd = NULL;

        skb_queue_walk(recv_queue, skb) {
                hd = (struct xb_frame_header_id*)skb->data;
                if(        hd->id == frameid &&
                        hd->type != XBEE_FRM_RX64 &&
                        hd->type != XBEE_FRM_RX16 &&
                        hd->type != XBEE_FRM_RX64IO &&
                        hd->type != XBEE_FRM_RX16IO &&
                        hd->type != XBEE_FRM_MSTAT) {
                        skb_unlink(skb, recv_queue);
                        return skb;
                }
        }

        return NULL;
}

/**
 * frameq_enqueue_send()
 * @send_queue: send queue
 * @send_frame: send frame
 */
static void
frameq_enqueue_send(struct sk_buff_head *send_queue, struct sk_buff* send_frame)
{
        skb_queue_tail(send_queue, send_frame);
}

/**
 * frameq_enqueue_send_at()
 *
 * @send_queue: send queue
 * @atcmd: AT command type.
 * @id: frameid to assign send frame.
 * @buf: Buffer contains parameter for this AT command.
 * @buflen: Length of buf.
 */
static void
frameq_enqueue_send_at(struct sk_buff_head *send_queue, unsigned short atcmd,
                                uint8_t id, char* buf, unsigned short buflen)
{
        struct sk_buff* newskb = NULL;
        struct xb_frame_atcmd* atfrm = NULL;

        unsigned char checksum = 0;
        int datalen = 0;

        newskb = frame_alloc(buflen + XBEE_FRAME_OFFSET_PAYLOAD, XBEE_FRM_ATCMD, true);
        atfrm = (struct xb_frame_atcmd*)newskb->data;

        atfrm->id = id;
        atfrm->command = htons(atcmd);

        datalen = htons(atfrm->hd.length);

        memmove(newskb->data + sizeof(struct xb_frame_atcmd), buf, buflen);

        checksum = frame_calc_checksum(newskb);
        newskb->data[datalen+XBEE_FRAME_OFFSET_PAYLOAD] = checksum;
        //frame_put_checksum(newskb);

        frameq_enqueue_send(send_queue, newskb);
}

/**
 * xb_frameid()
 * @xb: XBee device context.
 */
static uint8_t
xb_frameid(struct xb_device* xb)
{
        xb->frameid++;
        if(xb->frameid == 0) {
                xb->frameid++;
        }
        return xb->frameid;
}

/**
 * xb_enqueue_send_at()
 *
 * @xb: XBee device context.
 * @atcmd: AT command type.
 * @buf: Buffer contains parameter for this AT command.
 * @buflen: Length of buf.
 */
static uint8_t
xb_enqueue_send_at(struct xb_device *xb, unsigned short atcmd,
                                char* buf, unsigned short buflen)
{
        uint8_t frameid = xb_frameid(xb);
        frameq_enqueue_send_at(&xb->send_queue, atcmd, frameid, buf, buflen);
        return frameid;
}

/**
 * xb_send_queue()
 * @xb: XBee device context.
 */
static int
xb_send_queue(struct xb_device* xb)
{
        struct tty_struct* tty = xb->tty;
        int send_count = 0;

        mutex_lock(&xb->queue_mutex);

        while( !skb_queue_empty(&xb->send_queue) ) {
                struct sk_buff* skb = skb_dequeue(&xb->send_queue);

                if(xb->api == XBEE_API_V2) {
                        frame_escape(skb);
                }

                print_hex_dump_bytes(">>>> ", DUMP_PREFIX_NONE,
                                skb->data, skb->len);

                /*
                if (newskb)
                        xbee_rx_irqsafe(xb, newskb, 0xcc);
                */

                tty->ops->write(tty, skb->data, skb->len);
                tty_driver_flush_buffer(tty);
                kfree_skb(skb);

                send_count++;
        }

        mutex_unlock(&xb->queue_mutex);

        return send_count;
}

/**
 * xb_send()
 * @xb: XBee device context.
 */
static int
xb_send(struct xb_device* xb)
{
        queue_work(xb->sendrecv_workq, (struct work_struct*)&xb->send_work.work);
        //return xb_send_queue(xb);
        return 0;
}

/**
 * xb_recv()
 *
 * @xb: XBee device context.
 * @expect_id: Wait to receive frame that have this ID.
 * @timeout: timeout in milliseconds
 */
static struct sk_buff*
xb_recv(struct xb_device* xb, uint8_t expect_id, unsigned long timeout)
{
        int ret = 0;
        struct sk_buff* skb = NULL;

        mutex_lock(&xb->queue_mutex);
        skb = frameq_dequeue_by_id(&xb->recv_queue, expect_id);
        mutex_unlock(&xb->queue_mutex);

        if(skb != NULL) return skb;

        queue_work(xb->sendrecv_workq, (struct work_struct*)&xb->recv_work.work);
        reinit_completion(&xb->cmd_resp_done);
        ret = wait_for_completion_timeout(&xb->cmd_resp_done, msecs_to_jiffies(timeout) );

        if(ret > 0) {
                mutex_lock(&xb->queue_mutex);
                skb = frameq_dequeue_by_id(&xb->recv_queue, expect_id);
                mutex_unlock(&xb->queue_mutex);
                return skb;
        }
        else if(ret == -ERESTARTSYS) {
                pr_debug("%s: interrupted %d\n", __func__, ret);
                return NULL;
        }
        else {
                pr_debug("%s: timeout %d\n", __func__, ret);
                return NULL;
        }
}

/**
 * xb_sendrecv()
 *
 * @xb: XBee device context.
 * @expect_id: Wait to receive frame that have this ID.
 */
static struct sk_buff*
xb_sendrecv(struct xb_device* xb, uint8_t expect_id)
{
        int i=0;
        struct sk_buff* skb = NULL;

        xb_send(xb);
        for(i=0; i<5; i++) {
                skb = xb_recv(xb, expect_id, 1000);
                if(skb) return skb;
        }
        return NULL;
}

/**
 * xb_sendrecv_atcmd()
 *
 * @xb: XBee device context.
 * @atcmd: AT command type.
 * @buf: Buffer contains parameter for this AT command.
 * @buflen: Length of buf.
 */
static struct sk_buff*
xb_sendrecv_atcmd(struct xb_device* xb, unsigned short atcmd,
                                char* buf, unsigned short buflen)
{
        uint8_t recvid = xb_enqueue_send_at(xb, atcmd, buf, buflen);
        return xb_sendrecv(xb, recvid);
}

/**
 * xb_receive()
 * @xb: XBee device context.
 * @skb: sk_buff. That contains received data from XBee.
 * @lqi: Link quality indicator.
 */
static void
xb_receive(struct xb_device *xb, struct sk_buff *skb, u8 lqi)
{
        int ret;
        struct xbee_sub_if_data *sdata = netdev_priv(xb->dev);
        struct ieee802154_hdr hdr;

        rcu_read_lock();

        ret = ieee802154_parse_frame_start(skb, &hdr);
        if (ret) {
                pr_debug("got invalid frame\n");
                goto err;
        }

        mac_cb(skb)->lqi = lqi;

        ieee802154_subif_frame(sdata, skb, &hdr);
        skb = NULL;

err:
        kfree_skb(skb);
        rcu_read_unlock();

        return;
}

/**
 * xb_frame_recv_rx64()
 *
 * @xb: XBee device context.
 * @skb: RX frame with 64bit address.
 */
static void
xb_frame_recv_rx64(struct xb_device *xb, struct sk_buff *skb)
{
        struct xbee_sub_if_data *sdata = netdev_priv(xb->dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;
        struct xb_frame_rx64* rx = (struct xb_frame_rx64*)skb->data;
        struct ieee802154_hdr hdr = {};
        int hlen = 0;

        if(xb->api == XBEE_API_V2)
                frame_unescape(skb);

        rx = (struct xb_frame_rx64*)skb->data;

        pr_debug("RX64: addr=%016llx rssi=%d options=%x\n",
                        rx->srcaddr, rx->rssi, rx->options);
        hdr.fc.type = IEEE802154_FC_TYPE_DATA;
        hdr.seq = 0; //XBee doesn't tell seqno.
        hdr.source.mode = IEEE802154_ADDR_LONG;
        extended_addr_hton(&hdr.dest.extended_addr, &rx->srcaddr);
        hdr.source.pan_id = (rx->options & 0x2) ? IEEE802154_PANID_BROADCAST : wpan_dev->pan_id;
        hdr.dest.mode = (rx->options & 0x1) ? IEEE802154_ADDR_SHORT : IEEE802154_ADDR_LONG;
        hdr.dest.short_addr = IEEE802154_ADDR_BROADCAST;
        hdr.dest.extended_addr = wpan_dev->extended_addr;
        hdr.dest.pan_id = (rx->options & 0x2) ? IEEE802154_PANID_BROADCAST : wpan_dev->pan_id;

        skb_pull(skb, sizeof(struct xb_frame_rx64) );
        frame_trim_checksum(skb);
        hlen = ieee802154_hdr_push(skb, &hdr);
        xb_receive(xb, skb, rx->rssi);
}

/**
 * xb_frame_recv_rx16()
 *
 * @xb: XBee device context.
 * @skb: RX frame with 16bit address.
 */
static void
xb_frame_recv_rx16(struct xb_device* xb, struct sk_buff *skb)
{
        struct xbee_sub_if_data *sdata = netdev_priv(xb->dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;
        struct xb_frame_rx16* rx = (struct xb_frame_rx16*)skb->data;
        struct ieee802154_hdr hdr = {};
        int hlen = 0;

        if(xb->api == XBEE_API_V2)
                frame_unescape(skb);

        pr_debug("RX16: addr=%04x rssi=%d options=%x\n", rx->srcaddr, rx->rssi, rx->options);
        hdr.fc.type = IEEE802154_FC_TYPE_DATA;
        hdr.seq = 0; //XBee doesn't tell seqno.
        hdr.source.mode = IEEE802154_ADDR_SHORT;
        hdr.source.short_addr = htons(rx->srcaddr);
        hdr.source.pan_id = (rx->options & 0x2) ? IEEE802154_PANID_BROADCAST : wpan_dev->pan_id;
        hdr.dest.mode = IEEE802154_ADDR_SHORT;
        hdr.dest.short_addr = (rx->options & 0x1) ? IEEE802154_ADDR_BROADCAST : wpan_dev->short_addr;
        hdr.dest.pan_id = (rx->options & 0x2) ? IEEE802154_PANID_BROADCAST : wpan_dev->pan_id;

        skb_pull(skb, sizeof(struct xb_frame_rx16) );
        frame_trim_checksum(skb);
        hlen = ieee802154_hdr_push(skb, &hdr);
        xb_receive(xb, skb, rx->rssi);
}

/**
 * xb_frame_recv_mstat()
 *
 * @xb: XBee device context.
 * @skb: Modem status frame.
 */
static void
xb_frame_recv_mstat(struct xb_device *xb, struct sk_buff *skb)
{
        struct xb_frame_mstat* mstat = (struct xb_frame_mstat*)skb->data;
        complete_all(&xb->modem_status_receive);
        pr_debug("MSTA: status=%d\n", mstat->status);
}

/**
 * xb_frame_recv_txstat()
 *
 * @xb: XBee device context.
 * @skb: Transmit status frame to print.
 */
static void
xb_frame_recv_txstat(struct xb_device* xb, struct sk_buff *skb)
{
        struct xb_frame_txstat* txstat = (struct xb_frame_txstat*)skb->data;
        pr_debug("TXST: id->0x%02x options=%x\n", txstat->id, txstat->options);
}

/**
 * xb_frame_recv_dispatch()
 *
 * @xb: xbee device
 * @frame: sk_buff. That contains received frame from XBee.
 *
 * Verify the XBee frame, then take appropriate action depending on the
 * frame type.
 */
static void
xb_frame_recv_dispatch(struct xb_device *xb, struct sk_buff *frame)
{
        struct xb_frame_header* hdr= (struct xb_frame_header*)frame->data;

        switch (hdr->type) {
        case XBEE_FRM_MSTAT:        xb_frame_recv_mstat(xb, frame);        break;
        case XBEE_FRM_ATCMDR:        pr_frame_atcmdr(frame);        break;
        case XBEE_FRM_RCMDR:        pr_frame_rcmdr(frame);        break;
        case XBEE_FRM_RX64:        xb_frame_recv_rx64(xb, frame);        break;
        case XBEE_FRM_RX16:        xb_frame_recv_rx16(xb, frame);        break;
        case XBEE_FRM_RX64IO:   pr_frame_rx64io(frame);        break;
        case XBEE_FRM_RX16IO:   pr_frame_rx16io(frame);        break;
        case XBEE_FRM_ATCMD:        pr_frame_atcmd(frame);        break;
        case XBEE_FRM_ATCMDQ:        pr_frame_atcmdq(frame);        break;
        case XBEE_FRM_RCMD:        pr_frame_rcmd(frame);        break;
        case XBEE_FRM_TX64:        pr_frame_tx64(frame);        break;
        case XBEE_FRM_TX16:        pr_frame_tx16(frame);        break;
        case XBEE_FRM_TXSTAT:        xb_frame_recv_txstat(xb, frame);        break;
        default:                pr_frame_default(frame);        break;
        }
}

/**
 * xb_set_get_param()
 *
 * @xb: XBee device context.
 * @atcmd: AT command type to set/get param.
 * @reqbuf: AT command parameter for request.
 * @reqsize: Length of reqbuf.
 * @respbuf: Pointer to the buffer that store command response.
 * @respsize: Length of reqpbuf.
 */
static int
xb_set_get_param(struct xb_device *xb, uint16_t atcmd,
                                const uint8_t* reqbuf, size_t reqsize,
                                uint8_t* respbuf, size_t respsize)
{
        int ret = -EINVAL;
        struct sk_buff *skb = NULL;
        struct xb_frame_atcmdr *resp = NULL;

        pr_debug("enter %s", __func__);

        skb = xb_sendrecv_atcmd(xb, atcmd, (uint8_t*)reqbuf, reqsize);
        if(!skb) {
                pr_debug("exit %s %d", __func__, -EINVAL);
                return -EINVAL;
        }

        if(frame_atcmdr_result(skb) == XBEE_ATCMDR_OK) {
                if(respbuf) {
                        resp = (struct xb_frame_atcmdr*)skb->data;
                        memcpy(respbuf, resp->response, respsize);
                }

                ret = 0;
        }
        kfree_skb(skb);

        pr_debug("exit %s %d", __func__, ret);
        return ret;
}

/**
 * xb_get_param()
 *
 * @xb: XBee device context.
 * @atcmd: AT command type to get param.
 * @respbuf: Pointer to the buffer that store command response.
 * @respsize: Length of reqpbuf.
 */
static int
xb_get_param(struct xb_device *xb, uint16_t atcmd,
                                uint8_t* respbuf, size_t respsize)
{
        return xb_set_get_param(xb, atcmd, NULL, 0, respbuf, respsize);
}

/**
 * xb_set_param()
 *
 * @xb: XBee device context.
 * @atcmd: AT command type to set param.
 * @reqbuf: AT command parameter for request.
 * @reqsize: Length of reqbuf.
 */
static int
xb_set_param(struct xb_device *xb, uint16_t atcmd,
                                const uint8_t* reqbuf, size_t reqsize)
{
        return xb_set_get_param(xb, atcmd, reqbuf, reqsize, "", 0);
}


/**
 * xb_set_channel()
 *
 * @xb: XBee device context.
 * @page: New channel page to use.
 * @channel: New channel to use.
 */
static int
xb_set_channel(struct xb_device *xb, u8 page, u8 channel)
{
        u8 ch = channel;
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_CH, &ch, sizeof(ch) );
}


/**
 * xb_get_channel()
 *
 * @xb: XBee device context.
 * @page: Pointer to the value that store channel page.
 * @channel: Pointer to the value that store channel.
 */
static int
xb_get_channel(struct xb_device *xb, u8 *page, u8 *channel)
{
        int err = -EINVAL;
        u8 ch = 0;

        if(!page) return -EINVAL;
        if(!channel) return -EINVAL;
        err = xb_get_param(xb, XBEE_AT_CH, &ch, sizeof(ch) );

        if(err) return err;

        *page = 0;
        *channel = ch;

        return 0;
}

/**
 * xb_set_cca_mode()
 *
 * @xb: XBee device context.
 * @cca: Pointer to value that contains new cca seting.
 */
static int
xb_set_cca_mode(struct xb_device *xb, const struct wpan_phy_cca *cca)
{
        return -EOPNOTSUPP;
#if 0
        pr_debug("%s cca=%p\n", __func__, cca);

        switch(cca->mode) {
        case NL802154_CCA_ENERGY:
        case NL802154_CCA_CARRIER:
        case NL802154_CCA_ENERGY_CARRIER:
        case NL802154_CCA_ALOHA:
        case NL802154_CCA_UWB_SHR:
        case NL802154_CCA_UWB_MULTIPLEXED:
        default:
        }

        switch(cca->opts) {
        case NL802154_CCA_OPT_ENERGY_CARRIER_AND:
        case NL802154_CCA_OPT_ENERGY_CARRIER_OR:
        default:
        }
        return 0;
#endif
}

/**
 * xb_set_cca_ed_level()
 *
 * @xb: XBee device context.
 * @ed_level: New energy detect level.
 */
static int
xb_set_cca_ed_level(struct xb_device *xb, s32 ed_level)
{
        u8 ca = -ed_level/100;
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_CA, &ca, sizeof(ca) );
}

/**
 * xb_get_cca_ed_level()
 *
 * @xb: XBee device context.
 * @ed_level: Pointer to the value that store energy detect level.
 */
static int
xb_get_cca_ed_level(struct xb_device *xb, s32 *ed_level)
{
        int err = -EINVAL;
        u8 ca = 0;

        if(!ed_level) return -EINVAL;

        err = xb_get_param(xb, XBEE_AT_CA, &ca, sizeof(ca) );

        if(err) return err;

        *ed_level = ca * -100;

        return 0;
}

/**
 * xb_set_tx_power()
 *
 * @xb: XBee device context.
 * @power: New transmit power value.
 */
static int
xb_set_tx_power(struct xb_device *xb, s32 power)
{
        u8 pl = 4;

        pr_debug("%s mbm=%d\n", __func__, power);

        if(power <= -200) {
                pl=3;
        }
        if(power <= -400) {
                pl=2;
        }
        if(power <= -600) {
                pl=1;
        }
        if(power <= -1000) {
                pl=0;
        }

        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_PL, &pl, sizeof(pl) );
}

/**
 * xb_get_tx_power()
 * @xb: XBee device context.
 * @power: Pointer to the value that store transmit power.
 */
static int
xb_get_tx_power(struct xb_device *xb, s32 *power)
{
        int err = -EINVAL;
        u8 pl = 0;

        if(!power) return -EINVAL;

        err = xb_get_param(xb, XBEE_AT_PL, &pl, sizeof(pl) );

        if(err) return err;

        if(pl == 0) {
                *power = -1000;
        } else if(pl == 1) {
                *power = -600;
        } else if(pl == 2) {
                *power = -400;
        } else if(pl == 3) {
                *power = -200;
        } else {
                *power = 0;
        }

        return 0;
}

/**
 * xb_set_pan_id()
 *
 * @xb: XBee device context.
 * @pan_id: New PAN ID value.
 */
static int
xb_set_pan_id(struct xb_device *xb, __le16 pan_id)
{
        __be16 id = htons(pan_id);
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_ID, (uint8_t*)&id, sizeof(id) );
}


/**
 * xb_get_pan_id()
 *
 * @xb: XBee device context.
 * @pan_id: Pointer to the value that store PAN ID.
 */
static int
xb_get_pan_id(struct xb_device *xb, __le16 *pan_id)
{
        int err = -EINVAL;
        __be16 beid = 0;

        pr_debug("enter %s", __func__);

        if(!pan_id) return -EINVAL;
        err = xb_get_param(xb, XBEE_AT_ID, (uint8_t*)&beid, sizeof(beid) );

        pr_debug("%s %d %x", __func__, err, beid);

        if(err) return err;

        *pan_id = htons(beid);

        return 0;
}

/**
 * xb_set_short_addr()
 *
 * @xb: XBee device context.
 * @short_addr: New short address value.
 */
static int
xb_set_short_addr(struct xb_device *xb, __le16 short_addr)
{
        __be16 my = htons(short_addr);
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_MY, (uint8_t*)&my, sizeof(my) );
}

/**
 * xb_get_short_addr()
 *
 * @xb: XBee device context.
 * @short_addr: Pointer to the value that store short_addr.
 */
static int
xb_get_short_addr(struct xb_device *xb, __le16 *short_addr)
{
        int err = -EINVAL;
        __be16 beaddr = 0;

        if(!short_addr) return -EINVAL;

        err = xb_get_param(xb, XBEE_AT_MY, (uint8_t*)&beaddr, sizeof(beaddr) );

        if(err) return err;

        *short_addr = htons(beaddr);

        return 0;
}

/**
 * xb_set_backoff_exponent()
 *
 * @xb: XBee device context.
 * @min_be: New minimum backoff exponent value.
 * @max_be: New maximum backoff exponent value.
 */
static int
xb_set_backoff_exponent(struct xb_device *xb, u8 min_be, u8 max_be)
{
        u8 rr = min_be;
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_RN, &rr, sizeof(rr) );
}

/**
 * xb_get_backoff_exponent()
 *
 * @xb: XBee device context.
 * @min_be: Pointer to the value that store minimum backoff exponent.
 * @max_be: Pointer to the value that store maximum backoff exponent.
 */
static int
xb_get_backoff_exponent(struct xb_device *xb, u8* min_be, u8* max_be)
{
        int err = -EINVAL;
        u8 rn = 0;

        if(!min_be) return -EINVAL;
        if(!max_be) return -EINVAL;
        err = xb_get_param(xb, XBEE_AT_RN, &rn, sizeof(rn) );

        if(err) return err;

        *min_be = rn;

        return 0;
}

/**
 * xb_set_max_csma_backoffs()
 *
 * @xb: XBee device context.
 * @max_csma_backoffs: New maximum csma backoffs value.
 */
static int
xb_set_max_csma_backoffs(struct xb_device *xb, u8 max_csma_backoffs)
{
        return -EOPNOTSUPP;
}
#if 0
/**
 * xb_get_max_csma_backoffs()
 * @xb: XBee device context.
 * @max_csma_backoffs: Pointer to the value that store maximum csma backoffs.
 */
static int
xb_get_max_csma_backoffs(struct xb_device *xb, u8* max_csma_backoffs)
{
        return -EOPNOTSUPP;
}
#endif

/**
 * xb_set_max_frame_retries()
 *
 * @xb: XBee device context.
 * @max_frame_retries: New max frame retry count.
 */
static int
xb_set_max_frame_retries(struct xb_device *xb, s8 max_frame_retries)
{
        return -EOPNOTSUPP;
}

/**
 * xb_set_lbt_mode()
 *
 * @xb: XBee device context.
 * @mode: New lbt mode value to set.
 */
static int
xb_set_lbt_mode(struct xb_device *xb, bool mode)
{
        return -EOPNOTSUPP;
}

/**
 * xb_set_ackreq_default()
 *
 * @xb: XBee device context.
 * @ackreq: New ACK request default setting value.
 */
static int
xb_set_ackreq_default(struct xb_device *xb, bool ackreq)
{
        u8 mm = ackreq ? XBEE_MM_802154_WITH_ACK : XBEE_MM_802154_NO_ACK;
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_MM, &mm, sizeof(mm) );
}

/**
 * xb_get_ackreq_default()
 *
 * @xb: XBee device context.
 * @ackreq: Pointer to the value that store ACK request default setting.
 */
static int
xb_get_ackreq_default(struct xb_device *xb, bool* ackreq)
{
        int err = -EINVAL;
        u8 mm = 0;
        if(!ackreq) return -EINVAL;

        err = xb_get_param(xb, XBEE_AT_MM, &mm, sizeof(mm) );

        if(err) return err;

        *ackreq = (mm == XBEE_MM_802154_WITH_ACK);

        return 0;
}

/**
 * xb_get_extended_addr()
 *
 * @xb: XBee device context.
 * @extended_addr: Pointer to the value that store 64bit address.
 */
static int
xb_get_extended_addr(struct xb_device *xb, __le64 *extended_addr)
{
        int err = -EINVAL;
        __be32 behi = 0;
        __be32 belo = 0;
        __be64 addr = 0;

        err = xb_get_param(xb, XBEE_AT_SH, (uint8_t*)&behi, sizeof(behi) );
        if(err)
                return err;
        err = xb_get_param(xb, XBEE_AT_SL, (uint8_t*)&belo, sizeof(belo) );
        if(err)
                return err;

        addr = ((__be64)belo << 32) | behi;

        extended_addr_hton(extended_addr, &addr);
        
        return 0;
}

/**
 * xb_get_api_mode()
 *
 * @xb: XBee device context.
 * @api_version: Pointer to the value that store API version.
 */
static int
xb_get_api_mode(struct xb_device *xb, u8* api_version)
{
        int err = -EINVAL;
        u8 ap = 0;
        err = xb_get_param(xb, XBEE_AT_AP, &ap, sizeof(ap) );

        if(err) return err;

        if(api_version) *api_version = ap;

        return 0;
}

/**
 * xb_set_scan_channels()
 *
 * @xb: XBee device context.
 * @channels: Scan channel bitmask.
 */
static int
xb_set_scan_channels(struct xb_device* xb, u32 channels)
{
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_SC,
                        (uint8_t*)&channels, sizeof(channels) );
}

/**
 * xb_set_scan_duration()
 *
 * @xb: XBee device context.
 * @duration: scan duration in milliseconds.
 */
static int
xb_set_scan_duration(struct xb_device* xb, u8 duration)
{
        pr_debug("%s\n", __func__);
        return xb_set_param(xb, XBEE_AT_SD, &duration, sizeof(duration) );
}

/**
 * xb_energy_detect()
 *
 * @xb: XBee device context.
 * @scantime: ED scan duration.
 * @edl: Buffer to store ed scan result.
 * @edllen: Length of edl buffer.
 */
static int
xb_energy_detect(struct xb_device* xb, u8 scantime, u8* edl, size_t edllen)
{
        pr_debug("%s\n", __func__);
        return xb_set_get_param(xb, XBEE_AT_ED,
                        &scantime, sizeof(scantime), edl, edllen);
}

/**
 * xb_active_scan()
 * @scantime: active scan duration.
 * @xb: XBee device context.
 */
static int
xb_active_scan(struct xb_device* xb, u8 scantime, u8* buffer, size_t bufsize)
{
        pr_debug("%s\n", __func__);
        return xb_set_get_param(xb, XBEE_AT_ED,
                        &scantime, sizeof(scantime), buffer, bufsize);
}


/**
 * xb_alloc_netdev()
 * @xb: XBee device context.
 */
static struct net_device*
xb_alloc_netdev(struct xb_device* xb)
{
        struct net_device *ndev = xb->dev;
        struct xbee_sub_if_data *sdata = NULL;
        int ret = 0;
        
        ndev = alloc_netdev(sizeof(*sdata), "wpan%d",
                            NET_NAME_ENUM, ieee802154_if_setup);
        if (!ndev) {
                pr_err("failure to allocate netdev\n");
                return NULL;
        }

        ndev->needed_headroom = IEEE802154_MAX_HEADER_LEN;
        ndev->type = ARPHRD_IEEE802154;

        ret = dev_alloc_name(ndev, ndev->name);
        if (ret < 0) {
                pr_err("failure to allocate device name\n");
                goto free_dev;
        }
        return ndev;

free_dev:
        free_netdev(ndev);
        return NULL;
}

/**
 * xb_alloc_device()
 */
static struct xb_device* xb_alloc_device(const struct cfg802154_ops* ptr_cfg802154_ops)
{
        struct xb_device *xb = NULL;
        struct net_device *ndev = NULL;
        struct wpan_phy *phy = NULL;
        size_t priv_size;

        priv_size = ALIGN(sizeof(*xb), NETDEV_ALIGN) + sizeof(struct xb_device);
        phy = wpan_phy_new(ptr_cfg802154_ops, priv_size);
        if (!phy) {
                pr_err("failure to allocate master IEEE802.15.4 device\n");
                return NULL;
        }
        phy->privid = xbee_wpan_phy_privid;
        pr_debug("wpan_phy_priv\n");
        xb = wpan_phy_priv(phy);

        xb->magic = XBEE802154_MAGIC;


        xb->phy = phy;
        ndev = xb_alloc_netdev(xb);
        if(!ndev)
                goto free_phy;
        
        xb->dev = ndev;

        pr_debug("wpan_phy_set_dev\n");
        wpan_phy_set_dev(xb->phy, xb->parent);

        return xb;

free_phy:
        wpan_phy_free(phy);
        return NULL;
}

/**
 * xb_register_netdev()
 * @dev: net_device that is associated with this XBee.
 */
static int
xb_register_netdev(struct net_device* dev)
{
        int ret;

        rtnl_lock();

        ret = register_netdevice(dev);

        rtnl_unlock();

        return ret;
}

/**
 * xb_register_device()
 * @xb: XBee device context.
 */
static int
xb_register_device(struct xb_device* xb)
{
        int ret;
                
        ret = wpan_phy_register(xb->phy);
        if(ret < 0)
                return ret;

        ret = xb_register_netdev(xb->dev);
        if(ret < 0)
                goto unregister_wpan;
        
        return 0;

unregister_wpan:
        wpan_phy_unregister(xb->phy);
        return ret;
}

/**
 * xb_unregister_netdev()
 * @dev: net_device that is associated with this XBee.
 */
static void
xb_unregister_netdev(struct net_device* dev)
{
        pr_debug("%s\n", __func__);
        if(!dev)
                return;
        pr_debug("%d\n", __LINE__);
        rtnl_lock();
        unregister_netdevice(dev);
        rtnl_unlock();
        pr_debug("%d\n", __LINE__);
}

/**
 * xb_unregister_device() - Unregister xb_device.
 * @xb: XBee device context.
 */
static void
xb_unregister_device(struct xb_device* xb)
{
        pr_debug("%s\n", __func__);
        xb_unregister_netdev(xb->dev);
        wpan_phy_unregister(xb->phy);
}

/**
 * xb_free() - Free xb_device.
 * @xb: XBee device context.
 */
static void
xb_free(struct xb_device* xb)
{
        if(xb->phy) {
                wpan_phy_free(xb->phy);
                xb->phy = NULL;
        }
}

/**
 * xb_set_supported() - Set xbee support parameter.
 * @xb: XBee device context.
 */
static void
xb_set_supported(struct xb_device* xb)
{
        struct wpan_phy *phy = xb->phy;

        /* always supported */
        phy->supported.channels[0] = 0x7fff800;
        phy->supported.cca_modes = BIT(NL802154_CCA_ENERGY);
        phy->supported.cca_opts = NL802154_CCA_ENERGY;
        phy->supported.iftypes = BIT(NL802154_IFTYPE_NODE);
        phy->supported.lbt = NL802154_SUPPORTED_BOOL_FALSE;
        phy->supported.min_minbe = 0;
        phy->supported.max_minbe = 3;
        phy->supported.min_maxbe = 5; /* N/A */
        phy->supported.max_maxbe = 5; /* N/A */
        phy->supported.min_csma_backoffs = 0; /* N/A */
        phy->supported.max_csma_backoffs = 0; /* N/A */
        phy->supported.min_frame_retries = 0;
        phy->supported.max_frame_retries = 0;
        phy->supported.tx_powers_size = 0;

        phy->supported.cca_ed_levels_size = 41;

        {
        static const s32 ed_levels [] = {
                -3600, -3700, -3800, -3900, -4000,
                -4100, -4200, -4300, -4400, -4500,
                -4600, -4700, -4800, -4900, -5000,
                -5100, -5200, -5300, -5400, -5500,
                -5600, -5700, -5800, -5900, -6000,
                -6100, -6200, -6300, -6400, -6500,
                -6600, -6700, -6800, -6900, -8000,
        };
        phy->supported.cca_ed_levels = ed_levels;
        phy->supported.cca_ed_levels_size =
                sizeof(ed_levels)/sizeof(ed_levels[0]);
        }

        {
        static const s32 tx_powers[] = {
                1000, 600, 400, 200, 0
        };
        phy->supported.tx_powers = tx_powers;
        phy->supported.tx_powers_size =
                sizeof(tx_powers)/sizeof(tx_powers[0]);
        }
}

/**
 * xb_read_config() - Read current configuration from device.
 * @xb: XBee device context.
 */
static void
xb_read_config(struct xb_device* xb)
{
        struct wpan_phy *wpan_phy = xb->phy;
        struct xbee_sub_if_data *sdata = netdev_priv(xb->dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;

        __le64 extended_addr = 0;
        __le16 pan_id = 0;
        __le16 short_addr = 0;
        u8 page = 0;
        u8 channel = 0;
        u8 min_be = 0;
        u8 max_be = 0;
        s32 tx_power = 0;
        s32 ed_level = 0;
        bool ackreq = 0;
        u8 api = 0;

        xb_get_api_mode(xb, &api);
        xb->api = api;

        xb_get_extended_addr(xb, &extended_addr);
        xb_get_pan_id(xb, &pan_id);
        xb_get_channel(xb, &page, &channel);
        xb_get_tx_power(xb, &tx_power);
        xb_get_short_addr(xb, &short_addr);
        xb_get_backoff_exponent(xb, &min_be, &max_be);
        xb_get_ackreq_default(xb, &ackreq);
        xb_get_cca_ed_level(xb, &ed_level);

        wpan_phy->current_channel = channel;
        wpan_phy->current_page = page;
        wpan_phy->transmit_power = tx_power;
        wpan_phy->cca_ed_level = ed_level;
        wpan_phy->perm_extended_addr = extended_addr;
        //phy->cca = 0;
        wpan_phy->symbol_duration = 16;

        pr_debug("pan_id %x", pan_id);
        pr_debug("short_addr %x", short_addr);
        pr_debug("extended_addr %016llx", extended_addr);

        wpan_phy->lifs_period =
                IEEE802154_LIFS_PERIOD * wpan_phy->symbol_duration;
        wpan_phy->sifs_period =
                IEEE802154_SIFS_PERIOD * wpan_phy->symbol_duration;

        wpan_dev->min_be = min_be;
        wpan_dev->max_be = max_be;
        wpan_dev->pan_id = pan_id;
        wpan_dev->short_addr = short_addr;
        wpan_dev->extended_addr = extended_addr;
        wpan_dev->ackreq = ackreq;

        wpan_dev->csma_retries = 0;
        wpan_dev->frame_retries = 0;
        wpan_dev->promiscuous_mode = false;
        wpan_dev->iftype = NL802154_IFTYPE_NODE;
        wpan_phy->flags = WPAN_PHY_FLAG_TXPOWER |
                        WPAN_PHY_FLAG_CCA_ED_LEVEL |
                        WPAN_PHY_FLAG_CCA_MODE;
}


/**
 * DOC: ************** Export APIs. ***************** 
 */

/**
 * xbee_header_create()
 * @dev: net_device that is associated with this XBee.
 * @skb: -
 * @type: -
 * @daddr: -
 * @saddr: -
 * @len: -
 */
static int
xbee_header_create(struct sk_buff *skb,
                                   struct net_device *dev,
                                   unsigned short type,
                                   const void *daddr,
                                   const void *saddr,
                                   unsigned len)
{
        struct ieee802154_addr daddr802154;
        struct ieee802154_addr saddr802154;

        struct xbee_sub_if_data *sdata = netdev_priv(dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;

        daddr802154.mode = IEEE802154_ADDR_LONG;
        daddr802154.pan_id = IEEE802154_PANID_BROADCAST;
        extended_addr_hton(&daddr802154.extended_addr, (uint64_t*)daddr);

        saddr802154.mode = IEEE802154_ADDR_LONG;
        saddr802154.pan_id = wpan_dev->pan_id;
        saddr802154.extended_addr = wpan_dev->extended_addr;

        return ieee802154_header_create(skb, dev, &daddr802154, &saddr802154, len);
}

/**
 * xbee_header_parse()
 *
 * @skb: Received packet
 * @haddr: Hardware address
 */
static int
xbee_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
        struct ieee802154_hdr hdr;

        if (ieee802154_hdr_peek_addrs(skb, &hdr) < 0) {
                pr_debug("malformed packet\n");
                return 0;
        }

        if (hdr.source.mode == IEEE802154_ADDR_LONG) {
                extended_addr_hton((uint64_t*)haddr, &hdr.source.extended_addr);
                return sizeof(hdr.source.extended_addr);
        } else if (hdr.source.mode == IEEE802154_ADDR_SHORT) {
                *((uint16_t*)haddr) = htons(hdr.source.short_addr);
                return sizeof(hdr.source.short_addr);
        }

        return 0;
}

/**
 * xbee_header_validate()
 *
 * @ll_header: -
 * @len: -
 */
static bool
xbee_header_validate(const char *ll_header, unsigned int len)
{
        WARN_ON(true);
        pr_debug("%s\n", __func__);

        print_hex_dump_bytes(" hdr> ", DUMP_PREFIX_NONE, ll_header, len);

        return true;
}

/**
 * xbee_mlme_assoc_req()
 *
 * @dev: net_device that is associated with this XBee.
 * @addr: Address to send association request.
 * @channel: Channel to use.
 * @page: Channel page to use.
 * @cap: Capability
 * TODO
 */
static int
xbee_mlme_assoc_req(struct net_device *dev, struct ieee802154_addr *addr,
                                u8 channel, u8 page, u8 cap)
{
        pr_debug("%s(addr=%1u:%016llx, channels=%u, page=%u, cap=%x\n",
                        __func__, addr->mode,addr->extended_addr,
                        channel, page, cap);
        return 0;
}

/**
 * xbee_mlme_assoc_req()
 *
 * @dev: net_device that is associated with this XBee.
 * @addr: -
 * @short_addr: -
 * @status: -
 *
 * TODO not be implemented.
 */
static int
xbee_mlme_assoc_resp(struct net_device *dev, struct ieee802154_addr *addr,
                                __le16 short_addr, u8 status)
{
        pr_debug("%s(addr=%1u:%016llx, short=%04x status=%x\n",
                        __func__, addr->mode,addr->extended_addr,
                        short_addr, status);
        return 0;
}

/**
 * xbee_mlme_disassoc_req()
 *
 * @dev: net_device that is associated with this XBee.
 * @addr: -
 * @reason: -
 *
 * TODO not be implemented.
 */
static int
xbee_mlme_disassoc_req(struct net_device *dev,
                struct ieee802154_addr *addr, u8 reason)
{
        pr_debug("%s(addr=%1u:%016llx, reason=%x\n",
                        __func__, addr->mode,addr->extended_addr, reason);
        return 0;
}

/**
 * xbee_mlme_start_req()
 *
 * @dev: net_device that is associated with this XBee.
 * @addr: -
 * @channel: Channel to use.
 * @page: Channel page to use.
 * @bcn_ord: -
 * @sf_ord: -
 * @pan_coord: -
 * @blx: -
 * @coord_realign: -
 *
 * TODO
 */
static int
xbee_mlme_start_req(struct net_device *dev, struct ieee802154_addr *addr,
                u8 channel, u8 page, u8 bcn_ord, u8 sf_ord,
                u8 pan_coord, u8 blx, u8 coord_realign)
{
        pr_debug("%s(addr=%1u:%016llx, channel=%u, page=%u, "
                        "bcn_ord=%u sf_ord=%u, pan_coord=%u, blx=%u, "
                        "coord_realign=%u\n",
                        __func__, addr->mode,addr->extended_addr,
                        channel, page, bcn_ord, sf_ord, pan_coord,
                        blx, coord_realign);

        //xbee_coordinator_enable(true);
        return 0;
}

/**
 * xbee_mlme_scan_req()
 *
 * @dev: net_device that is associated with this XBee.
 * @type: Scan type
 * @channels: Scan channels bitmask.
 * @page: Channel page to use.
 * @duration: Scan duration.
 */
static int
xbee_mlme_scan_req(struct net_device *dev, u8 type, u32 channels,
                                                u8 page, u8 duration)
{
        struct xbee_sub_if_data *sdata = netdev_priv(dev);
        struct xb_device* xb = sdata->local;
        int ret = 0;
        pr_debug("%s(type=%u, channels%x, page=%u, duration=%u\n",
                        __func__, type, channels, page, duration);

        ret = xb_set_scan_channels(xb, channels);
        ret = xb_set_scan_duration(xb, duration); // TODO duration

        if(type == IEEE802154_MAC_SCAN_ED) {
                u8 edl[32];
                // TODO duration
                ret = xb_energy_detect(xb, duration, edl, sizeof(edl) );

                // net/ieee802154/netlink.c are not export any functions.
                // so, we can't send any response.
                ret = -EOPNOTSUPP;
        }
        else if(type == IEEE802154_MAC_SCAN_ACTIVE) {
                u8 buffer[128];
                // TODO duration
                ret = xb_active_scan(xb, duration, buffer, sizeof(buffer) );

                // net/ieee802154/netlink.c are not export any functions.
                // so, we can't send any response.
                ret = -EOPNOTSUPP;
        }
        else { //passive, orphan
                ret = -EOPNOTSUPP;
        }

        {
                static bool msg_print = false;
                if(!msg_print) {
                        printk("xbee: XBee module does not support response for scan_req.\n");
                        msg_print = true;
                }
        }

        return ret;
}

/**
 * xbee_mlme_set_mac_params()
 *
 * @dev: net_device that is associated with this XBee.
 * @params: New MAC parameters to set.
 */
static int
xbee_mlme_set_mac_params(struct net_device *dev,
                        const struct ieee802154_mac_params *params)
{
        struct xbee_sub_if_data *sdata = netdev_priv(dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;

        pr_debug("%s\n", __func__);

        if(wpan_dev->wpan_phy->transmit_power != params->transmit_power) {
                xb_set_tx_power(sdata->local, params->transmit_power);
        }
        if( (wpan_dev->min_be != params->min_be)
         || (wpan_dev->max_be != params->max_be) ) {
                xb_set_backoff_exponent(sdata->local,
                                params->min_be, params->max_be);
        }
        if(wpan_dev->csma_retries != params->csma_retries) {
                xb_set_max_csma_backoffs(sdata->local,
                                params->csma_retries);
        }
        if(wpan_dev->frame_retries != params->frame_retries) {
                xb_set_max_frame_retries(sdata->local,
                                params->frame_retries);
        }
        if(wpan_dev->lbt != params->lbt) {
                xb_set_lbt_mode(sdata->local, params->lbt);
        }
        if( wpan_dev->wpan_phy->cca.mode != params->cca.mode
         && wpan_dev->wpan_phy->cca.opt  != params->cca.opt) {
                xb_set_cca_mode(sdata->local, &params->cca);
        }
        if(wpan_dev->wpan_phy->cca_ed_level != params->cca_ed_level) {
                xb_set_cca_ed_level(sdata->local, params->cca_ed_level);
        }

        return 0;
}

/**
 * xbee_mlme_get_mac_params()
 *
 * @dev: net_device that is associated with this XBee.
 * @params: Pointer to the value that store MAC parameters.
 */
static void
xbee_mlme_get_mac_params(struct net_device *dev,
                        struct ieee802154_mac_params *params)
{
        struct xbee_sub_if_data *sdata = netdev_priv(dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;

        pr_debug("%s\n", __func__);

        params->transmit_power = wpan_dev->wpan_phy->transmit_power;
        params->min_be = wpan_dev->min_be;
        params->max_be = wpan_dev->max_be;
        params->csma_retries = wpan_dev->csma_retries;
        params->frame_retries = wpan_dev->frame_retries;
        params->lbt = wpan_dev->lbt;
        params->cca = wpan_dev->wpan_phy->cca;
        params->cca_ed_level = wpan_dev->wpan_phy->cca_ed_level;

        return;
}

/**
 * xbee_ndo_open()
 * @dev: net_device that is associated with this XBee.
 */
static int
xbee_ndo_open(struct net_device *dev)
{
        pr_debug("%s\n", __func__);
        ASSERT_RTNL();

        rcu_read_lock();
        netif_start_queue(dev);
        rcu_read_unlock();
        return 0;
}

/**
 * xbee_ndo_stop()
 * @dev: net_device that is associated with this XBee.
 */
static int
xbee_ndo_stop(struct net_device *dev)
{
        pr_debug("%s\n", __func__);
        rcu_read_lock();
        netif_stop_queue(dev);
        rcu_read_unlock();
        return 0;
}

/**
 * xbee_ndo_start_xmit()
 *
 * @skb: sk_buff to transmit. That is must start with ieee802154_hdr.
 * @dev: net_device that is associated with this XBee.
 */
static netdev_tx_t
xbee_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
        struct xbee_sub_if_data *sdata = netdev_priv(dev);
        struct wpan_dev *wpan_dev = &sdata->wpan_dev;
        struct xb_device *xb = sdata->local;
        struct ieee802154_hdr hdr = {};
        struct xb_frame_tx16* tx16 = NULL;
        struct xb_frame_tx64* tx64 = NULL;
        int hlen = 0;
        //int esclen = 0;

        hlen = ieee802154_hdr_pull(skb, &hdr);

        pr_ieee802154_hdr(&hdr);
        //print_hex_dump_bytes(" hdr> ", DUMP_PREFIX_NONE, &hdr, sizeof(hdr));

        if( hdr.dest.pan_id != wpan_dev->pan_id
         && hdr.dest.pan_id != IEEE802154_PANID_BROADCAST) {
                pr_debug("%s different pan_id %x:%x\n",
                                __func__, hdr.dest.pan_id, wpan_dev->pan_id);
                goto err_xmit;
        }

        if(hdr.dest.mode == IEEE802154_ADDR_SHORT) {
                tx16 = (struct xb_frame_tx16*)
                        skb_push(skb, sizeof(struct xb_frame_tx16) );
                tx16->hd.start_delimiter = XBEE_DELIMITER;
                tx16->hd.length = htons(skb->len - XBEE_FRAME_OFFSET_PAYLOAD);
                tx16->hd.type = XBEE_FRM_TX16;
                tx16->id = xb_frameid(xb);
                tx16->destaddr = htons(hdr.dest.short_addr);
                tx16->options |= (hdr.fc.ack_request ? 0x00 : 0x01);
        }
        else {
                tx64 = (struct xb_frame_tx64*)
                        skb_push(skb, sizeof(struct xb_frame_tx64) );
                tx64->hd.start_delimiter = XBEE_DELIMITER;
                tx64->hd.length = htons(skb->len - XBEE_FRAME_OFFSET_PAYLOAD);
                tx64->hd.type = XBEE_FRM_TX64;
                tx64->id = xb_frameid(xb);
                ieee802154_le64_to_be64(&tx64->destaddr, &hdr.dest.extended_addr);
                tx64->options |= (hdr.fc.ack_request ? 0x00 : 0x01);
        }

        frame_put_checksum(skb);

        print_hex_dump_bytes("xmit> ", DUMP_PREFIX_NONE, skb->data, skb->len);

        /* loopback test code */
        /*
        {
        struct sk_buff *newskb = pskb_copy(skb, GFP_ATOMIC);
         if (newskb)
                 xbee_rx_irqsafe(xb, newskb, 0xcc);
        }
        */

        frameq_enqueue_send(&xb->send_queue, skb);
        xb_send(xb);

        pr_debug("%s\n", __func__);
        return NETDEV_TX_OK;

err_xmit:
        kfree_skb(skb);
        return NETDEV_TX_OK;
}

#if 0
/**
 * xbee_ndo_set_mac_address()
 * @dev: net_device that is associated with this XBee.
 * @p: -
 */
static int
xbee_ndo_set_mac_address(struct net_device *dev, void *p)
{
        pr_debug("%s\n", __func__);
        return 0;
}
#endif

/**
 * xbee_cfg802154_suspend()
 * @wpan_phy: WPAN phy that is associated with this XBee.
 */
static int
xbee_cfg802154_suspend(struct wpan_phy *wpan_phy)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        pr_debug("%s\n", __func__);
        rcu_read_lock();
        netif_stop_queue(xb->dev);
        rcu_read_unlock();
        synchronize_net();
        return 0;
}

/**
 * xbee_cfg802154_resume()
 * @wpan_phy: WPAN phy that is associated with this XBee.
 */
static int
xbee_cfg802154_resume(struct wpan_phy *wpan_phy)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        pr_debug("%s\n", __func__);

        rcu_read_lock();
        netif_wake_queue(xb->dev);
        rcu_read_unlock();

        return 0;
}

#if 0
/**
 * xbee_cfg802154_add_virtual_intf_deprecated()
 * TODO
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @name: -
 * @name_assign_type: -
 * @type: -
 */
static struct net_device*
xbee_cfg802154_add_virtual_intf_deprecated(struct wpan_phy *wpan_phy,
                                        const char *name,
                                        unsigned char name_assign_type,
                                        int type)
{
        pr_debug("%s\n", __func__);
        return NULL;
}

/**
 * xbee_cfg802154_del_virtual_intf_deprecated()
 * TODO
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @dev: net_device that is associated with this XBee.
 */
static void
xbee_cfg802154_del_virtual_intf_deprecated(struct wpan_phy *wpan_phy,
                                               struct net_device *dev)
{
        pr_debug("%s\n", __func__);
}
/**
 * xbee_cfg802154_add_virtual_intf()
 * TODO should NOT impl it.
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @name: -
 * @name_assign_type: -
 * @type: -
 * @extended_addr: -
 */
static int
xbee_cfg802154_add_virtual_intf(struct wpan_phy *wpan_phy,
                                    const char *name,
                                    unsigned char name_assign_type,
                                    enum nl802154_iftype type,
                                    __le64 extended_addr)
{
        pr_debug("%s\n", __func__);
        return 0;
}
        
/**
 * xbee_cfg802154_del_virtual_intf()
 * TODO should NOT impl it.
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 */
static int
xbee_cfg802154_del_virtual_intf(struct wpan_phy *wpan_phy,
                                    struct wpan_dev *wpan_dev)
{
        pr_debug("%s\n", __func__);
        return 0;
}
#endif
/**
 * xbee_cfg802154_set_channel()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @page: New page value to set.
 * @channel: New channel value to set.
 */
static int
xbee_cfg802154_set_channel(struct wpan_phy *wpan_phy, u8 page, u8 channel)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_channel(xb, page, channel);
}

/**
 * xbee_cfg802154_set_cca_mode()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @cca: Pointer to value that contains new cca seting.
 */
static int
xbee_cfg802154_set_cca_mode(struct wpan_phy *wpan_phy,
                                const struct wpan_phy_cca *cca)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        pr_debug("%s\n", __func__);
        return xb_set_cca_mode(xb, cca);
}

/**
 * xbee_cfg802154_set_cca_ed_level()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @ed_level: New energy detect level.
 */
static int
xbee_cfg802154_set_cca_ed_level(struct wpan_phy *wpan_phy, s32 ed_level)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        pr_debug("%s\n", __func__);
        return xb_set_cca_ed_level(xb, ed_level);
}

/**
 * xbee_cfg802154_set_tx_power()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @power: New transmit power value to set.
 */
static int
xbee_cfg802154_set_tx_power(struct wpan_phy *wpan_phy, s32 power)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_tx_power(xb, power);
}

/**
 * xbee_cfg802154_set_pan_id()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @pan_id: New PAN ID value to set.
 */
static int
xbee_cfg802154_set_pan_id(struct wpan_phy *wpan_phy,
                                struct wpan_dev *wpan_dev, __le16 pan_id)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_pan_id(xb, pan_id);
}

/**
 * xbee_cfg802154_set_short_addr()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @short_addr: New short address value to set.
 */
static int
xbee_cfg802154_set_short_addr(struct wpan_phy *wpan_phy,
                                struct wpan_dev *wpan_dev, __le16 short_addr)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_short_addr(xb, short_addr);
}

/**
 * xbee_cfg802154_set_backoff_exponent()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @min_be: New minimum backoff exponent value.
 * @max_be: New maximum backoff exponent value.
 */
static int
xbee_cfg802154_set_backoff_exponent(struct wpan_phy *wpan_phy,
                        struct wpan_dev *wpan_dev, u8 min_be, u8 max_be)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_backoff_exponent(xb, min_be, max_be);
}

/**
 * xbee_cfg802154_set_max_csma_backoffs()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @max_csma_backoffs: New maximum csma backoffs value.
 */
static int
xbee_cfg802154_set_max_csma_backoffs(struct wpan_phy *wpan_phy,
                        struct wpan_dev *wpan_dev, u8 max_csma_backoffs)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_max_csma_backoffs(xb, max_csma_backoffs);
}

/**
 * xbee_cfg802154_set_max_frame_retries()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @max_frame_retries: New max frame retry count.
 */
static int
xbee_cfg802154_set_max_frame_retries(struct wpan_phy *wpan_phy,
                                         struct wpan_dev *wpan_dev,
                                         s8 max_frame_retries)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_max_frame_retries(xb, max_frame_retries);
}

/**
 * xbee_cfg802154_set_lbt_mode()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @mode: New lbt mode value to set.
 */
static int
xbee_cfg802154_set_lbt_mode(struct wpan_phy *wpan_phy,
                                struct wpan_dev *wpan_dev, bool mode)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_lbt_mode(xb, mode);
}

/**
 * xbee_cfg802154_set_ackreq_default()
 *
 * @wpan_phy: WPAN phy that is associated with this XBee.
 * @wpan_dev: WPAN dev that is associated with this XBee.
 * @ackreq: New ACK request default setting value to set.
 */
static int
xbee_cfg802154_set_ackreq_default(struct wpan_phy *wpan_phy,
                                      struct wpan_dev *wpan_dev, bool ackreq)
{
        struct xb_device *xb = wpan_phy_priv(wpan_phy);
        return xb_set_ackreq_default(xb, ackreq);
}

static const struct wpan_dev_header_ops xbee_wpan_dev_header_ops = {
        .create                        = ieee802154_header_create,
};

static const struct header_ops xbee_header_ops = {
        .create                        = xbee_header_create,
        .parse                        = xbee_header_parse,
        .validate                = xbee_header_validate,
};

static const struct net_device_ops xbee_net_device_ops = {
        .ndo_open                = xbee_ndo_open,
        .ndo_stop                = xbee_ndo_stop,
        .ndo_start_xmit                = xbee_ndo_start_xmit,
        .ndo_do_ioctl                = mac802154_wpan_ioctl,
};

static struct ieee802154_mlme_ops xbee_ieee802154_mlme_ops = {
        .assoc_req                = xbee_mlme_assoc_req,
        .assoc_resp                = xbee_mlme_assoc_resp,
        .disassoc_req                = xbee_mlme_disassoc_req,
        .start_req                = xbee_mlme_start_req,
        .scan_req                = xbee_mlme_scan_req,
        .set_mac_params                = xbee_mlme_set_mac_params,
        .get_mac_params                = xbee_mlme_get_mac_params,
};

static const struct cfg802154_ops xbee_cfg802154_ops = {
        .suspend                = xbee_cfg802154_suspend,
        .resume                        = xbee_cfg802154_resume,
        .set_channel                = xbee_cfg802154_set_channel,
        .set_cca_mode                = xbee_cfg802154_set_cca_mode,
        .set_cca_ed_level        = xbee_cfg802154_set_cca_ed_level,
        .set_tx_power                = xbee_cfg802154_set_tx_power,
        .set_pan_id                = xbee_cfg802154_set_pan_id,
        .set_short_addr                = xbee_cfg802154_set_short_addr,
        .set_backoff_exponent        = xbee_cfg802154_set_backoff_exponent,
        .set_max_csma_backoffs        = xbee_cfg802154_set_max_csma_backoffs,
        .set_max_frame_retries        = xbee_cfg802154_set_max_frame_retries,
        .set_lbt_mode                = xbee_cfg802154_set_lbt_mode,
        .set_ackreq_default        = xbee_cfg802154_set_ackreq_default,
};


/**
 * sendrecv_work_fn()
 * @param: workqueue parameter.
 */
static void
sendrecv_work_fn(struct work_struct *param)
{
        struct xb_work* xbw = (struct xb_work*)param;
        struct xb_device* xb = xbw->xb;
        struct sk_buff* skb = NULL;
        struct sk_buff* prev_atresp = xb->last_atresp;
        struct xb_frame_header* hdr;

        if(&xb->send_work.work == param) {
                int send_count = 0;
                send_count = xb_send_queue(xb);
                complete_all(&xb->send_done);
        } else {
                mutex_lock(&xb->queue_mutex);
                skb = skb_peek(&xb->recv_queue);
                while(skb) {
                        hdr = (struct xb_frame_header*)skb->data;
                        if(hdr->type != XBEE_FRM_ATCMDR) {
                                struct sk_buff* consume = skb;
                                skb = skb_peek_next(consume, &xb->recv_queue);
                                skb_unlink(consume, &xb->recv_queue);
                                xb_frame_recv_dispatch(xb, consume);
                        } else {
                                xb->last_atresp = skb;
                                skb = skb_peek_next(skb, &xb->recv_queue);
                        }
                }

                if(prev_atresp != xb->last_atresp)
                        complete_all(&xb->cmd_resp_done);

                mutex_unlock(&xb->queue_mutex);
        }
}

/**
 * init_work_fn()
 * @param: workqueue parameter.
 */
static void
init_work_fn(struct work_struct *param)
{
        struct xb_work* xbw = (struct xb_work*)param;
        struct xb_device* xb = xbw->xb;
        struct tty_struct* tty = xb->tty;
        struct xbee_sub_if_data *sdata = netdev_priv(xb->dev);
        struct net_device* ndev = xb->dev;
        uint8_t tmp;
        int err = -EINVAL;

        INIT_WORK( (struct work_struct*)&xb->send_work.work, sendrecv_work_fn);
        INIT_WORK( (struct work_struct*)&xb->recv_work.work, sendrecv_work_fn);

        xb_enqueue_send_at(xb, XBEE_AT_FR, "", 0);
        xb_send(xb);
        err = wait_for_completion_timeout(&xb->modem_status_receive,
                                        msecs_to_jiffies(3000) );
        if(err == 0) {
                printk(KERN_ERR "%s: XBee software reset failed\n", __func__);
                goto err;
        }

        SET_NETDEV_DEV(xb->dev, &xb->phy->dev);
        sdata->dev = xb->dev;
        sdata->wpan_dev.wpan_phy = xb->phy;
        sdata->local = xb;

        xb_read_config(xb);
        xb_set_supported(xb);

        ndev->ieee802154_ptr = &sdata->wpan_dev;

        ieee802154_le64_to_be64(ndev->perm_addr,
                                &xb->phy->perm_extended_addr);

        if (ieee802154_is_valid_extended_unicast_addr(xb->phy->perm_extended_addr))
                ieee802154_le64_to_be64(ndev->dev_addr, &xb->phy->perm_extended_addr);
        else
                memcpy(ndev->dev_addr, ndev->perm_addr, IEEE802154_EXTENDED_ADDR_LEN);

        get_random_bytes(&tmp, sizeof(tmp));
        atomic_set(&sdata->wpan_dev.bsn, tmp);
        get_random_bytes(&tmp, sizeof(tmp));
        atomic_set(&sdata->wpan_dev.dsn, tmp);

        sdata->dev->header_ops = &xbee_header_ops;
        sdata->dev->netdev_ops = &xbee_net_device_ops;
        sdata->dev->destructor = mac802154_wpan_free;
        sdata->dev->ml_priv = &xbee_ieee802154_mlme_ops;
        sdata->wpan_dev.header_ops = &xbee_wpan_dev_header_ops;

        pr_wpan_phy(xb->phy);
        pr_wpan_phy_supported(xb->phy);
        pr_wpan_dev(&sdata->wpan_dev);

        err = xb_register_device(xb);
        if (err) {
        printk(KERN_ERR "%s: device register failed\n", __func__);
                goto err_unreg;
        }

        return;

err_unreg:
        xb_unregister_device(xb);
        xb_free(xb);
err:
        tty->disc_data = NULL;
        tty_kref_put(tty);
        xb->tty = NULL;
}


/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/
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
        struct xb_device *xb = tty->disc_data;

        if (!capable(CAP_NET_ADMIN))
                return -EPERM;

        if(tty->ops->write == NULL)
                return -EOPNOTSUPP;

        if(xb && xb->magic == XBEE802154_MAGIC)
                return -EEXIST;

        xb = xb_alloc_device(&xbee_cfg802154_ops);
        if (!xb)
                return -ENOMEM;

        xb->parent = tty->dev;
        tty->disc_data = xb;

        xb->tty = tty_kref_get(tty);
        tty->receive_room = 65536;
        tty_driver_flush_buffer(tty);

        xb->recv_buf = dev_alloc_skb(IEEE802154_MTU);
        xb->frameid = 1; // Device does not respond if zero.
        xb->last_atresp = NULL;

        mutex_init(&xb->queue_mutex);
        skb_queue_head_init(&xb->recv_queue);
        skb_queue_head_init(&xb->send_queue);

        init_completion(&xb->cmd_resp_done);
        init_completion(&xb->send_done);
        init_completion(&xb->modem_status_receive);

        xb->sendrecv_workq = create_workqueue("sendrecv_workq");
        xb->send_work.xb = xb;
        xb->recv_work.xb = xb;
        xb->init_work.xb = xb;

        INIT_WORK( (struct work_struct*)&xb->init_work.work, init_work_fn);
        queue_work(xbee_init_workq, (struct work_struct*)&xb->init_work.work);
        return 0;
}

/**
 * xbee_ldisc_close - Close line discipline and unregister with ieee802154.
 *
 * @tty: TTY info for line.
 */
static void xbee_ldisc_close(struct tty_struct *tty)
{
        struct xb_device *xb = tty->disc_data;

        pr_debug("%s\n", __func__);

        if (NULL == xb) {
                printk(KERN_WARNING "%s: match is not found\n", __func__);
                return;
        }

        tty->disc_data = NULL;
        tty_kref_put(tty);
        xb->tty = NULL;

        destroy_workqueue(xb->sendrecv_workq);

        xb_unregister_device(xb);

        tty_ldisc_flush(tty);
        tty_driver_flush_buffer(tty);

        xb_free(xb);
}

/**
 * xbee_ldisc_ioctl - ...
 *
 * @tty: TTY info for line.
 * @file: ...
 * @cmd: ...
 * @arg: ...
 */
static int
xbee_ldisc_ioctl(struct tty_struct *tty, struct file *file,
                            unsigned int cmd, unsigned long arg)
{
        struct xb_device *xb = tty->disc_data;
        unsigned int tmp;

        /* First make sure we're connected. */
        if (!xb || xb->magic != XBEE802154_MAGIC)
                return -EINVAL;

        switch (cmd) {
        case SIOCGIFNAME:
                tmp = strlen(xb->dev->name) + 1;
                if (copy_to_user((void __user *)arg, xb->dev->name, tmp))
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
}

#ifdef MODTEST_ENABLE
#include "xbee802154_test.c"
#endif

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
        pr_debug("%s\n", __func__);
        xbee_ldisc_close(tty);
        return 0;
}

/**
 * xbee_ldisc_recv_buf - Receive serial bytes.
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
static int
xbee_ldisc_receive_buf2(struct tty_struct *tty,
                                const unsigned char *buf,
                                char *cflags, int count)
{
        struct xb_device *xb = tty->disc_data;
        int ret = 0;

        if (!tty->disc_data) {
                printk(KERN_ERR
                        "%s(): record for tty is not found\n", __func__);
                return 0;
        }

        ret = frame_put_received_data(xb->recv_buf, buf, count);

        if(ret == 0)
                return count;

        mutex_lock(&xb->queue_mutex);
        ret = frameq_enqueue_received(&xb->recv_queue, xb->recv_buf,
                        (xb->api == 2) );
        mutex_unlock(&xb->queue_mutex);

        if(ret > 0)
                ret = queue_work(xb->sendrecv_workq,
                                (struct work_struct*)&xb->recv_work.work);

        return count;
}

/*********************************************************************/

/**
 * xbee_ldisc - TTY line discipline ops.
 */
static struct tty_ldisc_ops xbee_ldisc_ops = {
        .owner               = THIS_MODULE,
        .magic               = TTY_LDISC_MAGIC,
         .name               = "n_ieee802154_xbee",
        .open                = xbee_ldisc_open,
        .close               = xbee_ldisc_close,
        .ioctl               = xbee_ldisc_ioctl,
         .hangup             = xbee_ldisc_hangup,
        .receive_buf2        = xbee_ldisc_receive_buf2,
};

/**
 * xbee_init() - Module initialize.
 */
static int __init xbee_init(void)
{
        pr_debug("%s\n", __func__);
        printk(KERN_INFO "Initializing ZigBee TTY interface\n");

        xbee_init_workq = create_workqueue("xbee_init_workq");
        if(!xbee_init_workq) {
                return -EINVAL;
        }

        if (tty_register_ldisc(N_IEEE802154_XBEE, &xbee_ldisc_ops) != 0) {
                printk(KERN_ERR "%s: line discipline register failed\n",
                                __func__);
                return -EINVAL;
        }

        return 0;
}

/**
 * xbee_exit() - Module deinitialize.
 */
static void __exit xbee_exit(void)
{
        pr_debug("%s\n", __func__);

        if(xbee_init_workq)
                destroy_workqueue(xbee_init_workq);

        if (tty_unregister_ldisc(N_IEEE802154_XBEE) != 0)
                printk(KERN_CRIT
                        "failed to unregister ZigBee line discipline.\n");

}

module_init(xbee_init);
module_exit(xbee_exit);

MODULE_DESCRIPTION("Digi XBee IEEE 802.15.4 serial driver");
MODULE_ALIAS_LDISC(N_IEEE802154_XBEE);
MODULE_LICENSE("GPL");

