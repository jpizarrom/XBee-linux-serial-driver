#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

#define N_IEEE802154_XBEE 25
#define VERSION 1

#define XBEE_CHAR_NEWFRM 0x7e

#define ZIGBEE_EXPLICIT_RX_INDICATOR 0x91

struct workqueue_struct *xbee_init_workq = NULL;

enum {
	STATE_WAIT_START1,
	STATE_WAIT_START2,
	STATE_WAIT_COMMAND,
	STATE_WAIT_PARAM1,
	STATE_WAIT_PARAM2,
	STATE_WAIT_DATA
};

/*********************************************************************/
struct xb_device;

struct xb_work {
        struct work_struct work;
        struct xb_device* xb;
};

struct xb_device {
	struct tty_struct *tty;
	struct ieee802154_hw *dev;

	/* locks the ldisc for the command */
	struct mutex		mutex;

	/* command completition */
    wait_queue_head_t frame_waitq;

    struct sk_buff *frame;
    int frame_esc;
    int frame_len;
//	struct list_head frame_pend;
	/* Command (rx) processing */
	int			state;
        struct completion cmd_resp_done;
        struct completion send_done;

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
	u8 addr[IEEE802154_ADDR_LEN];
//	u8 saddr[IEEE802154_SHORT_ALEN];
    __le16 saddr;
	u8 flags;
	u8 rssi;
	unsigned char *data;
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
        pr_debug("       tx_powers_size = %lu\n", supported->tx_powers_size);
        pr_debug("   cca_ed_levels_size = %lu\n", supported->cca_ed_levels_size);
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
/*
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
*/
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




static void
cleanup(struct xb_device *zbdev)
{
	pr_debug("%s\n", __func__);
    zbdev->state = STATE_WAIT_START1;
    zbdev->frame = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
/*    zbdev->id = 0;
    zbdev->param1 = 0;
    zbdev->param2 = 0;
    zbdev->index = 0;
    zbdev->pending_id = 0;
    zbdev->pending_size = 0;

    if (zbdev->pending_data)
    {
        kfree(zbdev->pending_data);
        zbdev->pending_data = NULL;
    }
*/
}

/*
 * Callbacks from mac802154 to the driver. Must handle xmit(). 
 *
 * See net/mac802154/ieee802154_hw.c, include/net/mac802154.h,
 * and net/mac802154/mac802154.h from linux-wsn.
 */

/**
 * xbee_ieee802154_set_channel - Set radio for listening on specific channel.
 *
 * @dev: ...
 * @page: ...
 * @channel: ...
 */
static int xbee_ieee802154_set_channel(struct ieee802154_hw *dev,
				       u8 page, u8 channel){
	pr_debug("%s\n", __func__);
    return 0;
}

/**
 * xbee_ieee802154_ed - Handler that 802.15.4 module calls for Energy Detection.
 *
 * @dev: ...
 * @level: ...
 */
static int xbee_ieee802154_ed(struct ieee802154_hw *dev, u8 *level){
	pr_debug("%s\n", __func__);
    return 0;
}

/**
 * xbee_ieee802154_xmit - Handler that 802.15.4 module calls for each transmitted frame.
 *
 * @dev: ...
 * @skb: ...
 */
static int xbee_ieee802154_xmit(struct ieee802154_hw *dev,
				struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
    return 0;
}

static int xbee_ieee802154_filter(struct ieee802154_hw *dev,
					  struct ieee802154_hw_addr_filt *filt,
					    unsigned long changed)
{
	pr_debug("%s\n", __func__);
    return 0;
}

/**
 * xbee_ieee802154_start - For device initialisation before the first interface is attached.
 *
 * @dev: ...
 */
static int xbee_ieee802154_start(struct ieee802154_hw *dev)
{
	struct xb_device *zbdev;
	int ret = 0;

	pr_debug("%s\n", __func__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return -EINVAL;
	}

	pr_debug("%s end (retval: %d)\n", __func__, ret);
	return ret;
}

/**
 * xbee_ieee802154_stop - For device cleanup after last interface is removed.
 *
 * @dev: ...
 */
static void xbee_ieee802154_stop(struct ieee802154_hw *dev){
	struct xb_device *zbdev;
	pr_debug("%s\n", __func__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return;
	}

	pr_debug("%s end\n", __func__);
}
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
        struct xb_device* xbdev = xbw->xb;
        struct ieee802154_hw* dev = xbdev->dev;
        struct tty_struct *tty = xbdev->tty;
        int err;

        err = ieee802154_register_hw(dev);
        if (err) {
//                XBEE_ERROR("%s: device register failed\n", __func__);
        printk(KERN_ERR "%s: device register failed\n", __func__);
                goto err;
        }

        return;

err:
        tty->disc_data = NULL;
        tty_kref_put(tty);
        xbdev->tty = NULL;

        ieee802154_unregister_hw(xbdev->dev);
        ieee802154_free_hw(xbdev->dev);

        return;
}

/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

/**
 * xbee_ieee802154_ops - ieee802154 MCPS ops.
 *
 * This is part of linux-wsn. It is similar to netdev_ops.
 */
static struct ieee802154_ops xbee_ieee802154_ops = {
	.owner		= THIS_MODULE,
	.xmit_sync	= xbee_ieee802154_xmit,
	.ed		= xbee_ieee802154_ed,
	.set_channel	= xbee_ieee802154_set_channel,
	.set_hw_addr_filt = xbee_ieee802154_filter,
	.start		= xbee_ieee802154_start,
	.stop		= xbee_ieee802154_stop,
};

/*
 * See Documentation/tty.txt for details.
 */
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

	struct ieee802154_hw *dev;
	struct xb_device *xbdev = tty->disc_data;
	int err;

	pr_debug("%s\n", __func__);

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

//	if (tty->ops->stop)
//		tty->ops->stop(tty);

	tty_driver_flush_buffer(tty);

	dev = ieee802154_alloc_hw(sizeof(*xbdev), &xbee_ieee802154_ops);
	if (!dev)
		return -ENOMEM;

	xbdev = dev->priv;
	xbdev->dev = dev;

	mutex_init(&xbdev->mutex);
//	init_completion(&xbdev->cmd_resp_done);
	init_waitqueue_head(&xbdev->frame_waitq);

	dev->extra_tx_headroom = 0;
	/* only 2.4 GHz band */
	dev->phy->supported.channels[0] = 0x7fff800;

	dev->flags = IEEE802154_HW_OMIT_CKSUM;

	dev->parent = tty->dev;

	xbdev->tty = tty_kref_get(tty);

    cleanup(xbdev);

	tty->disc_data = xbdev;
//	tty->receive_room = MAX_DATA_SIZE;
	tty->receive_room = 65536;

//	dev->ml_priv = &xbee_ieee802154_mlme_ops;

	if (tty->ldisc->ops->flush_buffer)
		tty->ldisc->ops->flush_buffer(tty);
	tty_driver_flush_buffer(tty);

	xbdev->recv_buf = dev_alloc_skb(IEEE802154_MTU);
	xbdev->last_atresp = NULL;

	xbdev->api = XBEE_API_V2;

	mutex_init(&xbdev->queue_mutex);
	skb_queue_head_init(&xbdev->recv_queue);
	skb_queue_head_init(&xbdev->send_queue);

	init_completion(&xbdev->cmd_resp_done);
	init_completion(&xbdev->send_done);

	xbdev->sendrecv_workq = create_workqueue("sendrecv_workq");
	xbdev->send_work.xb = xbdev;
	xbdev->recv_work.xb = xbdev;
	xbdev->init_work.xb = xbdev;

	INIT_WORK( (struct work_struct*)&xbdev->send_work.work, sendrecv_work_fn);
	INIT_WORK( (struct work_struct*)&xbdev->recv_work.work, sendrecv_work_fn);
	INIT_WORK( (struct work_struct*)&xbdev->init_work.work, init_work_fn);

	queue_work(xbee_init_workq, (struct work_struct*)&xbdev->init_work.work);

	return 0;

err:
	tty->disc_data = NULL;
	tty_kref_put(tty);
	xbdev->tty = NULL;

	ieee802154_unregister_hw(xbdev->dev);
	ieee802154_free_hw(xbdev->dev);

	return err;
}

/**
 * xbee_ldisc_close - Close line discipline and unregister with ieee802154.
 *
 * @tty: TTY info for line.
 */
static void xbee_ldisc_close(struct tty_struct *tty){

	struct xb_device *zbdev;
	pr_debug("%s\n", __func__);
	zbdev = tty->disc_data;
	if (NULL == zbdev) {
		printk(KERN_WARNING "%s: match is not found\n", __func__);
		return;
	}

	tty->disc_data = NULL;
	tty_kref_put(tty);
	zbdev->tty = NULL;
	mutex_destroy(&zbdev->mutex);
	destroy_workqueue(zbdev->sendrecv_workq);


	ieee802154_unregister_hw(zbdev->dev);

	tty_ldisc_flush(tty);
	tty_driver_flush_buffer(tty);

	ieee802154_free_hw(zbdev->dev);

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


        switch (cmd) {
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
//MODULE_LICENSE("Dual GPL/CC0");
MODULE_LICENSE("GPL");

