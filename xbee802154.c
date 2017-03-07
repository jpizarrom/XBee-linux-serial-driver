#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <net/mac802154.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

#define N_IEEE802154_XBEE 25
#define VERSION 1

#define XBEE_CHAR_NEWFRM 0x7e

#define ZIGBEE_EXPLICIT_RX_INDICATOR 0x91

enum {
	STATE_WAIT_START1,
	STATE_WAIT_START2,
	STATE_WAIT_COMMAND,
	STATE_WAIT_PARAM1,
	STATE_WAIT_PARAM2,
	STATE_WAIT_DATA
};

/*********************************************************************/

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
        struct sk_buff* recv_buf;

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

static int xbee_frm_xbee_verify(struct sk_buff *skb){
    int length;
	uint8_t checksum = 0;
    uint16_t i;
    pr_debug("%s skb->len %d\n", __func__, skb->len);

    if (skb->len > 2)
    {
        length = (*skb->data << 8) & 0xff00; // MSB
        length |= *(skb->data+1) & 0xff; // LSB
        pr_debug("%s length %d\n", __func__, length);
        if (skb->len == length+3){
            for(i=0;i<length;++i) {
                checksum += *(skb->data+i+2);
            }
            checksum = 0xFF - checksum;
            if (checksum==*(skb->data+length+3-1))
                return 0;
        }
    }
    return 1;
}

static int xbee_frm_xbee_id(struct sk_buff *skb){
	pr_debug("%s\n", __func__);
    return *(skb->data+2);
}
static int xbee_frame_peak_done(struct xb_device *xbdev){
	pr_debug("%s\n", __func__);
    return !xbee_frm_xbee_verify(xbdev->frame);
}
static void xbee_frame_recv_rx64(struct xb_device *xbdev,
                    struct sk_buff *skb)
{
    struct sk_buff *lskb;
	pr_debug("%s\n", __func__);
    lskb = alloc_skb(skb->len, GFP_ATOMIC);
    skb_put(lskb, skb->len);
    skb_copy_to_linear_data(lskb, skb->data, skb->len);
	ieee802154_rx_irqsafe(xbdev->dev, lskb, skb->len);
//	ieee802154_rx(xbdev->dev, skb, rssi);
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
	u8 id;
    int err;

	pr_debug("%s\n", __func__);

	/* verify length and checksum */
	err = xbee_frm_xbee_verify(skb);
	if (err) {
//		XBEE_WARN("dropping invalid frame 0x%x", err);
		printk(KERN_WARNING "%s: dropping invalid frame 0x%x\n", __func__, err);
		return;
	}

	id = xbee_frm_xbee_id(skb);
	switch (id) {
    case ZIGBEE_EXPLICIT_RX_INDICATOR:
		xbee_frame_recv_rx64(xbdev, skb);
		break;
/*	case XBEE_FRM_STAT:
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
		break;*/
	default:
//		XBEE_WARN("received unknown frame type 0x%x", id);
	    pr_debug("%s received unknown frame type 0x%x\n", __func__, id);
//		kfree_skb(skb);
		break;
	}
}

static int xbee_frm_new(struct xb_device *xbdev,
			struct sk_buff **skb)
{
	struct sk_buff *new_skb;

	new_skb = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
	if (new_skb == NULL) {
//		XBEE_ERR("failed to allocate new skb");
        printk(KERN_ERR "%s: failed to allocate new skb\n", __func__);
		return 1;
	} else {
//        pr_debug("%s 1 skb %d\n", __func__, skb);
//        pr_debug("%s 1 *skb %d\n", __func__, *skb);
		*skb = xbdev->frame;
//        pr_debug("%s 2 skb %d\n", __func__, skb);
//        pr_debug("%s 2 *skb %d\n", __func__, *skb);
		xbdev->frame = new_skb;
////		*skb = old_skb;

		xbdev->frame_len = 0;
		return 0;
	}
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
	err = ieee802154_register_hw(dev);
	if (err) {
//		XBEE_ERROR("%s: device register failed\n", __func__);
        printk(KERN_ERR "%s: device register failed\n", __func__);
		goto err;
	}

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
//	struct ieee802154_hw *dev;
	struct xb_device *xbdev;
	char c;
	int ret;
	struct sk_buff *skb;
	pr_debug("%s\n", __func__);

	/* Debug info */
//	printk(KERN_INFO "%s, received %d bytes\n", __func__,
//			count);
#ifdef DEBUG
	print_hex_dump_bytes("ieee802154_tty_receive ", DUMP_PREFIX_NONE,
			cp, count);
#endif

	/* Actual processing */
	xbdev = tty->disc_data;
	if (NULL == xbdev) {
		printk(KERN_ERR "%s(): record for tty is not found\n",
				__func__);
		return;
	}

	/* copy (i wish i could just lock and link them in an array) buffers */
	while (count--) {
		c = *cp++;
		/* escape this byte */
/*
		if (xbdev->frame_esc) {
			c ^= 0x20;
			xbdev->frame_esc = 0;
		}
*/
    
//    	pr_debug("char %x\n", c);

		switch (c) {
//		    case XBEE_CHAR_ESC: /* escape next byte */
//			    xbdev->frame_esc = 1;
//			    break;
		    case XBEE_CHAR_NEWFRM: /* new frame */
//			    XBEE_INFO("new frame");
                pr_debug("new frame\n");
			    /* switch to new frame buffer */
//                pr_debug("1 xbdev->frame->len %d\n", xbdev->frame->len);
//                pr_debug("1 xbdev->frame %d\n", xbdev->frame);
//                pr_debug("skb %d\n", skb);
//                pr_debug("&skb %d\n", &skb);
			    ret = xbee_frm_new(xbdev, &skb);
//                pr_debug("2 xbdev->frame->len %d\n", xbdev->frame->len);
//                pr_debug("2 &xbdev->frame %d\n", xbdev->frame);
//                pr_debug("skb %d\n", skb);
//                pr_debug("&skb %d\n", &skb);
//                pr_debug("skb->len %d\n", skb->len);
//			    if (unlikely(ret))
			    if (ret){
//				    XBEE_ERR("derp");
			    /* submit old frame buffer to stack */
                }
			    else {
				    xbee_frm_xbee_recv(xbdev, skb);
				    kfree_skb(skb);
			    }
			    /* reset overflow status */
//			    overflow = 0;
			    break;
		    default:
                pr_debug("append to frame buffer\n");
			    /* check for frame buffer overflow */
//			    if (overflow || xbdev->frame_len == XBEE_FRAME_MAXLEN) {
//				    overflow = 1;
//				    continue;
//			    }
			    /* append to frame buffer */
                memcpy(skb_put(xbdev->frame, 1), &c, 1);
			    /* increase current frame buffer len */
			    xbdev->frame_len += 1;
//                pr_debug("xbdev->frame_len %d\n", xbdev->frame_len);
//                pr_debug("xbdev->frame->len %d\n", xbdev->frame->len);
			    break;
        }
    }
//	if (overflow)
//		XBEE_WARN("was buffer overflow");

	/* peak at frame to check if completed */

	if (xbee_frame_peak_done(xbdev)) {
		ret = xbee_frm_new(xbdev, &skb);
		if (ret){
//		if (unlikely(ret))
//			XBEE_ERR("derp");
        }
		else {
			xbee_frm_xbee_recv(xbdev, skb);
			kfree_skb(skb);
		}
	}
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

static int __init xbee_init(void)
{
	pr_debug("%s\n", __func__);
	printk(KERN_INFO "Initializing ZigBee TTY interface\n");

	if (tty_register_ldisc(N_IEEE802154_XBEE, &xbee_ldisc_ops) != 0) {
		printk(KERN_ERR "%s: line discipline register failed\n",
				__func__);
		return -EINVAL;
	}

	return 0;
}

static void __exit xbee_exit(void)
{
	pr_debug("%s\n", __func__);
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

