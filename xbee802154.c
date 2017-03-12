#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <net/mac802154.h>

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
        default:
                return tty_mode_ioctl(tty, file, cmd, arg);
        }
}

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

