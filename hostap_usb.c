#define PRISM2_USB

#include <linux/module.h>
#include <linux/init.h>
#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include "hostap_wlan.h"


static char *dev_info = "hostap_usb";

MODULE_AUTHOR("Dmitry Eremin-Solenikov");
MODULE_DESCRIPTION("Support for Intersil Prism2.5-based 802.11 wireless LAN "
		   "USB cards.");
MODULE_SUPPORTED_DEVICE("Intersil Prism2.5-based WLAN PCI cards");
MODULE_LICENSE("GPL");

/* struct local_info::hw_priv */
struct hostap_usb_priv {
	struct usb_device *usb;
	int endp_in;
	int endp_out;
	int present;
	struct urb rx_urb;
	struct urb tx_urb;
	struct sk_buff *rx_skb;
	struct sk_buff_head tx_queue;
};

typedef void (*hostap_urb_calb)(struct net_device *dev, struct sk_buff *req);

struct hostap_usb_skb_cb {
	struct completion comp;
	struct sk_buff *response;
	hostap_urb_calb calb;
	unsigned error : 1,
		 acked : 1,
		 noresp : 1,
		 issued : 1;
};

static inline struct hostap_usb_skb_cb *hfa384x_cb(struct sk_buff *skb)
{
	return (struct hostap_usb_skb_cb *)skb->cb;
}

#define PRISM_USB_DEVICE(vid, pid, name)	\
	USB_DEVICE(vid, pid),			\
	.driver_info = (unsigned long) name

static struct usb_device_id prism2_usb_id_table[] = {
	{PRISM_USB_DEVICE(0x04bb, 0x0922, "IOData AirPort WN-B11/USBS")},
	{PRISM_USB_DEVICE(0x07aa, 0x0012, "Corega Wireless LAN USB Stick-11")},
	{PRISM_USB_DEVICE(0x09aa, 0x3642, "Prism2.x 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x1668, 0x0408, "Actiontec Prism2.5 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x1668, 0x0421, "Actiontec Prism2.5 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x1915, 0x2236, "Linksys WUSB11v3.0 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x066b, 0x2212, "Linksys WUSB11v2.5 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x066b, 0x2213, "Linksys WUSB12v1.1 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x067c, 0x1022, "Siemens SpeedStream 1022 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x049f, 0x0033,
	 "Compaq/Intel W100 PRO/Wireless 11Mbps multiport WLAN Adapter")},
	{PRISM_USB_DEVICE
	 (0x0411, 0x0016, "Melco WLI-USB-S11 11Mbps WLAN Adapter")},
	{PRISM_USB_DEVICE
	 (0x08de, 0x7a01, "PRISM25 IEEE 802.11 Mini USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x8086, 0x1111, "Intel PRO/Wireless 2011B LAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0d8e, 0x7a01, "PRISM25 IEEE 802.11 Mini USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x045e, 0x006e, "Microsoft MN510 Wireless USB Adapter")},
	{PRISM_USB_DEVICE(0x0967, 0x0204, "Acer Warplink USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0cde, 0x0002, "Z-Com 725/726 Prism2.5 USB/USB Integrated")},
	{PRISM_USB_DEVICE
	 (0x0cde, 0x0005, "Z-Com Xl735 Wireless 802.11b USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x413c, 0x8100, "Dell TrueMobile 1180 Wireless USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0b3b, 0x1601, "ALLNET 0193 11Mbps WLAN USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0b3b, 0x1602, "ZyXEL ZyAIR B200 Wireless USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0baf, 0x00eb, "USRobotics USR1120 Wireless USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0411, 0x0027, "Melco WLI-USB-KS11G 11Mbps WLAN Adapter")},
	{PRISM_USB_DEVICE
	 (0x04f1, 0x3009, "JVC MP-XP7250 Builtin USB WLAN Adapter")},
	{PRISM_USB_DEVICE(0x0846, 0x4110, "NetGear MA111")},
	{PRISM_USB_DEVICE(0x03f3, 0x0020, "Adaptec AWN-8020 USB WLAN Adapter")},
	{PRISM_USB_DEVICE(0x2821, 0x3300, "ASUS-WL140 Wireless USB Adapter")},
	{PRISM_USB_DEVICE(0x2001, 0x3700, "DWL-122 Wireless USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x2001, 0x3702, "DWL-120 Rev F Wireless USB Adapter")},
	{PRISM_USB_DEVICE(0x50c2, 0x4013, "Averatec USB WLAN Adapter")},
	{PRISM_USB_DEVICE(0x2c02, 0x14ea, "Planex GW-US11H WLAN USB Adapter")},
	{PRISM_USB_DEVICE(0x124a, 0x168b, "Airvast PRISM3 WLAN USB Adapter")},
	{PRISM_USB_DEVICE(0x083a, 0x3503, "T-Sinus 111 USB WLAN Adapter")},
	{PRISM_USB_DEVICE(0x2821, 0x3300, "Hawking HighDB USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0411, 0x0044, "Melco WLI-USB-KB11 11Mbps WLAN Adapter")},
	{PRISM_USB_DEVICE(0x1668, 0x6106, "ROPEX FreeLan 802.11b USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x124a, 0x4017, "Pheenet WL-503IA 802.11b USB Adapter")},
	{PRISM_USB_DEVICE(0x0bb2, 0x0302, "Ambit Microsystems Corp.")},
	{PRISM_USB_DEVICE
	 (0x9016, 0x182d, "Sitecom WL-022 802.11b USB Adapter")},
	{PRISM_USB_DEVICE
	 (0x0543, 0x0f01, "ViewSonic Airsync USB Adapter 11Mbps (Prism2.5)")},
	{ /* terminator */ }
};

MODULE_DEVICE_TABLE(usb, prism2_usb_id_table);

/* forward declarations from hostap_hw.c */
static void prism2_hw_reset(struct net_device *dev);

/* ignore interrupts for USB */
static void hfa384x_enable_interrupts(struct net_device *dev) {}
static void hfa384x_disable_interrupts(struct net_device *dev) {}
// FIXME: this is used during shutdown!
static void hfa384x_events_only_cmd(struct net_device *dev) {}

/* dummy read just for reporting in tx_timeout */
static void hfa384x_read_regs(struct net_device *dev,
			      struct hfa384x_regs *regs) {
	regs->cmd = 0xdead;
	regs->evstat = 0xdead;
	regs->offset0 = 0xdead;
	regs->offset1 = 0xdead;
	regs->swsupport0 = 0xdead;
}

struct hfa384x_usbin {
	u16 type;
	union {
		u16 boguspad[1207];
	};
} __packed;

enum {
	HFA384x_USB_TYPE_INFO,
	HFA384x_USB_TYPE_CMD,
	HFA384x_USB_TYPE_WRRID,
	HFA384x_USB_TYPE_RDRID,
	HFA384x_USB_TYPE_WRMEM,
	HFA384x_USB_TYPE_RDMEM,
};

#define ROUNDUP64(s)		(((s) + 63) & ~63)
#define ALLOC_TX_SKB(size)	dev_alloc_skb(ROUNDUP64(size))

struct hfa384x_cmd_req {
	__le16 type;
	__le16 cmd;
	__le16 param0;
	__le16 param1;
	__le16 param2;
} __packed;

struct hfa384x_rrid_req {
	__le16 type;
	__le16 frmlen;
	__le16 rid;
} __packed;


struct hfa384x_wrid_req {
	__le16 type;
	__le16 frmlen;
	__le16 rid;
/*	u8 data[xxx]; */
} __packed;


static void hfa384x_usbout_callback(struct urb *urb);

static void hfa384x_usbin_callback(struct urb *urb);

static int hfa384x_submit_rx_urb(struct net_device *dev, gfp_t flags)
{
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	struct sk_buff *skb;
	int ret;

	skb = dev_alloc_skb(sizeof(struct hfa384x_usbin));
	if (!skb)
		return -ENOMEM;

	usb_fill_bulk_urb(&hw_priv->rx_urb, hw_priv->usb,
			hw_priv->endp_in, skb->data, sizeof(struct hfa384x_usbin),
			hfa384x_usbin_callback, dev);

	hw_priv->rx_skb = skb;

	/* FIXME: don't resubmit while we are at stall ??? */
	ret = usb_submit_urb(&hw_priv->rx_urb, flags);
	if (ret == -EPIPE) {
		printk(KERN_ERR "%s rx pipe stall!\n", dev->name);
		// FIXME;
	}

	if (ret != 0) {
		printk(KERN_ERR "%s rx submit %d\n", dev->name, ret);
		hw_priv->rx_skb = NULL;
		dev_kfree_skb(skb);
	}

	return ret;
}

static int hfa384x_submit_tx_urb(struct net_device *dev, struct sk_buff *skb, gfp_t flags)
{
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	int ret;

	BUG_ON(!skb);

	usb_fill_bulk_urb(&hw_priv->tx_urb, hw_priv->usb,
			hw_priv->endp_out, skb->data, ROUNDUP64(skb->len),
			hfa384x_usbout_callback, dev);

	print_hex_dump_bytes("out ", DUMP_PREFIX_OFFSET, skb->data, skb->len);

	/* FIXME: don't resubmit while we are at stall ??? */
	ret = usb_submit_urb(&hw_priv->tx_urb, flags);
	if (ret == -EPIPE) {
		printk(KERN_ERR "%s tx pipe stall!\n", dev->name);
		// FIXME;
	}
	if (ret)
		printk(KERN_ERR "%s tx submit %d\n", dev->name, ret);

	return ret;
}

static int hfa384x_usbout(struct net_device *dev, struct sk_buff *skb)
{
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	unsigned long flags;
	struct sk_buff *for_tx;

	spin_lock_irqsave(&hw_priv->tx_queue.lock, flags);

	if (skb) {
		init_completion(&hfa384x_cb(skb)->comp);
		hfa384x_cb(skb)->response = NULL;
		hfa384x_cb(skb)->error = 0;
		hfa384x_cb(skb)->acked = 0;
		hfa384x_cb(skb)->issued = 0;
		__skb_queue_tail(&hw_priv->tx_queue, skb);
	}

	for_tx = skb_peek(&hw_priv->tx_queue);
	if (for_tx && !hfa384x_cb(for_tx)->issued)
		hfa384x_cb(for_tx)->issued = 1;
	else
		for_tx = NULL;

	printk(KERN_DEBUG "usbout: %p %d %d\n", skb, skb_queue_len(&hw_priv->tx_queue),
			for_tx ? 1 : 0);
	spin_unlock_irqrestore(&hw_priv->tx_queue.lock, flags);

	if (for_tx)
		return hfa384x_submit_tx_urb(dev, for_tx, GFP_ATOMIC);

	return 0;
}

static int hfa384x_wait(struct net_device *dev, struct sk_buff *skb)
{
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	int res;
	unsigned long flags;

	res = wait_for_completion_interruptible_timeout(&hfa384x_cb(skb)->comp, 5 * HZ);
	if (res > 0)
		return 0;

	if (res == 0) {
		res = -ETIMEDOUT;
	}

	usb_kill_urb(&hw_priv->tx_urb);
	// FIXME: rethink
	spin_lock_irqsave(&hw_priv->tx_queue.lock, flags);
	if (skb->next)
		skb_unlink(skb, &hw_priv->tx_queue);
	spin_unlock_irqrestore(&hw_priv->tx_queue.lock, flags);
	return res;
}

static int hfa384x_get_rid(struct net_device *dev, u16 rid, void *buf, int len,
			   int exact_len) {
	struct hostap_interface *iface;
	local_info_t *local;
	int res, rrid, rlen = 0;
	struct sk_buff *skb, *respskb;
	struct hfa384x_rrid_req ridrq;

	iface = netdev_priv(dev);
	local = iface->local;

	if (local->no_pri) {
		printk(KERN_DEBUG "%s: cannot get RID %04x (len=%d) - no PRI "
		       "f/w\n", dev->name, rid, len);
		return -ENOTTY; /* Well.. not really correct, but return
				 * something unique enough.. */
	}

	if ((local->func->card_present && !local->func->card_present(local)) ||
	    local->hw_downloading)
		return -ENODEV;

	skb = ALLOC_TX_SKB(sizeof(ridrq));
	if (!skb)
		return -ENOMEM;

	memset(&ridrq, 0, sizeof(ridrq));
	ridrq.type = cpu_to_le16(HFA384x_USB_TYPE_RDRID);
	ridrq.frmlen = cpu_to_le16(2);
	ridrq.rid = cpu_to_le16(rid);

	memcpy(skb_put(skb, sizeof(ridrq)), &ridrq, sizeof(ridrq));

	hfa384x_cb(skb)->calb = NULL;
	hfa384x_cb(skb)->noresp = 0;
	res = hfa384x_usbout(dev, skb);
	if (res) {
		dev_kfree_skb(skb);
		return res;
	}

	res = hfa384x_wait(dev, skb);

	respskb = hfa384x_cb(skb)->response;
	if (!respskb) {
		res = -EIO;
	}

	if (!res) {
		skb_pull(respskb, 2);
		rlen = le16_to_cpu(*(u16*)(respskb->data));
		skb_pull(respskb, 2);
		rlen = (rlen - 1) * 2;
	}

	if (!res && exact_len && rlen != len) {
		printk(KERN_DEBUG "%s: hfa384x_get_rid - RID len mismatch: "
		       "rid=0x%04x, len=%d (expected %d)\n",
		       dev->name, rid, rlen, len);
		res = -ENODATA;
	}

	if (!res) {
		rrid = le16_to_cpu(*(u16*)(respskb->data));
		if (rrid != rid) {
			printk(KERN_DEBUG "%s: hfa384x_get_rid - RID mismatch: "
			       "rid=0x%04x, got 0x%04x)\n",
			       dev->name, rid, rrid);
			res = -ENODATA;
		}
	}

	if (!res) {
		skb_pull(respskb, 2); /* skip RID */
		memcpy(buf, respskb->data, len);
	}

	if (respskb)
		dev_kfree_skb(respskb);
	dev_kfree_skb(skb);

	if (res) {
		if (res != -ENODATA)
			printk(KERN_DEBUG "%s: hfa384x_get_rid (rid=%04x, "
			       "len=%d) - failed - res=%d\n", dev->name, rid,
			       len, res);
		if (res == -ETIMEDOUT)
			prism2_hw_reset(dev);
		return res;
	}

	return rlen;
}

static int hfa384x_set_rid(struct net_device *dev, u16 rid, void *buf, int len) {
	struct hostap_interface *iface;
	local_info_t *local;
	int res;
	struct sk_buff *skb;
	struct hfa384x_wrid_req ridrq;

	iface = netdev_priv(dev);
	local = iface->local;

	if (local->no_pri) {
		printk(KERN_DEBUG "%s: cannot set RID %04x (len=%d) - no PRI "
		       "f/w\n", dev->name, rid, len);
		return -ENOTTY; /* Well.. not really correct, but return
				 * something unique enough.. */
	}

	if ((local->func->card_present && !local->func->card_present(local)) ||
	    local->hw_downloading)
		return -ENODEV;

	skb = ALLOC_TX_SKB(sizeof(ridrq) + len + 1);
	if (!skb)
		return -ENOMEM;

	memset(&ridrq, 0, sizeof(ridrq));
	ridrq.type = cpu_to_le16(HFA384x_USB_TYPE_WRRID);
	/* RID len in words and +1 for rec.rid */
	ridrq.frmlen = cpu_to_le16((len + 1) / 2 + 1);
	ridrq.rid = cpu_to_le16(rid);

	memcpy(skb_put(skb, sizeof(ridrq)), &ridrq, sizeof(ridrq));
	memcpy(skb_put(skb, len), buf, len);
	if (len % 2)
		*skb_put(skb, 1) = 0;

	hfa384x_cb(skb)->calb = NULL;
	hfa384x_cb(skb)->noresp = 0;
	res = hfa384x_usbout(dev, skb);
	if (res) {
		dev_kfree_skb(skb);
		return res;
	}

	res = hfa384x_wait(dev, skb);

	if (hfa384x_cb(skb)->response)
		dev_kfree_skb(hfa384x_cb(skb)->response);
	dev_kfree_skb(skb);

	if (res) {
		if (res != -ENODATA)
			printk(KERN_DEBUG "%s: hfa384x_get_rid (rid=%04x, "
			       "len=%d) - failed - res=%d\n", dev->name, rid,
			       len, res);
		if (res == -ETIMEDOUT)
			prism2_hw_reset(dev);
	}

	return res;
}

static void hfa384x_usb_cmd_callback(struct net_device *dev, struct sk_buff *skb);

static int hfa384x_cmd_issue(struct net_device *dev,
				    struct hostap_cmd_queue *entry)
{
	struct hostap_interface *iface;
	local_info_t *local;
	struct sk_buff *skb;
	struct hfa384x_cmd_req cmd;
	struct hostap_usb_priv *hw_priv;
	int ret = 0;

	printk(KERN_DEBUG "%s cmd %d\n", dev_info, entry->cmd);

	iface = netdev_priv(dev);
	local = iface->local;
	hw_priv =  local->hw_priv;

	if (local->func->card_present && !local->func->card_present(local))
		return -ENODEV;

	if (entry->issued) {
		printk(KERN_DEBUG "%s: driver bug - re-issuing command @%p\n",
		       dev->name, entry);
	}

	skb = ALLOC_TX_SKB(sizeof(cmd));
	if (!skb)
		return -ENOMEM;

	memset(&cmd, 0, sizeof(cmd));
	cmd.type = cpu_to_le16(HFA384x_USB_TYPE_CMD);
	cmd.cmd = entry->cmd;
	cmd.param0 = entry->param0;
	cmd.param1 = entry->param1;
	cmd.param2 = 0;
	memcpy(skb_put(skb, sizeof(cmd)), &cmd, sizeof(cmd));

	hfa384x_cb(skb)->calb = hfa384x_usb_cmd_callback;
	hfa384x_cb(skb)->noresp = 0;
	ret = hfa384x_usbout(dev, skb);

	// FIXME: support timeouts for commands (not here, in a timer!)

	if (!ret)
		entry->issued = 1;

	return ret;
}
static int prism2_tx_80211(struct sk_buff *skb, struct net_device *dev)
{
	return -1;
}

static int prism2_hw_init(struct net_device *dev, int initial)
{
	struct hostap_interface *iface;
	local_info_t *local;
	struct hostap_usb_priv *hw_priv;
	int ret;

	PDEBUG(DEBUG_FLOW, "prism2_hw_init()\n");

	iface = netdev_priv(dev);
	local = iface->local;
	hw_priv = local->hw_priv;

	if (!initial)
		usb_kill_urb(&hw_priv->rx_urb);
	ret = hfa384x_submit_rx_urb(dev, GFP_KERNEL);
	if (ret)
		return 1;

	clear_bit(HOSTAP_BITS_TRANSMIT, &local->bits);

	/* initialize HFA 384x */
	ret = local->func->cmd(dev, HFA384X_CMDCODE_INIT, 0, NULL, NULL);
	if (ret) {
		printk(KERN_DEBUG "%s: assuming no Primary image in "
		       "flash - card initialization not completed\n",
		       dev_info);
		local->no_pri = 1;
#ifdef PRISM2_DOWNLOAD_SUPPORT
		if (local->sram_type == -1)
			local->sram_type = prism2_get_ram_size(local);
#endif /* PRISM2_DOWNLOAD_SUPPORT */
		return 1;
	}
	msleep(500);
	local->no_pri = 0;
	return 0;
}

static void prism2_info(local_info_t *local, struct sk_buff *skb)
{
	struct net_device *dev = local->dev;
	u16 len, type;

	len = le16_to_cpu(*(u16*)(skb->data));
	type = le16_to_cpu(*(u16*)(skb->data + 2));

	if ((len & 0x8000) || len == 0 ||  len > 1031) {
		/* data register seems to give 0x8000 in some error cases even
		 * though busy bit is not set in offset register;
		 * in addition, length must be at least 1 due to type field */
		printk(KERN_DEBUG "%s: Received info frame with invalid "
		       "length 0x%04x (type 0x%04x)\n", dev->name,
		       len, type);
		dev_kfree_skb(skb);
	} else {
		skb_trim(skb, 2 + 2 * len);
		skb_queue_tail(&local->info_list, skb);
		tasklet_schedule(&local->info_tasklet);
	}
}

/* FIX: This might change at some point.. */
#include "hostap_hw.c"

static void hfa384x_usb_cmd_callback(struct net_device *dev, struct sk_buff *skb)
{
	// FIXME: handle error cases
	if (hfa384x_cb(skb)->response) {
		prism2_cmd_ev(dev, hfa384x_cb(skb)->response);
		dev_kfree_skb(hfa384x_cb(skb)->response);
	}
	dev_kfree_skb(skb);
}

static bool hfa384x_check_ctrl_response(struct net_device *dev, struct sk_buff *skb)
{
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	struct sk_buff *reqskb;
	unsigned long flags;
	bool ret = false;

	spin_lock_irqsave(&hw_priv->tx_queue.lock, flags);

	reqskb = skb_peek(&hw_priv->tx_queue);
	if (!reqskb || hfa384x_cb(reqskb)->response)
		goto out;

	if (hfa384x_cb(reqskb)->response)
		goto out;

	if ((reqskb->data[0] != skb->data[0]) || ((reqskb->data[1] | 0x80) != skb->data[1]))
		goto out;

	hfa384x_cb(reqskb)->response = skb;
	ret = true;
out:
	spin_unlock_irqrestore(&hw_priv->tx_queue.lock, flags);

	return ret;
}

static void hfa384x_process_reqs(struct net_device *dev) {
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	unsigned long flags;
	struct sk_buff *skb;
	int process = 0;
	int err = 0;

	printk(KERN_DEBUG "process_reqs\n");
	spin_lock_irqsave(&hw_priv->tx_queue.lock, flags);
	skb = skb_peek(&hw_priv->tx_queue);

	if (skb && (hfa384x_cb(skb)->error ||
			(hfa384x_cb(skb)->acked &&
			 (hfa384x_cb(skb)->response || hfa384x_cb(skb)->noresp)))) {
		process = 1;
		__skb_unlink(skb, &hw_priv->tx_queue);
	}

	printk(KERN_DEBUG "process_reqs %d %d %d %d %p\n",
			process,
			skb ? hfa384x_cb(skb)->error : -1,
			skb ? hfa384x_cb(skb)->acked: -1,
			skb ? hfa384x_cb(skb)->noresp: -1,
			skb ? hfa384x_cb(skb)->response: (void*)-1
			);

	print_hex_dump_bytes("pr ", DUMP_PREFIX_OFFSET, skb->data, skb->len);
	spin_unlock_irqrestore(&hw_priv->tx_queue.lock, flags);

	if (process) {
		hostap_urb_calb urb_calb = hfa384x_cb(skb)->calb;
		if (hfa384x_cb(skb)->error)
			err = 1;

		complete_all(&hfa384x_cb(skb)->comp);
		if (urb_calb)
			(*urb_calb)(dev, skb);

		if (!err)
			hfa384x_usbout(dev, NULL);
	}

	return;

}

static void hfa384x_usbout_callback(struct urb *urb)
{
	struct net_device *dev = urb->context;
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	struct sk_buff *skb;
	unsigned long flags;

	printk(KERN_DEBUG "hostap_usb urbout received!\n");
	switch (urb->status) {
	case 0:
		break;
	case -EPIPE:
		printk(KERN_ERR "tx pipe stall\n");
		break;
	default:
		printk(KERN_ERR "tx %d\n", urb->status);
		break;
	}

	spin_lock_irqsave(&hw_priv->tx_queue.lock, flags);
	if (WARN_ON(!urb))
		goto out;
	if (WARN_ON(!urb->transfer_buffer))
		goto out;
	printk(KERN_DEBUG "type %04x\n", *(u16*)(urb->transfer_buffer));
	skb = skb_peek(&hw_priv->tx_queue);
	if (!skb) {
		printk(KERN_ERR "usbout but no skb in queue!\n");
		goto out;
	}

	if (urb->status != 0)
		hfa384x_cb(skb)->error = 1;
		// FIXME: submit next from tx_queue ?
	else
		hfa384x_cb(skb)->acked = 1;

out:
	spin_unlock_irqrestore(&hw_priv->tx_queue.lock, flags);

	hfa384x_process_reqs(dev);
}

static void hfa384x_usbin_callback(struct urb *urb)
{
	struct net_device *dev = urb->context;
	struct hostap_interface *iface = netdev_priv(dev);
	local_info_t *local = iface->local;
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	struct sk_buff *skb;
	u16 type;

	printk(KERN_DEBUG "hostap_usb urbin received!\n");

	skb = hw_priv->rx_skb;
	hw_priv->rx_skb = NULL;
	BUG_ON(!skb || skb->data != urb->transfer_buffer);

	switch (urb->status) {
	case 0:
		break;
	case -EPIPE:
		printk(KERN_ERR "rx pipe stall\n");
		break;
	default:
		printk(KERN_ERR "rx %d\n", urb->status);
		break;
	}

	// FIXME
	if (urb->status) {
		dev_kfree_skb(skb);
		return;
	}

	skb_put(skb, urb->actual_length);
	print_hex_dump_bytes("urb ", DUMP_PREFIX_OFFSET, skb->data, skb->len);

	if (skb->len < 2) {
		printk(KERN_ERR "%s: %s urbin too short!\n", dev_info, dev->name);
		hfa384x_submit_rx_urb(dev, GFP_ATOMIC);
		return;
	}

	type = le16_to_cpu(*(u16*)(skb->data));
	printk(KERN_DEBUG "%s: type %04x\n", dev_info, type);

	if (type & 0x8000) {
		if (hfa384x_check_ctrl_response(dev, skb)) {
			hfa384x_process_reqs(dev);
			hfa384x_submit_rx_urb(dev, GFP_ATOMIC);
			return;
		}

		switch (type & ~0x8000) {
		case HFA384x_USB_TYPE_INFO:
			skb_pull(skb, 2);
			prism2_info(local, skb);
			break;
		default:
			dev_kfree_skb(skb);
			break;
		}

	} else {
		// FIXME: handle back tx completition
		// FIXME: handle RX errors (len, see prism2_rx)
		skb_queue_tail(&local->rx_list, skb);
		tasklet_schedule(&local->rx_tasklet);
	}

	hfa384x_submit_rx_urb(dev, GFP_ATOMIC);
}

static int prism2_usb_card_present(local_info_t *local)
{
	struct hostap_usb_priv *hw_priv = local->hw_priv;
	if (hw_priv != NULL && hw_priv->usb != NULL && hw_priv->present)
		return 1;
	printk(KERN_ERR "Device not present!!!\n");
	return 0;
}

static void prism2_usb_cor_sreset(local_info_t *local)
{
	struct hostap_usb_priv *hw_priv = local->hw_priv;

	printk(KERN_INFO "%s: resetting device %p\n", dev_info, hw_priv->usb);
	usb_reset_device(hw_priv->usb);
}

static struct prism2_helper_functions prism2_usb_funcs =
{
	.card_present	= prism2_usb_card_present,
	.cor_sreset	= prism2_usb_cor_sreset,
//	.genesis_reset	= prism2_usb_genesis_reset,
	.hw_type	= HOSTAP_HW_USB,
};


static int prism2_usb_probe(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	struct usb_device *usb;
	local_info_t *local = NULL;
	struct net_device *dev = NULL;
	static int cards_found /* = 0 */;
	struct hostap_interface *iface;
	struct hostap_usb_priv *hw_priv;

	hw_priv = kzalloc(sizeof(*hw_priv), GFP_KERNEL);
	if (hw_priv == NULL)
		return -ENOMEM;

	usb = interface_to_usbdev(interface);

	hw_priv->endp_in = usb_rcvbulkpipe(usb, 1);
	hw_priv->endp_out = usb_sndbulkpipe(usb, 2);
	usb_init_urb(&hw_priv->tx_urb);
	usb_init_urb(&hw_priv->rx_urb);
	hw_priv->present = 1;
	skb_queue_head_init(&hw_priv->tx_queue);

	dev = prism2_init_local_data(&prism2_usb_funcs, cards_found,
				     &interface->dev);
	if (dev == NULL)
		goto fail;
	iface = netdev_priv(dev);
	local = iface->local;
	local->hw_priv = hw_priv;
	cards_found++;

	hw_priv->usb = usb_get_dev(usb);

	prism2_usb_cor_sreset(local);

	usb_set_intfdata(interface, dev);

	if (!local->pri_only && prism2_hw_config(dev, 1)) {
		printk(KERN_DEBUG "%s: hardware initialization failed\n",
		       dev_info);
		goto fail2;
	}

	printk(KERN_INFO "%s: Intersil Prism2/2.5/3 USB", dev->name);

	return hostap_hw_ready(dev);

fail2:
	usb_put_dev(hw_priv->usb);
 fail:
	hw_priv->present = 0;
	prism2_free_local_data(dev);

	usb_kill_urb(&hw_priv->rx_urb);
	usb_kill_urb(&hw_priv->tx_urb);

// err_out_free:
	kfree(hw_priv);

	return -ENODEV;
}

static void prism2_usb_disconnect(struct usb_interface *interface)
{
	struct net_device *dev;
	struct hostap_interface *iface;
	struct hostap_usb_priv *hw_priv;

	dev = usb_get_intfdata(interface);
	if (dev != NULL) {
		iface = netdev_priv(dev);
		hw_priv = iface->local->hw_priv;

		hw_priv->present = 0;
		usb_kill_urb(&hw_priv->rx_urb);
		usb_kill_urb(&hw_priv->tx_urb);

		/* Reset the hardware, and ensure interrupts are disabled. */
		prism2_usb_cor_sreset(iface->local);

		prism2_free_local_data(dev);
		/* FIXME: or before free_local_data ? */
		usb_put_dev(hw_priv->usb);

		kfree(hw_priv);
	}

	usb_set_intfdata(interface, NULL);
}

static int prism2_usb_suspend(struct usb_interface *interface, pm_message_t state)
{
	struct net_device *dev = usb_get_intfdata(interface);

	// FIXME: kill some URBs???

	if (netif_running(dev)) {
		netif_stop_queue(dev);
		netif_device_detach(dev);
	}
	prism2_suspend(dev);

	return 0;
}

static int prism2_usb_resume(struct usb_interface *interface)
{
	struct net_device *dev = usb_get_intfdata(interface);

	prism2_hw_config(dev, 0);
	if (netif_running(dev)) {
		netif_device_attach(dev);
		netif_start_queue(dev);
	}

	return 0;
}

static struct usb_driver prism2_usb_driver = {
	.name = "hostap_usb",
	.probe = prism2_usb_probe,
	.disconnect = prism2_usb_disconnect,
	.id_table = prism2_usb_id_table,
	.suspend = prism2_usb_suspend,
	.resume = prism2_usb_resume,
//	.reset_resume = prism2_usb_resume,
};

static int __init prism2usb_init(void)
{
	BUILD_BUG_ON(sizeof(struct hostap_usb_skb_cb) > sizeof(((struct sk_buff*)NULL)->cb));
	return usb_register(&prism2_usb_driver);
};

static void __exit prism2usb_cleanup(void)
{
	usb_deregister(&prism2_usb_driver);
};

module_init(prism2usb_init);
module_exit(prism2usb_cleanup);
