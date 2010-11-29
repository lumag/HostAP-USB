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
};

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

/* FIXME */
static int hfa384x_get_rid(struct net_device *dev, u16 rid, void *buf, int len,
			   int exact_len) {return -ENOTTY;}
static int hfa384x_set_rid(struct net_device *dev, u16 rid, void *buf, int len) {return -ENOTTY;}
static int hfa384x_cmd_issue(struct net_device *dev,
				    struct hostap_cmd_queue *entry)
{
	return -EINVAL;
}
static int prism2_tx_80211(struct sk_buff *skb, struct net_device *dev)
{
	return -1;
}

static int prism2_hw_init(struct net_device *dev, int initial)
{
	struct hostap_interface *iface;
	local_info_t *local;
	int ret;

	PDEBUG(DEBUG_FLOW, "prism2_hw_init()\n");

	iface = netdev_priv(dev);
	local = iface->local;

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
	local->no_pri = 0;
	return 0;
}

/* FIX: This might change at some point.. */
#include "hostap_hw.c"

static struct prism2_helper_functions prism2_usb_funcs =
{
//	.card_present	= prism2_usb_card_present,
//	.cor_sreset	= prism2_usb_cor_sreset,
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

	dev = prism2_init_local_data(&prism2_usb_funcs, cards_found,
				     &dev->dev);
	if (dev == NULL)
		goto fail;
	iface = netdev_priv(dev);
	local = iface->local;
	local->hw_priv = hw_priv;
	cards_found++;

//	prism2_usb_cor_sreset(local);

	hw_priv->usb = usb_get_dev(usb);

	usb_set_intfdata(interface, dev);

	if (!local->pri_only && prism2_hw_config(dev, 1)) {
		printk(KERN_DEBUG "%s: hardware initialization failed\n",
		       dev_info);
		goto fail;
	}

	printk(KERN_INFO "%s: Intersil Prism2/2.5/3 USB", dev->name);

	return hostap_hw_ready(dev);

 fail:
	prism2_free_local_data(dev);

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

		/* Reset the hardware, and ensure interrupts are disabled. */
//		prism2_usb_cor_sreset(iface->local);
//		hfa384x_disable_interrupts(dev);

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
	return usb_register(&prism2_usb_driver);
};

static void __exit prism2usb_cleanup(void)
{
	usb_deregister(&prism2_usb_driver);
};

module_init(prism2usb_init);
module_exit(prism2usb_cleanup);
