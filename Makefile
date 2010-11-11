hostap-y := hostap_80211_rx.o hostap_80211_tx.o hostap_ap.o hostap_info.o \
            hostap_ioctl.o hostap_main.o hostap_proc.o 
obj-m += hostap.o

obj-m += hostap_usb.o
obj-m += hostap_cs.o
obj-m += hostap_plx.o
obj-m += hostap_pci.o

cflags-y += -DCONFIG_HOSTAP_FIRMWARE -DCONFIG_HOSTAP_FIRMWARE_NVRAM

KSRC ?= /lib/modules/$(shell uname -r)/build

modules modules_install clean:
	make -C $(KSRC) M=$(PWD) $@
