Digi XBee 802.15.4 device driver(under development)
========================

make

sudo modprobe af_802154

sudo modprobe mac802154

sudo insmod xbee2.ko

sudo izattach /dev/ttyUSB0 -b 9600

sudo iz listphy
