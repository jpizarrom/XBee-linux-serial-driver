XBee-linux-serial-driver
========================

make

sudo modprobe af_802154
sudo modprobe mac802154
sudo insmod xbee2.ko
sudo izattach /dev/ttyUSB0 -b 9600
sudo iz listphy
