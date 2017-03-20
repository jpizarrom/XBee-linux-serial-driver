Digi XBee 802.15.4 device driver
========================

Build
-----
Just execute make.

```
make
```

Module setup
-------

Call modprobe by dependency order.
Finally, call `ldattach` to attach a tty to XBee device.

```
sudo modprobe ieee802154
sudo modprobe ieee802154_socket
sudo modprobe ieee802154_6lowpan
sudo modprobe mac802154
sudo insmod xbee802154.ko
sudo ldattach -s 9600 -8 -n -1 25 /dev/ttyUSB0
```

WPAN,LoWPAN setup
------
Use `ip` command to configure network interface.

```
sudo ip link set wpan0 up
sudo ip link add link wpan0 name lowpan0 type lowpan
sudo ip link set lowpan0 up
```
