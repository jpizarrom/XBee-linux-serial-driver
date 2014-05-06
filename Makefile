#obj-m += hello-1.o
#obj-m := nothing.o
#obj-m := serial.o fakehard.o 
#obj-m := xbee.o
obj-m := xbee2.o
#obj-m := fakehard.o

CFLAGS_serial.o := -DDEBUG
CFLAGS_xbee2.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


