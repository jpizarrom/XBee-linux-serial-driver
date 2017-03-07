TARGET ?= xbee802154
TARGET_KO := $(TARGET).ko
obj-m := $(TARGET).o

ifeq (,$(KERNELRELEASE))
KVERS_UNAME ?= $(shell uname -r)
else
KVERS_UNAME ?= $(KERNELRELEASE)
endif

XBEE802154DIR := kernel/drivers/net/ieee802154
KBUILD ?= $(shell readlink -f /lib/modules/$(KVERS_UNAME)/build)

ifeq (,$(KBUILD))
$(error Kernel build tree not found - please set KBUILD to configured kernel)
endif

ifneq (,$(DEBUG))
EXTRA_CFLAGS += -DDEBUG
endif

EXTRA_CFLAGS += -Wformat=2 -Wall

ifneq ($(MODTEST_ENABLE),)
EXTRA_CFLAGS += -DMODTEST_ENABLE=$(MODTEST_ENABLE)
endif

all: modules

modules:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

install:
	$(MAKE) -C $(KBUILD) M=$(PWD) INSTALL_MOD_DIR=$(XBEE802154DIR) install


