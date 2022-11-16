// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Simple synchronous userspace interface to SPI devices
 *
 * Copyright (C) 2006 SWAPP
 *	Andrea Paterniani <a.paterniani@swapp-eng.it>
 * Copyright (C) 2007 David Brownell (simplification, cleanup)
 */

#include <linux/acpi.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
//#include <linux/spi/spircp.h>

#include <linux/uaccess.h>

/*
 * This supports access to SPI devices using normal userspace I/O calls.
 * Note that while traditional UNIX/POSIX I/O semantics are half duplex,
 * and often mask message boundaries, full SPI support requires full duplex
 * transfers.  There are several kinds of internal message boundaries to
 * handle chipselect management and other protocol options.
 *
 * SPI has a character major number assigned.  We allocate minor numbers
 * dynamically using a bitmask.  You must use hotplug tools, such as udev
 * (or mdev with busybox) to create and destroy the /dev/spircpB.C device
 * nodes, since there is no fixed association of minor numbers with any
 * particular SPI bus or device.
 */
#define SPIDEV_MAJOR 153 /* assigned */
#define N_SPI_MINORS 32	 /* ... up to 256 */

/* Bit masks for spi_device.mode management.  Note that incorrect
 * settings for some settings can cause *lots* of trouble for other
 * devices on a shared bus:
 *
 *  - CS_HIGH ... this device will be active when it shouldn't be
 *  - 3WIRE ... when active, it won't behave as it should
 *  - NO_CS ... there will be no explicit message boundaries; this
 *	is completely incompatible with the shared bus model
 *  - READY ... transfers may proceed when they shouldn't.
 *
 * REVISIT should changing those flags be privileged?
 */
struct spircp_data {
	dev_t devt;
	spinlock_t spi_lock;
	struct spi_device *spi;
	struct list_head device_entry;

	/* TX/RX buffers are NULL unless this device is open (users > 0) */
	struct mutex buf_lock;
	unsigned users;
	u8 *tx_buffer;
	u8 *rx_buffer;
	u32 speed_hz;
};

/*-------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------*/

/* The main reason to have this class is to make mdev/udev create the
 * /dev/spircpB.C character device nodes exposing our userspace API.
 * It also simplifies memory management.
 */

static struct class *spircp_class;

#ifdef CONFIG_OF
static const struct of_device_id spircp_dt_ids[] = {
	{.compatible = "openthread,spircp"},
	{},
};
MODULE_DEVICE_TABLE(of, spircp_dt_ids);
#endif

#ifdef CONFIG_ACPI

/* Dummy SPI devices not to be used in production systems */
#define SPIDEV_ACPI_DUMMY 1

static const struct acpi_device_id spircp_acpi_ids[] = {
	/*
	 * The ACPI SPT000* devices are only meant for development and
	 * testing. Systems used in production should have a proper ACPI
	 * description of the connected peripheral and they should also use
	 * a proper driver instead of poking directly to the SPI bus.
	 */
	{"SPT0001", SPIDEV_ACPI_DUMMY},
	{"SPT0002", SPIDEV_ACPI_DUMMY},
	{"SPT0003", SPIDEV_ACPI_DUMMY},
	{},
};
MODULE_DEVICE_TABLE(acpi, spircp_acpi_ids);

static void spircp_probe_acpi(struct spi_device *spi)
{
	const struct acpi_device_id *id;

	if (!has_acpi_companion(&spi->dev))
		return;

	id = acpi_match_device(spircp_acpi_ids, &spi->dev);
	if (WARN_ON(!id))
		return;

	if (id->driver_data == SPIDEV_ACPI_DUMMY)
		dev_warn(&spi->dev, "do not use this driver in production systems!\n");
}
#else
static inline void spircp_probe_acpi(struct spi_device *spi)
{
}
#endif

/*-------------------------------------------------------------------------*/

static int spircp_probe(struct spi_device *spi)
{
	struct spircp_data *spircp;
	int status;

	/*
	 * spircp should never be referenced in DT without a specific
	 * compatible string, it is a Linux implementation thing
	 * rather than a description of the hardware.
	 */
	WARN(spi->dev.of_node && of_device_is_compatible(spi->dev.of_node, "spircp"),
	     "%pOF: buggy DT: spircp listed directly in DT\n", spi->dev.of_node);

	spircp_probe_acpi(spi);

	/* Allocate driver data */
	spircp = kzalloc(sizeof(*spircp), GFP_KERNEL);
	if (!spircp)
		return -ENOMEM;

	/* Initialize the driver data */
	spircp->spi = spi;
	spin_lock_init(&spircp->spi_lock);
	mutex_init(&spircp->buf_lock);

	INIT_LIST_HEAD(&spircp->device_entry);

	spircp->speed_hz = spi->max_speed_hz;

	if (status == 0)
		spi_set_drvdata(spi, spircp);
	else
		kfree(spircp);

	return status;
}

static int spircp_remove(struct spi_device *spi)
{
	return 0;
}

static struct spi_driver spircp_spi_driver = {
	.driver =
		{
			.name = "spircp",
			.of_match_table = of_match_ptr(spircp_dt_ids),
			.acpi_match_table = ACPI_PTR(spircp_acpi_ids),
		},
	.probe = spircp_probe,
	.remove = spircp_remove,

	/* NOTE:  suspend/resume methods are not necessary here.
	 * We don't do anything except pass the requests to/from
	 * the underlying controller.  The refrigerator handles
	 * most issues; the controller driver handles the rest.
	 */
};

/*-------------------------------------------------------------------------*/

static int __init spircp_init(void)
{
	int status;

	spircp_class = class_create(THIS_MODULE, "spircp");
	if (IS_ERR(spircp_class)) {
		return PTR_ERR(spircp_class);
	}

	status = spi_register_driver(&spircp_spi_driver);
	if (status < 0) {
		class_destroy(spircp_class);
	}
	return status;
}
module_init(spircp_init);

static void __exit spircp_exit(void)
{
	spi_unregister_driver(&spircp_spi_driver);
	class_destroy(spircp_class);
}
module_exit(spircp_exit);

MODULE_AUTHOR("Andrea Paterniani, <a.paterniani@swapp-eng.it>");
MODULE_DESCRIPTION("User mode SPI device interface");
MODULE_LICENSE("GPL");
MODULE_ALIAS("spi:spircp");
