/*
 * Copyright (C) 2019 Andrew <mrju.email@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 */

#include <linux/err.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#define STR(x) _STR(x)
#define _STR(x) #x

#define VERSION_PREFIX virt-foo
#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define PATCH_VERSION 0

#define VERSION STR(VERSION_PREFIX-MAJOR_VERSION.MINOR_VERSION.PATCH_VERSION)

/*
 * Register layout
 * ------------------------------------------------------------------------------
 * | Register    | Address                  | RW | Description                  |
 * ------------------------------------------------------------------------------
 * | ID          | 0x0b00 0000(offset = 0)  | RO | Chip ID. Default is 0xf001   |
 * ------------------------------------------------------------------------------
 * | INIT        | 0x0b00 0004(offset = 4)  | RW | bit0: chip enable            |
 * ------------------------------------------------------------------------------
 * | COMMAND     | 0x0b00 0008(offset = 8)  | RW | Command buffer data          |
 * ------------------------------------------------------------------------------
 * | INT STATUS  | 0x0b00 000c(offset = 0xc)| RO | bit0: device is enabled      |
 * |             |                          |    | bit1: cmd buffer is enqueued |
 * ------------------------------------------------------------------------------
 */

#define REG_ID		0x0
#define REG_INIT	0x4
#define HW_ENABLE	1
#define HW_DISABLE	0
#define REG_CMD		0x8
#define REG_INT_STATUS	0xc
#define IRQ_ENABLED	BIT(0)
#define IRQ_BUF_ENQ	BIT(1)

#define DEVICE_NAME "virt_foo"
#define ENTRY_NAME "virt_foo"

struct virt_foo {
	struct device *dev;
	void __iomem *base;
};

static int foo_proc_show(struct seq_file *m, void *v)
{
	struct virt_foo *foo = PDE_DATA(file_inode(m->file));
	u32 id, val;

	id = readl_relaxed(foo->base + REG_ID);
	val = readl_relaxed(foo->base + REG_CMD);

	seq_printf(m, "id:0x%x cmd:0x%x\n", id, val);

	return 0;
}

static ssize_t foo_proc_write(struct file *filp, const char __user *buf,
			size_t size, loff_t *offset)
{
	struct virt_foo *foo = PDE_DATA(file_inode(filp));
	unsigned long val;
	int err;
	char *temp;

	temp = kzalloc(size, GFP_KERNEL);
	if (!temp)
		return -ENOMEM;

	if (copy_from_user(temp, buf, size)) {
		kfree(temp);
		return -EFAULT;
	}

	err = kstrtoul(temp, 10, &val);
	if (err)
		return err;

	writel_relaxed(val, foo->base + REG_CMD);

	kfree(temp);

	return size;
}

static int foo_proc_open(struct inode *inode, struct  file *file) {
	return single_open(file, foo_proc_show, NULL);
}

static struct file_operations foo_proc_fops = {
	.owner = THIS_MODULE,
	.open = foo_proc_open,
	.read = seq_read,
	.write = foo_proc_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static irqreturn_t foo_irq_handler(int irq, void *data)
{
	struct virt_foo *foo = data;
	u32 status;

	status = readl_relaxed(foo->base + REG_INT_STATUS);
	if (status & IRQ_BUF_ENQ)
		dev_info(foo->dev, "IRQ_BUF_ENQ\n");

	pr_info("%s(): %d irqs_disabled:0x%x\n",
			__func__, __LINE__, irqs_disabled());

	return IRQ_HANDLED;
}

static int foo_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	struct virt_foo *foo;
	struct proc_dir_entry *entry;
	int ret;

	foo = devm_kzalloc(dev, sizeof(*foo), GFP_KERNEL);
	if (!foo)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	foo->base = devm_ioremap(dev, res->start, resource_size(res));
	if (!foo->base)
		return -EINVAL;

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!res)
		return -ENODEV;

	ret = devm_request_irq(dev, res->start, foo_irq_handler,
				IRQF_TRIGGER_HIGH, "virt-foo", foo);
        if (ret)
            return ret;

	writel_relaxed(HW_ENABLE, foo->base + REG_INIT);

	entry = proc_create_data(ENTRY_NAME,
			S_IRUSR | S_IRGRP | S_IROTH,
			NULL, &foo_proc_fops, foo);
	if (!entry)
		return -ENOMEM;

	foo->dev = dev;
	platform_set_drvdata(pdev, foo);

	return 0;
}

static int foo_remove(struct platform_device *pdev)
{
	struct virt_foo *foo;

	foo = platform_get_drvdata(pdev);
	remove_proc_entry(ENTRY_NAME, NULL);
	writel_relaxed(HW_DISABLE, foo->base + REG_INIT);

	return 0;
}

static const struct of_device_id foo_of_match[] = {
	{
		.compatible = "artech,virt-foo",
	},
	{
		/* NULL */
	},
};
MODULE_DEVICE_TABLE(of, foo_of_match);

static struct platform_driver foo_driver = {
	.probe = foo_probe,
	.remove = foo_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = DEVICE_NAME,
		.of_match_table = foo_of_match,
	},
};

module_platform_driver(foo_driver);

MODULE_ALIAS("virt-foo-driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
MODULE_DESCRIPTION("Linux is not Unix");
MODULE_AUTHOR("andrew, mrju.email@gmail.com");
