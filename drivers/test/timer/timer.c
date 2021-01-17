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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/platform_device.h>

#define STR(x) _STR(x)
#define _STR(x) #x

#define VERSION_PREFIX Foo
#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define PATCH_VERSION 0
#define VERSION STR(VERSION_PREFIX-MAJOR_VERSION. \
		MINOR_VERSION.PATCH_VERSION)

#define DEVICE_NAME "foo"
#define ENTRY_NAME "timer_test"
#define KTHREAD_NAME "foo-task"
#define INTERVAL_IN_MSEC 10000

struct task_info {
	char *name;
	int id;
	int run;
	int (*func)(void *);
	struct task_struct *task;
};

extern int timer_test;
static DEFINE_PER_CPU(struct task_info *, task_info) = NULL;

static int task_func(void *data)
{
	struct task_info *info = data;

	while (!kthread_should_stop()) {
		if (timer_test)
			printk("%s(): name is %s, "
					"cpu is %d, id is %d, "
					"num_online_cpus is %d\n",
					__func__, current->comm,
					smp_processor_id(), info->id,
					num_online_cpus());
		if ((info->id == num_online_cpus() - 1)
				&& (info->id == num_online_cpus() - 2))
			mdelay(INTERVAL_IN_MSEC);
		else
			msleep(INTERVAL_IN_MSEC);
	}

	return 0;
}

static int foo_proc_show(struct seq_file *m, void *v) {
	seq_printf(m, "%d\n", timer_test);
	return 0;
}

static int foo_proc_open(struct inode *inode, struct  file *file) {
	return single_open(file, foo_proc_show, NULL);
}

static ssize_t foo_proc_write(struct file *filp, const char __user *buf,
			size_t size, loff_t *offset)
{
	int err, val;
	char *temp = kzalloc(size + 1, GFP_KERNEL);
	if (!temp)
		return -ENOMEM;

	if (copy_from_user(temp, buf, size)) {
		kfree(temp);
		return -EFAULT;
	}

	err = kstrtouint(temp, 10, &val);
	if (err) {
		kfree(temp);
		return err;
	}

	timer_test = val;

	kfree(temp);

	return size;
}

static struct file_operations foo_proc_fops = {
	.owner = THIS_MODULE,
	.open = foo_proc_open,
	.read = seq_read,
	.write = foo_proc_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int foo_probe(struct platform_device *pdev)
{
	int cpu, ret;
	struct proc_dir_entry *tt;
	struct task_info *info;

	printk("%s(): %d\n", __func__, __LINE__);

	tt = proc_create(ENTRY_NAME,
			S_IRUSR | S_IRGRP | S_IROTH, NULL,
			&foo_proc_fops);
	if (!tt)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		info = devm_kzalloc(&pdev->dev,
				sizeof(*info), GFP_KERNEL);
		if (!info) {
			ret = -ENOMEM;
			goto alloc_err;
		}

		info->name = KTHREAD_NAME;
		info->id = cpu;
		info->run = 0;
		info->func = task_func;
		info->task = kthread_create(info->func,
			(void *)info, "%s-%d", info->name, cpu);
		if (IS_ERR(info->task)) {
			ret = -ENOMEM;
			goto alloc_err;
		}

		per_cpu(task_info, cpu) = info;
		kthread_bind(info->task, cpu);
		wake_up_process(info->task);
	}

	return 0;

alloc_err:
	remove_proc_entry(ENTRY_NAME, NULL);
	for_each_possible_cpu(cpu) {
		info = per_cpu(task_info, cpu);
		if (info && !IS_ERR(info->task))
			kthread_stop(info->task);
	}

	return ret;
}

static int foo_remove(struct platform_device *pdev)
{
	int cpu;
	struct task_info *info;

	remove_proc_entry(ENTRY_NAME, NULL);
	for_each_possible_cpu(cpu) {
		info = per_cpu(task_info, cpu);
		if (info) {
			if (!IS_ERR(info->task))
				kthread_stop(info->task);
			devm_kfree(&pdev->dev, info);
			per_cpu(task_info, cpu) = NULL;
		}
	}

	return 0;
}

static struct platform_driver foo_drv = {
	.probe	= foo_probe,
	.remove	= foo_remove,
	.driver	= {
		.name = DEVICE_NAME,
	}
};

static int __init foo_init(void)
{
	int ret;
	struct platform_device *pdev;

	pdev = platform_device_register_simple(DEVICE_NAME, -1, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);

	ret = platform_driver_register(&foo_drv);
	if (ret) {
		platform_device_unregister(pdev);
		return ret;
	}

	return 0;
}

static void __exit foo_exit(void)
{
	struct device *dev;

	dev = bus_find_device_by_name(foo_drv.driver.bus, NULL, DEVICE_NAME);
	if (dev)
		platform_device_unregister(to_platform_device(dev));

	platform_driver_unregister(&foo_drv);
}

module_init(foo_init);
module_exit(foo_exit);

MODULE_ALIAS("foo-driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
MODULE_DESCRIPTION("Linux is not Unix");
MODULE_AUTHOR("andrew, mrju.email@gmail.com");
