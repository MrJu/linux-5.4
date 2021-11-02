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
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/debug_utils.h>

#define STR(x) _STR(x)
#define _STR(x) #x

#define VERSION_PREFIX queue_buffer
#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define PATCH_VERSION 0

#define VERSION STR(VERSION_PREFIX-MAJOR_VERSION.MINOR_VERSION.PATCH_VERSION)

#define QB_NR_MAX_ENTRIES (1024 * 4)
#define QB_NR_ENTRIES 512

#define QB_PREFIX_MAX 9
#ifdef CONFIG_PRINTK_CALLER
#define PREFIX_MAX 48
#else
#define PREFIX_MAX 32
#endif
#define LOG_LINE_MAX	(1024 - PREFIX_MAX - QB_PREFIX_MAX)

struct queue_entry {
	int index;
	char *addr;
	struct list_head list;
};

struct queue_buffer {
	unsigned long int nr_entries;
	unsigned long int flags;
	ssize_t limit;
	struct queue_entry *entries;
	unsigned long int *map;
	char *area;
	struct list_head head;
};

struct qb_key_op {
	void (*handler)(int);
	char *help_msg;
	char *action_msg;
};

static DEFINE_SPINLOCK(slock);
static struct queue_buffer *queue = NULL;

static void set_queue_buffer(struct queue_buffer *qbuf)
{
	queue = qbuf;
}

static struct queue_buffer *get_queue_buffer(void)
{
	return queue;
}

struct queue_buffer *alloc_queue_buffer(unsigned long nr_entries,
					ssize_t limit)
{
	struct queue_buffer *qbuf;
	unsigned long int flags;
	void *entries, *area = NULL;
	ssize_t size;
	int err;

	if (WARN(nr_entries > QB_NR_MAX_ENTRIES,
			"%s: nr_entries:%lu QB_NR_MAX_ENTRIES:%lu\n",
			__func__, nr_entries, QB_NR_MAX_ENTRIES)) {
		pr_warn("%s: reset nr_entries to QB_NR_MAX_ENTRIES:%lu\n",
				__func__,
				(unsigned long) QB_NR_MAX_ENTRIES);
		nr_entries = QB_NR_MAX_ENTRIES;
	}

	if (WARN(limit > LOG_LINE_MAX, "%s: limit:%ld LOG_LINE_MAX:%lu\n",
				__func__, limit,
				(unsigned long) LOG_LINE_MAX)) {
		pr_warn("%s: reset limit to LOG_LINE_MAX:%lu\n",
				__func__, (unsigned long) LOG_LINE_MAX);
		limit = LOG_LINE_MAX;
	}

	size = sizeof(struct queue_entry) * nr_entries;
	entries = vmalloc(size);
	if (!entries) {
		err = -ENOMEM;
		goto err0;
	}

	if (limit) {
		size = limit * nr_entries;
		area = vmalloc(size);
		if (!area) {
			err = -ENOMEM;
			goto err1;
		}
	}

	spin_lock_irqsave(&slock, flags);
	qbuf = kzalloc(sizeof(*qbuf), GFP_NOWAIT);
	if (!qbuf) {
		err = -ENOMEM;
		goto err2;
	}

	size = BITS_TO_LONGS(nr_entries) * sizeof(long);
	qbuf->map = kzalloc(size, GFP_NOWAIT);
	if (!qbuf->map) {
		err = -ENOMEM;
		goto err3;
	}

	qbuf->nr_entries = nr_entries;
	qbuf->flags = 0;
	qbuf->limit = limit;
	INIT_LIST_HEAD(&qbuf->head);
	qbuf->entries = entries;
	qbuf->area = area;
	set_queue_buffer(qbuf);
	spin_unlock_irqrestore(&slock, flags);

	return qbuf;

err3:
	kfree(qbuf);

err2:
	spin_unlock_irqrestore(&slock, flags);
	vfree(area);

err1:
	vfree(entries);

err0:
	return ERR_PTR(err);
}

void free_queue_buffer(void)
{
	struct queue_buffer *qbuf = get_queue_buffer();
	unsigned long int flags;

	spin_lock_irqsave(&slock, flags);
	if (!qbuf)
		return;

	kfree(qbuf->map);
	vfree(qbuf->entries);
	if (qbuf->area)
		vfree(qbuf->area);

	kfree(qbuf);
	spin_unlock_irqrestore(&slock, flags);
}

ssize_t print_queue(const char *fmt, ...)
{
	struct queue_buffer *qbuf = get_queue_buffer();
	struct queue_entry *entry;
	va_list args;
	char *addr = NULL;
	ssize_t size0, size1, exceed = 0;
	unsigned long int index, flags;

	va_start(args, fmt);
	size0 = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	size1 = size0;
	if (size0 > LOG_LINE_MAX - 1) {
		WARN_ONCE(1, "%s: %d size0:%ld LOG_LINE_MAX:%ld\n",
				__func__, __LINE__, size0,
				(unsigned long) LOG_LINE_MAX);
		exceed = LOG_LINE_MAX - size0 - 1;
		size1 = LOG_LINE_MAX - 1;
	}

	if (!qbuf->limit) {
		addr = kzalloc(size1 + 1, GFP_NOWAIT);
		if (!addr)
			return -ENOMEM;
	} else {
		if (size1 > qbuf->limit - 1) {
			WARN_ONCE(1, "%s: %d size0:%ld limit:%ld\n",
					__func__, __LINE__,
					size0, qbuf->limit);
			exceed = qbuf->limit - size0 - 1;
			size1 = qbuf->limit - 1;
		}
	}

	spin_lock_irqsave(&slock, flags);
	index = find_first_zero_bit(qbuf->map, qbuf->nr_entries);
	if (index == qbuf->nr_entries) {
		list_move_tail(qbuf->head.next, &qbuf->head);
		entry = list_entry(qbuf->head.prev,
				struct queue_entry, list);
		if (!qbuf->limit)
			kfree(entry->addr);
	} else {
		entry = &qbuf->entries[index];
		entry->index = index;
		INIT_LIST_HEAD(&entry->list);
		list_add_tail(&entry->list, &qbuf->head);
		set_bit(entry->index, qbuf->map);
	}

	if (!addr)
		addr = (char *) (qbuf->area + entry->index * qbuf->limit);

	entry->addr = addr;
	size0 = vsnprintf(entry->addr, size1 + 1, fmt, args);
	if (exceed < 0)
		addr[size1] = '\n';
	spin_unlock_irqrestore(&slock, flags);

	return size0;
}
EXPORT_SYMBOL_GPL(print_queue);

unsigned int flush_queue(void)
{
	struct queue_buffer *qbuf = get_queue_buffer();
	struct queue_entry *entry, *next;
	unsigned long int flags;
	unsigned int nr_entries = 0;

	spin_lock_irqsave(&slock, flags);
	list_for_each_entry_safe(entry, next,
			&qbuf->head, list) {
		list_del_init(&entry->list);
		printk("%s", entry->addr);
		if (!qbuf->limit)
			kfree(entry->addr);
		clear_bit(entry->index, qbuf->map);
		nr_entries++;
	}
	spin_unlock_irqrestore(&slock, flags);

	return nr_entries;
}

static void *qb_start(struct seq_file *m, loff_t *pos)
{
	struct queue_buffer *qbuf = PDE_DATA(file_inode(m->file));
	spin_lock_irqsave(&slock, qbuf->flags);
	return seq_list_start(&qbuf->head, *pos);
}

static void *qb_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct queue_buffer *qbuf = PDE_DATA(file_inode(m->file));
	return seq_list_next(p, &qbuf->head, pos);
}

static void qb_stop(struct seq_file *m, void *p)
{
	struct queue_buffer *qbuf = PDE_DATA(file_inode(m->file));
	spin_unlock_irqrestore(&slock, qbuf->flags);
}

static int qb_show(struct seq_file *m, void *p)
{
	struct queue_entry *entry = list_entry(p, struct queue_entry, list);
	seq_printf(m, "%s", entry->addr);
	return 0;
}

static const struct seq_operations qb_seq_ops = {
	.start	= qb_start,
	.next	= qb_next,
	.stop	= qb_stop,
	.show	= qb_show,
};

static int qb_file_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &qb_seq_ops);
}

static void qb_handle_showmem(int key)
{
	show_mem(0, NULL);
}

static struct qb_key_op qb_showmem_op = {
	.handler	= qb_handle_showmem,
	.help_msg	= "show-memory-usage(m)",
	.action_msg	= "Show Memory",
};

static void qb_handle_clear(int key)
{
	struct queue_buffer *qbuf = get_queue_buffer();
	struct queue_entry *entry, *next;
	unsigned long int flags;

	spin_lock_irqsave(&slock, flags);
	list_for_each_entry_safe(entry, next,
			&qbuf->head, list) {
		list_del_init(&entry->list);
		if (!qbuf->limit)
			kfree(entry->addr);
		clear_bit(entry->index, qbuf->map);
	}
	spin_unlock_irqrestore(&slock, flags);
}

static struct qb_key_op qb_clear_op = {
	.handler	= qb_handle_clear,
	.help_msg	= "clear-queue-buffer(c)",
	.action_msg	= "Clear Queue Buffer",
};

static struct qb_key_op *qb_key_table[36] = {
	NULL,			/* 0 */
	NULL,			/* 1 */
	NULL,			/* 2 */
	NULL,			/* 3 */
	NULL,			/* 4 */
	NULL,			/* 5 */
	NULL,			/* 6 */
	NULL,			/* 7 */
	NULL,			/* 8 */
	NULL,			/* 9 */
	NULL,			/* a */
	NULL,			/* b */
	&qb_clear_op,		/* c */
	NULL,			/* d */
	NULL,			/* e */
	NULL,			/* f */
	NULL,			/* g */
	NULL,			/* h - reerved for help */
	NULL,			/* i */
	NULL,			/* j */
	NULL,			/* k */
	NULL,			/* l */
	&qb_showmem_op,		/* m */
	NULL,			/* n */
	NULL,			/* o */
	NULL,			/* p */
	NULL,			/* q */
	NULL,			/* r */
	NULL,			/* s */
	NULL,			/* t */
	NULL,			/* u */
	NULL,			/* v */
	NULL,			/* w */
	NULL,			/* x */
	NULL,			/* y */
	NULL,			/* z */
};

static int qb_key2index(int key)
{
	int ret;

	if ((key >= '0') && (key <= '9'))
		ret = key - '0';
	else if ((key >= 'a') && (key <= 'z'))
		ret = key + 10 - 'a';
	else
		ret = -1;

	return ret;
}

struct qb_key_op *qb_get_key_op(int key)
{
	struct qb_key_op *op_p = NULL;
	int i;

	i = qb_key2index(key);
	if (i != -1)
		op_p = qb_key_table[i];

	return op_p;
}

static void handle_params(int key, bool check_mask)
{
	struct qb_key_op *op_p;
	int i;

	rcu_read_lock();
	op_p = qb_get_key_op(key);
	if (op_p) {
		pr_info("%s\n", op_p->action_msg);
		op_p->handler(key);
	} else {
		pr_info("HELP : ");
		for (i = 0; i < ARRAY_SIZE(qb_key_table); i++)
			if (qb_key_table[i])
				pr_cont("%s ", qb_key_table[i]->help_msg);
		pr_cont("\n");
	}
	rcu_read_unlock();
}
 static ssize_t qb_proc_write(struct file *file, const char __user *buf,
		 		size_t count, loff_t *ppos)
{
	char c;

	if (count) {
		if (get_user(c, buf))
			return -EFAULT;
		handle_params(c, false);
	}

	return count;
}

static struct file_operations qb_file_ops = {
	.owner		= THIS_MODULE,
	.open		= qb_file_open,
	.read		= seq_read,
	.write		= qb_proc_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init queue_buffer_init(void)
{
	struct queue_buffer *qbuf;
	struct proc_dir_entry *entry;
	int ret;

	qbuf = alloc_queue_buffer(QB_NR_ENTRIES, 0 /* LOG_LINE_MAX */);
	if (IS_ERR(qbuf))
		return PTR_ERR(qbuf);

	entry = proc_create_data("queuebuffer",
			S_IRUSR | S_IRGRP | S_IROTH,
			NULL, &qb_file_ops, qbuf);
	if (!entry) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;

err:
	free_queue_buffer();
	return ret;
}

static void __exit queue_buffer_exit(vold)
{
	remove_proc_entry("queuebuffer", NULL);
	free_queue_buffer();
}

core_initcall(queue_buffer_init);
__exitcall(queue_buffer_exit);

MODULE_ALIAS("queue-buffer-driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
MODULE_DESCRIPTION("Linux is not Unix");
MODULE_AUTHOR("andrew, mrju.email@gmail.com");
