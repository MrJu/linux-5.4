/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_DEBUG_UTILS__
#define __LINUX_DEBUG_UTILS__

#ifdef CONFIG_DEBUG_UTILS
extern ssize_t print_queue(const char *fmt, ...);
extern unsigned int flush_queue(void);
#else
ssize_t print_queue(const char *fmt, ...) { return 0; }
unsigned int flush_queue(void) { return 0; }
#endif

#endif

