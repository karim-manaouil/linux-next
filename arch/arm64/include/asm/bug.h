/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015  ARM Limited
 * Author: Dave Martin <Dave.Martin@arm.com>
 */

#ifndef _ARCH_ARM64_ASM_BUG_H
#define _ARCH_ARM64_ASM_BUG_H

#include <linux/stringify.h>

#include <asm/asm-bug.h>

#ifdef HAVE_BUG_FUNCTION
# define __BUG_FUNC	__func__
#else
# define __BUG_FUNC	NULL
#endif

#define __BUG_FLAGS(flags)				\
	asm volatile (__stringify(ASM_BUG_FLAGS(flags, %c0)) : : "i" (__BUG_FUNC));

#define BUG() do {					\
	__BUG_FLAGS(0);					\
	unreachable();					\
} while (0)

#define __WARN_FLAGS(flags) __BUG_FLAGS(BUGFLAG_WARNING|(flags))

#define HAVE_ARCH_BUG

#include <asm-generic/bug.h>

#endif /* ! _ARCH_ARM64_ASM_BUG_H */
