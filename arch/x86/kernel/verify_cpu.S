/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 *	verify_cpu.S - Code for cpu long mode and SSE verification. This
 *	code has been borrowed from boot/setup.S and was introduced by
 * 	Andi Kleen.
 *
 *	Copyright (c) 2007  Andi Kleen (ak@suse.de)
 *	Copyright (c) 2007  Eric Biederman (ebiederm@xmission.com)
 *	Copyright (c) 2007  Vivek Goyal (vgoyal@in.ibm.com)
 *	Copyright (c) 2010  Kees Cook (kees.cook@canonical.com)
 *
 *	This is a common code for verification whether CPU supports
 * 	long mode and SSE or not. It is not called directly instead this
 *	file is included at various places and compiled in that context.
 *	This file is expected to run in 32bit code.  Currently:
 *
 *	arch/x86/boot/compressed/head_64.S: Boot cpu verification
 *	arch/x86/kernel/trampoline_64.S: secondary processor verification
 *	arch/x86/kernel/head_32.S: processor startup
 *
 *	verify_cpu, returns the status of longmode and SSE in register %eax.
 *		0: Success    1: Failure
 *
 *	On Intel, the XD_DISABLE flag will be cleared as a side-effect.
 *
 * 	The caller needs to check for the error code and take the action
 * 	appropriately. Either display a message or halt.
 */

#include <asm/cpufeatures.h>
#include <asm/cpufeaturemasks.h>
#include <asm/msr-index.h>

#define SSE_MASK	\
	(REQUIRED_MASK0 & ((1<<(X86_FEATURE_XMM & 31)) | (1<<(X86_FEATURE_XMM2 & 31))))

SYM_FUNC_START_LOCAL(verify_cpu)
	pushf				# Save caller passed flags
	push	$0			# Kill any dangerous flags
	popf

#ifndef __x86_64__
	pushfl				# standard way to check for cpuid
	popl	%eax
	movl	%eax,%ebx
	xorl	$0x200000,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	cmpl	%eax,%ebx
	jz	.Lverify_cpu_no_longmode	# cpu has no cpuid
#endif

	movl	$0x0,%eax		# See if cpuid 1 is implemented
	cpuid
	cmpl	$0x1,%eax
	jb	.Lverify_cpu_no_longmode	# no cpuid 1

	xor	%di,%di
	cmpl	$0x68747541,%ebx	# AuthenticAMD
	jnz	.Lverify_cpu_noamd
	cmpl	$0x69746e65,%edx
	jnz	.Lverify_cpu_noamd
	cmpl	$0x444d4163,%ecx
	jnz	.Lverify_cpu_noamd
	mov	$1,%di			# cpu is from AMD
	jmp	.Lverify_cpu_check

.Lverify_cpu_noamd:
	cmpl	$0x756e6547,%ebx        # GenuineIntel?
	jnz	.Lverify_cpu_check
	cmpl	$0x49656e69,%edx
	jnz	.Lverify_cpu_check
	cmpl	$0x6c65746e,%ecx
	jnz	.Lverify_cpu_check

	# only call IA32_MISC_ENABLE when:
	# family > 6 || (family == 6 && model >= 0xd)
	movl	$0x1, %eax		# check CPU family and model
	cpuid
	movl	%eax, %ecx

	andl	$0x0ff00f00, %eax	# mask family and extended family
	shrl	$8, %eax
	cmpl	$6, %eax
	ja	.Lverify_cpu_clear_xd	# family > 6, ok
	jb	.Lverify_cpu_check	# family < 6, skip

	andl	$0x000f00f0, %ecx	# mask model and extended model
	shrl	$4, %ecx
	cmpl	$0xd, %ecx
	jb	.Lverify_cpu_check	# family == 6, model < 0xd, skip

.Lverify_cpu_clear_xd:
	movl	$MSR_IA32_MISC_ENABLE, %ecx
	rdmsr
	btrl	$2, %edx		# clear MSR_IA32_MISC_ENABLE_XD_DISABLE
	jnc	.Lverify_cpu_check	# only write MSR if bit was changed
	wrmsr

.Lverify_cpu_check:
	movl    $0x1,%eax		# Does the cpu have what it takes
	cpuid
	andl	$REQUIRED_MASK0,%edx
	xorl	$REQUIRED_MASK0,%edx
	jnz	.Lverify_cpu_no_longmode

	movl    $0x80000000,%eax	# See if extended cpuid is implemented
	cpuid
	cmpl    $0x80000001,%eax
	jb      .Lverify_cpu_no_longmode	# no extended cpuid

	movl    $0x80000001,%eax	# Does the cpu have what it takes
	cpuid
	andl    $REQUIRED_MASK1,%edx
	xorl    $REQUIRED_MASK1,%edx
	jnz     .Lverify_cpu_no_longmode

.Lverify_cpu_sse_test:
	movl	$1,%eax
	cpuid
	andl	$SSE_MASK,%edx
	cmpl	$SSE_MASK,%edx
	je	.Lverify_cpu_sse_ok
	test	%di,%di
	jz	.Lverify_cpu_no_longmode	# only try to force SSE on AMD
	movl	$MSR_K7_HWCR,%ecx
	rdmsr
	btr	$15,%eax		# enable SSE
	wrmsr
	xor	%di,%di			# don't loop
	jmp	.Lverify_cpu_sse_test	# try again

.Lverify_cpu_no_longmode:
	popf				# Restore caller passed flags
	movl $1,%eax
	RET
.Lverify_cpu_sse_ok:
	popf				# Restore caller passed flags
	xorl %eax, %eax
	RET
SYM_FUNC_END(verify_cpu)
