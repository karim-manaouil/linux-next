// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM port to Qualcomm's Gunyah Hypervisor
 *
 * Copyright (C) 2024-2025 Linaro Ltd.
 *
 * Author: Karim Manaouil <karim.manaouil@linaro.org>
 *
 */
#include <linux/cpumask.h>
#include <linux/kvm_host.h>
#include <linux/kvm_irqfd.h>
#include <asm/kvm_mmu.h>
#include <linux/perf_event.h>

#include <linux/gunyah_rsc_mgr.h>
#include <linux/gunyah.h>

#undef pr_fmt
#define pr_fmt(fmt) "gunyah: " fmt

static enum kvm_mode kvm_mode = KVM_MODE_DEFAULT;

enum kvm_mode kvm_get_mode(void)
{
	return kvm_mode;
}

const struct _kvm_stats_desc kvm_vm_stats_desc[] = {
	KVM_GENERIC_VM_STATS()
};

const struct kvm_stats_header kvm_vm_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vm_stats_desc),
	.id_offset =  sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vm_stats_desc),
};

const struct _kvm_stats_desc kvm_vcpu_stats_desc[] = {
	KVM_GENERIC_VCPU_STATS(),
	STATS_DESC_COUNTER(VCPU, hvc_exit_stat),
	STATS_DESC_COUNTER(VCPU, wfe_exit_stat),
	STATS_DESC_COUNTER(VCPU, wfi_exit_stat),
	STATS_DESC_COUNTER(VCPU, mmio_exit_user),
	STATS_DESC_COUNTER(VCPU, mmio_exit_kernel),
	STATS_DESC_COUNTER(VCPU, signal_exits),
	STATS_DESC_COUNTER(VCPU, exits)
};

const struct kvm_stats_header kvm_vcpu_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vcpu_stats_desc),
	.id_offset = sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vcpu_stats_desc),
};

static bool core_reg_offset_is_vreg(u64 off)
{
	return off >= KVM_REG_ARM_CORE_REG(fp_regs.vregs) &&
		off < KVM_REG_ARM_CORE_REG(fp_regs.fpsr);
}

static u64 core_reg_offset_from_id(u64 id)
{
	return id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE);
}

static int core_reg_size_from_offset(const struct kvm_vcpu *vcpu, u64 off)
{
	int size;

	switch (off) {
	case KVM_REG_ARM_CORE_REG(regs.regs[0]) ...
	     KVM_REG_ARM_CORE_REG(regs.regs[30]):
	case KVM_REG_ARM_CORE_REG(regs.sp):
	case KVM_REG_ARM_CORE_REG(regs.pc):
	case KVM_REG_ARM_CORE_REG(regs.pstate):
	case KVM_REG_ARM_CORE_REG(sp_el1):
	case KVM_REG_ARM_CORE_REG(elr_el1):
	case KVM_REG_ARM_CORE_REG(spsr[0]) ...
	     KVM_REG_ARM_CORE_REG(spsr[KVM_NR_SPSR - 1]):
		size = sizeof(__u64);
		break;

	case KVM_REG_ARM_CORE_REG(fp_regs.vregs[0]) ...
	     KVM_REG_ARM_CORE_REG(fp_regs.vregs[31]):
		size = sizeof(__uint128_t);
		break;

	case KVM_REG_ARM_CORE_REG(fp_regs.fpsr):
	case KVM_REG_ARM_CORE_REG(fp_regs.fpcr):
		size = sizeof(__u32);
		break;

	default:
		return -EINVAL;
	}

	if (!IS_ALIGNED(off, size / sizeof(__u32)))
		return -EINVAL;

	/*
	 * The KVM_REG_ARM64_SVE regs must be used instead of
	 * KVM_REG_ARM_CORE for accessing the FPSIMD V-registers on
	 * SVE-enabled vcpus:
	 */
	if (vcpu_has_sve(vcpu) && core_reg_offset_is_vreg(off))
		return -EINVAL;

	return size;
}

static void *core_reg_addr(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	u64 off = core_reg_offset_from_id(reg->id);
	int size = core_reg_size_from_offset(vcpu, off);

	if (size < 0)
		return NULL;

	if (KVM_REG_SIZE(reg->id) != size)
		return NULL;

	switch (off) {
	case KVM_REG_ARM_CORE_REG(regs.regs[0]) ...
	     KVM_REG_ARM_CORE_REG(regs.regs[30]):
		off -= KVM_REG_ARM_CORE_REG(regs.regs[0]);
		off /= 2;
		return &vcpu->arch.ctxt.regs.regs[off];

	case KVM_REG_ARM_CORE_REG(regs.sp):
		return &vcpu->arch.ctxt.regs.sp;

	case KVM_REG_ARM_CORE_REG(regs.pc):
		return &vcpu->arch.ctxt.regs.pc;

	case KVM_REG_ARM_CORE_REG(regs.pstate):
		return &vcpu->arch.ctxt.regs.pstate;

	case KVM_REG_ARM_CORE_REG(sp_el1):
		return __ctxt_sys_reg(&vcpu->arch.ctxt, SP_EL1);

	case KVM_REG_ARM_CORE_REG(elr_el1):
		return __ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1);

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_EL1]):
		return __ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1);

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_ABT]):
		return &vcpu->arch.ctxt.spsr_abt;

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_UND]):
		return &vcpu->arch.ctxt.spsr_und;

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_IRQ]):
		return &vcpu->arch.ctxt.spsr_irq;

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_FIQ]):
		return &vcpu->arch.ctxt.spsr_fiq;

	case KVM_REG_ARM_CORE_REG(fp_regs.vregs[0]) ...
	     KVM_REG_ARM_CORE_REG(fp_regs.vregs[31]):
		off -= KVM_REG_ARM_CORE_REG(fp_regs.vregs[0]);
		off /= 4;
		return &vcpu->arch.ctxt.fp_regs.vregs[off];

	case KVM_REG_ARM_CORE_REG(fp_regs.fpsr):
		return &vcpu->arch.ctxt.fp_regs.fpsr;

	case KVM_REG_ARM_CORE_REG(fp_regs.fpcr):
		return &vcpu->arch.ctxt.fp_regs.fpcr;

	default:
		return NULL;
	}
}

static int get_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/*
	 * Because the kvm_regs structure is a mix of 32, 64 and
	 * 128bit fields, we index it as if it was a 32bit
	 * array. Hence below, nr_regs is the number of entries, and
	 * off the index in the "array".
	 */
	__u32 __user *uaddr = (__u32 __user *)(unsigned long)reg->addr;
	int nr_regs = sizeof(struct kvm_regs) / sizeof(__u32);
	void *addr;
	u32 off;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= nr_regs ||
	    (off + (KVM_REG_SIZE(reg->id) / sizeof(__u32))) >= nr_regs)
		return -ENOENT;

	addr = core_reg_addr(vcpu, reg);
	if (!addr)
		return -EINVAL;

	if (copy_to_user(uaddr, addr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int set_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	__u32 __user *uaddr = (__u32 __user *)(unsigned long)reg->addr;
	int nr_regs = sizeof(struct kvm_regs) / sizeof(__u32);
	__uint128_t tmp;
	void *valp = &tmp, *addr;
	u64 off;
	int err = 0;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= nr_regs ||
	    (off + (KVM_REG_SIZE(reg->id) / sizeof(__u32))) >= nr_regs)
		return -ENOENT;

	addr = core_reg_addr(vcpu, reg);
	if (!addr)
		return -EINVAL;

	if (KVM_REG_SIZE(reg->id) > sizeof(tmp))
		return -EINVAL;

	if (copy_from_user(valp, uaddr, KVM_REG_SIZE(reg->id))) {
		err = -EFAULT;
		goto out;
	}

	memcpy(addr, valp, KVM_REG_SIZE(reg->id));
out:
	return err;
}

static int get_sys_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	__u32 __user *uaddr = (__u32 __user *)(unsigned long)reg->addr;
	u64 dummy_val = 0;

	if (copy_to_user(uaddr, &dummy_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int copy_core_reg_indices(const struct kvm_vcpu *vcpu,
				 u64 __user *uindices)
{
	unsigned int i;
	int n = 0;

	for (i = 0; i < sizeof(struct kvm_regs) / sizeof(__u32); i++) {
		u64 reg = KVM_REG_ARM64 | KVM_REG_ARM_CORE | i;
		int size = core_reg_size_from_offset(vcpu, i);

		if (size < 0)
			continue;

		switch (size) {
		case sizeof(__u32):
			reg |= KVM_REG_SIZE_U32;
			break;

		case sizeof(__u64):
			reg |= KVM_REG_SIZE_U64;
			break;

		case sizeof(__uint128_t):
			reg |= KVM_REG_SIZE_U128;
			break;

		default:
			WARN_ON(1);
			continue;
		}

		if (uindices) {
			if (put_user(reg, uindices))
				return -EFAULT;
			uindices++;
		}

		n++;
	}

	return n;
}

static unsigned long num_core_regs(const struct kvm_vcpu *vcpu)
{
	return copy_core_reg_indices(vcpu, NULL);
}

int kvm_arm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/* We currently use nothing arch-specific in upper 32 bits */
	if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM64 >> 32)
		return -EINVAL;

	switch (reg->id & KVM_REG_ARM_COPROC_MASK) {
	case KVM_REG_ARM_CORE:
		return get_core_reg(vcpu, reg);
	case KVM_REG_ARM64_SYSREG:
		return get_sys_reg(vcpu, reg);
	default:
		return -ENOENT;
	}
}

int kvm_arm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/* We currently use nothing arch-specific in upper 32 bits */
	if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM64 >> 32)
		return -EINVAL;

	switch (reg->id & KVM_REG_ARM_COPROC_MASK) {
	case KVM_REG_ARM_CORE:
		return set_core_reg(vcpu, reg);
	default:
		return -ENOENT;
	}
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

void kvm_arch_create_vm_debugfs(struct kvm *kvm)
{
}

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

bool kvm_arch_irqchip_in_kernel(struct kvm *kvm)
{
	return false;
}

bool kvm_arch_intc_initialized(struct kvm *kvm)
{
	return true;
}

struct kvm_vcpu *kvm_arch_vcpu_alloc(void)
{
	return NULL;
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	return -EINVAL;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	return 0;
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return false;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	return -EINVAL;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_ARM_VCPU_INIT: {
		struct kvm_vcpu_init init;

		r = -EFAULT;
		if (copy_from_user(&init, argp, sizeof(init)))
			break;

		vcpu_set_flag(vcpu, VCPU_INITIALIZED);
		r = 0;
		break;
	}
	case KVM_SET_ONE_REG:
	case KVM_GET_ONE_REG: {
		struct kvm_one_reg reg;

		r = -ENOEXEC;
		if (unlikely(!kvm_vcpu_initialized(vcpu)))
			break;

		r = -EFAULT;
		if (copy_from_user(&reg, argp, sizeof(reg)))
			break;

		if (ioctl == KVM_SET_ONE_REG)
			r = kvm_arm_set_reg(vcpu, &reg);
		else
			r = kvm_arm_get_reg(vcpu, &reg);
		break;
	}
	case KVM_GET_REG_LIST: {
		struct kvm_reg_list __user *user_list = argp;
		struct kvm_reg_list reg_list;
		unsigned n;

		r = -ENOEXEC;
		if (unlikely(!kvm_vcpu_initialized(vcpu)))
			break;

		r = -EFAULT;
		if (copy_from_user(&reg_list, user_list, sizeof(reg_list)))
			break;

		n = reg_list.n;
		reg_list.n = num_core_regs(vcpu);
		if (copy_to_user(user_list, &reg_list, sizeof(reg_list)))
			break;
		r = -E2BIG;
		if (n < reg_list.n)
			break;

		r = 0;
		copy_core_reg_indices(vcpu, user_list->reg);
		break;
	}
	case KVM_ARM_VCPU_FINALIZE: {
		return 0;
	}
	default:
		pr_info("gunyah: %s: unrecognised vcpu ioctl %u\n", __func__, ioctl);
		r = -EINVAL;
	}

	return r;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				  struct kvm_translation *tr)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	return -EINVAL;
}

void kvm_arch_vcpu_put_debug_state_flags(struct kvm_vcpu *vcpu)
{
}

int kvm_vm_ioctl_enable_cap(struct kvm *kvm,
			    struct kvm_enable_cap *cap)
{
	return -EINVAL;
}

int kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	switch (ioctl) {
	case KVM_ARM_PREFERRED_TARGET: {
		struct kvm_vcpu_init init = {
			.target = KVM_ARM_TARGET_GENERIC_V8,
		};

		if (copy_to_user(argp, &init, sizeof(init)))
			return -EFAULT;

		return 0;
	}
	case KVM_ARM_SET_COUNTER_OFFSET: {
		return -ENXIO;
	}
	case KVM_ARM_SET_DEVICE_ADDR: {
		struct kvm_arm_device_addr dev_addr;

		if (copy_from_user(&dev_addr, argp, sizeof(dev_addr)))
			return -EFAULT;

		return -ENODEV;
	}
	case KVM_HAS_DEVICE_ATTR: {
		return -ENXIO;
	}
	case KVM_SET_DEVICE_ATTR: {
		return -ENXIO;
	}
	case KVM_ARM_GET_REG_WRITABLE_MASKS: {
		return -ENXIO;
	}
	default:
		return -EINVAL;
	}
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_VCPU_ATTRIBUTES:
	case KVM_CAP_ARM_USER_IRQ:
	case KVM_CAP_ARM_SET_DEVICE_ADDR:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		/*
		 * ARM64 treats KVM_CAP_NR_CPUS differently from all other
		 * architectures, as it does not always bound it to
		 * KVM_CAP_MAX_VCPUS. It should not matter much because
		 * this is just an advisory value.
		 */
		r = min_t(unsigned int, num_online_cpus(), KVM_MAX_VCPUS);
		break;
	case KVM_CAP_MAX_VCPUS:
	case KVM_CAP_MAX_VCPU_ID:
		r = KVM_MAX_VCPUS;
		break;
	default:
		r = 0;
	}

	return r;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
			  bool line_status)
{
	return -ENXIO;
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	return 0;
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
}

int kvm_arch_flush_remote_tlbs(struct kvm *kvm)
{
	return -EINVAL;
}

int kvm_arch_flush_remote_tlbs_range(struct kvm *kvm,
				      gfn_t gfn, u64 nr_pages)
{
	return -EINVAL;
}

void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
		struct kvm_memory_slot *slot,
		gfn_t gfn_offset, unsigned long mask)
{
}

static int gunyah_pin_user_memory(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
	unsigned int gup_flags = FOLL_WRITE | FOLL_LONGTERM;
	unsigned long start = memslot->userspace_addr;
	struct vm_area_struct *vma;
	struct page **pages;
	int ret;

	if (!memslot->npages)
		return 0;

	/* It needs to be a valid VMA-backed region */
	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, start);
	if (!vma || start < vma->vm_start) {
		mmap_read_unlock(current->mm);
		return 0;
	}
	if (!(vma->vm_flags & VM_READ) || !(vma->vm_flags & VM_WRITE)) {
		mmap_read_unlock(current->mm);
		return 0;
	}
	mmap_read_unlock(current->mm);

	pages = kvcalloc(memslot->npages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	ret = pin_user_pages_fast(start, memslot->npages, gup_flags, pages);
	if (ret < 0) {
		goto err;
	} else if (ret != memslot->npages) {
		ret = -EIO;
		goto err;
	} else {
		memslot->arch.pages = pages;
		return 0;
	}
err:
	kvfree(pages);
	return ret;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				   const struct kvm_memory_slot *old,
				   struct kvm_memory_slot *new,
				   enum kvm_mr_change change)
{
	int ret;

	switch (change) {
	case KVM_MR_CREATE:
		ret = gunyah_pin_user_memory(kvm, new);
		break;
	default:
		return 0;
	}
	return ret;
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				   struct kvm_memory_slot *old,
				   const struct kvm_memory_slot *new,
				   enum kvm_mr_change change)
{
}

void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	if (!slot->arch.pages)
		return;

	unpin_user_pages(slot->arch.pages, slot->npages);

	kvfree(slot->arch.pages);
}

void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen)
{
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
				   struct kvm_memory_slot *slot)
{
}

bool kvm_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	return false;
}


bool kvm_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	return false;
}

bool kvm_unmap_gfn_range(struct kvm *kvm, struct kvm_gfn_range *range)
{
	return false;
}

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	return -EINVAL;
}

__init void kvm_compute_layout(void)
{
}

__init void kvm_apply_hyp_relocations(void)
{
}

void __init kvm_hyp_reserve(void)
{
}

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return -EINVAL;
}

static int gunyah_vm_rm_notification_status(struct gunyah_vm *ghvm, void *data)
{
	struct gunyah_rm_vm_status_payload *payload = data;

	if (le16_to_cpu(payload->vmid) != ghvm->vmid)
		return NOTIFY_OK;

	/* All other state transitions are synchronous to a corresponding RM call */
	if (payload->vm_status == GUNYAH_RM_VM_STATUS_RESET) {
		down_write(&ghvm->status_lock);
		ghvm->vm_status = payload->vm_status;
		up_write(&ghvm->status_lock);
		wake_up(&ghvm->vm_status_wait);
	}

	return NOTIFY_DONE;
}

static int gunyah_vm_rm_notification_exited(struct gunyah_vm *ghvm, void *data)
{
	struct gunyah_rm_vm_exited_payload *payload = data;

	if (le16_to_cpu(payload->vmid) != ghvm->vmid)
		return NOTIFY_OK;

	down_write(&ghvm->status_lock);
	ghvm->vm_status = GUNYAH_RM_VM_STATUS_EXITED;
	up_write(&ghvm->status_lock);
	wake_up(&ghvm->vm_status_wait);

	return NOTIFY_DONE;
}

static int gunyah_vm_rm_notification(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct gunyah_vm *ghvm = container_of(nb, struct gunyah_vm, nb);

	switch (action) {
	case GUNYAH_RM_NOTIFICATION_VM_STATUS:
		return gunyah_vm_rm_notification_status(ghvm, data);
	case GUNYAH_RM_NOTIFICATION_VM_EXITED:
		return gunyah_vm_rm_notification_exited(ghvm, data);
	default:
		return NOTIFY_OK;
	}
}

static void gunyah_vm_stop(struct gunyah_vm *ghvm)
{
	int ret;

	if (ghvm->vm_status == GUNYAH_RM_VM_STATUS_RUNNING) {
		ret = gunyah_rm_vm_stop(ghvm->rm, ghvm->vmid);
		if (ret)
			pr_warn("Failed to stop VM: %d\n", ret);
	}

	wait_event(ghvm->vm_status_wait,
		   ghvm->vm_status != GUNYAH_RM_VM_STATUS_RUNNING);
}

static int gunyah_vm_start(struct gunyah_vm *ghvm)
{
	int ret;

	down_write(&ghvm->status_lock);
	if (ghvm->vm_status != GUNYAH_RM_VM_STATUS_NO_STATE) {
		up_write(&ghvm->status_lock);
		return 0;
	}

	ghvm->nb.notifier_call = gunyah_vm_rm_notification;
	ret = gunyah_rm_notifier_register(ghvm->rm, &ghvm->nb);
	if (ret)
		goto err;

	ret = gunyah_rm_alloc_vmid(ghvm->rm, 0);
	if (ret < 0) {
		gunyah_rm_notifier_unregister(ghvm->rm, &ghvm->nb);
		goto err;
	}
	ghvm->vmid = ret;
	ghvm->vm_status = GUNYAH_RM_VM_STATUS_LOAD;

	ret = gunyah_rm_vm_configure(ghvm->rm, ghvm->vmid, ghvm->auth, 0, 0, 0, 0, 0);
	if (ret) {
		pr_warn("Failed to configure VM: %d\n", ret);
		goto err;
	}

	ret = gunyah_rm_vm_init(ghvm->rm, ghvm->vmid);
	if (ret) {
		ghvm->vm_status = GUNYAH_RM_VM_STATUS_INIT_FAILED;
		pr_warn("Failed to initialize VM: %d\n", ret);
		goto err;
	}
	ghvm->vm_status = GUNYAH_RM_VM_STATUS_READY;

	ret = gunyah_rm_vm_start(ghvm->rm, ghvm->vmid);
	if (ret) {
		pr_warn("Failed to start VM: %d\n", ret);
		goto err;
	}

	ghvm->vm_status = GUNYAH_RM_VM_STATUS_RUNNING;
	up_write(&ghvm->status_lock);
	return 0;
err:
	up_write(&ghvm->status_lock);
	return ret;
}

static struct gunyah_vm *gunyah_vm_alloc(struct gunyah_rm *rm)
{
	struct gunyah_vm *ghvm;

	ghvm = kzalloc(sizeof(*ghvm), GFP_KERNEL);
	if (!ghvm)
		return ERR_PTR(-ENOMEM);

	ghvm->vmid = GUNYAH_VMID_INVAL;
	ghvm->rm = rm;

	init_rwsem(&ghvm->status_lock);
	init_waitqueue_head(&ghvm->vm_status_wait);
	ghvm->vm_status = GUNYAH_RM_VM_STATUS_NO_STATE;

	return ghvm;
}

static void gunyah_destroy_vm(struct gunyah_vm *ghvm)
{
	int ret;

	/**
	 * We might race with a VM exit notification, but that's ok:
	 * gh_rm_vm_stop() will just return right away.
	 */
	if (ghvm->vm_status == GUNYAH_RM_VM_STATUS_RUNNING)
		gunyah_vm_stop(ghvm);

	if (ghvm->vm_status == GUNYAH_RM_VM_STATUS_EXITED ||
	    ghvm->vm_status == GUNYAH_RM_VM_STATUS_READY ||
	    ghvm->vm_status == GUNYAH_RM_VM_STATUS_INIT_FAILED) {
		ret = gunyah_rm_vm_reset(ghvm->rm, ghvm->vmid);
		if (!ret)
			wait_event(ghvm->vm_status_wait,
				   ghvm->vm_status == GUNYAH_RM_VM_STATUS_RESET);
		else
			pr_warn("Failed to reset the vm: %d\n", ret);
	}

	if (ghvm->vm_status > GUNYAH_RM_VM_STATUS_NO_STATE) {
		gunyah_rm_notifier_unregister(ghvm->rm, &ghvm->nb);
		ret = gunyah_rm_dealloc_vmid(ghvm->rm, ghvm->vmid);
		if (ret)
			pr_warn("Failed to deallocate vmid: %d\n", ret);
	}
}

struct kvm *kvm_arch_alloc_vm(void)
{
	struct gunyah_vm *ghvm;

	ghvm = gunyah_vm_alloc(gunyah_rm);
	if (IS_ERR(ghvm))
		return NULL;

	return &ghvm->kvm;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	struct gunyah_vm *ghvm = kvm_to_gunyah(kvm);

	kvm_destroy_vcpus(kvm);
	gunyah_destroy_vm(ghvm);
}

void kvm_arch_free_vm(struct kvm *kvm)
{
	struct gunyah_vm *ghvm = kvm_to_gunyah(kvm);

	kfree(ghvm);
}
