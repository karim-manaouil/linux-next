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
#include <linux/perf_event.h>
#include <asm/kvm_mmu.h>

#include <linux/gunyah_rsc_mgr.h>
#include <linux/gunyah.h>

#undef pr_fmt
#define pr_fmt(fmt) "gunyah: " fmt

#define GUNYAH_VM_ADDRSPACE_LABEL			0
#define GUNYAH_VM_MEM_EXTENT_GUEST_PRIVATE_LABEL	0
#define GUNYAH_VM_MEM_EXTENT_HOST_SHARED_LABEL		1
#define GUNYAH_VM_MEM_EXTENT_GUEST_SHARED_LABEL		3
#define GUNYAH_VM_MEM_EXTENT_HOST_PRIVATE_LABEL		2

#define WRITE_TAG (1 << 0)
#define SHARE_TAG (1 << 1)

static int gunyah_vm_start(struct gunyah_vm *ghvm);

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

static bool gunyah_vm_resource_ticket_populate_noop(
	struct gunyah_vm_resource_ticket *ticket, struct gunyah_resource *ghrsc)
{
	return true;
}
static void gunyah_vm_resource_ticket_unpopulate_noop(
	struct gunyah_vm_resource_ticket *ticket, struct gunyah_resource *ghrsc)
{
}

static inline struct gunyah_resource *
__first_resource(struct gunyah_vm_resource_ticket *ticket)
{
	return list_first_entry_or_null(&ticket->resources,
					struct gunyah_resource, list);
}

static int gunyah_vm_add_resource_ticket(struct gunyah_vm *ghvm,
				  struct gunyah_vm_resource_ticket *ticket)
{
	struct gunyah_vm_resource_ticket *iter;
	struct gunyah_resource *ghrsc, *rsc_iter;
	int ret = 0;

	mutex_lock(&ghvm->resources_lock);
	list_for_each_entry(iter, &ghvm->resource_tickets, vm_list) {
		if (iter->resource_type == ticket->resource_type &&
		    iter->label == ticket->label) {
			ret = -EEXIST;
			goto out;
		}
	}

	list_add(&ticket->vm_list, &ghvm->resource_tickets);
	INIT_LIST_HEAD(&ticket->resources);

	list_for_each_entry_safe(ghrsc, rsc_iter, &ghvm->resources, list) {
		if (ghrsc->type == ticket->resource_type &&
		    ghrsc->rm_label == ticket->label) {
			if (ticket->populate(ticket, ghrsc))
				list_move(&ghrsc->list, &ticket->resources);
		}
	}
out:
	mutex_unlock(&ghvm->resources_lock);
	return ret;
}

static void __gunyah_vm_remove_resource_ticket(struct gunyah_vm *ghvm,
		struct gunyah_vm_resource_ticket *ticket)
{
	struct gunyah_resource *ghrsc, *iter;

	list_for_each_entry_safe(ghrsc, iter, &ticket->resources, list) {
		ticket->unpopulate(ticket, ghrsc);
		list_move(&ghrsc->list, &ghvm->resources);
	}
	list_del(&ticket->vm_list);
}

static void gunyah_vm_remove_resource_ticket(struct gunyah_vm *ghvm,
		struct gunyah_vm_resource_ticket *ticket)
{

	mutex_lock(&ghvm->resources_lock);
	__gunyah_vm_remove_resource_ticket(ghvm, ticket);
	mutex_unlock(&ghvm->resources_lock);
}

static void gunyah_vm_add_resource(struct gunyah_vm *ghvm,
		struct gunyah_resource *ghrsc)
{
	struct gunyah_vm_resource_ticket *ticket;

	mutex_lock(&ghvm->resources_lock);
	list_for_each_entry(ticket, &ghvm->resource_tickets, vm_list) {
		if (ghrsc->type == ticket->resource_type &&
		    ghrsc->rm_label == ticket->label) {
			if (ticket->populate(ticket, ghrsc))
				list_add(&ghrsc->list, &ticket->resources);
			else
				list_add(&ghrsc->list, &ghvm->resources);
			/* unconditonal -- we prevent multiple identical
			 * resource tickets so there will not be some other
			 * ticket elsewhere in the list if populate() failed.
			 */
			goto found;
		}
	}
	list_add(&ghrsc->list, &ghvm->resources);
found:
	mutex_unlock(&ghvm->resources_lock);
}

static void gunyah_vm_clean_resources(struct gunyah_vm *ghvm)
{
	struct gunyah_vm_resource_ticket *ticket, *titer;
	struct gunyah_resource *ghrsc, *riter;

	mutex_lock(&ghvm->resources_lock);
	if (!list_empty(&ghvm->resource_tickets)) {
		pr_warn("Dangling resource tickets:\n");
		list_for_each_entry_safe(ticket, titer, &ghvm->resource_tickets,
					 vm_list) {
			pr_warn("  %pS\n", ticket->populate);
			__gunyah_vm_remove_resource_ticket(ghvm, ticket);
		}
	}

	list_for_each_entry_safe(ghrsc, riter, &ghvm->resources, list) {
		gunyah_rm_free_resource(ghrsc);
	}
	mutex_unlock(&ghvm->resources_lock);
}

static inline u32 donate_flags(bool share)
{
	if (share)
		return FIELD_PREP_CONST(GUNYAH_MEMEXTENT_OPTION_TYPE_MASK,
					GUNYAH_MEMEXTENT_DONATE_TO_SIBLING);
	else
		return FIELD_PREP_CONST(GUNYAH_MEMEXTENT_OPTION_TYPE_MASK,
					GUNYAH_MEMEXTENT_DONATE_TO_PROTECTED);
}

static inline u32 reclaim_flags(bool share)
{
	if (share)
		return FIELD_PREP_CONST(GUNYAH_MEMEXTENT_OPTION_TYPE_MASK,
					GUNYAH_MEMEXTENT_DONATE_TO_SIBLING);
	else
		return FIELD_PREP_CONST(GUNYAH_MEMEXTENT_OPTION_TYPE_MASK,
					GUNYAH_MEMEXTENT_DONATE_FROM_PROTECTED);
}

static int gunyah_memory_provide_folio(struct gunyah_vm *ghvm,
		struct folio *folio, gfn_t gfn, bool share, bool write)
{
	struct gunyah_resource *guest_extent, *host_extent, *addrspace;
	u32 map_flags = BIT(GUNYAH_ADDRSPACE_MAP_FLAG_PARTIAL);
	u64 extent_attrs;
	gfn_t gpa = gfn_to_gpa(gfn);
	phys_addr_t pa = PFN_PHYS(folio_pfn(folio));
	enum gunyah_pagetable_access access;
	size_t size = folio_size(folio);
	enum gunyah_error gunyah_error;
	unsigned long tag = 0;
	int ret, tmp;

	if (share) {
		guest_extent = __first_resource(&ghvm->guest_shared_extent_ticket);
		host_extent = __first_resource(&ghvm->host_shared_extent_ticket);
	} else {
		guest_extent = __first_resource(&ghvm->guest_private_extent_ticket);
		host_extent = __first_resource(&ghvm->host_private_extent_ticket);
	}
	addrspace = __first_resource(&ghvm->addrspace_ticket);

	if (!addrspace || !guest_extent || !host_extent)
		return -ENODEV;

	if (share) {
		map_flags |= BIT(GUNYAH_ADDRSPACE_MAP_FLAG_VMMIO);
		tag |= SHARE_TAG;
	} else {
		map_flags |= BIT(GUNYAH_ADDRSPACE_MAP_FLAG_PRIVATE);
	}

	if (write)
		tag |= WRITE_TAG;

	if (share && write)
		access = GUNYAH_PAGETABLE_ACCESS_RW;
	else if (share && !write)
		access = GUNYAH_PAGETABLE_ACCESS_R;
	else if (!share && write)
		access = GUNYAH_PAGETABLE_ACCESS_RWX;
	else /* !share && !write */
		access = GUNYAH_PAGETABLE_ACCESS_RX;

	ret = gunyah_rm_platform_pre_demand_page(ghvm->rm, ghvm->vmid, access,
						 folio);
	if (ret)
		return ret;

	gunyah_error = gunyah_hypercall_memextent_donate(donate_flags(share),
							 host_extent->capid,
							 guest_extent->capid,
							 pa, size);
	if (gunyah_error != GUNYAH_ERROR_OK) {
		pr_err("Failed to donate memory for guest address 0x%016llx: %d\n",
		       gpa, gunyah_error);
		ret = gunyah_error_remap(gunyah_error);
		goto platform_release;
	}

	extent_attrs =
		FIELD_PREP_CONST(GUNYAH_MEMEXTENT_MAPPING_TYPE,
				 ARCH_GUNYAH_DEFAULT_MEMTYPE) |
		FIELD_PREP(GUNYAH_MEMEXTENT_MAPPING_USER_ACCESS, access) |
		FIELD_PREP(GUNYAH_MEMEXTENT_MAPPING_KERNEL_ACCESS, access);
	gunyah_error = gunyah_hypercall_addrspace_map(addrspace->capid,
						      guest_extent->capid, gpa,
						      extent_attrs, map_flags,
						      pa, size);
	if (gunyah_error != GUNYAH_ERROR_OK) {
		pr_err("Failed to map guest address 0x%016llx: %d\n", gpa,
		       gunyah_error);
		ret = gunyah_error_remap(gunyah_error);
		goto memextent_reclaim;
	}

	return 0;
memextent_reclaim:
	gunyah_error = gunyah_hypercall_memextent_donate(reclaim_flags(share),
							 guest_extent->capid,
							 host_extent->capid, pa,
							 size);
	if (gunyah_error != GUNYAH_ERROR_OK)
		pr_err("Failed to reclaim memory donation for guest address 0x%016llx: %d\n",
		       gpa, gunyah_error);
platform_release:
	tmp = gunyah_rm_platform_reclaim_demand_page(ghvm->rm, ghvm->vmid,
						     access, folio);
	if (tmp) {
		pr_err("Platform failed to reclaim memory for guest address 0x%016llx: %d",
		       gpa, tmp);
		return ret;
	}
	return ret;
}

static int gunyah_memory_reclaim_folio(struct gunyah_vm *ghvm,
		struct folio *folio, gfn_t gfn, bool share)
{
	u32 map_flags = BIT(GUNYAH_ADDRSPACE_MAP_FLAG_PARTIAL);
	struct gunyah_resource *guest_extent, *host_extent, *addrspace;
	enum gunyah_error gunyah_error;
	enum gunyah_pagetable_access access;
	phys_addr_t pa;
	size_t size;
	int ret;

	addrspace = __first_resource(&ghvm->addrspace_ticket);
	if (!addrspace)
		return -ENODEV;

	guest_extent = __first_resource(&ghvm->guest_private_extent_ticket);
	host_extent = __first_resource(&ghvm->host_private_extent_ticket);
	map_flags |= BIT(GUNYAH_ADDRSPACE_MAP_FLAG_PRIVATE);

	pa = PFN_PHYS(folio_pfn(folio));
	size = folio_size(folio);

	gunyah_error = gunyah_hypercall_addrspace_unmap(addrspace->capid,
							guest_extent->capid,
							gfn_to_gpa(gfn),
							map_flags, pa, size);
	if (gunyah_error != GUNYAH_ERROR_OK) {
		pr_err_ratelimited(
			"Failed to unmap guest address 0x%016llx: %d\n",
			gfn_to_gpa(gfn), gunyah_error);
		ret = gunyah_error_remap(gunyah_error);
		goto err;
	}

	gunyah_error = gunyah_hypercall_memextent_donate(reclaim_flags(share),
							 guest_extent->capid,
							 host_extent->capid, pa,
							 size);
	if (gunyah_error != GUNYAH_ERROR_OK) {
		pr_err_ratelimited(
			"Failed to reclaim memory donation for guest address 0x%016llx: %d\n",
			gfn_to_gpa(gfn), gunyah_error);
		ret = gunyah_error_remap(gunyah_error);
		goto err;
	}

	access = GUNYAH_PAGETABLE_ACCESS_RWX;

	ret = gunyah_rm_platform_reclaim_demand_page(ghvm->rm, ghvm->vmid, access, folio);
	if (ret) {
		pr_err_ratelimited(
			"Platform failed to reclaim memory for guest address 0x%016llx: %d",
			gfn_to_gpa(gfn), ret);
		goto err;
	}

	return 0;
err:
	return ret;
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

/*
 * When hypervisor allows us to schedule vCPU again, it gives us an interrupt
 */
static irqreturn_t gunyah_vcpu_irq_handler(int irq, void *data)
{
	struct gunyah_vcpu *vcpu = data;

	complete(&vcpu->ready);
	return IRQ_HANDLED;
}

static int gunyah_vcpu_rm_notification(struct notifier_block *nb,
				       unsigned long action, void *data)
{
	struct gunyah_vcpu *vcpu = container_of(nb, struct gunyah_vcpu, nb);
	struct gunyah_rm_vm_exited_payload *exit_payload = data;

	/* Wake up userspace waiting for the vCPU to be runnable again */
	if (action == GUNYAH_RM_NOTIFICATION_VM_EXITED &&
	    le16_to_cpu(exit_payload->vmid) == vcpu->ghvm->vmid)
		complete(&vcpu->ready);

	return NOTIFY_OK;
}

static int gunyah_handle_page_fault(
	struct gunyah_vcpu *vcpu,
	const struct gunyah_hypercall_vcpu_run_resp *vcpu_run_resp)
{
	return -EINVAL;
}

static bool gunyah_kvm_handle_mmio(struct gunyah_vcpu *vcpu,
		unsigned long resume_data[3],
		const struct gunyah_hypercall_vcpu_run_resp *vcpu_run_resp)
{
	struct kvm_vcpu *kvm_vcpu = &vcpu->kvm_vcpu;
	struct kvm_run *run = kvm_vcpu->run;
	u64 addr = vcpu_run_resp->state_data[0];
	u64 len = vcpu_run_resp->state_data[1];
	u64 data = vcpu_run_resp->state_data[2];
	bool write;

	if (WARN_ON(len > sizeof(u64)))
		len = sizeof(u64);

	if (vcpu_run_resp->state == GUNYAH_VCPU_ADDRSPACE_VMMIO_READ) {
		write = false;
		/*
		 * Record that we need to give vCPU user's supplied
		 * value next gunyah_vcpu_run()
		 */
		vcpu->state = GUNYAH_VCPU_RUN_STATE_MMIO_READ;
	} else {
		/* TODO: HANDLE IOEVENTFD !! */
		write = true;
		vcpu->state = GUNYAH_VCPU_RUN_STATE_MMIO_WRITE;
	}

	if (write)
		memcpy(run->mmio.data, &data, len);

	run->mmio.is_write = write;
	run->mmio.phys_addr = addr;
	run->mmio.len = len;
	kvm_vcpu->mmio_needed = 1;

	kvm_vcpu->stat.mmio_exit_user++;
	run->exit_reason = KVM_EXIT_MMIO;

	return false;
}

static int gunyah_handle_mmio_resume(struct gunyah_vcpu *vcpu,
				     unsigned long resume_data[3])
{
	struct kvm_vcpu *kvm_vcpu = &vcpu->kvm_vcpu;
	struct kvm_run *run = kvm_vcpu->run;

	resume_data[1] = GUNYAH_ADDRSPACE_VMMIO_ACTION_EMULATE;
	if (vcpu->state == GUNYAH_VCPU_RUN_STATE_MMIO_READ)
		memcpy(&resume_data[0], run->mmio.data, run->mmio.len);
	return 0;
}

/**
 * gunyah_vcpu_check_system() - Check whether VM as a whole is running
 * @vcpu: Pointer to gunyah_vcpu
 *
 * Returns true if the VM is alive.
 * Returns false if the vCPU is the VM is not alive (can only be that VM is shutting down).
 */
static bool gunyah_vcpu_check_system(struct gunyah_vcpu *vcpu)
	__must_hold(&vcpu->lock)
{
	bool ret = true;

	down_read(&vcpu->ghvm->status_lock);
	if (likely(vcpu->ghvm->vm_status == GUNYAH_RM_VM_STATUS_RUNNING))
		goto out;

	vcpu->state = GUNYAH_VCPU_RUN_STATE_SYSTEM_DOWN;
	ret = false;
out:
	up_read(&vcpu->ghvm->status_lock);
	return ret;
}

static int gunyah_vcpu_run(struct gunyah_vcpu *vcpu)
{
	struct gunyah_hypercall_vcpu_run_resp vcpu_run_resp;
	struct kvm_vcpu *kvm_vcpu = &vcpu->kvm_vcpu;
	struct kvm_run *run = kvm_vcpu->run;
	unsigned long resume_data[3] = { 0 };
	enum gunyah_error gunyah_error;
	int ret = 0;

	if (mutex_lock_interruptible(&vcpu->lock))
		return -ERESTARTSYS;

	if (!vcpu->rsc) {
		ret = -ENODEV;
		goto out;
	}

	switch (vcpu->state) {
	case GUNYAH_VCPU_RUN_STATE_UNKNOWN:
		if (vcpu->ghvm->vm_status != GUNYAH_RM_VM_STATUS_RUNNING) {
			/**
			 * Check if VM is up. If VM is starting, will block
			 * until VM is fully up since that thread does
			 * down_write.
			 */
			if (!gunyah_vcpu_check_system(vcpu))
				goto out;
		}
		vcpu->state = GUNYAH_VCPU_RUN_STATE_READY;
		break;
	case GUNYAH_VCPU_RUN_STATE_MMIO_READ:
	case GUNYAH_VCPU_RUN_STATE_MMIO_WRITE:
		ret = gunyah_handle_mmio_resume(vcpu, resume_data);
		if (ret)
			goto out;
		vcpu->state = GUNYAH_VCPU_RUN_STATE_READY;
		break;
	case GUNYAH_VCPU_RUN_STATE_SYSTEM_DOWN:
		goto out;
	default:
		break;
	}

	run->exit_reason = KVM_EXIT_UNKNOWN;

	while (!ret && !signal_pending(current)) {
		if (vcpu->immediate_exit) {
			ret = -EINTR;
			goto out;
		}
		gunyah_error = gunyah_hypercall_vcpu_run(
				vcpu->rsc->capid, resume_data, &vcpu_run_resp);

		if (gunyah_error == GUNYAH_ERROR_OK) {
			memset(resume_data, 0, sizeof(resume_data));

			switch (vcpu_run_resp.state) {
			case GUNYAH_VCPU_STATE_READY:
				if (need_resched())
					schedule();
				break;
			case GUNYAH_VCPU_STATE_POWERED_OFF:
				/**
				 * vcpu might be off because the VM is shut down
				 * If so, it won't ever run again
				 */
				if (!gunyah_vcpu_check_system(vcpu))
					goto out;
				/**
				 * Otherwise, another vcpu will turn it on (e.g.
				 * by PSCI) and hyp sends an interrupt to wake
				 * Linux up.
				 */
				fallthrough;
			case GUNYAH_VCPU_STATE_EXPECTS_WAKEUP:
				ret = wait_for_completion_interruptible(
					&vcpu->ready);
				/**
				 * reinitialize completion before next
				 * hypercall. If we reinitialize after the
				 * hypercall, interrupt may have already come
				 * before re-initializing the completion and
				 * then end up waiting for event that already
				 * happened.
				 */
				reinit_completion(&vcpu->ready);
				/**
				 * Check VM status again. Completion
				 * might've come from VM exiting
				 */
				if (!ret && !gunyah_vcpu_check_system(vcpu))
					goto out;
				break;
			case GUNYAH_VCPU_STATE_BLOCKED:
				schedule();
				break;
			case GUNYAH_VCPU_ADDRSPACE_VMMIO_READ:
			case GUNYAH_VCPU_ADDRSPACE_VMMIO_WRITE:
				if (!gunyah_kvm_handle_mmio(vcpu, resume_data,
							&vcpu_run_resp))
					goto out;
				break;
			case GUNYAH_VCPU_ADDRSPACE_PAGE_FAULT:
				ret = gunyah_handle_page_fault(vcpu, &vcpu_run_resp);
				if (ret)
					goto out;
				break;
			default:
				pr_warn(
					"Unknown vCPU state: %llx\n",
					vcpu_run_resp.sized_state);
				schedule();
				break;
			}
		} else if (gunyah_error == GUNYAH_ERROR_RETRY) {
			schedule();
		} else {
			ret = gunyah_error_remap(gunyah_error);
		}
	}

out:
	mutex_unlock(&vcpu->lock);

	if (signal_pending(current))
		return -ERESTARTSYS;

	return ret;
}

static bool gunyah_vcpu_populate(struct gunyah_vm_resource_ticket *ticket,
				 struct gunyah_resource *ghrsc)
{
	struct gunyah_vcpu *vcpu =
		container_of(ticket, struct gunyah_vcpu, ticket);
	int ret;

	mutex_lock(&vcpu->lock);
	if (vcpu->rsc) {
		pr_warn("vcpu%d already got a Gunyah resource", vcpu->ticket.label);
		ret = -EEXIST;
		goto out;
	}
	vcpu->rsc = ghrsc;

	ret = request_irq(vcpu->rsc->irq, gunyah_vcpu_irq_handler,
			  IRQF_TRIGGER_RISING, "gunyah_vcpu", vcpu);
	if (ret) {
		pr_warn("Failed to request vcpu irq %d: %d", vcpu->rsc->irq,
			ret);
		goto out;
	}

	enable_irq_wake(vcpu->rsc->irq);
out:
	mutex_unlock(&vcpu->lock);
	return !ret;
}

static void gunyah_vcpu_unpopulate(struct gunyah_vm_resource_ticket *ticket,
				   struct gunyah_resource *ghrsc)
{
	struct gunyah_vcpu *vcpu =
		container_of(ticket, struct gunyah_vcpu, ticket);

	vcpu->immediate_exit = true;
	complete_all(&vcpu->ready);
	mutex_lock(&vcpu->lock);
	free_irq(vcpu->rsc->irq, vcpu);
	vcpu->rsc = NULL;
	mutex_unlock(&vcpu->lock);
}

static int gunyah_vcpu_create(struct gunyah_vm *ghvm, struct gunyah_vcpu *vcpu, int id)
{
	int r;

	mutex_init(&vcpu->lock);
	init_completion(&vcpu->ready);

	vcpu->ghvm = ghvm;
	vcpu->nb.notifier_call = gunyah_vcpu_rm_notification;
	/**
	 * Ensure we run after the vm_mgr handles the notification and does
	 * any necessary state changes.
	 */
	vcpu->nb.priority = -1;
	r = gunyah_rm_notifier_register(ghvm->rm, &vcpu->nb);
	if (r)
		return r;

	vcpu->ticket.resource_type = GUNYAH_RESOURCE_TYPE_VCPU;
	vcpu->ticket.label = id;
	vcpu->ticket.populate = gunyah_vcpu_populate;
	vcpu->ticket.unpopulate = gunyah_vcpu_unpopulate;

	return gunyah_vm_add_resource_ticket(ghvm, &vcpu->ticket);
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	GUNYAH_STATE(vcpu);
	return gunyah_vcpu_create(ghvm, ghvcpu, vcpu->vcpu_id);
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	GUNYAH_STATE(vcpu);

	gunyah_rm_notifier_unregister(ghvcpu->ghvm->rm, &ghvcpu->nb);
	gunyah_vm_remove_resource_ticket(ghvcpu->ghvm, &ghvcpu->ticket);
	kfree(ghvcpu);
}

struct kvm_vcpu *kvm_arch_vcpu_alloc(void)
{
	struct gunyah_vcpu *vcpu;

	vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL_ACCOUNT);
	if (!vcpu)
		return NULL;
	return &vcpu->kvm_vcpu;
}

void kvm_arch_vcpu_free(struct kvm_vcpu *kvm_vcpu)
{
	struct gunyah_vcpu *vcpu = gunyah_vcpu(kvm_vcpu);

	kfree(vcpu);
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
	GUNYAH_STATE(vcpu);
	int ret;

	if (!xchg(&ghvm->started, 1)) {
		ret = gunyah_vm_start(ghvm);
		if (ret) {
			xchg(&ghvm->started, 0);
			goto out;
		}
	}
	ret = gunyah_vcpu_run(ghvcpu);
out:
	return ret;

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
	struct gunyah_rm_hyp_resources *resources;
	struct gunyah_resource *ghrsc;
	int i, n, ret;

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

	ret = gunyah_rm_get_hyp_resources(ghvm->rm, ghvm->vmid, &resources);
	if (ret) {
		pr_warn("Failed to get hyp resources for VM: %d\n", ret);
		goto err;
	}

	for (i = 0, n = le32_to_cpu(resources->n_entries); i < n; i++) {
		ghrsc = gunyah_rm_alloc_resource(ghvm->rm,
						 &resources->entries[i]);
		if (!ghrsc) {
			ret = -ENOMEM;
			goto err;
		}
		gunyah_vm_add_resource(ghvm, ghrsc);
	}

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

static inline void setup_extent_ticket(struct gunyah_vm *ghvm,
				       struct gunyah_vm_resource_ticket *ticket,
				       u32 label)
{
	ticket->resource_type = GUNYAH_RESOURCE_TYPE_MEM_EXTENT;
	ticket->label = label;
	ticket->populate = gunyah_vm_resource_ticket_populate_noop;
	ticket->unpopulate = gunyah_vm_resource_ticket_unpopulate_noop;
	gunyah_vm_add_resource_ticket(ghvm, ticket);
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
	mutex_init(&ghvm->resources_lock);
	INIT_LIST_HEAD(&ghvm->resources);
	INIT_LIST_HEAD(&ghvm->resource_tickets);

	ghvm->addrspace_ticket.resource_type = GUNYAH_RESOURCE_TYPE_ADDR_SPACE;
	ghvm->addrspace_ticket.label = GUNYAH_VM_ADDRSPACE_LABEL;
	ghvm->addrspace_ticket.populate = gunyah_vm_resource_ticket_populate_noop;
	ghvm->addrspace_ticket.unpopulate = gunyah_vm_resource_ticket_unpopulate_noop;
	gunyah_vm_add_resource_ticket(ghvm, &ghvm->addrspace_ticket);

	setup_extent_ticket(ghvm, &ghvm->host_private_extent_ticket,
			    GUNYAH_VM_MEM_EXTENT_HOST_PRIVATE_LABEL);
	setup_extent_ticket(ghvm, &ghvm->host_shared_extent_ticket,
			    GUNYAH_VM_MEM_EXTENT_HOST_SHARED_LABEL);
	setup_extent_ticket(ghvm, &ghvm->guest_private_extent_ticket,
			    GUNYAH_VM_MEM_EXTENT_GUEST_PRIVATE_LABEL);
	setup_extent_ticket(ghvm, &ghvm->guest_shared_extent_ticket,
			    GUNYAH_VM_MEM_EXTENT_GUEST_SHARED_LABEL);
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

	gunyah_vm_remove_resource_ticket(ghvm, &ghvm->addrspace_ticket);
	gunyah_vm_remove_resource_ticket(ghvm, &ghvm->host_shared_extent_ticket);
	gunyah_vm_remove_resource_ticket(ghvm, &ghvm->host_private_extent_ticket);
	gunyah_vm_remove_resource_ticket(ghvm, &ghvm->guest_shared_extent_ticket);
	gunyah_vm_remove_resource_ticket(ghvm, &ghvm->guest_private_extent_ticket);

	gunyah_vm_clean_resources(ghvm);

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
