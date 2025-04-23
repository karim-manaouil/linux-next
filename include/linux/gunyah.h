/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _LINUX_GUNYAH_H
#define _LINUX_GUNYAH_H

#include <linux/bitfield.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>

#include <asm/gunyah.h>
#include <linux/gunyah_rsc_mgr.h>

#define gunyah_vcpu(kvm_vcpu_ptr) \
	container_of(kvm_vcpu_ptr, struct gunyah_vcpu, kvm_vcpu)

#define kvm_to_gunyah(kvm_ptr) \
	container_of(kvm_ptr, struct gunyah_vm, kvm)

#define GUNYAH_STATE(kvm_vcpu)							\
	struct gunyah_vm __maybe_unused *ghvm = kvm_to_gunyah(kvm_vcpu->kvm);	\
	struct gunyah_vcpu __maybe_unused *ghvcpu = gunyah_vcpu(kvm_vcpu)

struct gunyah_vm;

/* Matches resource manager's resource types for VM_GET_HYP_RESOURCES RPC */
enum gunyah_resource_type {
	/* clang-format off */
	GUNYAH_RESOURCE_TYPE_BELL_TX	= 0,
	GUNYAH_RESOURCE_TYPE_BELL_RX	= 1,
	GUNYAH_RESOURCE_TYPE_MSGQ_TX	= 2,
	GUNYAH_RESOURCE_TYPE_MSGQ_RX	= 3,
	GUNYAH_RESOURCE_TYPE_VCPU	= 4,
	GUNYAH_RESOURCE_TYPE_MEM_EXTENT	= 9,
	GUNYAH_RESOURCE_TYPE_ADDR_SPACE	= 10,
	/* clang-format on */
};

struct gunyah_resource {
	enum gunyah_resource_type type;
	u64 capid;
	unsigned int irq;
	struct list_head list;
	u32 rm_label;
};

/**
 * struct gunyah_vm_resource_ticket - Represents a ticket to reserve access to VM resource(s)
 * @label: Label of the resource from resource manager this ticket reserves.
 * @vm_list: for @gunyah_vm->resource_tickets
 * @resources: List of resource(s) associated with this ticket
 *             (members are from @gunyah_resource->list)
 * @resource_type: Type of resource this ticket reserves
 * @populate: callback provided by the ticket owner and called when a resource is found that
 *            matches @resource_type and @label. Note that this callback could be called
 *            multiple times if userspace created mutliple resources with the same type/label.
 *            This callback may also have significant delay after gunyah_vm_add_resource_ticket()
 *            since gunyah_vm_add_resource_ticket() could be called before the VM starts.
 * @unpopulate: callback provided by the ticket owner and called when the ticket owner should no
 *              longer use the resource provided in the argument. When unpopulate() returns,
 *              the ticket owner should not be able to use the resource any more as the resource
 *              might being freed.
 */
struct gunyah_vm_resource_ticket {
	u32 label;
	struct list_head vm_list;
	struct list_head resources;
	enum gunyah_resource_type resource_type;
	bool (*populate)(struct gunyah_vm_resource_ticket *ticket,
			 struct gunyah_resource *ghrsc);
	void (*unpopulate)(struct gunyah_vm_resource_ticket *ticket,
			   struct gunyah_resource *ghrsc);
};


/**
 * struct gunyah_vm - Main representation of a Gunyah Virtual machine
                              memory shared with the guest.
 * @vmid: Gunyah's VMID for this virtual machine
 * @kvm: kvm instance for this VM
 * @rm: Pointer to the resource manager struct to make RM calls
 * @nb: Notifier block for RM notifications
 * @vm_status: Current state of the VM, as last reported by RM
 * @vm_status_wait: Wait queue for status @vm_status changes
 * @status_lock: Serializing state transitions
 * @resource_lock: Serializing addition of resources and resource tickets
 * @resources: List of &struct gunyah_resource that are associated with this VM
 * @resource_tickets: List of &struct gunyah_vm_resource_ticket
 * @auth: Authentication mechanism to be used by resource manager when
 *        launching the VM
 * @dtb: For tracking dtb configuration when launching the VM
 * @dtb.parcel_start: Guest frame number where the memory parcel that we lent to
 *                    VM (DTB could start in middle of folio; we lend entire
 *                    folio; parcel_start is start of the folio)
 * @dtb.parcel_pages: Number of pages lent for the memory parcel
 * @dtb.parcel: Data for resource manager to lend the parcel
 */
struct gunyah_vm {
	u16 vmid;
	bool started;
	struct kvm kvm;
	struct gunyah_rm *rm;
	struct notifier_block nb;
	enum gunyah_rm_vm_status vm_status;
	wait_queue_head_t vm_status_wait;
	struct rw_semaphore status_lock;
	struct mutex resources_lock;
	struct list_head resources;
	struct list_head resource_tickets;
	enum gunyah_rm_vm_auth_mechanism auth;
	struct gunyah_vm_resource_ticket addrspace_ticket;
	struct gunyah_vm_resource_ticket host_private_extent_ticket;
	struct gunyah_vm_resource_ticket host_shared_extent_ticket;
	struct gunyah_vm_resource_ticket guest_private_extent_ticket;
	struct gunyah_vm_resource_ticket guest_shared_extent_ticket;
	struct {
		gfn_t parcel_start, parcel_pages;
		struct gunyah_rm_mem_parcel parcel;
	} dtb;
};

/**
 * struct gunyah_vcpu - Track an instance of gunyah vCPU
 * @kvm_vcpu: kvm instance
 * @rsc: Pointer to the Gunyah vCPU resource, will be NULL until VM starts
 * @lock: One userspace thread at a time should run the vCPU
 * @ghvm: Pointer to the main VM struct; quicker look up than going through
 *        @f->ghvm
 * @state: Our copy of the state of the vCPU, since userspace could trick
 *         kernel to behave incorrectly if we relied on @vcpu_run
 * @ready: if vCPU goes to sleep, hypervisor reports to us that it's sleeping
 *         and will signal interrupt (from @rsc) when it's time to wake up.
 *         This completion signals that we can run vCPU again.
 * @nb: When VM exits, the status of VM is reported via @vcpu_run->status.
 *      We need to track overall VM status, and the nb gives us the updates from
 *      Resource Manager.
 * @ticket: resource ticket to claim vCPU# for the VM
 */
struct gunyah_vcpu {
	struct kvm_vcpu kvm_vcpu;
	struct gunyah_resource *rsc;
	struct mutex lock;
	struct gunyah_vm *ghvm;

	/**
	 * Track why the vcpu_run hypercall returned. This mirrors the vcpu_run
	 * structure shared with userspace, except is used internally to avoid
	 * trusting userspace to not modify the vcpu_run structure.
	 */
	enum {
		GUNYAH_VCPU_RUN_STATE_UNKNOWN = 0,
		GUNYAH_VCPU_RUN_STATE_READY,
		GUNYAH_VCPU_RUN_STATE_MMIO_READ,
		GUNYAH_VCPU_RUN_STATE_MMIO_WRITE,
		GUNYAH_VCPU_RUN_STATE_SYSTEM_DOWN,
	} state;

	bool immediate_exit;
	struct completion ready;

	struct notifier_block nb;
	struct gunyah_vm_resource_ticket ticket;
};

enum gunyah_pagetable_access {
	/* clang-format off */
	GUNYAH_PAGETABLE_ACCESS_NONE		= 0,
	GUNYAH_PAGETABLE_ACCESS_X		= 1,
	GUNYAH_PAGETABLE_ACCESS_W		= 2,
	GUNYAH_PAGETABLE_ACCESS_R		= 4,
	GUNYAH_PAGETABLE_ACCESS_RX		= 5,
	GUNYAH_PAGETABLE_ACCESS_RW		= 6,
	GUNYAH_PAGETABLE_ACCESS_RWX		= 7,
	/* clang-format on */
};

struct gunyah_rm_platform_ops {
	int (*pre_mem_share)(struct gunyah_rm *rm,
			     struct gunyah_rm_mem_parcel *mem_parcel);
	int (*post_mem_reclaim)(struct gunyah_rm *rm,
				struct gunyah_rm_mem_parcel *mem_parcel);

	int (*pre_demand_page)(struct gunyah_rm *rm, u16 vmid,
			       enum gunyah_pagetable_access access,
			       struct folio *folio);
	int (*release_demand_page)(struct gunyah_rm *rm, u16 vmid,
				   enum gunyah_pagetable_access access,
				   struct folio *folio);
};

#if IS_ENABLED(CONFIG_GUNYAH_PLATFORM_HOOKS)
int gunyah_rm_register_platform_ops(
	const struct gunyah_rm_platform_ops *platform_ops);
void gunyah_rm_unregister_platform_ops(
	const struct gunyah_rm_platform_ops *platform_ops);
int devm_gunyah_rm_register_platform_ops(
	struct device *dev, const struct gunyah_rm_platform_ops *ops);
#else
static inline int gunyah_rm_register_platform_ops(
	const struct gunyah_rm_platform_ops *platform_ops)
{
	return 0;
}
static inline void gunyah_rm_unregister_platform_ops(
	const struct gunyah_rm_platform_ops *platform_ops)
{
}
static inline int
devm_gunyah_rm_register_platform_ops(struct device *dev,
				     const struct gunyah_rm_platform_ops *ops)
{
	return 0;
}
#endif

/******************************************************************************/
/* Common arch-independent definitions for Gunyah hypercalls                  */
#define GUNYAH_CAPID_INVAL U64_MAX
#define GUNYAH_VMID_ROOT_VM 0xff

enum gunyah_error {
	/* clang-format off */
	GUNYAH_ERROR_OK				= 0,
	GUNYAH_ERROR_UNIMPLEMENTED		= -1,
	GUNYAH_ERROR_RETRY			= -2,

	GUNYAH_ERROR_ARG_INVAL			= 1,
	GUNYAH_ERROR_ARG_SIZE			= 2,
	GUNYAH_ERROR_ARG_ALIGN			= 3,

	GUNYAH_ERROR_NOMEM			= 10,

	GUNYAH_ERROR_ADDR_OVFL			= 20,
	GUNYAH_ERROR_ADDR_UNFL			= 21,
	GUNYAH_ERROR_ADDR_INVAL			= 22,

	GUNYAH_ERROR_DENIED			= 30,
	GUNYAH_ERROR_BUSY			= 31,
	GUNYAH_ERROR_IDLE			= 32,

	GUNYAH_ERROR_IRQ_BOUND			= 40,
	GUNYAH_ERROR_IRQ_UNBOUND		= 41,

	GUNYAH_ERROR_CSPACE_CAP_NULL		= 50,
	GUNYAH_ERROR_CSPACE_CAP_REVOKED		= 51,
	GUNYAH_ERROR_CSPACE_WRONG_OBJ_TYPE	= 52,
	GUNYAH_ERROR_CSPACE_INSUF_RIGHTS	= 53,
	GUNYAH_ERROR_CSPACE_FULL		= 54,

	GUNYAH_ERROR_MSGQUEUE_EMPTY		= 60,
	GUNYAH_ERROR_MSGQUEUE_FULL		= 61,
	/* clang-format on */
};

/**
 * gunyah_error_remap() - Remap Gunyah hypervisor errors into a Linux error code
 * @gunyah_error: Gunyah hypercall return value
 */
static inline int gunyah_error_remap(enum gunyah_error gunyah_error)
{
	switch (gunyah_error) {
	case GUNYAH_ERROR_OK:
		return 0;
	case GUNYAH_ERROR_NOMEM:
		return -ENOMEM;
	case GUNYAH_ERROR_DENIED:
	case GUNYAH_ERROR_CSPACE_CAP_NULL:
	case GUNYAH_ERROR_CSPACE_CAP_REVOKED:
	case GUNYAH_ERROR_CSPACE_WRONG_OBJ_TYPE:
	case GUNYAH_ERROR_CSPACE_INSUF_RIGHTS:
		return -EACCES;
	case GUNYAH_ERROR_CSPACE_FULL:
	case GUNYAH_ERROR_BUSY:
	case GUNYAH_ERROR_IDLE:
		return -EBUSY;
	case GUNYAH_ERROR_IRQ_BOUND:
	case GUNYAH_ERROR_IRQ_UNBOUND:
	case GUNYAH_ERROR_MSGQUEUE_FULL:
	case GUNYAH_ERROR_MSGQUEUE_EMPTY:
		return -EIO;
	case GUNYAH_ERROR_UNIMPLEMENTED:
		return -EOPNOTSUPP;
	case GUNYAH_ERROR_RETRY:
		return -EAGAIN;
	default:
		return -EINVAL;
	}
}

enum gunyah_api_feature {
	/* clang-format off */
	GUNYAH_FEATURE_DOORBELL		= 1,
	GUNYAH_FEATURE_MSGQUEUE		= 2,
	GUNYAH_FEATURE_VCPU		= 5,
	GUNYAH_FEATURE_MEMEXTENT	= 6,
	/* clang-format on */
};

bool arch_is_gunyah_guest(void);

#define GUNYAH_API_V1 1

/* Other bits reserved for future use and will be zero */
/* clang-format off */
#define GUNYAH_API_INFO_API_VERSION_MASK	GENMASK_ULL(13, 0)
#define GUNYAH_API_INFO_BIG_ENDIAN		BIT_ULL(14)
#define GUNYAH_API_INFO_IS_64BIT		BIT_ULL(15)
#define GUNYAH_API_INFO_VARIANT_MASK 		GENMASK_ULL(63, 56)
/* clang-format on */

struct gunyah_hypercall_hyp_identify_resp {
	u64 api_info;
	u64 flags[3];
};

static inline u16
gunyah_api_version(const struct gunyah_hypercall_hyp_identify_resp *gunyah_api)
{
	return FIELD_GET(GUNYAH_API_INFO_API_VERSION_MASK,
			 gunyah_api->api_info);
}

void gunyah_hypercall_hyp_identify(
	struct gunyah_hypercall_hyp_identify_resp *hyp_identity);

enum gunyah_error gunyah_hypercall_bell_send(u64 capid, u64 new_flags,
					     u64 *old_flags);
enum gunyah_error gunyah_hypercall_bell_set_mask(u64 capid, u64 enable_mask,
						 u64 ack_mask);

/* Immediately raise RX vIRQ on receiver VM */
#define GUNYAH_HYPERCALL_MSGQ_TX_FLAGS_PUSH BIT(0)

enum gunyah_error gunyah_hypercall_msgq_send(u64 capid, size_t size, void *buff,
					     u64 tx_flags, bool *ready);
enum gunyah_error gunyah_hypercall_msgq_recv(u64 capid, void *buff, size_t size,
					     size_t *recv_size, bool *ready);

#define GUNYAH_ADDRSPACE_SELF_CAP 0

/* clang-format off */
#define GUNYAH_MEMEXTENT_MAPPING_USER_ACCESS		GENMASK_ULL(2, 0)
#define GUNYAH_MEMEXTENT_MAPPING_KERNEL_ACCESS		GENMASK_ULL(6, 4)
#define GUNYAH_MEMEXTENT_MAPPING_TYPE			GENMASK_ULL(23, 16)
/* clang-format on */

enum gunyah_memextent_donate_type {
	/* clang-format off */
	GUNYAH_MEMEXTENT_DONATE_TO_CHILD		= 0,
	GUNYAH_MEMEXTENT_DONATE_TO_PARENT		= 1,
	GUNYAH_MEMEXTENT_DONATE_TO_SIBLING		= 2,
	GUNYAH_MEMEXTENT_DONATE_TO_PROTECTED		= 3,
	GUNYAH_MEMEXTENT_DONATE_FROM_PROTECTED		= 4,
	/* clang-format on */
};

enum gunyah_addrspace_map_flag_bits {
	/* clang-format off */
	GUNYAH_ADDRSPACE_MAP_FLAG_PARTIAL	= 0,
	GUNYAH_ADDRSPACE_MAP_FLAG_PRIVATE	= 1,
	GUNYAH_ADDRSPACE_MAP_FLAG_VMMIO		= 2,
	GUNYAH_ADDRSPACE_MAP_FLAG_NOSYNC	= 31,
	/* clang-format on */
};

enum gunyah_error gunyah_hypercall_addrspace_map(u64 capid, u64 extent_capid,
						 u64 vbase, u32 extent_attrs,
						 u32 flags, u64 offset,
						 u64 size);
enum gunyah_error gunyah_hypercall_addrspace_unmap(u64 capid, u64 extent_capid,
						   u64 vbase, u32 flags,
						   u64 offset, u64 size);

/* clang-format off */
#define GUNYAH_MEMEXTENT_OPTION_TYPE_MASK	GENMASK_ULL(7, 0)
#define GUNYAH_MEMEXTENT_OPTION_NOSYNC		BIT(31)
/* clang-format on */

enum gunyah_error gunyah_hypercall_memextent_donate(u32 options, u64 from_capid,
						    u64 to_capid, u64 offset,
						    u64 size);

struct gunyah_hypercall_vcpu_run_resp {
	union {
		enum {
			/* clang-format off */
			/* VCPU is ready to run */
			GUNYAH_VCPU_STATE_READY			= 0,
			/* VCPU is sleeping until an interrupt arrives */
			GUNYAH_VCPU_STATE_EXPECTS_WAKEUP	= 1,
			/* VCPU is powered off */
			GUNYAH_VCPU_STATE_POWERED_OFF		= 2,
			/* VCPU is blocked in EL2 for unspecified reason */
			GUNYAH_VCPU_STATE_BLOCKED		= 3,
			/* VCPU has returned for MMIO READ */
			GUNYAH_VCPU_ADDRSPACE_VMMIO_READ	= 4,
			/* VCPU has returned for MMIO WRITE */
			GUNYAH_VCPU_ADDRSPACE_VMMIO_WRITE	= 5,
			/* VCPU blocked on fault where we can demand page */
			GUNYAH_VCPU_ADDRSPACE_PAGE_FAULT	= 7,
			/* clang-format on */
		} state;
		u64 sized_state;
	};
	u64 state_data[3];
};

enum {
	GUNYAH_ADDRSPACE_VMMIO_ACTION_EMULATE = 0,
	GUNYAH_ADDRSPACE_VMMIO_ACTION_RETRY = 1,
	GUNYAH_ADDRSPACE_VMMIO_ACTION_FAULT = 2,
};

enum gunyah_error
gunyah_hypercall_vcpu_run(u64 capid, unsigned long *resume_data,
			  struct gunyah_hypercall_vcpu_run_resp *resp);

int kvm_gunyah_init(void);
#endif
