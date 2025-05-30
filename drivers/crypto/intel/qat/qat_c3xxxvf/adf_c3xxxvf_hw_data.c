// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */
#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_gen2_config.h>
#include <adf_gen2_dc.h>
#include <adf_gen2_hw_csr_data.h>
#include <adf_gen2_hw_data.h>
#include <adf_gen2_pfvf.h>
#include <adf_pfvf_vf_msg.h>
#include "adf_c3xxxvf_hw_data.h"

static struct adf_hw_device_class c3xxxiov_class = {
	.name = ADF_C3XXXVF_DEVICE_NAME,
	.type = DEV_C3XXXVF,
};

static u32 get_accel_mask(struct adf_hw_device_data *self)
{
	return ADF_C3XXXIOV_ACCELERATORS_MASK;
}

static u32 get_ae_mask(struct adf_hw_device_data *self)
{
	return ADF_C3XXXIOV_ACCELENGINES_MASK;
}

static u32 get_num_accels(struct adf_hw_device_data *self)
{
	return ADF_C3XXXIOV_MAX_ACCELERATORS;
}

static u32 get_num_aes(struct adf_hw_device_data *self)
{
	return ADF_C3XXXIOV_MAX_ACCELENGINES;
}

static u32 get_misc_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C3XXXIOV_PMISC_BAR;
}

static u32 get_etr_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C3XXXIOV_ETR_BAR;
}

static enum dev_sku_info get_sku(struct adf_hw_device_data *self)
{
	return DEV_SKU_VF;
}

static int adf_vf_int_noop(struct adf_accel_dev *accel_dev)
{
	return 0;
}

static void adf_vf_void_noop(struct adf_accel_dev *accel_dev)
{
}

void adf_init_hw_data_c3xxxiov(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class = &c3xxxiov_class;
	hw_data->num_banks = ADF_C3XXXIOV_ETR_MAX_BANKS;
	hw_data->num_rings_per_bank = ADF_ETR_MAX_RINGS_PER_BANK;
	hw_data->num_accel = ADF_C3XXXIOV_MAX_ACCELERATORS;
	hw_data->num_logical_accel = 1;
	hw_data->num_engines = ADF_C3XXXIOV_MAX_ACCELENGINES;
	hw_data->tx_rx_gap = ADF_C3XXXIOV_RX_RINGS_OFFSET;
	hw_data->tx_rings_mask = ADF_C3XXXIOV_TX_RINGS_MASK;
	hw_data->ring_to_svc_map = ADF_GEN2_DEFAULT_RING_TO_SRV_MAP;
	hw_data->alloc_irq = adf_vf_isr_resource_alloc;
	hw_data->free_irq = adf_vf_isr_resource_free;
	hw_data->enable_error_correction = adf_vf_void_noop;
	hw_data->init_admin_comms = adf_vf_int_noop;
	hw_data->exit_admin_comms = adf_vf_void_noop;
	hw_data->send_admin_init = adf_vf2pf_notify_init;
	hw_data->init_arb = adf_vf_int_noop;
	hw_data->exit_arb = adf_vf_void_noop;
	hw_data->disable_iov = adf_vf2pf_notify_shutdown;
	hw_data->get_accel_mask = get_accel_mask;
	hw_data->get_ae_mask = get_ae_mask;
	hw_data->get_num_accels = get_num_accels;
	hw_data->get_num_aes = get_num_aes;
	hw_data->get_etr_bar_id = get_etr_bar_id;
	hw_data->get_misc_bar_id = get_misc_bar_id;
	hw_data->get_sku = get_sku;
	hw_data->enable_ints = adf_vf_void_noop;
	hw_data->dev_class->instances++;
	hw_data->dev_config = adf_gen2_dev_config;
	adf_devmgr_update_class_index(hw_data);
	adf_gen2_init_vf_pfvf_ops(&hw_data->pfvf_ops);
	adf_gen2_init_hw_csr_ops(&hw_data->csr_ops);
	adf_gen2_init_dc_ops(&hw_data->dc_ops);
}

void adf_clean_hw_data_c3xxxiov(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class->instances--;
	adf_devmgr_update_class_index(hw_data);
}
