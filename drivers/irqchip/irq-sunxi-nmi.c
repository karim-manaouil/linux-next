/*
 * Allwinner A20/A31 SoCs NMI IRQ chip driver.
 *
 * Carlo Caione <carlo.caione@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#define DRV_NAME	"sunxi-nmi"
#define pr_fmt(fmt)	DRV_NAME ": " fmt

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>

#define SUNXI_NMI_SRC_TYPE_MASK	0x00000003

#define SUNXI_NMI_IRQ_BIT	BIT(0)

/*
 * For deprecated sun6i-a31-sc-nmi compatible.
 */
#define SUN6I_NMI_CTRL		0x00
#define SUN6I_NMI_PENDING	0x04
#define SUN6I_NMI_ENABLE	0x34

#define SUN7I_NMI_CTRL		0x00
#define SUN7I_NMI_PENDING	0x04
#define SUN7I_NMI_ENABLE	0x08

#define SUN9I_NMI_CTRL		0x00
#define SUN9I_NMI_ENABLE	0x04
#define SUN9I_NMI_PENDING	0x08

enum {
	SUNXI_SRC_TYPE_LEVEL_LOW = 0,
	SUNXI_SRC_TYPE_EDGE_FALLING,
	SUNXI_SRC_TYPE_LEVEL_HIGH,
	SUNXI_SRC_TYPE_EDGE_RISING,
};

struct sunxi_sc_nmi_data {
	struct {
		u32	ctrl;
		u32	pend;
		u32	enable;
	} reg_offs;
	u32		enable_val;
};

static const struct sunxi_sc_nmi_data sun6i_data __initconst = {
	.reg_offs.ctrl		= SUN6I_NMI_CTRL,
	.reg_offs.pend		= SUN6I_NMI_PENDING,
	.reg_offs.enable	= SUN6I_NMI_ENABLE,
};

static const struct sunxi_sc_nmi_data sun7i_data __initconst = {
	.reg_offs.ctrl		= SUN7I_NMI_CTRL,
	.reg_offs.pend		= SUN7I_NMI_PENDING,
	.reg_offs.enable	= SUN7I_NMI_ENABLE,
};

static const struct sunxi_sc_nmi_data sun9i_data __initconst = {
	.reg_offs.ctrl		= SUN9I_NMI_CTRL,
	.reg_offs.pend		= SUN9I_NMI_PENDING,
	.reg_offs.enable	= SUN9I_NMI_ENABLE,
};

static const struct sunxi_sc_nmi_data sun55i_a523_data __initconst = {
	.reg_offs.ctrl		= SUN9I_NMI_CTRL,
	.reg_offs.pend		= SUN9I_NMI_PENDING,
	.reg_offs.enable	= SUN9I_NMI_ENABLE,
	.enable_val		= BIT(31),
};

static inline void sunxi_sc_nmi_write(struct irq_chip_generic *gc, u32 off, u32 val)
{
	irq_reg_writel(gc, val, off);
}

static inline u32 sunxi_sc_nmi_read(struct irq_chip_generic *gc, u32 off)
{
	return irq_reg_readl(gc, off);
}

static void sunxi_sc_nmi_handle_irq(struct irq_desc *desc)
{
	struct irq_domain *domain = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);

	chained_irq_enter(chip, desc);
	generic_handle_domain_irq(domain, 0);
	chained_irq_exit(chip, desc);
}

static int sunxi_sc_nmi_set_type(struct irq_data *data, unsigned int flow_type)
{
	struct irq_chip_generic *gc = irq_data_get_irq_chip_data(data);
	struct irq_chip_type *ct = gc->chip_types;
	u32 src_type_reg;
	u32 ctrl_off = ct->regs.type;
	unsigned int src_type;
	unsigned int i;

	guard(raw_spinlock)(&gc->lock);

	switch (flow_type & IRQF_TRIGGER_MASK) {
	case IRQ_TYPE_EDGE_FALLING:
		src_type = SUNXI_SRC_TYPE_EDGE_FALLING;
		break;
	case IRQ_TYPE_EDGE_RISING:
		src_type = SUNXI_SRC_TYPE_EDGE_RISING;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		src_type = SUNXI_SRC_TYPE_LEVEL_HIGH;
		break;
	case IRQ_TYPE_NONE:
	case IRQ_TYPE_LEVEL_LOW:
		src_type = SUNXI_SRC_TYPE_LEVEL_LOW;
		break;
	default:
		pr_err("Cannot assign multiple trigger modes to IRQ %d.\n", data->irq);
		return -EBADR;
	}

	irqd_set_trigger_type(data, flow_type);
	irq_setup_alt_chip(data, flow_type);

	for (i = 0; i < gc->num_ct; i++, ct++)
		if (ct->type & flow_type)
			ctrl_off = ct->regs.type;

	src_type_reg = sunxi_sc_nmi_read(gc, ctrl_off);
	src_type_reg &= ~SUNXI_NMI_SRC_TYPE_MASK;
	src_type_reg |= src_type;
	sunxi_sc_nmi_write(gc, ctrl_off, src_type_reg);
	return IRQ_SET_MASK_OK;
}

static int __init sunxi_sc_nmi_irq_init(struct device_node *node,
					const struct sunxi_sc_nmi_data *data)
{
	unsigned int irq, clr = IRQ_NOREQUEST | IRQ_NOPROBE | IRQ_NOAUTOEN;
	struct irq_chip_generic *gc;
	struct irq_domain *domain;
	int ret;

	domain = irq_domain_add_linear(node, 1, &irq_generic_chip_ops, NULL);
	if (!domain) {
		pr_err("Could not register interrupt domain.\n");
		return -ENOMEM;
	}

	ret = irq_alloc_domain_generic_chips(domain, 1, 2, DRV_NAME,
					     handle_fasteoi_irq, clr, 0,
					     IRQ_GC_INIT_MASK_CACHE);
	if (ret) {
		pr_err("Could not allocate generic interrupt chip.\n");
		goto fail_irqd_remove;
	}

	irq = irq_of_parse_and_map(node, 0);
	if (irq <= 0) {
		pr_err("unable to parse irq\n");
		ret = -EINVAL;
		goto fail_irqd_remove;
	}

	gc = irq_get_domain_generic_chip(domain, 0);
	gc->reg_base = of_io_request_and_map(node, 0, of_node_full_name(node));
	if (IS_ERR(gc->reg_base)) {
		pr_err("unable to map resource\n");
		ret = PTR_ERR(gc->reg_base);
		goto fail_irqd_remove;
	}

	gc->chip_types[0].type			= IRQ_TYPE_LEVEL_MASK;
	gc->chip_types[0].chip.irq_mask		= irq_gc_mask_clr_bit;
	gc->chip_types[0].chip.irq_unmask	= irq_gc_mask_set_bit;
	gc->chip_types[0].chip.irq_eoi		= irq_gc_ack_set_bit;
	gc->chip_types[0].chip.irq_set_type	= sunxi_sc_nmi_set_type;
	gc->chip_types[0].chip.flags		= IRQCHIP_EOI_THREADED |
						  IRQCHIP_EOI_IF_HANDLED |
						  IRQCHIP_SKIP_SET_WAKE;
	gc->chip_types[0].regs.ack		= data->reg_offs.pend;
	gc->chip_types[0].regs.mask		= data->reg_offs.enable;
	gc->chip_types[0].regs.type		= data->reg_offs.ctrl;

	gc->chip_types[1].type			= IRQ_TYPE_EDGE_BOTH;
	gc->chip_types[1].chip.irq_ack		= irq_gc_ack_set_bit;
	gc->chip_types[1].chip.irq_mask		= irq_gc_mask_clr_bit;
	gc->chip_types[1].chip.irq_unmask	= irq_gc_mask_set_bit;
	gc->chip_types[1].chip.irq_set_type	= sunxi_sc_nmi_set_type;
	gc->chip_types[1].regs.ack		= data->reg_offs.pend;
	gc->chip_types[1].regs.mask		= data->reg_offs.enable;
	gc->chip_types[1].regs.type		= data->reg_offs.ctrl;
	gc->chip_types[1].handler		= handle_edge_irq;

	/* Disable any active interrupts */
	sunxi_sc_nmi_write(gc, data->reg_offs.enable, data->enable_val);

	/* Clear any pending NMI interrupts */
	sunxi_sc_nmi_write(gc, data->reg_offs.pend, SUNXI_NMI_IRQ_BIT);

	irq_set_chained_handler_and_data(irq, sunxi_sc_nmi_handle_irq, domain);

	return 0;

fail_irqd_remove:
	irq_domain_remove(domain);

	return ret;
}

static int __init sun6i_sc_nmi_irq_init(struct device_node *node,
					struct device_node *parent)
{
	return sunxi_sc_nmi_irq_init(node, &sun6i_data);
}
IRQCHIP_DECLARE(sun6i_sc_nmi, "allwinner,sun6i-a31-sc-nmi", sun6i_sc_nmi_irq_init);

static int __init sun7i_sc_nmi_irq_init(struct device_node *node,
					struct device_node *parent)
{
	return sunxi_sc_nmi_irq_init(node, &sun7i_data);
}
IRQCHIP_DECLARE(sun7i_sc_nmi, "allwinner,sun7i-a20-sc-nmi", sun7i_sc_nmi_irq_init);

static int __init sun9i_nmi_irq_init(struct device_node *node,
				     struct device_node *parent)
{
	return sunxi_sc_nmi_irq_init(node, &sun9i_data);
}
IRQCHIP_DECLARE(sun9i_nmi, "allwinner,sun9i-a80-nmi", sun9i_nmi_irq_init);

static int __init sun55i_nmi_irq_init(struct device_node *node,
				      struct device_node *parent)
{
	return sunxi_sc_nmi_irq_init(node, &sun55i_a523_data);
}
IRQCHIP_DECLARE(sun55i_nmi, "allwinner,sun55i-a523-nmi", sun55i_nmi_irq_init);
