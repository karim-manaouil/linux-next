/*
 * Cryptographic API.
 *
 * Glue code for the SHA256 Secure Hash Algorithm assembler implementations
 * using SSSE3, AVX, AVX2, and SHA-NI instructions.
 *
 * This file is based on sha256_generic.c
 *
 * Copyright (C) 2013 Intel Corporation.
 *
 * Author:
 *     Tim Chen <tim.c.chen@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <asm/cpu_device_id.h>
#include <crypto/internal/hash.h>
#include <crypto/sha2.h>
#include <crypto/sha256_base.h>
#include <linux/kernel.h>
#include <linux/module.h>

asmlinkage void sha256_transform_ssse3(struct crypto_sha256_state *state,
				       const u8 *data, int blocks);

static const struct x86_cpu_id module_cpu_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_SHA_NI, NULL),
	X86_MATCH_FEATURE(X86_FEATURE_AVX2, NULL),
	X86_MATCH_FEATURE(X86_FEATURE_AVX, NULL),
	X86_MATCH_FEATURE(X86_FEATURE_SSSE3, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, module_cpu_ids);

static int _sha256_update(struct shash_desc *desc, const u8 *data,
			  unsigned int len,
			  sha256_block_fn *sha256_xform)
{
	int remain;

	/*
	 * Make sure struct crypto_sha256_state begins directly with the SHA256
	 * 256-bit internal state, as this is what the asm functions expect.
	 */
	BUILD_BUG_ON(offsetof(struct crypto_sha256_state, state) != 0);

	kernel_fpu_begin();
	remain = sha256_base_do_update_blocks(desc, data, len, sha256_xform);
	kernel_fpu_end();

	return remain;
}

static int sha256_finup(struct shash_desc *desc, const u8 *data,
	      unsigned int len, u8 *out, sha256_block_fn *sha256_xform)
{
	kernel_fpu_begin();
	sha256_base_do_finup(desc, data, len, sha256_xform);
	kernel_fpu_end();

	return sha256_base_finish(desc, out);
}

static int sha256_ssse3_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	return _sha256_update(desc, data, len, sha256_transform_ssse3);
}

static int sha256_ssse3_finup(struct shash_desc *desc, const u8 *data,
	      unsigned int len, u8 *out)
{
	return sha256_finup(desc, data, len, out, sha256_transform_ssse3);
}

static int sha256_ssse3_digest(struct shash_desc *desc, const u8 *data,
	      unsigned int len, u8 *out)
{
	return sha256_base_init(desc) ?:
	       sha256_ssse3_finup(desc, data, len, out);
}

static struct shash_alg sha256_ssse3_algs[] = { {
	.digestsize	=	SHA256_DIGEST_SIZE,
	.init		=	sha256_base_init,
	.update		=	sha256_ssse3_update,
	.finup		=	sha256_ssse3_finup,
	.digest		=	sha256_ssse3_digest,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha256",
		.cra_driver_name =	"sha256-ssse3",
		.cra_priority	=	150,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA256_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	=	SHA224_DIGEST_SIZE,
	.init		=	sha224_base_init,
	.update		=	sha256_ssse3_update,
	.finup		=	sha256_ssse3_finup,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha224",
		.cra_driver_name =	"sha224-ssse3",
		.cra_priority	=	150,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA224_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
} };

static int register_sha256_ssse3(void)
{
	if (boot_cpu_has(X86_FEATURE_SSSE3))
		return crypto_register_shashes(sha256_ssse3_algs,
				ARRAY_SIZE(sha256_ssse3_algs));
	return 0;
}

static void unregister_sha256_ssse3(void)
{
	if (boot_cpu_has(X86_FEATURE_SSSE3))
		crypto_unregister_shashes(sha256_ssse3_algs,
				ARRAY_SIZE(sha256_ssse3_algs));
}

asmlinkage void sha256_transform_avx(struct crypto_sha256_state *state,
				     const u8 *data, int blocks);

static int sha256_avx_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	return _sha256_update(desc, data, len, sha256_transform_avx);
}

static int sha256_avx_finup(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	return sha256_finup(desc, data, len, out, sha256_transform_avx);
}

static int sha256_avx_digest(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	return sha256_base_init(desc) ?:
	       sha256_avx_finup(desc, data, len, out);
}

static struct shash_alg sha256_avx_algs[] = { {
	.digestsize	=	SHA256_DIGEST_SIZE,
	.init		=	sha256_base_init,
	.update		=	sha256_avx_update,
	.finup		=	sha256_avx_finup,
	.digest		=	sha256_avx_digest,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha256",
		.cra_driver_name =	"sha256-avx",
		.cra_priority	=	160,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA256_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	=	SHA224_DIGEST_SIZE,
	.init		=	sha224_base_init,
	.update		=	sha256_avx_update,
	.finup		=	sha256_avx_finup,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha224",
		.cra_driver_name =	"sha224-avx",
		.cra_priority	=	160,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA224_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
} };

static bool avx_usable(void)
{
	if (!cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL)) {
		if (boot_cpu_has(X86_FEATURE_AVX))
			pr_info("AVX detected but unusable.\n");
		return false;
	}

	return true;
}

static int register_sha256_avx(void)
{
	if (avx_usable())
		return crypto_register_shashes(sha256_avx_algs,
				ARRAY_SIZE(sha256_avx_algs));
	return 0;
}

static void unregister_sha256_avx(void)
{
	if (avx_usable())
		crypto_unregister_shashes(sha256_avx_algs,
				ARRAY_SIZE(sha256_avx_algs));
}

asmlinkage void sha256_transform_rorx(struct crypto_sha256_state *state,
				      const u8 *data, int blocks);

static int sha256_avx2_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	return _sha256_update(desc, data, len, sha256_transform_rorx);
}

static int sha256_avx2_finup(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	return sha256_finup(desc, data, len, out, sha256_transform_rorx);
}

static int sha256_avx2_digest(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	return sha256_base_init(desc) ?:
	       sha256_avx2_finup(desc, data, len, out);
}

static struct shash_alg sha256_avx2_algs[] = { {
	.digestsize	=	SHA256_DIGEST_SIZE,
	.init		=	sha256_base_init,
	.update		=	sha256_avx2_update,
	.finup		=	sha256_avx2_finup,
	.digest		=	sha256_avx2_digest,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha256",
		.cra_driver_name =	"sha256-avx2",
		.cra_priority	=	170,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA256_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	=	SHA224_DIGEST_SIZE,
	.init		=	sha224_base_init,
	.update		=	sha256_avx2_update,
	.finup		=	sha256_avx2_finup,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha224",
		.cra_driver_name =	"sha224-avx2",
		.cra_priority	=	170,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA224_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
} };

static bool avx2_usable(void)
{
	if (avx_usable() && boot_cpu_has(X86_FEATURE_AVX2) &&
		    boot_cpu_has(X86_FEATURE_BMI2))
		return true;

	return false;
}

static int register_sha256_avx2(void)
{
	if (avx2_usable())
		return crypto_register_shashes(sha256_avx2_algs,
				ARRAY_SIZE(sha256_avx2_algs));
	return 0;
}

static void unregister_sha256_avx2(void)
{
	if (avx2_usable())
		crypto_unregister_shashes(sha256_avx2_algs,
				ARRAY_SIZE(sha256_avx2_algs));
}

asmlinkage void sha256_ni_transform(struct crypto_sha256_state *digest,
				    const u8 *data, int rounds);

static int sha256_ni_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	return _sha256_update(desc, data, len, sha256_ni_transform);
}

static int sha256_ni_finup(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	return sha256_finup(desc, data, len, out, sha256_ni_transform);
}

static int sha256_ni_digest(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	return sha256_base_init(desc) ?:
	       sha256_ni_finup(desc, data, len, out);
}

static struct shash_alg sha256_ni_algs[] = { {
	.digestsize	=	SHA256_DIGEST_SIZE,
	.init		=	sha256_base_init,
	.update		=	sha256_ni_update,
	.finup		=	sha256_ni_finup,
	.digest		=	sha256_ni_digest,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha256",
		.cra_driver_name =	"sha256-ni",
		.cra_priority	=	250,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA256_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	=	SHA224_DIGEST_SIZE,
	.init		=	sha224_base_init,
	.update		=	sha256_ni_update,
	.finup		=	sha256_ni_finup,
	.descsize	=	sizeof(struct crypto_sha256_state),
	.base		=	{
		.cra_name	=	"sha224",
		.cra_driver_name =	"sha224-ni",
		.cra_priority	=	250,
		.cra_flags	=	CRYPTO_AHASH_ALG_BLOCK_ONLY |
					CRYPTO_AHASH_ALG_FINUP_MAX,
		.cra_blocksize	=	SHA224_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
} };

static int register_sha256_ni(void)
{
	if (boot_cpu_has(X86_FEATURE_SHA_NI))
		return crypto_register_shashes(sha256_ni_algs,
				ARRAY_SIZE(sha256_ni_algs));
	return 0;
}

static void unregister_sha256_ni(void)
{
	if (boot_cpu_has(X86_FEATURE_SHA_NI))
		crypto_unregister_shashes(sha256_ni_algs,
				ARRAY_SIZE(sha256_ni_algs));
}

static int __init sha256_ssse3_mod_init(void)
{
	if (!x86_match_cpu(module_cpu_ids))
		return -ENODEV;

	if (register_sha256_ssse3())
		goto fail;

	if (register_sha256_avx()) {
		unregister_sha256_ssse3();
		goto fail;
	}

	if (register_sha256_avx2()) {
		unregister_sha256_avx();
		unregister_sha256_ssse3();
		goto fail;
	}

	if (register_sha256_ni()) {
		unregister_sha256_avx2();
		unregister_sha256_avx();
		unregister_sha256_ssse3();
		goto fail;
	}

	return 0;
fail:
	return -ENODEV;
}

static void __exit sha256_ssse3_mod_fini(void)
{
	unregister_sha256_ni();
	unregister_sha256_avx2();
	unregister_sha256_avx();
	unregister_sha256_ssse3();
}

module_init(sha256_ssse3_mod_init);
module_exit(sha256_ssse3_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA256 Secure Hash Algorithm, Supplemental SSE3 accelerated");

MODULE_ALIAS_CRYPTO("sha256");
MODULE_ALIAS_CRYPTO("sha256-ssse3");
MODULE_ALIAS_CRYPTO("sha256-avx");
MODULE_ALIAS_CRYPTO("sha256-avx2");
MODULE_ALIAS_CRYPTO("sha224");
MODULE_ALIAS_CRYPTO("sha224-ssse3");
MODULE_ALIAS_CRYPTO("sha224-avx");
MODULE_ALIAS_CRYPTO("sha224-avx2");
MODULE_ALIAS_CRYPTO("sha256-ni");
MODULE_ALIAS_CRYPTO("sha224-ni");
