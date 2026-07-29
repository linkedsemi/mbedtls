/*
 *  LinkedSemi OTBN hook for RSA public/private operations.
 *
 *  This file implements optional hardware acceleration for
 *  mbedtls_rsa_public() and mbedtls_rsa_private(). When the hook returns 0,
 *  the caller in rsa.c uses the result directly; otherwise it falls back to
 *  the normal software implementation.
 *
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_RSA_OTBN_HOOK) && \
    !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)

#include <errno.h>

#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "rsa_alt_helpers.h"

#include "ls_otbn_config.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "ls_otbn_rsa.h"

#include <string.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(mbedtls, CONFIG_MBEDTLS_LOG_LEVEL);

#define OTBN_FIRMWARE_RSA_MODEXP    OTBN_FIRMWARE_USER_BASE

static void reverse_buf(const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = in[len - 1 - i];
    }
}

static int rsa_otbn_load_app(void)
{
    if (!HAL_OTBN_In_Idle_State()) {
        LOG_ERR("OTBN not idle before loading RSA firmware");
        return -EBUSY;
    }

    return ls_otbn_imem_write(0, (uint32_t *)rsa_imem, RSA_IMEM_SIZE);
}

static uint32_t rsa_otbn_select_mode(size_t n_bits, bool is_public, bool is_f4)
{
    if (is_public) {
        switch (n_bits) {
        case 2048:
            return is_f4 ? MODE_RSA_2048_MODEXP_F4 : MODE_RSA_2048_MODEXP;
        case 3072:
            return is_f4 ? MODE_RSA_3072_MODEXP_F4 : MODE_RSA_3072_MODEXP;
        case 4096:
            return is_f4 ? MODE_RSA_4096_MODEXP_F4 : MODE_RSA_4096_MODEXP;
        }
    } else {
        switch (n_bits) {
        case 2048:
            return MODE_RSA_2048_MODEXP;
        case 3072:
            return MODE_RSA_3072_MODEXP;
        case 4096:
            return MODE_RSA_4096_MODEXP;
        }
    }

    return 0;
}

static int rsa_otbn_modexp(const uint8_t *in_le,
                           uint8_t *out_le,
                           uint32_t mode,
                           const uint8_t *exp_le,
                           const uint8_t *n_le,
                           size_t num_bytes)
{
    int ret;

    ret = ls_otbn_session_acquire(OTBN_FIRMWARE_RSA_MODEXP, 10);
    if (ret != 0) {
        LOG_DBG("OTBN session acquire failed: %d", ret);
        return -EBUSY;
    }

    ret = rsa_otbn_load_app();
    if (ret != 0) {
        LOG_ERR("Failed to load RSA firmware: %d", ret);
        goto exit;
    }

    ret = ls_otbn_dmem_write(RSA_OFFSET_MODE, (uint32_t *)&mode, sizeof(mode));
    if (ret != 0) {
        goto exit;
    }

    if (exp_le != NULL) {
        ret = ls_otbn_dmem_write(RSA_OFFSET_D, (uint32_t *)exp_le, num_bytes);
        if (ret != 0) {
            goto exit;
        }
    }

    ret = ls_otbn_dmem_write(RSA_OFFSET_INOUT, (uint32_t *)in_le, num_bytes);
    if (ret != 0) {
        goto exit;
    }

    ret = ls_otbn_dmem_write(RSA_OFFSET_N, (uint32_t *)n_le, num_bytes);
    if (ret != 0) {
        goto exit;
    }

    ret = ls_otbn_cmd(OTBN_CMD_EXECUTE);
    if (ret != 0 || HAL_OTBN_Error_Bit_Get()) {
        LOG_ERR("OTBN RSA modexp execution failed: %d", ret);
        ret = -EIO;
        goto exit;
    }

    ret = ls_otbn_dmem_read(RSA_OFFSET_INOUT, (uint32_t *)out_le, num_bytes);

exit:
    ls_otbn_session_release();
    return ret;
}

int mbedtls_rsa_public_otbn(mbedtls_rsa_context *ctx,
                            const unsigned char *input,
                            unsigned char *output)
{
    int ret;
    size_t num_bytes = ctx->len;
    uint8_t n_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t exp_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t in_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t out_le[MBEDTLS_MPI_MAX_SIZE];
    uint32_t e_val;
    bool is_f4 = false;
    uint32_t mode;

    if (num_bytes != 256 && num_bytes != 384 && num_bytes != 512) {
        return -ENOTSUP;
    }

    if (mbedtls_rsa_check_pubkey(ctx) != 0) {
        return -EINVAL;
    }

    ret = mbedtls_mpi_write_binary_le(&ctx->N, n_le, num_bytes);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_mpi_write_binary_le(&ctx->E, exp_le, num_bytes);
    if (ret != 0) {
        return ret;
    }

    e_val = exp_le[0] | (exp_le[1] << 8) |
            (exp_le[2] << 16) | (exp_le[3] << 24);
    if (e_val == 65537) {
        is_f4 = true;
    }

    reverse_buf(input, in_le, num_bytes);

    mode = rsa_otbn_select_mode(num_bytes * 8, true, is_f4);
    if (mode == 0) {
        return -EINVAL;
    }

    ret = rsa_otbn_modexp(in_le, out_le, mode,
                          is_f4 ? NULL : exp_le,
                          n_le, num_bytes);
    if (ret != 0) {
        return ret;
    }

    reverse_buf(out_le, output, num_bytes);

    mbedtls_platform_zeroize(n_le, sizeof(n_le));
    mbedtls_platform_zeroize(exp_le, sizeof(exp_le));
    mbedtls_platform_zeroize(in_le, sizeof(in_le));
    mbedtls_platform_zeroize(out_le, sizeof(out_le));

    return 0;
}

int mbedtls_rsa_private_otbn(mbedtls_rsa_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng,
                             const unsigned char *input,
                             unsigned char *output)
{
    int ret;
    size_t num_bytes = ctx->len;
    uint8_t n_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t d_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t in_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t out_le[MBEDTLS_MPI_MAX_SIZE];
    uint32_t mode;

    (void)f_rng;
    (void)p_rng;

    if (num_bytes != 256 && num_bytes != 384 && num_bytes != 512) {
        return -ENOTSUP;
    }

    /* The OTBN firmware needs the full private exponent D. If only CRT
     * parameters are present, try to complete the key first. */
    if (mbedtls_mpi_cmp_int(&ctx->D, 0) == 0) {
        ret = mbedtls_rsa_complete(ctx);
        if (ret != 0 || mbedtls_mpi_cmp_int(&ctx->D, 0) == 0) {
            return -EINVAL;
        }
    }

    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        return -EINVAL;
    }

    ret = mbedtls_mpi_write_binary_le(&ctx->N, n_le, num_bytes);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_mpi_write_binary_le(&ctx->D, d_le, num_bytes);
    if (ret != 0) {
        return ret;
    }

    reverse_buf(input, in_le, num_bytes);

    mode = rsa_otbn_select_mode(num_bytes * 8, false, false);
    if (mode == 0) {
        return -EINVAL;
    }

    ret = rsa_otbn_modexp(in_le, out_le, mode, d_le,
                          n_le, num_bytes);
    if (ret != 0) {
        return ret;
    }

    reverse_buf(out_le, output, num_bytes);

    mbedtls_platform_zeroize(n_le, sizeof(n_le));
    mbedtls_platform_zeroize(d_le, sizeof(d_le));
    mbedtls_platform_zeroize(in_le, sizeof(in_le));
    mbedtls_platform_zeroize(out_le, sizeof(out_le));

    return 0;
}

#endif /* MBEDTLS_RSA_C && MBEDTLS_RSA_OTBN_HOOK && !delegation client */
