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
#include "otbn_rsa_keygen.h"

#include <string.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(mbedtls_otbn, CONFIG_LINKEDSEMI_OTBN_LOG_LEVEL);

static void reverse_buf(const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = in[len - 1 - i];
    }
}

static int rsa_otbn_load_app(void)
{
    int ret;

    if (!HAL_OTBN_In_Idle_State()) {
        LOG_ERR("OTBN not idle before loading RSA firmware");
        return -EBUSY;
    }

    ret = ls_otbn_imem_write(0, (uint32_t *)rsa_imem, RSA_IMEM_SIZE);
    if (ret == 0) {
        /* The IMEM image changed: publish it via the shared firmware state
         * so other modules (hash/ECC) reload on their next use. */
        ls_otbn_imem_firmware_confirm(OTBN_FIRMWARE_RSA_MODEXP);
    }
    return ret;
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

/* Adapter between the mbedtls RNG signature and the callback shape used by
 * otbn_rsa_keygen(). The keygen algorithm itself lives in
 * zephyr/soc/linkedsemi/lsqsh/otbn/otbn_rsa_keygen.c. */
typedef struct {
    int (*f_rng)(void *, unsigned char *, size_t);
    void *p_rng;
} rsa_otbn_rng_ctx_t;

static int rsa_otbn_rng_trampoline(void *ctx, uint8_t *buf, size_t len)
{
    rsa_otbn_rng_ctx_t *rng = (rsa_otbn_rng_ctx_t *)ctx;

    return rng->f_rng(rng->p_rng, buf, len);
}

int mbedtls_rsa_gen_key_otbn(mbedtls_rsa_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng,
                             unsigned int nbits, int exponent)
{
    int ret = -ENOTSUP;
    size_t num_bytes = nbits / 8;
    size_t prime_bytes = num_bytes / 2;
    otbn_rsa_keygen_size_t size;
    /* 4-byte aligned: otbn_rsa_keygen() passes these straight to the OTBN
     * memory helpers, which program the DMEM bus from 32-bit words. */
    uint8_t p_le[MBEDTLS_MPI_MAX_SIZE / 2] __aligned(4);
    uint8_t q_le[MBEDTLS_MPI_MAX_SIZE / 2] __aligned(4);
    uint8_t n_le[MBEDTLS_MPI_MAX_SIZE] __aligned(4);
    uint8_t d_le[MBEDTLS_MPI_MAX_SIZE] __aligned(4);
    rsa_otbn_rng_ctx_t rng_ctx = { .f_rng = f_rng, .p_rng = p_rng };
    otbn_rsa_keygen_req_t req;
    mbedtls_mpi N, E, D, P, Q, DP, DQ, QP;
    mbedtls_rsa_context tmp;

    if (exponent != 65537) {
        return -ENOTSUP;
    }

    switch (nbits) {
    case 2048:
        size = OTBN_RSA_KEYGEN_2048;
        break;
    case 3072:
        size = OTBN_RSA_KEYGEN_3072;
        break;
    case 4096:
        size = OTBN_RSA_KEYGEN_4096;
        break;
    default:
        return -ENOTSUP;
    }

    req.size = size;
    req.rng = rsa_otbn_rng_trampoline;
    req.rng_ctx = &rng_ctx;
    req.p_le = p_le;
    req.q_le = q_le;
    req.n_le = n_le;
    req.d_le = d_le;

    /* Runs the whole search (candidate generation, small-prime trial division,
     * Miller-Rabin and n/d derivation) under one OTBN session. */
    ret = otbn_rsa_keygen(&req);
    if (ret != 0) {
        LOG_ERR("OTBN RSA keygen failed: %d", ret);
        goto exit;
    }

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);
    mbedtls_rsa_init(&tmp);

    ret = mbedtls_mpi_read_binary_le(&N, n_le, num_bytes);
    if (ret != 0) {
        goto mpi_exit;
    }

    ret = mbedtls_mpi_lset(&E, exponent);
    if (ret != 0) {
        goto mpi_exit;
    }

    ret = mbedtls_mpi_read_binary_le(&D, d_le, num_bytes);
    if (ret != 0) {
        goto mpi_exit;
    }

    ret = mbedtls_mpi_read_binary_le(&P, p_le, prime_bytes);
    if (ret != 0) {
        goto mpi_exit;
    }

    ret = mbedtls_mpi_read_binary_le(&Q, q_le, prime_bytes);
    if (ret != 0) {
        goto mpi_exit;
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    ret = mbedtls_rsa_deduce_crt(&P, &Q, &D, &DP, &DQ, &QP);
    if (ret != 0) {
        goto mpi_exit;
    }
#endif

    tmp.len = num_bytes;
    mbedtls_mpi_swap(&tmp.N, &N);
    mbedtls_mpi_swap(&tmp.E, &E);
    mbedtls_mpi_swap(&tmp.D, &D);
    mbedtls_mpi_swap(&tmp.P, &P);
    mbedtls_mpi_swap(&tmp.Q, &Q);
#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_swap(&tmp.DP, &DP);
    mbedtls_mpi_swap(&tmp.DQ, &DQ);
    mbedtls_mpi_swap(&tmp.QP, &QP);
#endif

    ret = mbedtls_rsa_check_privkey(&tmp);
    if (ret == 0) {
        ctx->len = num_bytes;
        mbedtls_mpi_swap(&ctx->N, &tmp.N);
        mbedtls_mpi_swap(&ctx->E, &tmp.E);
        mbedtls_mpi_swap(&ctx->D, &tmp.D);
        mbedtls_mpi_swap(&ctx->P, &tmp.P);
        mbedtls_mpi_swap(&ctx->Q, &tmp.Q);
#if !defined(MBEDTLS_RSA_NO_CRT)
        mbedtls_mpi_swap(&ctx->DP, &tmp.DP);
        mbedtls_mpi_swap(&ctx->DQ, &tmp.DQ);
        mbedtls_mpi_swap(&ctx->QP, &tmp.QP);
#endif
    }

mpi_exit:
    mbedtls_rsa_free(&tmp);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);

exit:
    mbedtls_platform_zeroize(p_le, sizeof(p_le));
    mbedtls_platform_zeroize(q_le, sizeof(q_le));
    mbedtls_platform_zeroize(n_le, sizeof(n_le));
    mbedtls_platform_zeroize(d_le, sizeof(d_le));

    return ret;
}

/*
 * Byte-level entry point for the OTBN delegation server.
 *
 * A delegated request arrives as raw buffers: there is no mbedtls_rsa_context
 * to call with, and importing one would cost a full MPI round trip on the peer
 * for no gain. The semantics are those of mbedtls_rsa_public_otbn() /
 * mbedtls_rsa_private_otbn() with exp = e or d -- big-endian buffers,
 * num_bytes = modulus length (256/384/512), and the same F4 shortcut for a
 * 65537 public exponent, so the delegated result matches the local one.
 */
int mbedtls_ls_otbn_rsa_modexp(const uint8_t *input, uint8_t *output,
                               const uint8_t *exp, const uint8_t *n,
                               size_t num_bytes, bool is_public)
{
    uint8_t n_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t exp_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t in_le[MBEDTLS_MPI_MAX_SIZE];
    uint8_t out_le[MBEDTLS_MPI_MAX_SIZE];
    uint32_t e_val = 0;
    bool is_f4 = false;
    uint32_t mode;
    int ret;

    if (num_bytes != 256 && num_bytes != 384 && num_bytes != 512) {
        return -ENOTSUP;
    }

    reverse_buf(input, in_le, num_bytes);
    reverse_buf(n, n_le, num_bytes);
    reverse_buf(exp, exp_le, num_bytes);
    if (is_public) {
        e_val = exp_le[0] | (exp_le[1] << 8) | (exp_le[2] << 16) | (exp_le[3] << 24);
        if (e_val == 65537) {
            is_f4 = true;
        }
    }

    mode = rsa_otbn_select_mode(num_bytes * 8, is_public, is_f4);
    if (mode == 0) {
        ret = -EINVAL;
        goto exit;
    }

    ret = rsa_otbn_modexp(in_le, out_le, mode, is_f4 ? NULL : exp_le, n_le, num_bytes);
    if (ret != 0) {
        goto exit;
    }
    reverse_buf(out_le, output, num_bytes);

exit:
    mbedtls_platform_zeroize(n_le, sizeof(n_le));
    mbedtls_platform_zeroize(exp_le, sizeof(exp_le));
    mbedtls_platform_zeroize(in_le, sizeof(in_le));
    mbedtls_platform_zeroize(out_le, sizeof(out_le));

    return ret;
}

#endif /* MBEDTLS_RSA_C && MBEDTLS_RSA_OTBN_HOOK && !delegation client */
