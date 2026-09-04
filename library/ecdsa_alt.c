
/*
 *  Elliptic curve DSA
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 */
#if !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
#include "common.h"

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/hmac_drbg.h"
#endif

#include "mbedtls/platform.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "field_manipulate.h"
#include "reg_sysc_sec_cpu.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/threading.h"

#include "ls_otbn_ecc.h"
#include "ls_otbn_config.h"

#include <zephyr/irq.h>
#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(mbedtls_otbn, CONFIG_LINKEDSEMI_OTBN_LOG_LEVEL);
#define MAX_ECC_CURVE_SIZE   64
#define MBEDTLS_ERR_LS_OTBN_BUSY -0x135
#define ASSERT_MBEDTLS(error) {if(error){__ASSERT_PRINT("mbedtls :stack is too small\n"); err = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL; goto exit;}}

void mbedtls_ls_otbn_moudle_init(void);
int mbedtls_ls_otbn_operation_init(otbn_firmware_t firmware_id);
otbn_firmware_t mbedtls_get_otbn_curve_id(mbedtls_ecp_group_id mbedtls_curve);
int get_curve_otbn_info(uint32_t curve, ecc_remote_addr *info);

bool ecc_random_check(uint8_t *in, uint32_t size)
{
    uint8_t zero_cnt = 0;
    size -= 1;
    while(size--)
    {
        if(in[size] == 0)
        {
            zero_cnt++;
        }else
        {
            zero_cnt = 0;
        }
        if(zero_cnt > 3)
        {
            return false;
        }
    }
    return true;
}

void ecc_p384_random_copy(uint8_t *buf)
{
    uint8_t tmp[16];
    memcpy(tmp, &buf[32], 16);

    memset(&buf[32],0,32);
    memcpy(&buf[40],tmp,16);
}


void reverse_buf(const uint8_t *input, uint8_t *output,uint16_t input_len, uint16_t output_len)
{
    uint8_t tmp[input_len];
    if(input == NULL)
    {
        assert(0);
    }
    for(uint16_t i = 0; i < input_len; i++)
    {
        tmp[i] = input[input_len -i - 1];
    }
    memset(output,0,output_len);
    memcpy(output,tmp,input_len);
}

void mbedtls_ls_OTBN_FIRMWARE_ECDSA_deinit(void)
{
    unsigned int key;
    key = irq_lock();
    ls_otbn_session_release();
    irq_unlock(key);
}

#if defined(MBEDTLS_ECDSA_SIGN_ALT)
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int err = 0;
    uint32_t mode = LS_OTBN_MODE_SIGN;
    uint8_t otbn_msg[MAX_ECC_CURVE_SIZE];
    uint8_t cc_buf[MAX_ECC_CURVE_SIZE];
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;
    ecc_remote_addr otbn_curve_info;

    if(!(grp->id == MBEDTLS_ECP_DP_SECP384R1 || grp->id == MBEDTLS_ECP_DP_SECP256R1 || grp->id == MBEDTLS_ECP_DP_SM2))
    {
        LOG_DBG(" the curve is not supported, curve id: %d\n",grp->id);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    err = mbedtls_ls_otbn_operation_init(mbedtls_get_otbn_curve_id(grp->id));
    if(err)
    {
        return err;
    }

    if(get_curve_otbn_info(mbedtls_get_otbn_curve_id(grp->id),&otbn_curve_info) != 0)
    {
        LOG_DBG("Otbn err state or curve don't adaptived\n");
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }

    uint16_t size_align = 0;
    if(otbn_curve_info.curve_size == 48)
    {
        size_align = 64;
    }else
    {
        size_align = otbn_curve_info.curve_size;
    }
    f_rng(p_rng,cc_buf,otbn_curve_info.curve_size);

    if(!ecc_random_check(cc_buf,otbn_curve_info.curve_size))
    {
        LOG_DBG("mbedtls :trng error\n");
        err = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto exit;
    }
    reverse_buf(cc_buf,cc_buf,otbn_curve_info.curve_size,otbn_curve_info.curve_size);
    /* for compare with mbedtls software implementation*/
    if(grp->id == MBEDTLS_ECP_DP_SECP384R1)
    {
        ecc_p384_random_copy(cc_buf);
    }

    if(ls_otbn_dmem_write(otbn_curve_info.remote_random_addr, (uint32_t *)cc_buf, size_align))
    {
        LOG_DBG("mbedtls :trng error\n");
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }
    if(err == 0)
    {
        err |=ls_otbn_dmem_write(otbn_curve_info.remote_mode_addr, (uint32_t *)&mode, 4);
        mbedtls_mpi_write_binary_le(d,cc_buf,n_size);
        err |=ls_otbn_dmem_write(otbn_curve_info.remote_addr_d0, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err |=ls_otbn_dmem_set(otbn_curve_info.remote_addr_d1,0,otbn_curve_info.curve_size);
        reverse_buf(buf,otbn_msg,use_size,otbn_curve_info.curve_size);
        err |=ls_otbn_dmem_write(otbn_curve_info.remote_addr_msg, (uint32_t *)otbn_msg, otbn_curve_info.curve_size);
    }
    if(err != 0)
    {
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        LOG_DBG("mbedtls :otbn error 1\n");
        goto exit;
    }

    ls_otbn_cmd(OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        LOG_DBG("mbedtls: OTBN operation causes an error, error bit : 0x%x\r\n",err);
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    else
    {
        ls_otbn_dmem_read(otbn_curve_info.remote_addr_r, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err = mbedtls_mpi_read_binary_le(r,cc_buf,otbn_curve_info.curve_size);
        ASSERT_MBEDTLS(err);
        ls_otbn_dmem_read(otbn_curve_info.remote_addr_s, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err = mbedtls_mpi_read_binary_le(s,cc_buf,otbn_curve_info.curve_size);
        ASSERT_MBEDTLS(err);
    }

exit:
    (void)mbedtls_ls_OTBN_FIRMWARE_ECDSA_deinit();
    return err;
}
#endif


#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    int err = 0;
    uint32_t mode = LS_OTBN_MODE_VERIFY;
    uint8_t cc_buf[MAX_ECC_CURVE_SIZE];
    uint8_t r_x[MAX_ECC_CURVE_SIZE];
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;
    ecc_remote_addr otbn_curve_info;

    if(!(grp->id == MBEDTLS_ECP_DP_SECP384R1 || grp->id == MBEDTLS_ECP_DP_SECP256R1 || grp->id == MBEDTLS_ECP_DP_SM2))
    {
        LOG_DBG(" the curve is not supported, curve id: %d\n",grp->id);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    err = mbedtls_ls_otbn_operation_init(mbedtls_get_otbn_curve_id(grp->id));
    if(err)
    {
        LOG_DBG("mbedtls : otbn initial failed");
        return err;
    }

    if(get_curve_otbn_info(mbedtls_get_otbn_curve_id(grp->id),&otbn_curve_info) != 0)
    {
        LOG_DBG("Otbn err state or curve don't adaptived\n");
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }

    err = ls_otbn_dmem_write(otbn_curve_info.remote_mode_addr, (uint32_t *)&mode, 4);
    if(err != 0)
    {
        LOG_DBG("mbedtls : MBEDTLS_ERR_ECP_IN_PROGRESS 1\n");
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }

    ASSERT_MBEDTLS(mbedtls_mpi_write_binary_le(&Q->X,cc_buf,n_size));
    err |= ls_otbn_dmem_write(otbn_curve_info.remote_addr_qx, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
    ASSERT_MBEDTLS(mbedtls_mpi_write_binary_le(&Q->Y,cc_buf,n_size));
    err |= ls_otbn_dmem_write(otbn_curve_info.remote_addr_qy, (uint32_t *)cc_buf, otbn_curve_info.curve_size);

    reverse_buf(buf,cc_buf,use_size,otbn_curve_info.curve_size);
    err |= ls_otbn_dmem_write(otbn_curve_info.remote_addr_msg, (uint32_t *)cc_buf, otbn_curve_info.curve_size);

    ASSERT_MBEDTLS(mbedtls_mpi_write_binary_le(s,cc_buf,n_size));
    err |= ls_otbn_dmem_write(otbn_curve_info.remote_addr_s, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
    ASSERT_MBEDTLS(mbedtls_mpi_write_binary_le(r,cc_buf,n_size));
    err |= ls_otbn_dmem_write(otbn_curve_info.remote_addr_r, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
    if(err != 0)
    {
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }

    ls_otbn_cmd(OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        LOG_DBG("mbedtls: OTBN operation causes an error, error bit : 0x%x\r\n",err);
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    else
    {
        ls_otbn_dmem_read(otbn_curve_info.remote_addr_r_x, (uint32_t *)r_x, otbn_curve_info.curve_size);
        if(memcmp(r_x,cc_buf,otbn_curve_info.curve_size))
        {
            err = MBEDTLS_ERR_ECP_VERIFY_FAILED;
            LOG_DBG("mbedtls: ecc verify failed, curve id: %d\n",grp->id);
        }
    }

exit:
    (void)mbedtls_ls_OTBN_FIRMWARE_ECDSA_deinit();
    return err;
}
#endif


#if defined(MBEDTLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int err = 0;
    uint32_t mode = LS_OTBN_MODE_KEYGEN;
    uint8_t cc_buf[MAX_ECC_CURVE_SIZE];
    // size_t n_size = (ctx->grp.nbits + 7) / 8;
    ecc_remote_addr otbn_curve_info;

    if(!(gid == MBEDTLS_ECP_DP_SECP384R1 || gid == MBEDTLS_ECP_DP_SECP256R1 || gid == MBEDTLS_ECP_DP_SM2))
    {
        LOG_DBG(" the curve is not supported, curve id: %d\n",gid);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    err = mbedtls_ls_otbn_operation_init(mbedtls_get_otbn_curve_id(gid));
    if(err)
    {
        return err;
    }

    if(get_curve_otbn_info(mbedtls_get_otbn_curve_id(gid),&otbn_curve_info) != 0)
    {
        LOG_DBG("Otbn err state or curve don't adaptived\n");
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }

    err = ls_otbn_dmem_write(otbn_curve_info.remote_mode_addr, (uint32_t *)&mode, 4);
    if(err != 0)
    {
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }
    uint16_t size_align = 0;
    if(otbn_curve_info.curve_size == 48)
    {
        size_align = 64;
    }else
    {
        size_align = otbn_curve_info.curve_size;
    }
    f_rng(p_rng,cc_buf,otbn_curve_info.curve_size);

    if(!ecc_random_check(cc_buf,otbn_curve_info.curve_size))
    {
        LOG_DBG("mbedtls :trng error\n");
        err = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto exit;
    }
    reverse_buf(cc_buf,cc_buf,otbn_curve_info.curve_size,otbn_curve_info.curve_size);
    /* for compare with mbedtls software implementation*/
    if(gid == MBEDTLS_ECP_DP_SECP384R1)
    {
        ecc_p384_random_copy(cc_buf);
    }
    err = ls_otbn_dmem_write(otbn_curve_info.remote_random_addr, (uint32_t *)cc_buf, size_align);
    if(err != 0)
    {
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
        goto exit;
    }

    ls_otbn_cmd(OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        LOG_DBG("mbedtls: OTBN operation causes an error, error bit : 0x%x\r\n",err);
        err = MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    else
    {
        ls_otbn_dmem_read(otbn_curve_info.remote_addr_d0, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err = mbedtls_mpi_read_binary_le(&ctx->d,cc_buf,otbn_curve_info.curve_size);
        ASSERT_MBEDTLS(err);
        ls_otbn_dmem_read(otbn_curve_info.remote_addr_qx, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err = mbedtls_mpi_read_binary_le(&ctx->Q.X,cc_buf,otbn_curve_info.curve_size);
        ASSERT_MBEDTLS(err);
        ls_otbn_dmem_read(otbn_curve_info.remote_addr_qy, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err = mbedtls_mpi_read_binary_le(&ctx->Q.Y,cc_buf,otbn_curve_info.curve_size);
        ASSERT_MBEDTLS(err);
    }

exit:
    (void)mbedtls_ls_OTBN_FIRMWARE_ECDSA_deinit();
    return err;
}

#endif

otbn_firmware_t mbedtls_get_otbn_curve_id(mbedtls_ecp_group_id mbedtls_curve)
{
    otbn_firmware_t id = OTBN_FIRMWARE_UNUSED;
    switch (mbedtls_curve)
    {
    case MBEDTLS_ECP_DP_SECP256R1:
        id = OTBN_FIRMWARE_ECDSA_P256;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        id = OTBN_FIRMWARE_ECDSA_P384;
        break;
    case MBEDTLS_ECP_DP_SM2:
        id = OTBN_FIRMWARE_SM2;
        break;
    default:
        break;
    }

    return id;
}


#endif /* MBEDTLS_ECDSA_C */
#endif /* !CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT */